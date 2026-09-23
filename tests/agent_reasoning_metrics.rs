use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use again::store::{
    GatewayCallAcquisition, GatewayCompletion, GatewayCoordinatorInputV1, GatewayDependencyV1,
    GatewayExecutionStart, GatewayFreshnessEvidenceV1, GatewayOperationDispositionV1, Store,
    StoredResult, ValidatedGatewayReadV1, gateway_policy_digest,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

const POLICY: &str = "reasoning-metrics-proof-v1";
const OMITTED_BYTES: i64 = 800;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn digest(label: &str) -> String {
    blake3::hash(label.as_bytes()).to_hex().to_string()
}

fn binding() -> ValidatedGatewayReadV1 {
    let state_digest = digest("metrics-state");
    ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
        request_digest: digest("metrics-request"),
        state_digest: state_digest.clone(),
        policy_digest: gateway_policy_digest(POLICY),
        operation: GatewayOperationDispositionV1::ReplayEligibleRead,
        freshness: GatewayFreshnessEvidenceV1 {
            snapshot_digest: state_digest,
            observed_at_ms: now_ms().saturating_sub(1),
            valid_until_ms: now_ms().saturating_add(60_000),
        },
        dependencies: vec![GatewayDependencyV1 {
            key_digest: digest("metrics-dependency-key"),
            value_digest: digest("metrics-dependency-value"),
        }],
    })
    .unwrap()
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    gateway_result_id: String,
    result: StoredResult,
}

fn fixture() -> Fixture {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let binding = binding();
    let lease = match store
        .acquire_gateway_call(&binding, "metrics-owner")
        .unwrap()
    {
        GatewayCallAcquisition::Leader { lease_id, .. } => lease_id,
        other => panic!("expected leader, got {other:?}"),
    };
    let result = store
        .insert_result(
            binding.request_digest(),
            b"verified-output",
            b"verified-diagnostic",
            0,
            37,
            POLICY,
            "{\"proof\":\"exact\"}",
        )
        .unwrap();
    assert_eq!(
        store
            .start_gateway_execution(&lease, "metrics-owner")
            .unwrap(),
        GatewayExecutionStart::Started
    );
    let gateway_result_id = match store.complete_gateway_call(&lease, &result.id).unwrap() {
        GatewayCompletion::Completed {
            gateway_result_id, ..
        } => gateway_result_id,
        other => panic!("expected completion, got {other:?}"),
    };
    drop(store);
    Fixture {
        _temp: temp,
        root,
        gateway_result_id,
        result,
    }
}

fn connection(root: &Path) -> Connection {
    let connection = Connection::open(root.join("again.sqlite")).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    connection
}

fn insert_confirmed_delivery(fixture: &Fixture, duplicate_compact: bool) {
    let mut connection = connection(&fixture.root);
    let transaction = connection.transaction().unwrap();
    let now = now_ms();
    let authorization = digest("authorization");
    let connection_digest = digest("connection");
    let connection_generation = digest("connection-generation");
    let response_request = digest("response-request");
    let call_digest = digest("call");
    let full_envelope = digest("full-envelope");
    let compact_envelope = digest("compact-envelope");
    transaction
        .execute(
            "INSERT INTO gateway_delivery_receipts_v2 (
                 receipt_id, challenge_id, authorization_scope_digest, connection_digest,
                 connection_generation, session_id, turn_id, agent_id, compaction_generation,
                 response_request_id_digest, call_digest, gateway_result_id, result_digest,
                 exact_status, stdout_digest, stdout_bytes, stderr_digest, stderr_bytes,
                 response_envelope_digest, presentation, source_receipt_id, acknowledged_ms
             ) VALUES (
                 'full-receipt', 'full-challenge', ?1, ?2, ?3, 'session', 'turn', 'agent', 4,
                 ?4, ?5, ?6, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'full', NULL, ?13
             )",
            params![
                authorization,
                connection_digest,
                connection_generation,
                response_request,
                call_digest,
                fixture.gateway_result_id,
                fixture.result.exit_code,
                fixture.result.stdout_digest,
                fixture.result.stdout_bytes,
                fixture.result.stderr_digest,
                fixture.result.stderr_bytes,
                full_envelope,
                now,
            ],
        )
        .unwrap();
    let compact_receipts = if duplicate_compact { 2 } else { 1 };
    for ordinal in 1..=compact_receipts {
        let receipt_id = format!("compact-receipt-{ordinal}");
        let challenge_id = format!("compact-challenge-{ordinal}");
        transaction
            .execute(
                "INSERT INTO gateway_delivery_receipts_v2 (
                     receipt_id, challenge_id, authorization_scope_digest, connection_digest,
                     connection_generation, session_id, turn_id, agent_id, compaction_generation,
                     response_request_id_digest, call_digest, gateway_result_id, result_digest,
                     exact_status, stdout_digest, stdout_bytes, stderr_digest, stderr_bytes,
                     response_envelope_digest, presentation, source_receipt_id, acknowledged_ms
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, 'session', 'turn', 'agent', 4,
                     ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     'compact', 'full-receipt', ?15
                 )",
                params![
                    receipt_id,
                    challenge_id,
                    authorization,
                    connection_digest,
                    connection_generation,
                    response_request,
                    call_digest,
                    fixture.gateway_result_id,
                    fixture.result.exit_code,
                    fixture.result.stdout_digest,
                    fixture.result.stdout_bytes,
                    fixture.result.stderr_digest,
                    fixture.result.stderr_bytes,
                    compact_envelope,
                    now.saturating_add(i64::from(ordinal)),
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO gateway_delivery_savings_v2 (
                     receipt_id, response_envelope_digest, bytes_omitted,
                     estimated_tokens_avoided, recorded_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    receipt_id,
                    compact_envelope,
                    OMITTED_BYTES,
                    OMITTED_BYTES / 4,
                    now.saturating_add(10),
                ],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
}

#[test]
fn confirmed_metrics_survive_reopen_deduplicate_and_support_concurrent_readers() {
    let fixture = fixture();
    insert_confirmed_delivery(&fixture, true);

    let expected_context_bytes = fixture
        .result
        .stdout_bytes
        .saturating_add(fixture.result.stderr_bytes);
    for _ in 0..2 {
        let store = Store::open(&fixture.root).unwrap();
        let stats = store.gateway_stats().unwrap();
        assert_eq!(stats.compact_deliveries, 1);
        assert_eq!(stats.context_bytes_delivered, expected_context_bytes);
        assert_eq!(stats.delivery_confirmed_bytes_omitted, 800);
        assert_eq!(stats.confirmed_tokens_avoided, 200);
        assert_eq!(stats.estimated_tokens_avoided, 200);
    }

    const READERS: usize = 8;
    let root = Arc::new(fixture.root.clone());
    let barrier = Arc::new(Barrier::new(READERS));
    let handles = (0..READERS)
        .map(|_| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = Store::open(root.as_ref()).unwrap();
                barrier.wait();
                store.gateway_stats().unwrap()
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        let stats = handle.join().unwrap();
        assert_eq!(stats.compact_deliveries, 1);
        assert_eq!(stats.delivery_confirmed_bytes_omitted, 800);
        assert_eq!(stats.confirmed_tokens_avoided, 200);
    }
}

#[test]
fn legacy_compact_events_summaries_and_result_ids_confirm_no_savings() {
    let fixture = fixture();
    let database = connection(&fixture.root);
    database
        .execute(
            "INSERT INTO gateway_events (
                 event_type, gateway_result_id, estimated_tokens_avoided, created_ms
             ) VALUES ('compact_delivery', ?1, 9999, ?2)",
            params![fixture.gateway_result_id, now_ms()],
        )
        .unwrap();
    database
        .execute(
            "INSERT INTO gateway_deliveries (
                 session_id, turn_id, agent_id, compaction_epoch, gateway_result_id,
                 presentation, estimated_tokens_avoided, delivered_ms
             ) VALUES ('legacy-session', 'legacy-turn', 'legacy-agent', 0, ?1,
                       'compact', 9999, ?2)",
            params![fixture.gateway_result_id, now_ms()],
        )
        .unwrap();
    drop(database);

    let store = Store::open(&fixture.root).unwrap();
    let stats = store.gateway_stats().unwrap();
    assert_eq!(stats.compact_deliveries, 0);
    assert_eq!(stats.delivery_confirmed_bytes_omitted, 0);
    assert_eq!(stats.confirmed_tokens_avoided, 0);
    assert_eq!(stats.estimated_tokens_avoided, 0);
    let serialized = serde_json::to_value(stats).unwrap();
    for field in [
        "requested",
        "executed",
        "exact_hits",
        "coverage_hits",
        "inflight_joins",
        "compact_deliveries",
        "estimated_tokens_avoided",
        "stale_or_divergent_quarantines",
        "delivery_confirmed_bytes_omitted",
        "confirmed_tokens_avoided",
        "estimated_execution_time_saved_ms",
    ] {
        assert!(
            serialized.get(field).is_some(),
            "missing serialized field {field}"
        );
    }
    let version: i64 = connection(&fixture.root)
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 14);
}

#[test]
fn mismatched_envelope_accounting_refuses_stats_and_reopen() {
    let fixture = fixture();
    insert_confirmed_delivery(&fixture, false);
    let store = Store::open(&fixture.root).unwrap();
    connection(&fixture.root)
        .execute(
            "UPDATE gateway_delivery_savings_v2
             SET response_envelope_digest = ?1
             WHERE receipt_id = 'compact-receipt-1'",
            [digest("forged-envelope")],
        )
        .unwrap();
    assert!(store.gateway_stats().is_err());
    drop(store);
    assert!(Store::open(&fixture.root).is_err());
}

#[test]
fn inconsistent_duplicate_savings_are_refused_instead_of_selected() {
    let fixture = fixture();
    insert_confirmed_delivery(&fixture, true);
    let store = Store::open(&fixture.root).unwrap();
    connection(&fixture.root)
        .execute(
            "UPDATE gateway_delivery_savings_v2
             SET bytes_omitted = 804, estimated_tokens_avoided = 201
             WHERE receipt_id = 'compact-receipt-2'",
            [],
        )
        .unwrap();
    assert!(store.gateway_stats().is_err());
}
