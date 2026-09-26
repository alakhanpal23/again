use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use again::agent_gateway::context::{ReasoningRecipientV1, ReasoningScopeV1};
use again::store::{
    GatewayAgentContext, GatewayCallAcquisition, GatewayCallObservation, GatewayCompletion,
    GatewayCoordinatorInputV1, GatewayDependencyV1, GatewayExecutionStart, GatewayFailure,
    GatewayFailureReason, GatewayFollowerCancellation, GatewayFreshnessEvidenceV1,
    GatewayOperationDispositionV1, GatewayReasoningContextQueryV1, GatewayRefusalReason,
    GatewayServedRouteV1, Store, StoredResult, ValidatedGatewayReadV1, gateway_policy_digest,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

const POLICY: &str = "gateway-test-v1";

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

fn binding_with_deadline(request: &str, state: &str, deadline: i64) -> ValidatedGatewayReadV1 {
    let state_digest = digest(state);
    ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
        request_digest: digest(request),
        state_digest: state_digest.clone(),
        policy_digest: gateway_policy_digest(POLICY),
        operation: GatewayOperationDispositionV1::ReplayEligibleRead,
        freshness: GatewayFreshnessEvidenceV1 {
            snapshot_digest: state_digest,
            observed_at_ms: now_ms().saturating_sub(10),
            valid_until_ms: deadline,
        },
        dependencies: vec![
            GatewayDependencyV1 {
                key_digest: digest("dependency-a"),
                value_digest: digest(&format!("{state}-a")),
            },
            GatewayDependencyV1 {
                key_digest: digest("dependency-b"),
                value_digest: digest(&format!("{state}-b")),
            },
        ],
    })
    .unwrap()
}

fn binding(request: &str, state: &str) -> ValidatedGatewayReadV1 {
    binding_with_deadline(request, state, now_ms() + 60_000)
}

fn leader(value: GatewayCallAcquisition) -> (String, String) {
    match value {
        GatewayCallAcquisition::Leader {
            call_id, lease_id, ..
        } => (call_id, lease_id),
        other => panic!("expected leader, got {other:?}"),
    }
}

fn follower(value: GatewayCallAcquisition) -> String {
    match value {
        GatewayCallAcquisition::Follower { call_id, .. } => call_id,
        other => panic!("expected follower, got {other:?}"),
    }
}

fn stored_result(root: &Path, binding: &ValidatedGatewayReadV1, stdout: &[u8]) -> StoredResult {
    Store::open(root)
        .unwrap()
        .insert_result(
            binding.request_digest(),
            stdout,
            b"diagnostic",
            0,
            7,
            POLICY,
            "{\"proof\":\"exact\"}",
        )
        .unwrap()
}

fn complete(store: &Store, lease: &str, owner: &str, result: &StoredResult) -> String {
    assert_eq!(
        store.start_gateway_execution(lease, owner).unwrap(),
        GatewayExecutionStart::Started
    );
    match store.complete_gateway_call(lease, &result.id).unwrap() {
        GatewayCompletion::Completed {
            gateway_result_id, ..
        } => gateway_result_id,
        other => panic!("expected completion, got {other:?}"),
    }
}

fn reasoning_query(
    proof: &ValidatedGatewayReadV1,
    authorization_scope_digest: &str,
    task: &str,
    agent: &str,
) -> GatewayReasoningContextQueryV1 {
    let scope = ReasoningScopeV1::new(
        task,
        "repository-01",
        "workspace-01",
        proof.state_digest(),
        &proof.dependency_digest(),
        authorization_scope_digest,
    )
    .unwrap();
    let recipient = ReasoningRecipientV1::new(
        agent,
        "session-01",
        "turn-01",
        &digest("connection-generation"),
        0,
        1,
    )
    .unwrap();
    GatewayReasoningContextQueryV1::new(scope, recipient, proof.clone()).unwrap()
}

fn insert_reasoning_delivery(
    root: &Path,
    gateway_result_id: &str,
    result: &StoredResult,
    authorization_scope_digest: &str,
    agent: &str,
) {
    Connection::open(root.join("again.sqlite"))
        .unwrap()
        .execute(
            "INSERT INTO gateway_delivery_receipts (challenge_id, authorization_scope_digest, connection_digest, session_id, turn_id, agent_id, compaction_generation, call_digest, gateway_result_id, result_digest, exact_status, stdout_digest, stdout_bytes, stderr_digest, stderr_bytes, acknowledged_ms) VALUES (?1, ?2, ?3, 'source-session', 'source-turn', ?4, 0, ?5, ?6, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                format!("reasoning-receipt-{agent}"),
                authorization_scope_digest,
                digest("source-connection"),
                agent,
                digest("source-call"),
                gateway_result_id,
                result.exit_code,
                result.stdout_digest,
                result.stdout_bytes,
                result.stderr_digest,
                result.stderr_bytes,
                now_ms(),
            ],
        )
        .unwrap();
}

#[test]
fn twenty_callers_elect_one_leader_for_exact_read_binding() {
    const CALLERS: usize = 20;
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    drop(Store::open(&root).unwrap());
    let proof = Arc::new(binding("shared-request", "shared-state"));
    let barrier = Arc::new(Barrier::new(CALLERS));
    let handles: Vec<_> = (0..CALLERS)
        .map(|index| {
            let root = root.clone();
            let proof = Arc::clone(&proof);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = Store::open(root).unwrap();
                barrier.wait();
                store
                    .acquire_gateway_call(&proof, &format!("owner-{index}"))
                    .unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|item| matches!(item, GatewayCallAcquisition::Leader { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|item| matches!(item, GatewayCallAcquisition::Follower { .. }))
            .count(),
        CALLERS - 1
    );
    let stats = Store::open(&root).unwrap().gateway_stats().unwrap();
    assert_eq!(stats.requested, CALLERS as u64);
    assert_eq!(stats.executed, 0, "acquisition is not execution");
    assert_eq!(
        stats.inflight_joins, 0,
        "acquisition candidates are not served joins"
    );
}

#[test]
fn follower_observes_and_retrieves_content_addressed_full_result() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("observe-request", "observe-state");
    let leader_store = Store::open(&root).unwrap();
    let (_, lease) = leader(
        leader_store
            .acquire_gateway_call(&proof, "leader-a")
            .unwrap(),
    );
    let follower_store = Store::open(&root).unwrap();
    follower(
        follower_store
            .acquire_gateway_call(&proof, "follower-a")
            .unwrap(),
    );
    let result = stored_result(&root, &proof, b"completed output");
    let gateway_result_id = complete(&leader_store, &lease, "leader-a", &result);
    assert_eq!(gateway_result_id.len(), 64);
    assert_eq!(
        follower_store.observe_gateway_call(&proof).unwrap(),
        GatewayCallObservation::Ready {
            gateway_result_id: gateway_result_id.clone()
        }
    );
    let full = follower_store
        .get_gateway_result(&proof, &gateway_result_id)
        .unwrap()
        .unwrap();
    assert_eq!(full.result, result);
    assert_eq!(full.stdout, b"completed output");
    assert_eq!(full.stderr, b"diagnostic");
    assert_eq!(full.dependencies.len(), 2);
}

#[test]
fn authenticated_observation_is_shared_across_agents_but_not_authorization_scopes() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("reasoning-shared-request", "reasoning-shared-state");
    let store = Store::open(&root).unwrap();
    let (_, lease) = leader(store.acquire_gateway_call(&proof, "source-agent").unwrap());
    let result = stored_result(&root, &proof, b"verified source bytes");
    let gateway_result_id = complete(&store, &lease, "source-agent", &result);
    let authorization_scope = digest("shared-authorization");
    insert_reasoning_delivery(
        &root,
        &gateway_result_id,
        &result,
        &authorization_scope,
        "source-agent",
    );

    let shared = store
        .reasoning_context_v1(&reasoning_query(
            &proof,
            &authorization_scope,
            "task-a",
            "recipient-agent",
        ))
        .unwrap();
    assert_eq!(shared.known_facts().len(), 1);
    assert_eq!(shared.completed_observations().len(), 1);
    assert_eq!(
        shared.known_facts()[0].sources()[0].result_id(),
        gateway_result_id
    );
    assert_eq!(shared.evidence_metrics().investigations_avoided, 1);
    assert_eq!(shared.evidence_metrics().provider_calls_avoided, 1);
    assert_eq!(
        shared.evidence_metrics().estimated_execution_time_saved_ms,
        7
    );

    let isolated = store
        .reasoning_context_v1(&reasoning_query(
            &proof,
            &digest("different-authorization"),
            "task-a",
            "isolated-agent",
        ))
        .unwrap();
    assert!(isolated.known_facts().is_empty());
    assert!(isolated.completed_observations().is_empty());
    assert_eq!(isolated.explicit_unknowns().len(), 1);
    assert_eq!(isolated.evidence_metrics().provider_calls_avoided, 0);
}

#[test]
fn reasoning_read_model_reports_other_agent_work_and_verified_failure() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("reasoning-inflight-request", "reasoning-inflight-state");
    let store = Store::open(&root).unwrap();
    let (_, lease) = leader(store.acquire_gateway_call(&proof, "leader-agent").unwrap());
    let query = reasoning_query(
        &proof,
        &digest("inflight-authorization"),
        "task-inflight",
        "follower-agent",
    );

    let inflight = store.reasoning_context_v1(&query).unwrap();
    assert_eq!(inflight.inflight_work().len(), 1);
    assert_eq!(inflight.evidence_metrics().inflight_joins, 1);
    assert_eq!(inflight.evidence_metrics().provider_calls_avoided, 1);

    assert!(matches!(
        store
            .fail_gateway_call(&lease, GatewayFailureReason::Transport)
            .unwrap(),
        GatewayFailure::Failed { .. }
    ));
    let failed = store.reasoning_context_v1(&query).unwrap();
    assert_eq!(failed.failed_approaches().len(), 1);
    assert_eq!(failed.explicit_unknowns().len(), 1);
    assert!(failed.known_facts().is_empty());
    assert_eq!(failed.evidence_metrics().provider_calls_avoided, 0);
}

#[test]
fn route_stats_require_final_served_promotion_and_are_idempotent() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("served-request", "served-state");
    let store = Store::open(&root).unwrap();
    let (_, lease) = leader(store.acquire_gateway_call(&proof, "leader").unwrap());
    let follower_call = follower(store.acquire_gateway_call(&proof, "follower").unwrap());
    let result = stored_result(&root, &proof, b"served output");
    let gateway_result_id = complete(&store, &lease, "leader", &result);
    let exact_call = match store.acquire_gateway_call(&proof, "exact").unwrap() {
        GatewayCallAcquisition::Ready {
            call_id,
            gateway_result_id: observed,
        } => {
            assert_eq!(observed, gateway_result_id);
            call_id
        }
        other => panic!("expected ready acquisition, got {other:?}"),
    };

    let before = store.gateway_stats().unwrap();
    assert_eq!(before.executed, 1);
    assert_eq!(before.exact_hits, 0);
    assert_eq!(before.inflight_joins, 0);
    assert!(
        !store
            .record_gateway_route_served(
                &follower_call,
                &gateway_result_id,
                GatewayServedRouteV1::Exact,
            )
            .unwrap()
    );
    assert!(
        store
            .record_gateway_route_served(
                &follower_call,
                &gateway_result_id,
                GatewayServedRouteV1::Inflight,
            )
            .unwrap()
    );
    assert!(
        !store
            .record_gateway_route_served(
                &follower_call,
                &gateway_result_id,
                GatewayServedRouteV1::Inflight,
            )
            .unwrap()
    );
    assert!(
        store
            .record_gateway_route_served(
                &exact_call,
                &gateway_result_id,
                GatewayServedRouteV1::Exact,
            )
            .unwrap()
    );
    let after = store.gateway_stats().unwrap();
    assert_eq!(after.exact_hits, 1);
    assert_eq!(after.inflight_joins, 1);
    assert_eq!(after.facts_reused, 1);
    assert_eq!(after.investigations_avoided, 2);
    assert_eq!(after.provider_calls_avoided, 2);
    assert_eq!(after.estimated_execution_time_saved_ms, 14);
    assert_eq!(after.confirmed_tokens_avoided, 0);
}

#[test]
fn validator_rejects_mutation_bad_digest_and_stale_freshness() {
    let state = digest("state");
    assert!(
        ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
            request_digest: digest("request"),
            state_digest: state.clone(),
            policy_digest: gateway_policy_digest(POLICY),
            operation: GatewayOperationDispositionV1::Mutation,
            freshness: GatewayFreshnessEvidenceV1 {
                snapshot_digest: state,
                observed_at_ms: now_ms(),
                valid_until_ms: now_ms() + 1_000,
            },
            dependencies: vec![],
        })
        .is_err()
    );
    let state = digest("state");
    assert!(
        ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
            request_digest: "bad".to_owned(),
            state_digest: state.clone(),
            policy_digest: gateway_policy_digest(POLICY),
            operation: GatewayOperationDispositionV1::ReplayEligibleRead,
            freshness: GatewayFreshnessEvidenceV1 {
                snapshot_digest: state,
                observed_at_ms: now_ms(),
                valid_until_ms: now_ms() + 1_000,
            },
            dependencies: vec![],
        })
        .is_err()
    );
    let stale = binding_with_deadline("stale-request", "stale-state", now_ms() - 1);
    let temp = TempDir::new().unwrap();
    assert_eq!(
        Store::open(temp.path().join("state"))
            .unwrap()
            .acquire_gateway_call(&stale, "owner")
            .unwrap(),
        GatewayCallAcquisition::Refused {
            reason: GatewayRefusalReason::FreshnessExpired
        }
    );
}

#[test]
fn observations_never_cross_complete_state_bindings() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let first = binding("same-request", "state-a");
    let second = binding("same-request", "state-b");
    let store = Store::open(&root).unwrap();
    let (_, first_lease) = leader(store.acquire_gateway_call(&first, "owner-a").unwrap());
    leader(store.acquire_gateway_call(&second, "owner-b").unwrap());
    let result = stored_result(&root, &first, b"first");
    complete(&store, &first_lease, "owner-a", &result);
    assert!(matches!(
        store.observe_gateway_call(&first).unwrap(),
        GatewayCallObservation::Ready { .. }
    ));
    assert!(matches!(
        store.observe_gateway_call(&second).unwrap(),
        GatewayCallObservation::Inflight { leader, .. } if leader == "owner-b"
    ));
}

#[test]
fn completion_refuses_request_and_policy_mismatch() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("exact-request", "exact-state");
    let store = Store::open(&root).unwrap();
    let (_, lease) = leader(store.acquire_gateway_call(&proof, "owner").unwrap());
    assert_eq!(
        store.start_gateway_execution(&lease, "owner").unwrap(),
        GatewayExecutionStart::Started
    );
    let wrong_request = Store::open(&root)
        .unwrap()
        .insert_result("wrong", b"wrong", b"", 0, 1, POLICY, "{}")
        .unwrap();
    assert_eq!(
        store
            .complete_gateway_call(&lease, &wrong_request.id)
            .unwrap(),
        GatewayCompletion::Refused {
            reason: GatewayRefusalReason::BindingMismatch
        }
    );
    let wrong_policy = Store::open(&root)
        .unwrap()
        .insert_result(
            proof.request_digest(),
            b"wrong-policy",
            b"",
            0,
            1,
            "different-policy",
            "{}",
        )
        .unwrap();
    assert_eq!(
        store
            .complete_gateway_call(&lease, &wrong_policy.id)
            .unwrap(),
        GatewayCompletion::Refused {
            reason: GatewayRefusalReason::BindingMismatch
        }
    );
}

#[test]
fn freshness_bounds_lease_and_stale_leader_cannot_complete() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let first_store = Store::open(&root).unwrap();
    let first = binding_with_deadline("takeover", "state", now_ms() + 2_000);
    let (_, stale_lease) = leader(first_store.acquire_gateway_call(&first, "owner-a").unwrap());
    thread::sleep(Duration::from_millis(2_100));
    let current = binding("takeover", "state");
    let current_store = Store::open(&root).unwrap();
    let (_, current_lease) = leader(
        current_store
            .acquire_gateway_call(&current, "owner-b")
            .unwrap(),
    );
    let result = stored_result(&root, &current, b"winner");
    assert_eq!(
        first_store
            .complete_gateway_call(&stale_lease, &result.id)
            .unwrap(),
        GatewayCompletion::Refused {
            reason: GatewayRefusalReason::LeaseExpired
        }
    );
    complete(&current_store, &current_lease, "owner-b", &result);
}

#[test]
fn cancellation_and_typed_failure_are_isolated_and_retryable() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("retry", "state");
    let store = Store::open(&root).unwrap();
    let (_, lease) = leader(store.acquire_gateway_call(&proof, "leader").unwrap());
    let cancelled = follower(store.acquire_gateway_call(&proof, "follower-a").unwrap());
    follower(store.acquire_gateway_call(&proof, "follower-b").unwrap());
    assert_eq!(
        store.cancel_gateway_follower(&cancelled).unwrap(),
        GatewayFollowerCancellation::Cancelled
    );
    assert!(matches!(
        store
            .fail_gateway_call(&lease, GatewayFailureReason::ProviderUnavailable)
            .unwrap(),
        GatewayFailure::Failed { .. }
    ));
    assert_eq!(
        store.observe_gateway_call(&proof).unwrap(),
        GatewayCallObservation::Failed {
            reason: GatewayFailureReason::ProviderUnavailable
        }
    );
    let (_, retry) = leader(
        Store::open(&root)
            .unwrap()
            .acquire_gateway_call(&proof, "retry-owner")
            .unwrap(),
    );
    assert_ne!(lease, retry);
}

#[test]
fn divergent_recompletion_quarantines_binding_and_stats() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("divergence", "state");
    let store = Store::open(&root).unwrap();
    let (_, lease) = leader(store.acquire_gateway_call(&proof, "owner").unwrap());
    let result = stored_result(&root, &proof, b"output");
    complete(&store, &lease, "owner", &result);
    let connection = Connection::open(root.join("again.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE results SET duration_ms = duration_ms + 1 WHERE id = ?1",
            [&result.id],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.complete_gateway_call(&lease, &result.id).unwrap(),
        GatewayCompletion::Quarantined { .. }
    ));
    assert!(matches!(
        store.observe_gateway_call(&proof).unwrap(),
        GatewayCallObservation::Quarantined { .. }
    ));
    let stats = store.gateway_stats().unwrap();
    assert_eq!(stats.executed, 1);
    assert_eq!(stats.stale_or_divergent_quarantines, 1);
}

#[test]
fn malformed_v6_schema_is_rejected_on_open() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    drop(Store::open(&root).unwrap());
    let connection = Connection::open(root.join("again.sqlite")).unwrap();
    connection
        .execute("DROP INDEX gateway_requests_binding_idx", [])
        .unwrap();
    drop(connection);
    let error = match Store::open(&root) {
        Ok(_) => panic!("malformed v6 schema accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("missing required index"));
}

#[test]
fn version_five_migrates_without_changing_legacy_result() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("legacy-v5");
    create_version_five_schema(&root);
    let database = root.join("again.sqlite");
    Connection::open(&database)
        .unwrap()
        .execute(
            "INSERT INTO results (id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, quarantined, created_ms, last_used_ms) VALUES ('legacy-result', 'legacy-key', ?1, ?2, 3, 0, 0, 7, 'v0', '{}', 0, 1, 1)",
            params!["a".repeat(64), "b".repeat(64)],
        )
        .unwrap();
    let store = Store::open(&root).unwrap();
    assert_eq!(
        store.get_result("legacy-key").unwrap().unwrap().id,
        "legacy-result"
    );
}

#[test]
fn delivery_and_cleanup_accounting_are_isolated() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let proof = binding("delivery", "state");
    let mut store = Store::open(&root).unwrap();
    let (_, lease) = leader(store.acquire_gateway_call(&proof, "owner").unwrap());
    let result = stored_result(&root, &proof, b"payload");
    let gateway_result_id = complete(&store, &lease, "owner", &result);
    let first = GatewayAgentContext::new("session", "turn", "agent", 0);
    let second = GatewayAgentContext::new("session", "turn", "agent", 1);
    let connection = Connection::open(root.join("again.sqlite")).unwrap();
    for context in [&first, &second] {
        connection
            .execute(
                "INSERT INTO gateway_deliveries (session_id, turn_id, agent_id, compaction_epoch, gateway_result_id, presentation, estimated_tokens_avoided, delivered_ms) VALUES (?1, ?2, ?3, ?4, ?5, 'full', 0, ?6)",
                params![
                    context.session_id,
                    context.turn_id,
                    context.agent_id,
                    context.compaction_epoch,
                    gateway_result_id,
                    now_ms()
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO gateway_delivery_receipts (challenge_id, authorization_scope_digest, connection_digest, session_id, turn_id, agent_id, compaction_generation, call_digest, gateway_result_id, result_digest, exact_status, stdout_digest, stdout_bytes, stderr_digest, stderr_bytes, acknowledged_ms) VALUES ('immutable-receipt', ?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?7, 0, ?8, ?9, ?10, ?11, ?12)",
            params![
                digest("scope"),
                digest("connection"),
                first.session_id,
                first.turn_id,
                first.agent_id,
                digest("call"),
                gateway_result_id,
                result.stdout_digest,
                result.stdout_bytes,
                result.stderr_digest,
                result.stderr_bytes,
                now_ms(),
            ],
        )
        .unwrap();
    assert_eq!(store.clear_gateway_deliveries(&first).unwrap(), 1);
    let receipt_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM gateway_delivery_receipts WHERE challenge_id = 'immutable-receipt'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(receipt_count, 1);
    connection
        .execute(
            "INSERT INTO gateway_events (event_type, estimated_tokens_avoided, created_ms) VALUES ('old_test_event', 0, 0)",
            [],
        )
        .unwrap();
    drop(connection);
    assert_eq!(store.cleanup().unwrap().gateway_events, 1);
}

fn create_version_five_schema(root: &Path) {
    fs::create_dir(root).unwrap();
    #[cfg(unix)]
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let database = root.join("again.sqlite");
    Connection::open(&database)
        .unwrap()
        .execute_batch(
            r#"
            CREATE TABLE pending_calls (id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
                turn_id TEXT, context_id TEXT, cwd TEXT NOT NULL, raw_command TEXT NOT NULL,
                argv_json TEXT NOT NULL, created_ms INTEGER NOT NULL);
            CREATE TABLE results (id TEXT PRIMARY KEY, request_key TEXT NOT NULL UNIQUE,
                stdout_digest TEXT NOT NULL, stderr_digest TEXT NOT NULL,
                stdout_bytes INTEGER NOT NULL, stderr_bytes INTEGER NOT NULL,
                exit_code INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
                policy_version TEXT NOT NULL, proof_json TEXT NOT NULL,
                quarantined INTEGER NOT NULL DEFAULT 0, quarantine_reason TEXT,
                created_ms INTEGER NOT NULL, last_used_ms INTEGER NOT NULL,
                hit_count INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE deliveries (session_id TEXT NOT NULL, context_id TEXT NOT NULL,
                result_id TEXT NOT NULL, delivered_ms INTEGER NOT NULL,
                PRIMARY KEY (session_id, context_id, result_id),
                FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE);
            CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, call_id TEXT,
                result_id TEXT, disposition TEXT NOT NULL, reason_code TEXT NOT NULL,
                elapsed_ms INTEGER NOT NULL DEFAULT 0, bytes_omitted INTEGER NOT NULL DEFAULT 0,
                created_ms INTEGER NOT NULL);
            CREATE INDEX events_created_idx ON events(created_ms);
            CREATE TABLE file_digests (device BLOB NOT NULL, inode BLOB NOT NULL,
                mode INTEGER NOT NULL, uid INTEGER NOT NULL, gid INTEGER NOT NULL,
                size BLOB NOT NULL, mtime_sec INTEGER NOT NULL, mtime_nsec INTEGER NOT NULL,
                ctime_sec INTEGER NOT NULL, ctime_nsec INTEGER NOT NULL, digest BLOB NOT NULL,
                row_checksum BLOB NOT NULL, last_used_ms INTEGER NOT NULL,
                PRIMARY KEY (device, inode)) WITHOUT ROWID;
            CREATE INDEX file_digests_lru_idx ON file_digests(last_used_ms);
            CREATE TABLE artifacts (digest TEXT PRIMARY KEY, created_ms INTEGER NOT NULL)
                WITHOUT ROWID;
            CREATE INDEX artifacts_created_idx ON artifacts(created_ms);
            CREATE INDEX pending_calls_created_idx ON pending_calls(created_ms);
            CREATE TABLE maintenance (name TEXT PRIMARY KEY, completed_ms INTEGER NOT NULL)
                WITHOUT ROWID;
            PRAGMA user_version = 5;
            "#,
        )
        .unwrap();
    #[cfg(unix)]
    fs::set_permissions(database, fs::Permissions::from_mode(0o600)).unwrap();
}
