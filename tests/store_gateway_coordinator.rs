use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use again::store::{
    GatewayAgentContext, GatewayCallAcquisition, GatewayCallObservation, GatewayCompletion,
    GatewayFailure, GatewayFollowerCancellation, GatewayHeartbeat, GatewayPresentation,
    GatewayRefusalReason, Store, StoredResult,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

fn open_initialized(root: &Path) {
    drop(Store::open(root).unwrap());
}

fn leader(acquisition: GatewayCallAcquisition) -> (String, String) {
    match acquisition {
        GatewayCallAcquisition::Leader {
            call_id, lease_id, ..
        } => (call_id, lease_id),
        other => panic!("expected leader, got {other:?}"),
    }
}

fn follower(acquisition: GatewayCallAcquisition) -> String {
    match acquisition {
        GatewayCallAcquisition::Follower { call_id, .. } => call_id,
        other => panic!("expected follower, got {other:?}"),
    }
}

fn stored_result(root: &Path, key: &str, stdout: &[u8]) -> StoredResult {
    Store::open(root)
        .unwrap()
        .insert_result(key, stdout, b"", 0, 1, "gateway-test", "{}")
        .unwrap()
}

#[test]
fn twenty_independent_callers_elect_exactly_one_leader() {
    const CALLERS: usize = 20;
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    open_initialized(&root);
    let barrier = Arc::new(Barrier::new(CALLERS));
    let handles: Vec<_> = (0..CALLERS)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            let root = root.clone();
            thread::spawn(move || {
                let store = Store::open(root).unwrap();
                barrier.wait();
                store
                    .acquire_gateway_call("shared-call", "state-v1", &format!("owner-{index}"))
                    .unwrap()
            })
        })
        .collect();
    let acquisitions: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    assert_eq!(
        acquisitions
            .iter()
            .filter(|outcome| matches!(outcome, GatewayCallAcquisition::Leader { .. }))
            .count(),
        1
    );
    assert_eq!(
        acquisitions
            .iter()
            .filter(|outcome| matches!(outcome, GatewayCallAcquisition::Follower { .. }))
            .count(),
        CALLERS - 1
    );
    let stats = Store::open(&root).unwrap().gateway_stats().unwrap();
    assert_eq!(stats.requested, CALLERS as u64);
    assert_eq!(stats.executed, 1);
    assert_eq!(stats.inflight_joins, (CALLERS - 1) as u64);
}

#[test]
fn follower_observes_leader_then_completed_result() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let leader_store = Store::open(&root).unwrap();
    let (leader_call_id, lease_id) = leader(
        leader_store
            .acquire_gateway_call("observe-call", "state-v1", "leader-a")
            .unwrap(),
    );
    let follower_store = Store::open(&root).unwrap();
    let follower_call_id = follower(
        follower_store
            .acquire_gateway_call("observe-call", "state-v1", "follower-a")
            .unwrap(),
    );
    assert_ne!(leader_call_id, follower_call_id);
    assert!(matches!(
        follower_store
            .observe_gateway_call("observe-call")
            .unwrap(),
        GatewayCallObservation::Inflight {
            leader,
            followers: 1,
            ..
        } if leader == "leader-a"
    ));

    let result = stored_result(&root, "provider-observe", b"completed");
    assert!(matches!(
        leader_store
            .complete_gateway_call(&lease_id, &result.id)
            .unwrap(),
        GatewayCompletion::Completed { result_id, .. } if result_id == result.id
    ));
    assert_eq!(
        follower_store.observe_gateway_call("observe-call").unwrap(),
        GatewayCallObservation::Ready {
            result_id: result.id.clone()
        }
    );
    assert!(matches!(
        Store::open(&root)
            .unwrap()
            .acquire_gateway_call("observe-call", "state-v1", "late-caller")
            .unwrap(),
        GatewayCallAcquisition::Ready { result_id, .. } if result_id == result.id
    ));
}

#[test]
fn expired_leader_is_replaced_and_cannot_complete_takeover() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let store_a = Store::open(&root).unwrap();
    let (_, stale_lease) = leader(
        store_a
            .acquire_gateway_call("takeover-call", "state-v1", "owner-a")
            .unwrap(),
    );
    assert_eq!(
        Store::open(&root)
            .unwrap()
            .expire_abandoned_gateway_calls(i64::MAX)
            .unwrap(),
        1
    );
    let store_b = Store::open(&root).unwrap();
    let (_, current_lease) = leader(
        store_b
            .acquire_gateway_call("takeover-call", "state-v1", "owner-b")
            .unwrap(),
    );
    assert_ne!(stale_lease, current_lease);

    let result = stored_result(&root, "provider-takeover", b"winner");
    assert_eq!(
        store_a
            .complete_gateway_call(&stale_lease, &result.id)
            .unwrap(),
        GatewayCompletion::Refused {
            reason: GatewayRefusalReason::LeaseExpired
        }
    );
    assert!(matches!(
        store_b
            .complete_gateway_call(&current_lease, &result.id)
            .unwrap(),
        GatewayCompletion::Completed { .. }
    ));
}

#[test]
fn cancelling_one_follower_leaves_leader_and_other_follower_live() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let leader_store = Store::open(&root).unwrap();
    let (_, lease_id) = leader(
        leader_store
            .acquire_gateway_call("cancel-call", "state-v1", "leader")
            .unwrap(),
    );
    let follower_store = Store::open(&root).unwrap();
    let cancelled = follower(
        follower_store
            .acquire_gateway_call("cancel-call", "state-v1", "follower-a")
            .unwrap(),
    );
    let retained = follower(
        Store::open(&root)
            .unwrap()
            .acquire_gateway_call("cancel-call", "state-v1", "follower-b")
            .unwrap(),
    );
    assert_ne!(cancelled, retained);
    assert_eq!(
        follower_store.cancel_gateway_follower(&cancelled).unwrap(),
        GatewayFollowerCancellation::Cancelled
    );
    assert_eq!(
        follower_store.cancel_gateway_follower(&cancelled).unwrap(),
        GatewayFollowerCancellation::AlreadyCancelled
    );
    assert!(matches!(
        follower_store.observe_gateway_call("cancel-call").unwrap(),
        GatewayCallObservation::Inflight { followers: 1, .. }
    ));
    assert!(matches!(
        leader_store
            .heartbeat_gateway_call(&lease_id, "leader")
            .unwrap(),
        GatewayHeartbeat::Extended { .. }
    ));
}

#[test]
fn failed_leader_allows_retry_with_a_new_lease() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let first = Store::open(&root).unwrap();
    let (_, first_lease) = leader(
        first
            .acquire_gateway_call("retry-call", "state-v1", "owner-a")
            .unwrap(),
    );
    assert!(matches!(
        first
            .fail_gateway_call(&first_lease, "provider_unavailable")
            .unwrap(),
        GatewayFailure::Failed { .. }
    ));
    assert_eq!(
        first.observe_gateway_call("retry-call").unwrap(),
        GatewayCallObservation::Failed {
            reason: "provider_unavailable".to_owned()
        }
    );

    let second = Store::open(&root).unwrap();
    let (_, second_lease) = leader(
        second
            .acquire_gateway_call("retry-call", "state-v1", "owner-b")
            .unwrap(),
    );
    assert_ne!(first_lease, second_lease);
}

#[test]
fn divergent_completion_quarantines_gateway_binding_only() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let store = Store::open(&root).unwrap();
    let (_, lease_id) = leader(
        store
            .acquire_gateway_call("divergent-call", "state-v1", "owner")
            .unwrap(),
    );
    let first = stored_result(&root, "provider-first", b"first");
    let second = stored_result(&root, "provider-second", b"second");
    assert!(matches!(
        store.complete_gateway_call(&lease_id, &first.id).unwrap(),
        GatewayCompletion::Completed { .. }
    ));
    assert!(matches!(
        store
            .complete_gateway_call(&lease_id, &second.id)
            .unwrap(),
        GatewayCompletion::Quarantined {
            existing_result_id,
            conflicting_result_id,
            ..
        } if existing_result_id == first.id && conflicting_result_id == second.id
    ));
    assert!(matches!(
        store.observe_gateway_call("divergent-call").unwrap(),
        GatewayCallObservation::Quarantined { .. }
    ));
    assert_eq!(store.get_result_by_id(&first.id).unwrap(), Some(first));
    assert_eq!(store.get_result_by_id(&second.id).unwrap(), Some(second));
}

#[test]
fn heartbeat_rejects_wrong_owner_and_extends_current_owner() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let store = Store::open(&root).unwrap();
    let (_, lease_id) = leader(
        store
            .acquire_gateway_call("heartbeat-call", "state-v1", "owner")
            .unwrap(),
    );
    assert_eq!(
        store.heartbeat_gateway_call(&lease_id, "impostor").unwrap(),
        GatewayHeartbeat::Refused {
            reason: GatewayRefusalReason::OwnerMismatch
        }
    );
    assert!(matches!(
        store.heartbeat_gateway_call(&lease_id, "owner").unwrap(),
        GatewayHeartbeat::Extended { .. }
    ));
}

#[test]
fn migrates_every_supported_prior_schema_idempotently() {
    for version in 0..=5 {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join(format!("state-v{version}"));
        create_prior_schema(&root, version);
        drop(Store::open(&root).unwrap());
        drop(Store::open(&root).unwrap());

        let connection = Connection::open(root.join("again.sqlite")).unwrap();
        let migrated: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(migrated, 6, "source schema v{version}");
        for table in [
            "gateway_requests",
            "gateway_results",
            "result_dependencies",
            "inflight_leases",
            "gateway_deliveries",
            "gateway_events",
        ] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "{table} missing after source schema v{version}");
        }
    }
}

#[test]
fn legacy_local_result_survives_gateway_migration_unchanged() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("legacy-v5");
    create_prior_schema(&root, 5);
    let database = root.join("again.sqlite");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "INSERT INTO results (id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, quarantined, created_ms, last_used_ms) VALUES ('legacy-result', 'legacy-key', ?1, ?2, 3, 0, 0, 7, 'v0', '{}', 0, 1, 1)",
            params!["a".repeat(64), "b".repeat(64)],
        )
        .unwrap();
    drop(connection);

    let store = Store::open(&root).unwrap();
    let result = store.get_result("legacy-key").unwrap().unwrap();
    assert_eq!(result.id, "legacy-result");
    assert_eq!(result.request_key, "legacy-key");
    assert_eq!(result.stdout_bytes, 3);
    assert!(matches!(
        store
            .acquire_gateway_call("new-gateway-call", "state-v1", "owner")
            .unwrap(),
        GatewayCallAcquisition::Leader { .. }
    ));
    assert_eq!(store.get_result("legacy-key").unwrap(), Some(result));
}

#[test]
fn delivery_isolation_and_compaction_clearing_cover_all_context_dimensions() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let store = Store::open(&root).unwrap();
    let result = stored_result(&root, "provider-delivery", b"payload");
    let contexts = [
        GatewayAgentContext::new("session-a", "turn-a", "agent-a", 0),
        GatewayAgentContext::new("session-b", "turn-a", "agent-a", 0),
        GatewayAgentContext::new("session-a", "turn-b", "agent-a", 0),
        GatewayAgentContext::new("session-a", "turn-a", "agent-b", 0),
        GatewayAgentContext::new("session-a", "turn-a", "agent-a", 1),
    ];
    for context in &contexts {
        assert!(
            store
                .record_gateway_delivery(
                    context,
                    &result.id,
                    GatewayPresentation::Compact {
                        estimated_tokens_avoided: 11
                    }
                )
                .unwrap()
        );
        assert!(
            !store
                .record_gateway_delivery(
                    context,
                    &result.id,
                    GatewayPresentation::Compact {
                        estimated_tokens_avoided: 11
                    }
                )
                .unwrap()
        );
    }
    assert_eq!(store.clear_gateway_deliveries(&contexts[0]).unwrap(), 1);
    assert!(
        store
            .record_gateway_delivery(
                &contexts[0],
                &result.id,
                GatewayPresentation::Compact {
                    estimated_tokens_avoided: 11
                }
            )
            .unwrap()
    );
    assert!(
        !store
            .record_gateway_delivery(
                &contexts[4],
                &result.id,
                GatewayPresentation::Compact {
                    estimated_tokens_avoided: 11
                }
            )
            .unwrap()
    );
    let stats = store.gateway_stats().unwrap();
    assert_eq!(stats.compact_deliveries, 6);
    assert_eq!(stats.estimated_tokens_avoided, 66);
}

fn create_prior_schema(root: &Path, version: i64) {
    fs::create_dir(root).unwrap();
    #[cfg(unix)]
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let database = root.join("again.sqlite");
    let connection = Connection::open(&database).unwrap();
    if version >= 1 {
        connection
            .execute_batch(
                r#"
                CREATE TABLE pending_calls (
                    id TEXT PRIMARY KEY, session_id TEXT NOT NULL, turn_id TEXT,
                    cwd TEXT NOT NULL, raw_command TEXT NOT NULL, argv_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL
                );
                CREATE TABLE results (
                    id TEXT PRIMARY KEY, request_key TEXT NOT NULL UNIQUE,
                    stdout_digest TEXT NOT NULL, stderr_digest TEXT NOT NULL,
                    stdout_bytes INTEGER NOT NULL, stderr_bytes INTEGER NOT NULL,
                    exit_code INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
                    policy_version TEXT NOT NULL, proof_json TEXT NOT NULL,
                    quarantined INTEGER NOT NULL DEFAULT 0, quarantine_reason TEXT,
                    created_ms INTEGER NOT NULL, last_used_ms INTEGER NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE deliveries (
                    session_id TEXT NOT NULL, result_id TEXT NOT NULL, delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, call_id TEXT, result_id TEXT,
                    disposition TEXT NOT NULL, reason_code TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL DEFAULT 0,
                    bytes_omitted INTEGER NOT NULL DEFAULT 0, created_ms INTEGER NOT NULL
                );
                CREATE INDEX events_created_idx ON events(created_ms);
                "#,
            )
            .unwrap();
    }
    if version >= 2 {
        connection
            .execute_batch(
                r#"
                CREATE TABLE file_digests (
                    device BLOB NOT NULL, inode BLOB NOT NULL, mode INTEGER NOT NULL,
                    uid INTEGER NOT NULL, gid INTEGER NOT NULL, size BLOB NOT NULL,
                    mtime_sec INTEGER NOT NULL, mtime_nsec INTEGER NOT NULL,
                    ctime_sec INTEGER NOT NULL, ctime_nsec INTEGER NOT NULL,
                    digest BLOB NOT NULL, row_checksum BLOB NOT NULL,
                    last_used_ms INTEGER NOT NULL, PRIMARY KEY (device, inode)
                ) WITHOUT ROWID;
                CREATE INDEX file_digests_lru_idx ON file_digests(last_used_ms);
                "#,
            )
            .unwrap();
    }
    if version >= 3 {
        connection
            .execute_batch(
                r#"
                CREATE TABLE artifacts (digest TEXT PRIMARY KEY, created_ms INTEGER NOT NULL)
                    WITHOUT ROWID;
                CREATE INDEX artifacts_created_idx ON artifacts(created_ms);
                CREATE INDEX pending_calls_created_idx ON pending_calls(created_ms);
                CREATE TABLE maintenance (name TEXT PRIMARY KEY, completed_ms INTEGER NOT NULL)
                    WITHOUT ROWID;
                "#,
            )
            .unwrap();
    }
    if version >= 4 {
        connection
            .execute_batch(
                r#"
                ALTER TABLE pending_calls ADD COLUMN context_id TEXT;
                DROP TABLE deliveries;
                CREATE TABLE deliveries (
                    session_id TEXT NOT NULL, context_id TEXT NOT NULL,
                    result_id TEXT NOT NULL, delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, context_id, result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
                );
                "#,
            )
            .unwrap();
    }
    connection
        .pragma_update(None, "user_version", version)
        .unwrap();
    drop(connection);
    #[cfg(unix)]
    fs::set_permissions(database, fs::Permissions::from_mode(0o600)).unwrap();
}
