use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use again::store::{
    GatewayCallAcquisition, GatewayCallObservation, GatewayCompletion, GatewayCoordinatorInputV1,
    GatewayDependencyV1, GatewayExecutionStart, GatewayFailure, GatewayFailureReason,
    GatewayFollowerCancellation, GatewayFreshnessEvidenceV1, GatewayHeartbeat,
    GatewayOperationDispositionV1, GatewayRefusalReason, Store, StoredResult,
    ValidatedGatewayReadV1, gateway_policy_digest,
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

const POLICY: &str = "gateway-multiprocess-v1";
const ACTION_ENV: &str = "AGAIN_GATEWAY_MP_ACTION";
const ROOT_ENV: &str = "AGAIN_GATEWAY_MP_ROOT";
const OUTPUT_ENV: &str = "AGAIN_GATEWAY_MP_OUTPUT";
const READY_ENV: &str = "AGAIN_GATEWAY_MP_READY";
const GATE_ENV: &str = "AGAIN_GATEWAY_MP_GATE";
const OWNER_ENV: &str = "AGAIN_GATEWAY_MP_OWNER";
const REQUEST_ENV: &str = "AGAIN_GATEWAY_MP_REQUEST";
const STATE_ENV: &str = "AGAIN_GATEWAY_MP_STATE";
const LEASE_ENV: &str = "AGAIN_GATEWAY_MP_LEASE";
const RESULT_ENV: &str = "AGAIN_GATEWAY_MP_RESULT";
const CALL_ENV: &str = "AGAIN_GATEWAY_MP_CALL";
const RELEASE_ENV: &str = "AGAIN_GATEWAY_MP_RELEASE";
const MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WorkerOutcome {
    Acquisition {
        value: GatewayCallAcquisition,
    },
    LeaderStarted {
        acquisition: GatewayCallAcquisition,
        start: GatewayExecutionStart,
    },
    Start {
        value: GatewayExecutionStart,
    },
    Heartbeat {
        value: GatewayHeartbeat,
    },
    Observation {
        value: GatewayCallObservation,
    },
    Completion {
        value: GatewayCompletion,
    },
    Failure {
        value: GatewayFailure,
    },
    Cancellation {
        value: GatewayFollowerCancellation,
    },
    Retrieval {
        served: bool,
        failed_closed: bool,
        stdout: Vec<u8>,
    },
    Open {
        opened: bool,
    },
    Attempt {
        succeeded: bool,
        elapsed_ms: u64,
    },
    LockReleased,
}

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

fn binding(request: &str, state: &str) -> ValidatedGatewayReadV1 {
    let state_digest = digest(state);
    ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
        request_digest: digest(request),
        state_digest: state_digest.clone(),
        policy_digest: gateway_policy_digest(POLICY),
        operation: GatewayOperationDispositionV1::ReplayEligibleRead,
        freshness: GatewayFreshnessEvidenceV1 {
            snapshot_digest: state_digest,
            observed_at_ms: now_ms().saturating_sub(10),
            valid_until_ms: now_ms().saturating_add(120_000),
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

fn env_value(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing worker environment {name}"))
}

fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_gate(path: &Path) {
    wait_for_file(path, Duration::from_secs(15));
}

fn emit(path: &Path, outcome: &WorkerOutcome) {
    let bytes = serde_json::to_vec(outcome).unwrap();
    let mut file = File::create(path).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

/// This test is also the child-process entrypoint. Parent tests invoke only
/// this exact harness case with a closed action vocabulary. Crash actions call
/// `process::exit` after durable output so Store destructors cannot turn the
/// process-death tests into graceful-close tests.
#[test]
fn multiprocess_worker() {
    let Some(action) = std::env::var_os(ACTION_ENV) else {
        return;
    };
    let action = action.to_string_lossy().into_owned();
    let root = PathBuf::from(env_value(ROOT_ENV));
    let output = PathBuf::from(env_value(OUTPUT_ENV));

    if action == "open" {
        emit(
            &output,
            &WorkerOutcome::Open {
                opened: Store::open(&root).is_ok(),
            },
        );
        return;
    }
    if action == "hold_lock" {
        let connection = Connection::open(root.join("again.sqlite")).unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        let ready = PathBuf::from(env_value(READY_ENV));
        fs::write(&ready, b"ready").unwrap();
        wait_for_gate(Path::new(&env_value(RELEASE_ENV)));
        connection.execute_batch("COMMIT").unwrap();
        emit(&output, &WorkerOutcome::LockReleased);
        return;
    }
    if action == "try_acquire" {
        let started = Instant::now();
        let outcome = Store::open(&root).and_then(|store| {
            store.acquire_gateway_call(
                &binding(&env_value(REQUEST_ENV), &env_value(STATE_ENV)),
                &env_value(OWNER_ENV),
            )
        });
        emit(
            &output,
            &WorkerOutcome::Attempt {
                succeeded: outcome.is_ok(),
                elapsed_ms: started.elapsed().as_millis().try_into().unwrap(),
            },
        );
        return;
    }

    let store = Store::open(&root).unwrap();
    if let Ok(ready) = std::env::var(READY_ENV) {
        fs::write(ready, b"ready").unwrap();
    }
    if let Ok(gate) = std::env::var(GATE_ENV) {
        wait_for_gate(Path::new(&gate));
    }
    let request = std::env::var(REQUEST_ENV).unwrap_or_else(|_| "request".to_owned());
    let state = std::env::var(STATE_ENV).unwrap_or_else(|_| "state".to_owned());
    let proof = binding(&request, &state);
    let owner = std::env::var(OWNER_ENV).unwrap_or_else(|_| "worker".to_owned());
    let outcome = match action.as_str() {
        "acquire" => WorkerOutcome::Acquisition {
            value: store.acquire_gateway_call(&proof, &owner).unwrap(),
        },
        "acquire_crash_before" => {
            let value = store.acquire_gateway_call(&proof, &owner).unwrap();
            let outcome = WorkerOutcome::Acquisition { value };
            emit(&output, &outcome);
            std::process::exit(0);
        }
        "acquire_crash_after" => {
            let acquisition = store.acquire_gateway_call(&proof, &owner).unwrap();
            let lease = leader_lease(&acquisition).to_owned();
            let start = store.start_gateway_execution(&lease, &owner).unwrap();
            let outcome = WorkerOutcome::LeaderStarted { acquisition, start };
            emit(&output, &outcome);
            std::process::exit(0);
        }
        "start" => WorkerOutcome::Start {
            value: store
                .start_gateway_execution(&env_value(LEASE_ENV), &owner)
                .unwrap(),
        },
        "heartbeat" => WorkerOutcome::Heartbeat {
            value: store
                .heartbeat_gateway_call(&env_value(LEASE_ENV), &owner)
                .unwrap(),
        },
        "observe" => WorkerOutcome::Observation {
            value: store.observe_gateway_call(&proof).unwrap(),
        },
        "complete" => WorkerOutcome::Completion {
            value: store
                .complete_gateway_call(&env_value(LEASE_ENV), &env_value(RESULT_ENV))
                .unwrap(),
        },
        "fail" => WorkerOutcome::Failure {
            value: store
                .fail_gateway_call(
                    &env_value(LEASE_ENV),
                    GatewayFailureReason::ProviderUnavailable,
                )
                .unwrap(),
        },
        "cancel" => WorkerOutcome::Cancellation {
            value: store.cancel_gateway_follower(&env_value(CALL_ENV)).unwrap(),
        },
        "get" => match store.get_gateway_result(&proof, &env_value(RESULT_ENV)) {
            Ok(Some(full)) => WorkerOutcome::Retrieval {
                served: true,
                failed_closed: false,
                stdout: full.stdout,
            },
            Ok(None) => WorkerOutcome::Retrieval {
                served: false,
                failed_closed: false,
                stdout: Vec::new(),
            },
            Err(_) => WorkerOutcome::Retrieval {
                served: false,
                failed_closed: true,
                stdout: Vec::new(),
            },
        },
        other => panic!("unknown worker action {other}"),
    };
    emit(&output, &outcome);
}

fn spawn_worker(
    root: &Path,
    output: &Path,
    action: &str,
    values: &[(&str, &str)],
    ready: Option<&Path>,
    gate: Option<&Path>,
) -> Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("multiprocess_worker")
        .arg("--nocapture")
        .env(ACTION_ENV, action)
        .env(ROOT_ENV, root)
        .env(OUTPUT_ENV, output)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(ready) = ready {
        command.env(READY_ENV, ready);
    }
    if let Some(gate) = gate {
        command.env(GATE_ENV, gate);
    }
    for (name, value) in values {
        command.env(name, value);
    }
    command.spawn().unwrap()
}

fn wait_worker(child: Child, output_path: &Path) -> WorkerOutcome {
    let process = child.wait_with_output().unwrap();
    assert!(
        process.status.success(),
        "worker failed: stdout={} stderr={}",
        String::from_utf8_lossy(&process.stdout),
        String::from_utf8_lossy(&process.stderr)
    );
    serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap()
}

fn run_worker(root: &Path, output: &Path, action: &str, values: &[(&str, &str)]) -> WorkerOutcome {
    let child = spawn_worker(root, output, action, values, None, None);
    wait_worker(child, output)
}

fn leader_lease(value: &GatewayCallAcquisition) -> &str {
    match value {
        GatewayCallAcquisition::Leader { lease_id, .. } => lease_id,
        other => panic!("expected leader, got {other:?}"),
    }
}

fn follower_parts(value: &GatewayCallAcquisition) -> (&str, &str) {
    match value {
        GatewayCallAcquisition::Follower {
            call_id, lease_id, ..
        } => (call_id, lease_id),
        other => panic!("expected follower, got {other:?}"),
    }
}

fn acquisition(outcome: WorkerOutcome) -> GatewayCallAcquisition {
    match outcome {
        WorkerOutcome::Acquisition { value } => value,
        other => panic!("expected acquisition, got {other:?}"),
    }
}

fn force_lease_expired(root: &Path, lease_id: &str) {
    // Tests advance only the durable deadline row. Production constants and
    // clocks remain untouched, and the public API must still perform the
    // transactional expiry/generation transition.
    Connection::open(root.join("again.sqlite"))
        .unwrap()
        .execute(
            "UPDATE inflight_leases SET expires_ms = ?2 WHERE lease_id = ?1",
            params![lease_id, now_ms().saturating_sub(1)],
        )
        .unwrap();
}

fn stored_result(root: &Path, proof: &ValidatedGatewayReadV1, stdout: &[u8]) -> StoredResult {
    Store::open(root)
        .unwrap()
        .insert_result(
            proof.request_digest(),
            stdout,
            b"diagnostic",
            0,
            7,
            POLICY,
            "{\"proof\":\"exact\"}",
        )
        .unwrap()
}

struct CompletedFixture {
    result: StoredResult,
    gateway_result_id: String,
    lease_id: String,
}

fn completed_fixture(root: &Path, request: &str, state: &str, stdout: &[u8]) -> CompletedFixture {
    let proof = binding(request, state);
    let store = Store::open(root).unwrap();
    let acquired = store.acquire_gateway_call(&proof, "fixture-owner").unwrap();
    let lease_id = leader_lease(&acquired).to_owned();
    assert_eq!(
        store
            .start_gateway_execution(&lease_id, "fixture-owner")
            .unwrap(),
        GatewayExecutionStart::Started
    );
    let result = stored_result(root, &proof, stdout);
    let gateway_result_id = match store.complete_gateway_call(&lease_id, &result.id).unwrap() {
        GatewayCompletion::Completed {
            gateway_result_id, ..
        } => gateway_result_id,
        other => panic!("expected completion, got {other:?}"),
    };
    CompletedFixture {
        result,
        gateway_result_id,
        lease_id,
    }
}

fn database(root: &Path) -> PathBuf {
    root.join("again.sqlite")
}

fn blob_path(root: &Path, digest: &str) -> PathBuf {
    root.join("blobs").join(&digest[..2]).join(&digest[2..])
}

#[test]
fn twenty_simultaneous_processes_elect_exactly_one_leader() {
    const CALLERS: usize = 20;
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    drop(Store::open(&root).unwrap());
    let gate = temp.path().join("gate");
    let mut children = Vec::new();
    let mut outputs = Vec::new();
    let mut ready_files = Vec::new();
    for index in 0..CALLERS {
        let output = temp.path().join(format!("out-{index}"));
        let ready = temp.path().join(format!("ready-{index}"));
        let owner = format!("owner-{index}");
        children.push(spawn_worker(
            &root,
            &output,
            "acquire",
            &[
                (OWNER_ENV, owner.as_str()),
                (REQUEST_ENV, "shared-request"),
                (STATE_ENV, "shared-state"),
            ],
            Some(&ready),
            Some(&gate),
        ));
        outputs.push(output);
        ready_files.push(ready);
    }
    for ready in &ready_files {
        wait_for_file(ready, Duration::from_secs(15));
    }
    fs::write(&gate, b"go").unwrap();
    let outcomes: Vec<_> = children
        .into_iter()
        .zip(&outputs)
        .map(|(child, output)| acquisition(wait_worker(child, output)))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, GatewayCallAcquisition::Leader { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, GatewayCallAcquisition::Follower { .. }))
            .count(),
        CALLERS - 1
    );
    let leader_lease = outcomes.iter().find_map(|value| match value {
        GatewayCallAcquisition::Leader { lease_id, .. } => Some(lease_id),
        _ => None,
    });
    assert!(outcomes.iter().all(|value| match value {
        GatewayCallAcquisition::Leader { lease_id, .. } => Some(lease_id) == leader_lease,
        GatewayCallAcquisition::Follower { lease_id, .. } => Some(lease_id) == leader_lease,
        _ => false,
    }));
}

#[test]
fn followers_join_only_the_current_lease_generation() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let first = acquisition(run_worker(
        &root,
        &temp.path().join("leader-1"),
        "acquire",
        &[(OWNER_ENV, "leader-1")],
    ));
    let first_lease = leader_lease(&first).to_owned();
    let old_follower = acquisition(run_worker(
        &root,
        &temp.path().join("follower-1"),
        "acquire",
        &[(OWNER_ENV, "follower-1")],
    ));
    assert_eq!(follower_parts(&old_follower).1, first_lease);
    force_lease_expired(&root, &first_lease);
    let second = acquisition(run_worker(
        &root,
        &temp.path().join("leader-2"),
        "acquire",
        &[(OWNER_ENV, "leader-2")],
    ));
    let second_lease = leader_lease(&second).to_owned();
    assert_ne!(first_lease, second_lease);
    let new_follower = acquisition(run_worker(
        &root,
        &temp.path().join("follower-2"),
        "acquire",
        &[(OWNER_ENV, "follower-2")],
    ));
    assert_eq!(follower_parts(&new_follower).1, second_lease);
    let generations: Vec<i64> = Connection::open(database(&root))
        .unwrap()
        .prepare("SELECT lifecycle_generation FROM inflight_leases ORDER BY lifecycle_generation")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(generations, vec![1, 2]);
}

#[test]
fn crashed_leader_before_execution_is_joined_until_expiry_then_replaced() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let crashed = acquisition(run_worker(
        &root,
        &temp.path().join("crashed"),
        "acquire_crash_before",
        &[(OWNER_ENV, "crashed-leader")],
    ));
    let old_lease = leader_lease(&crashed).to_owned();
    let restarted = acquisition(run_worker(
        &root,
        &temp.path().join("restart-before-expiry"),
        "acquire",
        &[(OWNER_ENV, "restarted")],
    ));
    assert_eq!(follower_parts(&restarted).1, old_lease);
    force_lease_expired(&root, &old_lease);
    let takeover = acquisition(run_worker(
        &root,
        &temp.path().join("restart-after-expiry"),
        "acquire",
        &[(OWNER_ENV, "takeover")],
    ));
    assert_ne!(leader_lease(&takeover), old_lease);
}

#[test]
fn crashed_leader_after_execution_start_is_joined_until_expiry_then_replaced() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let crashed = run_worker(
        &root,
        &temp.path().join("crashed"),
        "acquire_crash_after",
        &[(OWNER_ENV, "crashed-leader")],
    );
    let crashed_acquisition = match crashed {
        WorkerOutcome::LeaderStarted { acquisition, start } => {
            assert_eq!(start, GatewayExecutionStart::Started);
            acquisition
        }
        other => panic!("expected started leader, got {other:?}"),
    };
    let old_lease = leader_lease(&crashed_acquisition).to_owned();
    let restarted = acquisition(run_worker(
        &root,
        &temp.path().join("restart-before-expiry"),
        "acquire",
        &[(OWNER_ENV, "restarted")],
    ));
    assert_eq!(follower_parts(&restarted).1, old_lease);
    force_lease_expired(&root, &old_lease);
    let takeover = acquisition(run_worker(
        &root,
        &temp.path().join("restart-after-expiry"),
        "acquire",
        &[(OWNER_ENV, "takeover")],
    ));
    assert_ne!(leader_lease(&takeover), old_lease);
}

#[test]
fn stale_process_cannot_complete_after_new_generation_begins() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let first = acquisition(run_worker(
        &root,
        &temp.path().join("first"),
        "acquire",
        &[(OWNER_ENV, "first-owner")],
    ));
    let old_lease = leader_lease(&first).to_owned();
    force_lease_expired(&root, &old_lease);
    let second = acquisition(run_worker(
        &root,
        &temp.path().join("second"),
        "acquire",
        &[(OWNER_ENV, "second-owner")],
    ));
    let new_lease = leader_lease(&second).to_owned();
    let proof = binding("request", "state");
    let result = stored_result(&root, &proof, b"winner");
    let stale = run_worker(
        &root,
        &temp.path().join("stale-complete"),
        "complete",
        &[(LEASE_ENV, &old_lease), (RESULT_ENV, &result.id)],
    );
    assert_eq!(
        match stale {
            WorkerOutcome::Completion { value } => value,
            other => panic!("expected completion, got {other:?}"),
        },
        GatewayCompletion::Refused {
            reason: GatewayRefusalReason::LeaseExpired
        }
    );
    assert_eq!(
        match run_worker(
            &root,
            &temp.path().join("start-new"),
            "start",
            &[(LEASE_ENV, &new_lease), (OWNER_ENV, "second-owner")],
        ) {
            WorkerOutcome::Start { value } => value,
            other => panic!("expected start, got {other:?}"),
        },
        GatewayExecutionStart::Started
    );
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("complete-new"),
            "complete",
            &[(LEASE_ENV, &new_lease), (RESULT_ENV, &result.id)],
        ),
        WorkerOutcome::Completion {
            value: GatewayCompletion::Completed { .. }
        }
    ));
}

#[test]
fn heartbeat_extends_only_the_matching_active_owner() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let first = acquisition(run_worker(
        &root,
        &temp.path().join("leader"),
        "acquire",
        &[(OWNER_ENV, "heartbeat-owner")],
    ));
    let (lease, initial_expiry) = match first {
        GatewayCallAcquisition::Leader {
            lease_id,
            expires_at_ms,
            ..
        } => (lease_id, expires_at_ms),
        other => panic!("expected leader, got {other:?}"),
    };
    assert_eq!(
        match run_worker(
            &root,
            &temp.path().join("wrong-owner"),
            "heartbeat",
            &[(LEASE_ENV, &lease), (OWNER_ENV, "wrong-owner")],
        ) {
            WorkerOutcome::Heartbeat { value } => value,
            other => panic!("expected heartbeat, got {other:?}"),
        },
        GatewayHeartbeat::Refused {
            reason: GatewayRefusalReason::OwnerMismatch
        }
    );
    thread::sleep(Duration::from_millis(20));
    let extended = match run_worker(
        &root,
        &temp.path().join("right-owner"),
        "heartbeat",
        &[(LEASE_ENV, &lease), (OWNER_ENV, "heartbeat-owner")],
    ) {
        WorkerOutcome::Heartbeat {
            value: GatewayHeartbeat::Extended { expires_at_ms },
        } => expires_at_ms,
        other => panic!("expected extended heartbeat, got {other:?}"),
    };
    assert!(extended > initial_expiry);
    force_lease_expired(&root, &lease);
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("expired-heartbeat"),
            "heartbeat",
            &[(LEASE_ENV, &lease), (OWNER_ENV, "heartbeat-owner")],
        ),
        WorkerOutcome::Heartbeat {
            value: GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::LeaseExpired
            }
        }
    ));
}

#[test]
fn follower_cancellation_is_local_and_leader_remains_active() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let leader = acquisition(run_worker(
        &root,
        &temp.path().join("leader"),
        "acquire",
        &[(OWNER_ENV, "leader")],
    ));
    let lease = leader_lease(&leader).to_owned();
    let follower = acquisition(run_worker(
        &root,
        &temp.path().join("follower"),
        "acquire",
        &[(OWNER_ENV, "follower")],
    ));
    let call = follower_parts(&follower).0.to_owned();
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("cancel"),
            "cancel",
            &[(CALL_ENV, &call)],
        ),
        WorkerOutcome::Cancellation {
            value: GatewayFollowerCancellation::Cancelled
        }
    ));
    let replacement = acquisition(run_worker(
        &root,
        &temp.path().join("replacement-follower"),
        "acquire",
        &[(OWNER_ENV, "replacement")],
    ));
    assert_eq!(follower_parts(&replacement).1, lease);
    assert!(matches!(
        run_worker(&root, &temp.path().join("observe"), "observe", &[]),
        WorkerOutcome::Observation {
            value: GatewayCallObservation::Inflight { leader, .. }
        } if leader == "leader"
    ));
}

#[test]
fn leader_failure_releases_followers_to_retryable_generation() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let leader = acquisition(run_worker(
        &root,
        &temp.path().join("leader"),
        "acquire",
        &[(OWNER_ENV, "leader")],
    ));
    let lease = leader_lease(&leader).to_owned();
    let follower = acquisition(run_worker(
        &root,
        &temp.path().join("follower"),
        "acquire",
        &[(OWNER_ENV, "follower")],
    ));
    assert_eq!(follower_parts(&follower).1, lease);
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("fail"),
            "fail",
            &[(LEASE_ENV, &lease)],
        ),
        WorkerOutcome::Failure {
            value: GatewayFailure::Failed { .. }
        }
    ));
    assert!(matches!(
        run_worker(&root, &temp.path().join("observe"), "observe", &[]),
        WorkerOutcome::Observation {
            value: GatewayCallObservation::Failed {
                reason: GatewayFailureReason::ProviderUnavailable
            }
        }
    ));
    let retry = acquisition(run_worker(
        &root,
        &temp.path().join("retry"),
        "acquire",
        &[(OWNER_ENV, "retry")],
    ));
    assert_ne!(leader_lease(&retry), lease);
}

#[test]
fn distinct_bindings_elect_independent_process_leaders() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    drop(Store::open(&root).unwrap());
    let gate = temp.path().join("gate");
    let ready_a = temp.path().join("ready-a");
    let ready_b = temp.path().join("ready-b");
    let output_a = temp.path().join("out-a");
    let output_b = temp.path().join("out-b");
    let child_a = spawn_worker(
        &root,
        &output_a,
        "acquire",
        &[
            (OWNER_ENV, "owner-a"),
            (REQUEST_ENV, "request-a"),
            (STATE_ENV, "state-a"),
        ],
        Some(&ready_a),
        Some(&gate),
    );
    let child_b = spawn_worker(
        &root,
        &output_b,
        "acquire",
        &[
            (OWNER_ENV, "owner-b"),
            (REQUEST_ENV, "request-b"),
            (STATE_ENV, "state-b"),
        ],
        Some(&ready_b),
        Some(&gate),
    );
    wait_for_file(&ready_a, Duration::from_secs(15));
    wait_for_file(&ready_b, Duration::from_secs(15));
    fs::write(&gate, b"go").unwrap();
    let first = acquisition(wait_worker(child_a, &output_a));
    let second = acquisition(wait_worker(child_b, &output_b));
    assert!(matches!(first, GatewayCallAcquisition::Leader { .. }));
    assert!(matches!(second, GatewayCallAcquisition::Leader { .. }));
    assert_ne!(leader_lease(&first), leader_lease(&second));
    let first_lease = leader_lease(&first).to_owned();
    let second_lease = leader_lease(&second).to_owned();
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("start-a"),
            "start",
            &[(LEASE_ENV, &first_lease), (OWNER_ENV, "owner-a")],
        ),
        WorkerOutcome::Start {
            value: GatewayExecutionStart::Started
        }
    ));
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("start-b"),
            "start",
            &[(LEASE_ENV, &second_lease), (OWNER_ENV, "owner-b")],
        ),
        WorkerOutcome::Start {
            value: GatewayExecutionStart::Started
        }
    ));
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("fail-a"),
            "fail",
            &[(LEASE_ENV, &first_lease)],
        ),
        WorkerOutcome::Failure {
            value: GatewayFailure::Failed { .. }
        }
    ));
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("observe-b"),
            "observe",
            &[(REQUEST_ENV, "request-b"), (STATE_ENV, "state-b")],
        ),
        WorkerOutcome::Observation {
            value: GatewayCallObservation::Inflight { leader, .. }
        } if leader == "owner-b"
    ));
}

#[test]
fn sqlite_write_lock_contention_obeys_bounded_busy_timeout() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    drop(Store::open(&root).unwrap());
    let ready = temp.path().join("lock-ready");
    let release = temp.path().join("lock-release");
    let lock_output = temp.path().join("lock-output");
    let attempt_output = temp.path().join("attempt-output");
    let release_string = release.to_string_lossy().into_owned();
    let holder = spawn_worker(
        &root,
        &lock_output,
        "hold_lock",
        &[(RELEASE_ENV, &release_string)],
        Some(&ready),
        None,
    );
    wait_for_file(&ready, Duration::from_secs(15));
    let attempt = run_worker(
        &root,
        &attempt_output,
        "try_acquire",
        &[(OWNER_ENV, "blocked")],
    );
    fs::write(&release, b"release").unwrap();
    assert!(matches!(
        wait_worker(holder, &lock_output),
        WorkerOutcome::LockReleased
    ));
    match attempt {
        WorkerOutcome::Attempt {
            succeeded,
            elapsed_ms,
        } => {
            assert!(!succeeded, "contended write unexpectedly bypassed the lock");
            assert!(
                elapsed_ms >= 4_000,
                "busy timeout returned too early: {elapsed_ms}ms"
            );
            assert!(
                elapsed_ms < 8_000,
                "busy timeout was unbounded: {elapsed_ms}ms"
            );
        }
        other => panic!("expected bounded attempt, got {other:?}"),
    }
}

#[test]
fn malformed_duplicate_and_broken_relationships_refuse_open_or_reuse() {
    let temp = TempDir::new().unwrap();

    let malformed = temp.path().join("malformed");
    drop(Store::open(&malformed).unwrap());
    Connection::open(database(&malformed))
        .unwrap()
        .execute("DROP INDEX gateway_requests_binding_idx", [])
        .unwrap();
    assert!(matches!(
        run_worker(&malformed, &temp.path().join("malformed-out"), "open", &[]),
        WorkerOutcome::Open { opened: false }
    ));

    let duplicate = temp.path().join("duplicate");
    let fixture = completed_fixture(&duplicate, "duplicate", "state", b"duplicate");
    let connection = Connection::open(database(&duplicate)).unwrap();
    connection
        .execute_batch(
            "DROP INDEX gateway_results_ready_idx;
             CREATE INDEX gateway_results_ready_idx ON gateway_results(binding_digest);",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gateway_results SELECT ?1, request_digest, state_digest, policy_digest, binding_digest, result_id, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, result_policy_version, proof_digest, lease_id, status, quarantine_reason, created_ms, updated_ms FROM gateway_results WHERE gateway_result_id = ?2",
            params!["f".repeat(64), fixture.gateway_result_id],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        run_worker(&duplicate, &temp.path().join("duplicate-out"), "open", &[]),
        WorkerOutcome::Open { opened: false }
    ));

    let broken_fk = temp.path().join("broken-fk");
    drop(Store::open(&broken_fk).unwrap());
    let connection = Connection::open(database(&broken_fk)).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection
        .execute(
            "INSERT INTO gateway_request_dependencies (call_id, ordinal, dependency_key_digest, dependency_value_digest) VALUES ('missing-call', 0, ?1, ?2)",
            params![digest("fk-key"), digest("fk-value")],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        run_worker(&broken_fk, &temp.path().join("broken-fk-out"), "open", &[]),
        WorkerOutcome::Open { opened: false }
    ));

    let broken_origin = temp.path().join("broken-origin");
    let fixture = completed_fixture(&broken_origin, "broken-origin", "state", b"origin");
    Connection::open(database(&broken_origin))
        .unwrap()
        .execute(
            "UPDATE gateway_results SET lease_id = 'missing-lease' WHERE gateway_result_id = ?1",
            [&fixture.gateway_result_id],
        )
        .unwrap();
    assert!(matches!(
        run_worker(
            &broken_origin,
            &temp.path().join("broken-origin-get"),
            "get",
            &[
                (REQUEST_ENV, "broken-origin"),
                (STATE_ENV, "state"),
                (RESULT_ENV, &fixture.gateway_result_id),
            ],
        ),
        WorkerOutcome::Retrieval {
            served: false,
            failed_closed: true,
            ..
        }
    ));
    assert!(matches!(
        acquisition(run_worker(
            &broken_origin,
            &temp.path().join("broken-origin-out"),
            "acquire",
            &[
                (REQUEST_ENV, "broken-origin"),
                (STATE_ENV, "state"),
                (OWNER_ENV, "reader"),
            ],
        )),
        GatewayCallAcquisition::Refused {
            reason: GatewayRefusalReason::Quarantined
        }
    ));

    let inconsistent = temp.path().join("inconsistent");
    let fixture = completed_fixture(&inconsistent, "inconsistent", "state", b"dependency");
    Connection::open(database(&inconsistent))
        .unwrap()
        .execute(
            "UPDATE result_dependencies SET dependency_value_digest = ?2 WHERE gateway_result_id = ?1 AND ordinal = 0",
            params![fixture.gateway_result_id, digest("inconsistent-value")],
        )
        .unwrap();
    assert!(matches!(
        acquisition(run_worker(
            &inconsistent,
            &temp.path().join("inconsistent-out"),
            "acquire",
            &[
                (REQUEST_ENV, "inconsistent"),
                (STATE_ENV, "state"),
                (OWNER_ENV, "reader"),
            ],
        )),
        GatewayCallAcquisition::Refused {
            reason: GatewayRefusalReason::Quarantined
        }
    ));
}

#[test]
fn every_cas_corruption_shape_fails_closed_and_quarantines_ready_binding() {
    let temp = TempDir::new().unwrap();
    let cases = [
        "missing",
        "oversized",
        "truncated",
        "digest-mismatch",
        "symlink",
    ];
    for (index, case) in cases.into_iter().enumerate() {
        let root = temp.path().join(format!("state-{index}"));
        let request = format!("cas-{index}");
        let fixture = completed_fixture(&root, &request, "state", b"immutable payload");
        let path = blob_path(&root, &fixture.result.stdout_digest);
        match case {
            "missing" => fs::remove_file(&path).unwrap(),
            "oversized" => OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(MAX_BLOB_BYTES + 1)
                .unwrap(),
            "truncated" => OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(1)
                .unwrap(),
            "digest-mismatch" => fs::write(&path, b"mutable payload!!").unwrap(),
            "symlink" => {
                #[cfg(unix)]
                {
                    let outside = temp.path().join(format!("outside-{index}"));
                    fs::write(&outside, b"immutable payload").unwrap();
                    fs::remove_file(&path).unwrap();
                    symlink(&outside, &path).unwrap();
                }
                #[cfg(not(unix))]
                {
                    continue;
                }
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            run_worker(
                &root,
                &temp.path().join(format!("get-{index}")),
                "get",
                &[
                    (REQUEST_ENV, &request),
                    (STATE_ENV, "state"),
                    (RESULT_ENV, &fixture.gateway_result_id),
                ],
            ),
            WorkerOutcome::Retrieval {
                served: false,
                failed_closed: true,
                ..
            }
        ));
        assert!(matches!(
            acquisition(run_worker(
                &root,
                &temp.path().join(format!("acquire-{index}")),
                "acquire",
                &[
                    (REQUEST_ENV, &request),
                    (STATE_ENV, "state"),
                    (OWNER_ENV, "reader"),
                ],
            )),
            GatewayCallAcquisition::Refused {
                reason: GatewayRefusalReason::Quarantined
            }
        ));
    }

    let root = temp.path().join("pre-completion-corruption");
    let proof = binding("pre-completion-corruption", "state");
    let store = Store::open(&root).unwrap();
    let acquired = store
        .acquire_gateway_call(&proof, "pre-completion-owner")
        .unwrap();
    let lease = leader_lease(&acquired).to_owned();
    assert_eq!(
        store
            .start_gateway_execution(&lease, "pre-completion-owner")
            .unwrap(),
        GatewayExecutionStart::Started
    );
    let result = stored_result(&root, &proof, b"not publishable");
    fs::remove_file(blob_path(&root, &result.stdout_digest)).unwrap();
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("pre-completion-out"),
            "complete",
            &[(LEASE_ENV, &lease), (RESULT_ENV, &result.id)],
        ),
        WorkerOutcome::Completion {
            value: GatewayCompletion::Refused {
                reason: GatewayRefusalReason::ResultCorrupt
            }
        }
    ));
}

#[test]
fn divergent_process_completions_atomically_quarantine_binding() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let fixture = completed_fixture(&root, "divergent", "state", b"original");
    Connection::open(database(&root))
        .unwrap()
        .execute(
            "UPDATE results SET duration_ms = duration_ms + 1 WHERE id = ?1",
            [&fixture.result.id],
        )
        .unwrap();
    let gate = temp.path().join("gate");
    let mut children = Vec::new();
    let mut outputs = Vec::new();
    for index in 0..2 {
        let output = temp.path().join(format!("complete-{index}"));
        let ready = temp.path().join(format!("ready-{index}"));
        children.push(spawn_worker(
            &root,
            &output,
            "complete",
            &[
                (LEASE_ENV, &fixture.lease_id),
                (RESULT_ENV, &fixture.result.id),
            ],
            Some(&ready),
            Some(&gate),
        ));
        outputs.push((output, ready));
    }
    for (_, ready) in &outputs {
        wait_for_file(ready, Duration::from_secs(15));
    }
    fs::write(&gate, b"go").unwrap();
    let outcomes: Vec<_> = children
        .into_iter()
        .zip(&outputs)
        .map(|(child, (output, _))| wait_worker(child, output))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                WorkerOutcome::Completion {
                    value: GatewayCompletion::Quarantined { .. }
                }
            ))
            .count(),
        1
    );
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("observe"),
            "observe",
            &[(REQUEST_ENV, "divergent"), (STATE_ENV, "state")],
        ),
        WorkerOutcome::Observation {
            value: GatewayCallObservation::Quarantined { .. }
        }
    ));
}

#[test]
fn reopen_preserves_exact_bytes_but_not_stale_execution_authority() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("state");
    let fixture = completed_fixture(&root, "reopen", "state", b"persistent bytes");
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("get"),
            "get",
            &[
                (REQUEST_ENV, "reopen"),
                (STATE_ENV, "state"),
                (RESULT_ENV, &fixture.gateway_result_id),
            ],
        ),
        WorkerOutcome::Retrieval {
            served: true,
            failed_closed: false,
            stdout,
        } if stdout == b"persistent bytes"
    ));
    assert!(matches!(
        acquisition(run_worker(
            &root,
            &temp.path().join("ready"),
            "acquire",
            &[
                (REQUEST_ENV, "reopen"),
                (STATE_ENV, "state"),
                (OWNER_ENV, "reader"),
            ],
        )),
        GatewayCallAcquisition::Ready { .. }
    ));
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("start-stale"),
            "start",
            &[(LEASE_ENV, &fixture.lease_id), (OWNER_ENV, "fixture-owner")],
        ),
        WorkerOutcome::Start {
            value: GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::AlreadyTerminal
            }
        }
    ));
    assert!(matches!(
        run_worker(
            &root,
            &temp.path().join("wrong-binding"),
            "get",
            &[
                (REQUEST_ENV, "different-request"),
                (STATE_ENV, "different-state"),
                (RESULT_ENV, &fixture.gateway_result_id),
            ],
        ),
        WorkerOutcome::Retrieval {
            served: false,
            failed_closed: true,
            ..
        }
    ));
}
