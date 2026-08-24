#![cfg(target_os = "macos")]

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tempfile::TempDir;

const GENERATION_ID: &str = "0123456789abcdef0123456789abcdef";

fn again_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_again"))
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    set_mode(path, 0o600);
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run_inspect(workspace: &Path, profile: &Path, state: &Path, home: &Path) -> Output {
    let mut command = Command::new(again_binary());
    command
        .current_dir(workspace)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("AGAIN_HOME", state)
        .args(["team", "inspect", "--profile"])
        .arg(profile)
        .args(["--json", "--", "cat", "src/input.txt"])
        .output()
        .unwrap()
}

#[test]
fn inspect_is_deterministic_secret_free_and_never_uses_transport_or_target_command() {
    if again::executable::host_audited_apple_profile().is_err() {
        return;
    }

    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o700);
    let root = temp.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    let private = root.join("private");
    let checkpoint = private.join("checkpoints");
    let home = private.join("home");
    let state = private.join("state");
    fs::create_dir_all(workspace.join("src")).unwrap();
    for directory in [&private, &checkpoint, &home, &state] {
        fs::create_dir_all(directory).unwrap();
        set_mode(directory, 0o700);
    }
    let target_sentinel = "TARGET_COMMAND_MUST_NOT_RUN_5f42d1";
    fs::write(
        workspace.join("src/input.txt"),
        format!("{target_sentinel}\n"),
    )
    .unwrap();

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint_origin = format!("https://{}", listener.local_addr().unwrap());

    let profile = private.join("profile.json");
    let read_token = private.join("read.token");
    let repository_key = private.join("repository-key.json");
    let sharing_policy = private.join("sharing-policy.json");
    let trust_checkpoint = checkpoint.join("trust.json");
    let runtime_checkpoint = checkpoint.join("runtime.json");
    let write_token = private.join("write.token");
    let signing_key = private.join("producer-signing-key.json");

    let read_secret = "READ_TOKEN_MUST_NOT_LEAK_d621e8";
    let repository_secret = "REPOSITORY_KEY_MUST_NOT_LEAK_b45a09";
    let write_secret = "WRITE_TOKEN_MUST_NOT_LEAK_71cdaa";
    write_private(&read_token, read_secret.as_bytes());
    write_private(&repository_key, repository_secret.as_bytes());
    write_private(&write_token, write_secret.as_bytes());
    write_private(
        &sharing_policy,
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "namespace": "again.repository-sharing-policy.v1",
            "version": "sharing-v1",
            "include_prefixes": ["src"],
            "exclude_prefixes": ["target", ".env"],
            "max_output_bytes": 1024 * 1024
        }))
        .unwrap(),
    );
    write_private(
        &signing_key,
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "namespace": "again.producer-signing-key.v1",
            "key_id": "producer-key-1",
            "producer_id": "producer-a",
            "secret_key_hex": "2a".repeat(32)
        }))
        .unwrap(),
    );
    let root = SigningKey::from_bytes(&[9; 32]);
    write_private(
        &profile,
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "namespace": "again.team-profile.v1",
            "endpoint_origin": endpoint_origin,
            "tenant_id": "tenant-a",
            "repository_id": "repo-a",
            "generation_id": GENERATION_ID,
            "pinned_root_key_id": "root-key-1",
            "pinned_root_public_key_hex": lower_hex(&root.verifying_key().to_bytes()),
            "read_token_file": read_token,
            "repository_key_file": repository_key,
            "sharing_policy_file": sharing_policy,
            "checkpoint_file": trust_checkpoint,
            "runtime_attestation_checkpoint_file": runtime_checkpoint,
            "lookup_protocol": "legacy_v2",
            "lookup_budget": {
                "max_requests": 5,
                "max_response_bytes": 20 * 1024 * 1024,
                "total_timeout_ms": 15_000
            },
            "publisher": {
                "write_token_file": write_token,
                "producer_signing_key_file": signing_key,
                "publish_budget": {
                    "max_requests": 4,
                    "max_transfer_bytes": 20 * 1024 * 1024,
                    "total_timeout_ms": 15_000
                }
            }
        }))
        .unwrap(),
    );

    // The first call may create the reviewed runtime checkpoint. The second
    // must use the same fast runtime/request admission as `team run`; neither
    // call may execute `wc` or contact the configured endpoint.
    let first = run_inspect(&workspace, &profile, &state, &home);
    assert!(
        first.status.success(),
        "first inspect failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = run_inspect(&workspace, &profile, &state, &home);
    assert!(
        second.status.success(),
        "second inspect failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());

    let document: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["namespace"], "again.team-inspection.v1");
    assert_eq!(document["lookup_protocol"], "legacy_v2");
    assert_eq!(document["scope"]["generation_id"], GENERATION_ID);
    assert_eq!(document["scope"]["endpoint_origin"], endpoint_origin);
    assert_eq!(
        document["producer"]["public_key_hex"],
        lower_hex(
            &SigningKey::from_bytes(&[0x2a; 32])
                .verifying_key()
                .to_bytes()
        )
    );

    let output = String::from_utf8(second.stdout).unwrap();
    for forbidden in [
        target_sentinel,
        read_secret,
        repository_secret,
        write_secret,
        &"2a".repeat(32),
        profile.to_str().unwrap(),
        workspace.to_str().unwrap(),
        "token_file",
        "repository_key_file",
        "signing_key_file",
        "environment",
        "issued_at_unix_seconds",
        "expires_at_unix_seconds",
        "signature",
    ] {
        assert!(!output.contains(forbidden), "inspection leaked {forbidden}");
    }

    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("team inspect contacted its configured endpoint"),
        Err(error) => panic!("inspect loopback listener: {error}"),
    }
}
