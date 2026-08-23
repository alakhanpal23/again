use std::fs;

use again::setup::{SetupScope, hook_path, install_codex_hook, remove_codex_hook};
use again::store::{EventDisposition, Store};
use serde_json::Value;
use tempfile::TempDir;

const AGAIN_SENTINEL: &str = "AGAIN_CODEX_HOOK_V1=1";

fn hook_file(temp: &TempDir) -> std::path::PathBuf {
    temp.path().join(".codex").join("hooks.json")
}

fn executable_with_shell_sensitive_path(temp: &TempDir) -> std::path::PathBuf {
    let dir = temp.path().join("bin with spaces");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("again's binary");
    fs::write(&path, b"fake executable").unwrap();
    path
}

#[test]
fn cas_detects_corruption_after_storage() {
    let temp = TempDir::new().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let digest = store.put_blob(b"immutable bytes").unwrap();
    let blob_path = temp
        .path()
        .join("blobs")
        .join(&digest[..2])
        .join(&digest[2..]);

    fs::write(&blob_path, b"tampered bytes").unwrap();
    let error = store.get_blob(&digest).unwrap_err().to_string();
    assert!(
        error.contains("CAS corruption"),
        "unexpected error: {error}"
    );
}

#[test]
fn same_key_divergence_is_quarantined_and_hidden() {
    let temp = TempDir::new().unwrap();
    let mut store = Store::open(temp.path()).unwrap();
    let first = store
        .insert_result("same-key", b"first", b"", 0, 7, "v0", "{}")
        .unwrap();

    let error = store
        .insert_result("same-key", b"second", b"", 0, 7, "v0", "{}")
        .unwrap_err()
        .to_string();
    assert!(error.contains("differential mismatch"));
    assert!(store.get_result("same-key").unwrap().is_none());
    assert!(store.get_result_by_id(&first.id).unwrap().is_none());
    assert_eq!(
        store.last_event().unwrap(),
        Some((
            "quarantined".to_owned(),
            "same_key_different_result".to_owned(),
            Some(first.id),
        ))
    );
    assert_eq!(store.stats().unwrap().quarantines, 1);
}

#[test]
fn delivery_state_is_separate_per_session() {
    let temp = TempDir::new().unwrap();
    let mut store = Store::open(temp.path()).unwrap();
    let result = store
        .insert_result("key", b"stdout", b"stderr", 0, 20, "v0", "{}")
        .unwrap();

    assert!(!store.was_delivered("session-a", &result.id).unwrap());
    assert!(!store.was_delivered("session-b", &result.id).unwrap());
    store.mark_delivered("session-a", &result.id).unwrap();
    store.mark_delivered("session-a", &result.id).unwrap();
    assert!(store.was_delivered("session-a", &result.id).unwrap());
    assert!(!store.was_delivered("session-b", &result.id).unwrap());
}

#[test]
fn stats_aggregate_execution_replay_bypass_and_quarantine_events() {
    let temp = TempDir::new().unwrap();
    let mut store = Store::open(temp.path()).unwrap();
    let result = store
        .insert_result("key", b"stdout", b"", 0, 20, "v0", "{}")
        .unwrap();

    store
        .record_event(
            None,
            Some(&result.id),
            EventDisposition::Executed,
            "miss",
            0,
            0,
        )
        .unwrap();
    store
        .record_event(
            None,
            Some(&result.id),
            EventDisposition::ReplayedFull,
            "hit",
            20,
            0,
        )
        .unwrap();
    store
        .record_event(
            None,
            Some(&result.id),
            EventDisposition::ReplayedCompact,
            "same_session_duplicate",
            30,
            11,
        )
        .unwrap();
    store
        .record_event(None, None, EventDisposition::PassedThrough, "unsafe", 0, 0)
        .unwrap();
    store
        .record_event(
            None,
            None,
            EventDisposition::BypassedNoStore,
            "unknown",
            0,
            0,
        )
        .unwrap();
    store
        .record_event(
            None,
            Some(&result.id),
            EventDisposition::Quarantined,
            "validator_mismatch",
            0,
            0,
        )
        .unwrap();

    let stats = store.stats().unwrap();
    assert_eq!(stats.executions, 1);
    assert_eq!(stats.full_replays, 1);
    assert_eq!(stats.compact_replays, 1);
    assert_eq!(stats.bypasses, 2);
    assert_eq!(stats.quarantines, 1);
    assert_eq!(stats.duplicate_bytes_omitted, 11);
    assert_eq!(stats.estimated_execution_ms_saved, 50);
}

#[test]
fn project_hook_path_is_isolated_from_real_home() {
    let temp = TempDir::new().unwrap();
    assert_eq!(
        hook_path(SetupScope::Project, Some(temp.path())).unwrap(),
        temp.path().join(".codex/hooks.json")
    );
    assert!(hook_path(SetupScope::Project, None).is_err());
}

#[test]
fn install_is_idempotent_and_preserves_unrelated_hooks() {
    let temp = TempDir::new().unwrap();
    let path = hook_file(&temp);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        r#"{
          "description": "keep me",
          "other": {"value": 42},
          "hooks": {
            "PreToolUse": [
              {"matcher": "^Edit$", "hooks": [{"type": "command", "command": "other-hook"}]}
            ]
          }
        }"#,
    )
    .unwrap();
    let executable = executable_with_shell_sensitive_path(&temp);

    let first = install_codex_hook(&path, &executable, false).unwrap();
    assert!(first.changed);
    assert!(first.backup.as_ref().is_some_and(|backup| backup.exists()));
    let second = install_codex_hook(&path, &executable, false).unwrap();
    assert!(!second.changed);
    assert!(second.backup.is_none());

    let document: Value = serde_json::from_str(&second.rendered).unwrap();
    assert_eq!(document["description"], "keep me");
    assert_eq!(document["other"]["value"], 42);
    assert!(second.rendered.contains("other-hook"));
    assert_eq!(second.rendered.matches(AGAIN_SENTINEL).count(), 1);
}

#[test]
fn install_quotes_executable_paths_with_spaces_and_single_quotes() {
    let temp = TempDir::new().unwrap();
    let path = hook_file(&temp);
    let executable = executable_with_shell_sensitive_path(&temp);
    let change = install_codex_hook(&path, &executable, true).unwrap();
    let canonical = executable.canonicalize().unwrap();
    let canonical = canonical.to_str().unwrap();
    let quoted = format!("'{}'", canonical.replace('\'', "'\\''"));

    let document: Value = serde_json::from_str(&change.rendered).unwrap();
    let command = document["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        command.ends_with(&format!("{quoted} hook")),
        "command: {command}"
    );
    assert!(command.contains("bin with spaces"));
    assert!(command.contains("'\\''"));
}

#[test]
fn dry_run_does_not_create_or_modify_hook_file() {
    let temp = TempDir::new().unwrap();
    let path = hook_file(&temp);
    let executable = executable_with_shell_sensitive_path(&temp);
    let change = install_codex_hook(&path, &executable, true).unwrap();

    assert!(change.changed);
    assert!(change.backup.is_none());
    assert!(!path.exists());
    assert!(change.rendered.contains(AGAIN_SENTINEL));
}

#[test]
fn removal_removes_again_only_and_is_idempotent() {
    let temp = TempDir::new().unwrap();
    let path = hook_file(&temp);
    let executable = executable_with_shell_sensitive_path(&temp);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        r#"{"hooks":{"PreToolUse":[{"matcher":"^Edit$","hooks":[{"type":"command","command":"other-hook"}]}]}}"#,
    )
    .unwrap();
    install_codex_hook(&path, &executable, false).unwrap();

    let removed = remove_codex_hook(&path, false).unwrap();
    assert!(removed.changed);
    assert!(
        removed
            .backup
            .as_ref()
            .is_some_and(|backup| backup.exists())
    );
    assert!(!removed.rendered.contains(AGAIN_SENTINEL));
    assert!(removed.rendered.contains("other-hook"));
    assert!(!fs::read_to_string(&path).unwrap().contains(AGAIN_SENTINEL));

    let again = remove_codex_hook(&path, false).unwrap();
    assert!(!again.changed);
    assert!(again.backup.is_none());
}

#[test]
fn malformed_hook_shapes_fail_closed_without_writing() {
    let temp = TempDir::new().unwrap();
    let path = hook_file(&temp);
    let executable = executable_with_shell_sensitive_path(&temp);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, br#"{"hooks":{"PreToolUse":{"not":"an array"}}}"#).unwrap();
    let before = fs::read(&path).unwrap();

    assert!(install_codex_hook(&path, &executable, false).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(remove_codex_hook(&path, false).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
}
