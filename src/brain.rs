//! Bounded observations from coding-client event streams.
//!
//! Client events are useful history, not execution or freshness authority.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::store::{BrainEventV1, Store};

const MAX_OBSERVED_FILE_BYTES_V1: u64 = 1024 * 1024;

pub fn codex_completed_events_v1(
    value: &Value,
    workspace: &Path,
    session_id: &str,
    task_id: &str,
) -> Vec<BrainEventV1> {
    if value["type"] != "item.completed" {
        return Vec::new();
    }
    let item = &value["item"];
    let Some(event_id) = item["id"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 128)
    else {
        return Vec::new();
    };
    let created_ms = current_ms_v1();
    match item["type"].as_str() {
        Some("file_change") if item["status"] == "completed" => item["changes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|change| {
                let path = change["path"].as_str()?;
                let (relative, absolute) = workspace_file_v1(workspace, path)?;
                let size = fs::metadata(&absolute).ok()?.len();
                (size <= MAX_OBSERVED_FILE_BYTES_V1).then_some(())?;
                let bytes = fs::read(&absolute).ok()?;
                Some(BrainEventV1 {
                    session_id: session_id.to_owned(),
                    event_id: event_id.to_owned(),
                    task_id: task_id.to_owned(),
                    kind: "file_change".to_owned(),
                    path: Some(relative),
                    source_digest: Some(blake3::hash(&bytes).to_hex().to_string()),
                    command_digest: None,
                    command_hint: None,
                    exit_code: None,
                    created_ms,
                })
            })
            .collect(),
        Some("command_execution") => {
            let Some(command) = item["command"].as_str() else {
                return Vec::new();
            };
            let Some(exit_code) = item["exit_code"]
                .as_i64()
                .and_then(|code| i32::try_from(code).ok())
            else {
                return Vec::new();
            };
            let command_hint = (exit_code == 0)
                .then(|| known_test_command_v1(command))
                .flatten()
                .map(str::to_owned);
            vec![BrainEventV1 {
                session_id: session_id.to_owned(),
                event_id: event_id.to_owned(),
                task_id: task_id.to_owned(),
                kind: if command_hint.is_some() {
                    "test"
                } else {
                    "command"
                }
                .to_owned(),
                path: None,
                source_digest: None,
                command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
                command_hint,
                exit_code: Some(exit_code),
                created_ms,
            }]
        }
        _ => Vec::new(),
    }
}

pub fn codex_display_text_v1(value: &Value) -> Option<&str> {
    match (value["type"].as_str(), value["item"]["type"].as_str()) {
        (Some("item.completed"), Some("agent_message")) => value["item"]["text"].as_str(),
        (Some("item.completed"), Some("command_execution")) => value["item"]["aggregated_output"]
            .as_str()
            .filter(|text| !text.is_empty()),
        (Some("error"), _) => value["message"].as_str(),
        _ => None,
    }
}

/// Current, bounded hints from prior tasks in the same local workspace.
/// These are observed history and test suggestions, never cache authority.
pub fn repository_brief_v1(store: &Store, workspace: &Path, task: &str) -> anyhow::Result<Value> {
    let mut recent_files = Vec::new();
    let mut test_hint = None;
    let task_lower = task.to_ascii_lowercase();
    for event in store.recent_brain_events_v1(64)? {
        if event.kind == "test" && event.exit_code == Some(0) && test_hint.is_none() {
            test_hint = event.command_hint;
        } else if event.kind == "file_change"
            && recent_files.len() < 2
            && let (Some(path), Some(digest)) = (event.path, event.source_digest)
            && let Some((relative, absolute)) = workspace_file_v1(workspace, &path)
            && relative == path
            && fs::metadata(&absolute).is_ok_and(|meta| meta.len() <= MAX_OBSERVED_FILE_BYTES_V1)
            && fs::read(&absolute)
                .is_ok_and(|bytes| blake3::hash(&bytes).to_hex().as_str() == digest)
            && {
                let path_lower = path.to_ascii_lowercase();
                let stem = Path::new(&path)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                task_lower.contains(&path_lower) || (stem.len() >= 4 && task_lower.contains(&stem))
            }
        {
            recent_files.push(serde_json::json!({
                "path": path,
                "currentDigest": digest,
                "observation": "edited in a prior Again task; file content rechecked now",
            }));
        }
        if recent_files.len() == 2 && test_hint.is_some() {
            break;
        }
    }
    Ok(serde_json::json!({
        "recentCurrentFiles": recent_files,
        "previousSuccessfulTestCommand": test_hint,
        "testCommandAuthority": "unverified suggestion; run required validation",
    }))
}

fn workspace_file_v1(workspace: &Path, path: &str) -> Option<(String, PathBuf)> {
    let workspace = fs::canonicalize(workspace).ok()?;
    let candidate = Path::new(path);
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        workspace.join(candidate)
    };
    let canonical = fs::canonicalize(absolute).ok()?;
    let relative = canonical.strip_prefix(&workspace).ok()?;
    if relative
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
        || relative.starts_with(".git")
    {
        return None;
    }
    let relative = relative.to_str()?;
    if relative.is_empty() || relative.len() > 512 {
        return None;
    }
    Some((relative.to_owned(), canonical))
}

fn known_test_command_v1(command: &str) -> Option<&'static str> {
    let command = command.trim();
    match command {
        "python3 -m unittest discover -s tests"
        | "/bin/zsh -lc 'python3 -m unittest discover -s tests'" => {
            Some("python3 -m unittest discover -s tests")
        }
        "python3 -m pytest" | "/bin/zsh -lc 'python3 -m pytest'" => Some("python3 -m pytest"),
        _ => None,
    }
}

fn current_ms_v1() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_codex_events_keep_only_bounded_metadata() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.py"), "value = 2\n").unwrap();
        let edit = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"item_1","type":"file_change","status":"completed",
                    "changes":[{"path":dir.path().join("a.py")}]}
        });
        let edits = codex_completed_events_v1(&edit, dir.path(), "session", "task");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].path.as_deref(), Some("a.py"));
        assert!(edits[0].source_digest.is_some());

        let command = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"item_2","type":"command_execution",
                    "command":"/bin/zsh -lc 'python3 -m unittest discover -s tests'",
                    "aggregated_output":"OK", "exit_code":0}
        });
        let observed = codex_completed_events_v1(&command, dir.path(), "session", "task");
        assert_eq!(observed[0].kind, "test");
        assert_eq!(
            observed[0].command_hint.as_deref(),
            Some("python3 -m unittest discover -s tests")
        );
        assert!(
            !serde_json::to_string(&observed)
                .unwrap()
                .contains("aggregated_output")
        );
        assert!(codex_completed_events_v1(&serde_json::json!({"type":"item.started","item":{"id":"item_2","type":"command_execution"}}), dir.path(), "session", "task").is_empty());
    }

    #[test]
    fn repository_brain_carries_current_edits_and_withholds_stale_ones() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        fs::write(workspace.join("balances.py"), "value = 1\n").unwrap();
        let edit = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"item_1","type":"file_change","status":"completed",
                    "changes":[{"path":"balances.py"}]}
        });
        for event in codex_completed_events_v1(&edit, &workspace, "session", "old-task") {
            store.record_brain_event_v1(&event).unwrap();
            store.record_brain_event_v1(&event).unwrap();
        }
        assert_eq!(store.recent_brain_events_v1(8).unwrap().len(), 1);
        let brief = repository_brief_v1(&store, &workspace, "Repair balances.py").unwrap();
        assert_eq!(brief["recentCurrentFiles"].as_array().unwrap().len(), 1);
        fs::write(workspace.join("balances.py"), "value = 2\n").unwrap();
        let stale = repository_brief_v1(&store, &workspace, "Repair balances.py").unwrap();
        assert!(stale["recentCurrentFiles"].as_array().unwrap().is_empty());
    }
}
