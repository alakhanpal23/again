//! Bounded observations from coding-client event streams.
//!
//! Client events are useful history, not execution or freshness authority.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::store::{BrainEventV1, Store};

const MAX_OBSERVED_FILE_BYTES_V1: u64 = 1024 * 1024;

/// The local Brain has one repository-owner scope until its records carry
/// per-scope provenance. Do not present it through a custom MCP scope.
pub fn local_brain_scope_v1(workspace: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.local-mcp-authorization-scope.v1\0");
    hasher.update(workspace.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize().to_hex();
    format!("local-workspace:{}", &digest[..24])
}

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
            let mut events = vec![BrainEventV1 {
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
            }];
            if exit_code == 0
                && let Some((relative, bytes)) = matching_source_read_v1(item, workspace, command)
            {
                events.push(BrainEventV1 {
                    session_id: session_id.to_owned(),
                    event_id: event_id.to_owned(),
                    task_id: task_id.to_owned(),
                    kind: "command".to_owned(),
                    path: Some(relative),
                    source_digest: Some(blake3::hash(&bytes).to_hex().to_string()),
                    command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
                    command_hint: None,
                    exit_code: Some(exit_code),
                    created_ms,
                });
            }
            events
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
pub fn repository_brief_v1(
    store: &Store,
    workspace: &Path,
    candidate_paths: &[String],
    already_previewed_paths: &[String],
) -> anyhow::Result<Value> {
    let mut recent_files = Vec::new();
    let test_hint = store
        .brain_test_hints_v1(16)?
        .into_iter()
        .find(|hint| test_hint_relevant_v1(hint, workspace, candidate_paths));
    for path in candidate_paths.iter().take(16) {
        if recent_files.len() == 2 {
            break;
        }
        if let Ok(Some(observation)) = store.brain_file_v1(path)
            && let Some((relative, absolute)) = workspace_file_v1(workspace, path)
            && relative == *path
            && fs::metadata(&absolute).is_ok_and(|meta| meta.len() <= MAX_OBSERVED_FILE_BYTES_V1)
            && let Ok(bytes) = fs::read(&absolute)
            && blake3::hash(&bytes).to_hex().as_str() == observation.source_digest
        {
            let preview = if !recent_files
                .iter()
                .any(|file: &Value| file["currentCompletePreview"].as_str().is_some())
                && !already_previewed_paths.contains(path)
                && source_code_path_v1(path)
                && bytes.len() <= 256
                && let Ok(text) = String::from_utf8(bytes.clone())
                && crate::task_lifecycle::screen_sensitive_text_v1(&text).is_ok()
            {
                Some(text)
            } else {
                None
            };
            recent_files.push(serde_json::json!({
                "path": path,
                "currentDigest": observation.source_digest,
                "observedTaskId": observation.task_id,
                "observation": "observed after a prior read or edit; file content rechecked now",
                "currentCompletePreview": preview,
            }));
        }
    }
    Ok(serde_json::json!({
        "recentCurrentFiles": recent_files,
        "previousSuccessfulTestCommand": test_hint,
        "testCommandAuthority": "unverified suggestion; run required validation",
    }))
}

/// Select task-relevant Brain observations once for both MCP task.start and
/// noninteractive launchers. The source preview and code index are already
/// bounded by task.start; this adds at most two current file observations.
pub fn repository_brief_for_task_v1(
    store: &Store,
    workspace: &Path,
    source_previews: &Value,
    relevant_code: &Value,
) -> anyhow::Result<Option<Value>> {
    let already_previewed: Vec<String> = source_previews
        .as_array()
        .into_iter()
        .flatten()
        .take(2)
        .filter(|preview| preview["complete"] == true)
        .filter_map(|preview| preview["path"].as_str().map(str::to_owned))
        .collect();
    let mut paths = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let sources = source_previews
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|preview| preview["path"].as_str())
        .chain(
            relevant_code["candidates"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|candidate| candidate["locator"]["path"].as_str()),
        );
    for path in sources {
        if seen.insert(path.to_owned()) {
            paths.push(path.to_owned());
        }
        if paths.len() == 16 {
            break;
        }
    }
    let brain = repository_brief_v1(store, workspace, &paths, &already_previewed)?;
    let has_files = brain["recentCurrentFiles"]
        .as_array()
        .is_some_and(|files| !files.is_empty());
    let has_test = brain["previousSuccessfulTestCommand"].as_str().is_some();
    if (has_files || has_test) && serde_json::to_vec(&brain)?.len() <= 1024 {
        Ok(Some(brain))
    } else {
        Ok(None)
    }
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
    let command = command
        .strip_prefix("/bin/zsh -lc '")
        .and_then(|inner| inner.strip_suffix('\''))
        .unwrap_or(command);
    match command {
        "python3 -m unittest discover -s tests" => Some("python3 -m unittest discover -s tests"),
        "python3 -m pytest" => Some("python3 -m pytest"),
        "cargo test" => Some("cargo test"),
        "go test ./..." => Some("go test ./..."),
        _ => None,
    }
}

fn matching_source_read_v1(
    item: &Value,
    workspace: &Path,
    command: &str,
) -> Option<(String, Vec<u8>)> {
    let outer = shell_words::split(command).ok()?;
    let argv = if matches!(outer.as_slice(), [shell, flag, _]
        if shell == "/bin/zsh" && flag == "-lc")
    {
        shell_words::split(&outer[2]).ok()?
    } else {
        outer
    };
    let (path, lines) = match argv.as_slice() {
        [program, path] if program == "cat" => (path.as_str(), None),
        [program, flag, range, path] if program == "sed" && flag == "-n" => {
            let end = range
                .strip_prefix("1,")?
                .strip_suffix('p')?
                .parse::<usize>()
                .ok()?;
            if !(1..=200).contains(&end) {
                return None;
            }
            (path.as_str(), Some(end))
        }
        _ => return None,
    };
    // The client event omits effective cwd. Admit a relative operand only
    // when its returned bytes match this workspace file exactly.
    if path.chars().any(|character| {
        matches!(
            character,
            ';' | '|'
                | '&'
                | '<'
                | '>'
                | '$'
                | '`'
                | '*'
                | '?'
                | '['
                | ']'
                | '{'
                | '}'
                | '('
                | ')'
                | '\\'
        )
    }) {
        return None;
    }
    let (relative, absolute) = workspace_file_v1(workspace, path)?;
    if !source_code_path_v1(&relative)
        || !fs::metadata(&absolute).is_ok_and(|meta| meta.len() <= 8 * 1024)
    {
        return None;
    }
    let bytes = fs::read(&absolute).ok()?;
    let expected = if let Some(end) = lines {
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .take(end)
            .flatten()
            .copied()
            .collect::<Vec<_>>()
    } else {
        bytes.clone()
    };
    (item["aggregated_output"].as_str()?.as_bytes() == expected).then_some((relative, bytes))
}

fn source_code_path_v1(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("py" | "pyi" | "rs" | "go" | "js" | "jsx" | "ts" | "tsx")
    )
}

fn test_hint_relevant_v1(hint: &str, workspace: &Path, candidate_paths: &[String]) -> bool {
    let (extensions, manifest): (&[&str], Option<&str>) = match hint {
        "python3 -m unittest discover -s tests" | "python3 -m pytest" => (&["py", "pyi"], None),
        "cargo test" => (&["rs"], Some("Cargo.toml")),
        "go test ./..." => (&["go"], Some("go.mod")),
        _ => return false,
    };
    candidate_paths.iter().any(|path| {
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extensions.contains(&extension))
    }) && manifest.is_none_or(|manifest| workspace.join(manifest).is_file())
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
        let test = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"test_1","type":"command_execution",
                    "command":"python3 -m unittest discover -s tests", "exit_code":0}
        });
        for event in codex_completed_events_v1(&test, &workspace, "session", "old-task") {
            store.record_brain_event_v1(&event).unwrap();
        }
        for index in 0..80 {
            let command = BrainEventV1 {
                session_id: "session".to_owned(),
                event_id: format!("unrelated_{index}"),
                task_id: "old-task".to_owned(),
                kind: "command".to_owned(),
                path: None,
                source_digest: None,
                command_digest: Some(blake3::hash(b"unrelated command").to_hex().to_string()),
                command_hint: None,
                exit_code: Some(0),
                created_ms: current_ms_v1() + index,
            };
            store.record_brain_event_v1(&command).unwrap();
        }
        assert!(
            store
                .recent_brain_events_v1(64)
                .unwrap()
                .iter()
                .all(|event| event.kind == "command")
        );
        let candidates = ["balances.py".to_owned()];
        let brief = repository_brief_v1(&store, &workspace, &candidates, &[]).unwrap();
        assert_eq!(brief["recentCurrentFiles"].as_array().unwrap().len(), 1);
        assert_eq!(
            brief["previousSuccessfulTestCommand"],
            "python3 -m unittest discover -s tests"
        );
        let unrelated =
            repository_brief_v1(&store, &workspace, &["src/main.rs".to_owned()], &[]).unwrap();
        assert!(unrelated["previousSuccessfulTestCommand"].is_null());
        fs::write(workspace.join("balances.py"), "value = 2\n").unwrap();
        let stale = repository_brief_v1(&store, &workspace, &candidates, &[]).unwrap();
        assert!(stale["recentCurrentFiles"].as_array().unwrap().is_empty());
    }

    #[test]
    fn repository_brain_selects_relevant_observed_validation() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(
            workspace.join("Cargo.toml"),
            "[package]\nname = \"sample\"\n",
        )
        .unwrap();
        fs::write(workspace.join("go.mod"), "module example.com/sample\n").unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        for (index, command) in ["cargo test", "go test ./...", "python3 -m pytest"]
            .iter()
            .enumerate()
        {
            let completed = serde_json::json!({
                "type":"item.completed",
                "item":{"id":format!("test_{index}"),"type":"command_execution",
                        "command":command,"exit_code":0}
            });
            let mut event =
                codex_completed_events_v1(&completed, &workspace, "session", "old-task")
                    .pop()
                    .unwrap();
            event.created_ms += index as i64;
            store.record_brain_event_v1(&event).unwrap();
        }
        let rust =
            repository_brief_v1(&store, &workspace, &["src/lib.rs".to_owned()], &[]).unwrap();
        assert_eq!(rust["previousSuccessfulTestCommand"], "cargo test");
        let go = repository_brief_v1(&store, &workspace, &["main.go".to_owned()], &[]).unwrap();
        assert_eq!(go["previousSuccessfulTestCommand"], "go test ./...");
        fs::remove_file(workspace.join("go.mod")).unwrap();
        let stale = repository_brief_v1(&store, &workspace, &["main.go".to_owned()], &[]).unwrap();
        assert!(stale["previousSuccessfulTestCommand"].is_null());
        let failed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"failed","type":"command_execution",
                    "command":"cargo test","exit_code":1}
        });
        assert_eq!(
            codex_completed_events_v1(&failed, &workspace, "session", "old-task")[0].command_hint,
            None
        );
    }

    #[test]
    fn matched_source_read_adds_current_preview_without_replaying_command_output() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let source = workspace.join("helper.py");
        fs::write(&source, "def helper():\n    return 42\n").unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let completed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"read_1","type":"command_execution",
                    "command":format!("cat {}", source.display()),
                    "aggregated_output":"def helper():\n    return 42\n", "exit_code":0}
        });
        let observed = codex_completed_events_v1(&completed, &workspace, "session", "old-task");
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[1].path.as_deref(), Some("helper.py"));
        assert!(
            !serde_json::to_string(&observed)
                .unwrap()
                .contains("def helper")
        );
        for event in &observed {
            store.record_brain_event_v1(event).unwrap();
        }
        let paths = ["helper.py".to_owned()];
        let brief = repository_brief_v1(&store, &workspace, &paths, &[]).unwrap();
        assert_eq!(
            brief["recentCurrentFiles"][0]["currentCompletePreview"],
            "def helper():\n    return 42\n"
        );
        let previewed = repository_brief_v1(&store, &workspace, &paths, &paths).unwrap();
        assert!(previewed["recentCurrentFiles"][0]["currentCompletePreview"].is_null());
        fs::write(&source, "def helper():\n    return 0\n").unwrap();
        let stale = repository_brief_v1(&store, &workspace, &paths, &[]).unwrap();
        assert!(stale["recentCurrentFiles"].as_array().unwrap().is_empty());
        let relative = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"read_2","type":"command_execution",
                    "command":"cat helper.py", "aggregated_output":"wrong bytes", "exit_code":0}
        });
        assert_eq!(
            codex_completed_events_v1(&relative, &workspace, "session", "old-task").len(),
            1
        );
        let sed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"read_4","type":"command_execution",
                    "command":"/bin/zsh -lc \"sed -n '1,20p' helper.py\"",
                    "aggregated_output":"def helper():\n    return 0\n", "exit_code":0}
        });
        assert_eq!(
            codex_completed_events_v1(&sed, &workspace, "session", "old-task").len(),
            2
        );
        let composed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"read_3","type":"command_execution",
                    "command":format!("cat {};true", source.display()),
                    "aggregated_output":"def helper():\n    return 0\n", "exit_code":0}
        });
        assert_eq!(
            codex_completed_events_v1(&composed, &workspace, "session", "old-task").len(),
            1
        );
    }
}
