//! Bounded observations from coding-client event streams.
//!
//! Client events are useful history, not execution or freshness authority.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::store::{BrainEventV1, BrainRunV1, Store};

const MAX_OBSERVED_FILE_BYTES_V1: u64 = 1024 * 1024;
const MAX_BRAIN_PREVIEW_BYTES_V1: usize = 2 * 1024;
const MAX_BRAIN_PARTIAL_PREVIEW_BYTES_V1: usize = 5 * 1024;
const MAX_BRAIN_BRIEF_BYTES_V1: usize = 8 * 1024;
const MAX_TEST_SELECTOR_SCAN_BYTES_V1: u64 = 256 * 1024;

#[derive(Clone, Debug, Default)]
pub struct CodexRunObservationV1 {
    completed_commands: u32,
    completed_source_reads: u32,
    completed_edits: u32,
    completed_mcp_calls: u32,
    successful_tests: u32,
    turn_completed: bool,
    usage: Option<(i64, i64, i64)>,
    usage_invalid: bool,
}

impl CodexRunObservationV1 {
    pub fn observe(&mut self, value: &Value, events: &[BrainEventV1]) {
        if value["type"] == "item.completed" {
            match value["item"]["type"].as_str() {
                Some("command_execution") if value["item"]["exit_code"].as_i64().is_some() => {
                    self.completed_commands = self.completed_commands.saturating_add(1);
                }
                Some("file_change") if value["item"]["status"] == "completed" => {
                    self.completed_edits = self.completed_edits.saturating_add(1);
                }
                Some("mcp_tool_call") if value["item"]["status"] == "completed" => {
                    self.completed_mcp_calls = self.completed_mcp_calls.saturating_add(1);
                }
                _ => {}
            }
            self.completed_source_reads = self.completed_source_reads.saturating_add(
                events
                    .iter()
                    .filter(|event| event.kind == "command" && event.path.is_some())
                    .count() as u32,
            );
            self.successful_tests = self
                .successful_tests
                .saturating_add(events.iter().filter(|event| event.kind == "test").count() as u32);
        }
        if value["type"] == "turn.completed" {
            self.turn_completed = true;
            let parsed = (|| {
                let usage = &value["usage"];
                let input = i64::try_from(usage["input_tokens"].as_u64()?).ok()?;
                let cached = i64::try_from(usage["cached_input_tokens"].as_u64()?).ok()?;
                let output = i64::try_from(usage["output_tokens"].as_u64()?).ok()?;
                (cached <= input).then_some((input, cached, output))
            })();
            if let Some((input, cached, output)) = parsed {
                let prior = self.usage.unwrap_or((0, 0, 0));
                self.usage = prior
                    .0
                    .checked_add(input)
                    .zip(prior.1.checked_add(cached))
                    .zip(prior.2.checked_add(output))
                    .map(|((input, cached), output)| (input, cached, output));
                if self.usage.is_none() {
                    self.usage_invalid = true;
                }
            } else {
                self.usage_invalid = true;
            }
        }
    }

    pub fn into_run(
        self,
        session_id: String,
        task_id: String,
        workspace: &Path,
        started_ms: i64,
        exit_code: i32,
    ) -> BrainRunV1 {
        let usage = if self.usage_invalid || !self.turn_completed {
            None
        } else {
            self.usage
        };
        BrainRunV1 {
            session_id,
            task_id,
            authorization_scope_digest: local_brain_scope_digest_v1(workspace),
            started_ms,
            completed_ms: current_ms_v1().max(started_ms),
            exit_code,
            turn_completed: self.turn_completed,
            completed_commands: self.completed_commands,
            completed_source_reads: self.completed_source_reads,
            completed_edits: self.completed_edits,
            completed_mcp_calls: self.completed_mcp_calls,
            successful_tests: self.successful_tests,
            input_tokens: usage.map(|value| value.0),
            cached_input_tokens: usage.map(|value| value.1),
            output_tokens: usage.map(|value| value.2),
        }
    }
}

/// The local Brain has one repository-owner scope until its records carry
/// per-scope provenance. Do not present it through a custom MCP scope.
pub fn local_brain_scope_v1(workspace: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.local-mcp-authorization-scope.v1\0");
    hasher.update(workspace.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize().to_hex();
    format!("local-workspace:{}", &digest[..24])
}

pub fn local_brain_scope_digest_v1(workspace: &Path) -> String {
    let scope = crate::mcp_gateway::AuthorizationScopeId::new(local_brain_scope_v1(workspace))
        .expect("local Brain scope is a valid authorization scope");
    crate::mcp_gateway::authorization_scope_digest_v1(&scope)
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
    let authorization_scope_digest = Some(local_brain_scope_digest_v1(workspace));
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
                    read_start_line: None,
                    read_end_line: None,
                    command_digest: None,
                    command_hint: None,
                    exit_code: None,
                    created_ms,
                    authorization_scope_digest: authorization_scope_digest.clone(),
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
                .flatten();
            let completed_test =
                exit_code == 0 && (command_hint.is_some() || observed_cargo_test_v1(command));
            let mut events = vec![BrainEventV1 {
                session_id: session_id.to_owned(),
                event_id: event_id.to_owned(),
                task_id: task_id.to_owned(),
                kind: if completed_test { "test" } else { "command" }.to_owned(),
                path: None,
                source_digest: None,
                read_start_line: None,
                read_end_line: None,
                command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
                command_hint,
                exit_code: Some(exit_code),
                created_ms,
                authorization_scope_digest: authorization_scope_digest.clone(),
            }];
            if exit_code == 0 {
                for read in matching_source_reads_v1(item, workspace, command) {
                    events.push(BrainEventV1 {
                        session_id: session_id.to_owned(),
                        event_id: event_id.to_owned(),
                        task_id: task_id.to_owned(),
                        kind: "command".to_owned(),
                        path: Some(read.path),
                        source_digest: Some(blake3::hash(&read.bytes).to_hex().to_string()),
                        read_start_line: read.range.map(|(start, _)| start),
                        read_end_line: read.range.map(|(_, end)| end),
                        command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
                        command_hint: None,
                        exit_code: Some(exit_code),
                        created_ms,
                        authorization_scope_digest: authorization_scope_digest.clone(),
                    });
                }
            }
            if exit_code == 0 {
                for (relative, bytes) in matching_source_search_v1(item, workspace, command) {
                    events.push(BrainEventV1 {
                        session_id: session_id.to_owned(),
                        event_id: event_id.to_owned(),
                        task_id: task_id.to_owned(),
                        kind: "command".to_owned(),
                        path: Some(relative),
                        source_digest: Some(blake3::hash(&bytes).to_hex().to_string()),
                        read_start_line: None,
                        read_end_line: None,
                        command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
                        command_hint: None,
                        exit_code: Some(exit_code),
                        created_ms,
                        authorization_scope_digest: Some(local_brain_scope_digest_v1(workspace)),
                    });
                }
            }
            events
        }
        _ => Vec::new(),
    }
}

/// Convert a completed Codex PostToolUse envelope into bounded observations.
/// A plain Bash response can prove an exact source read, but not exit status.
pub fn codex_post_tool_event_v1(value: &Value, workspace: &Path) -> Option<Vec<BrainEventV1>> {
    if value["hook_event_name"] != "PostToolUse" {
        return None;
    }
    let session_id = value["session_id"].as_str()?;
    let event_id = value["tool_use_id"].as_str()?;
    let command = value["tool_input"]["command"].as_str()?;
    if session_id.is_empty()
        || session_id.len() > 128
        || event_id.is_empty()
        || event_id.len() > 128
        || command.is_empty()
        || command.len() > 64 * 1024
    {
        return None;
    }
    if value["tool_name"] == "apply_patch" {
        return Some(codex_post_patch_events_v1(
            value, workspace, session_id, event_id, command,
        ));
    }
    if value["tool_name"] != "Bash" {
        return None;
    }
    let response = &value["tool_response"];
    let exit_code = response["exit_code"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok());
    let output = response
        .as_str()
        .or_else(|| response["output"].as_str())
        .filter(|s| s.len() <= 1024 * 1024);
    let item = serde_json::json!({
        "id": event_id,
        "type": "command_execution",
        "command": command,
        "exit_code": exit_code,
        "aggregated_output": output,
    });
    let mut events = codex_completed_events_v1(
        &serde_json::json!({"type":"item.completed", "item":item}),
        workspace,
        session_id,
        session_id,
    );
    if events.is_empty() {
        let created_ms = current_ms_v1();
        let authorization_scope_digest = Some(local_brain_scope_digest_v1(workspace));
        events.push(BrainEventV1 {
            session_id: session_id.to_owned(),
            event_id: event_id.to_owned(),
            task_id: session_id.to_owned(),
            kind: "command".to_owned(),
            path: None,
            source_digest: None,
            read_start_line: None,
            read_end_line: None,
            command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
            command_hint: None,
            exit_code: None,
            created_ms,
            authorization_scope_digest: authorization_scope_digest.clone(),
        });
        if exit_code.is_none() {
            for read in matching_source_reads_v1(&item, workspace, command) {
                events.push(BrainEventV1 {
                    session_id: session_id.to_owned(),
                    event_id: event_id.to_owned(),
                    task_id: session_id.to_owned(),
                    kind: "command".to_owned(),
                    path: Some(read.path),
                    source_digest: Some(blake3::hash(&read.bytes).to_hex().to_string()),
                    read_start_line: read.range.map(|(start, _)| start),
                    read_end_line: read.range.map(|(_, end)| end),
                    command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
                    command_hint: None,
                    exit_code: None,
                    created_ms,
                    authorization_scope_digest: authorization_scope_digest.clone(),
                });
            }
        }
        if exit_code.is_none() {
            for (relative, bytes) in matching_source_search_v1(&item, workspace, command) {
                events.push(BrainEventV1 {
                    session_id: session_id.to_owned(),
                    event_id: event_id.to_owned(),
                    task_id: session_id.to_owned(),
                    kind: "command".to_owned(),
                    path: Some(relative),
                    source_digest: Some(blake3::hash(&bytes).to_hex().to_string()),
                    read_start_line: None,
                    read_end_line: None,
                    command_digest: Some(blake3::hash(command.as_bytes()).to_hex().to_string()),
                    command_hint: None,
                    exit_code: None,
                    created_ms,
                    authorization_scope_digest: Some(local_brain_scope_digest_v1(workspace)),
                });
            }
        }
    }
    Some(events)
}

fn codex_post_patch_events_v1(
    value: &Value,
    workspace: &Path,
    session_id: &str,
    event_id: &str,
    patch: &str,
) -> Vec<BrainEventV1> {
    let Some(response) = value["tool_response"].as_str() else {
        return Vec::new();
    };
    if response.len() > 1024 * 1024
        || !response.starts_with("Exit code: 0\n")
        || !response.contains("\nOutput:\nSuccess. Updated the following files:\n")
    {
        return Vec::new();
    }
    let mut events = Vec::new();
    let scope = Some(local_brain_scope_digest_v1(workspace));
    let created_ms = current_ms_v1();
    for line in response
        .lines()
        .skip_while(|line| *line != "Success. Updated the following files:")
        .skip(1)
    {
        if events.len() == 32 {
            break;
        }
        let Some((change, path)) = line.split_once(' ') else {
            continue;
        };
        let directive = match change {
            "M" => "*** Update File: ",
            "A" => "*** Add File: ",
            "D" => "*** Delete File: ",
            _ => continue,
        };
        if !safe_patch_path_v1(path)
            || !patch
                .lines()
                .any(|line| line.strip_prefix(directive) == Some(path))
        {
            continue;
        }
        let source_digest = if change == "D" {
            None
        } else {
            workspace_file_v1(workspace, path)
                .filter(|(relative, absolute)| {
                    relative == path
                        && fs::metadata(absolute)
                            .is_ok_and(|meta| meta.len() <= MAX_OBSERVED_FILE_BYTES_V1)
                })
                .and_then(|(_, absolute)| fs::read(absolute).ok())
                .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        };
        events.push(BrainEventV1 {
            session_id: session_id.to_owned(),
            event_id: event_id.to_owned(),
            task_id: session_id.to_owned(),
            kind: "file_change".to_owned(),
            path: Some(path.to_owned()),
            source_digest,
            read_start_line: None,
            read_end_line: None,
            command_digest: None,
            command_hint: None,
            exit_code: None,
            created_ms,
            authorization_scope_digest: scope.clone(),
        });
    }
    events
}

fn safe_patch_path_v1(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.starts_with(".git/")
        && Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
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
    authorization_scope_digest: &str,
) -> anyhow::Result<Value> {
    let mut recent_files = Vec::new();
    let test_hint = store
        .brain_test_hints_v1(authorization_scope_digest, 16)?
        .into_iter()
        .find(|hint| test_hint_relevant_v1(hint, workspace, candidate_paths));
    let test_scope = test_hint
        .as_deref()
        .and_then(filtered_cargo_test_v1)
        .map(|_| "filtered test only; other required validation remains unverified");
    for path in candidate_paths.iter().take(16) {
        if recent_files.len() == 2 {
            break;
        }
        if let Ok(Some(observation)) = store.brain_file_v1(path, authorization_scope_digest)
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
                && bytes.len() <= MAX_BRAIN_PREVIEW_BYTES_V1
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
                "observation": "observed after a prior read, search, or edit; file content rechecked now",
                "observedReadRange": observation.read_start_line.zip(observation.read_end_line)
                    .map(|(start, end)| serde_json::json!({"startLine": start, "endLine": end})),
                "currentCompletePreview": preview,
            }));
        }
    }
    Ok(serde_json::json!({
        "recentCurrentFiles": recent_files,
        "previousSuccessfulTestCommand": test_hint,
        "testCommandAuthority": "unverified suggestion; run required validation",
        "testCommandScope": test_scope,
    }))
}

/// Select task-relevant Brain observations once for both MCP task.start and
/// noninteractive launchers. The source preview and code index are already
/// bounded by task.start; this adds at most two current file observations.
pub struct BrainTaskQueryV1<'a> {
    pub task_text: &'a str,
    pub repository_id: &'a str,
    pub workspace_id: &'a str,
    pub authorization_scope_digest: &'a str,
}

pub fn repository_brief_for_task_v1(
    store: &Store,
    workspace: &Path,
    source_previews: &Value,
    relevant_code: &Value,
    query: BrainTaskQueryV1<'_>,
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
    let task_tokens = meaningful_task_tokens_v1(query.task_text);
    let mut historical = store
        .brain_files_with_task_prompts_v1(
            query.repository_id,
            query.workspace_id,
            query.authorization_scope_digest,
        )?
        .into_iter()
        .filter_map(|entry| {
            if seen.contains(&entry.observation.path) {
                return None;
            }
            let prior_tokens = meaningful_task_tokens_v1(&entry.task_prompt);
            let path_tokens = meaningful_task_tokens_v1(&entry.observation.path);
            let shared = task_tokens.intersection(&prior_tokens).count();
            let path_shared = task_tokens.intersection(&path_tokens).count();
            (path_shared > 0 || shared >= 2).then_some((
                shared * 2 + path_shared * 3,
                entry.observation.observed_ms,
                entry.observation.path,
            ))
        })
        .collect::<Vec<_>>();
    historical.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    let history_paths: Vec<String> = historical
        .into_iter()
        .take(2)
        .map(|(_, _, path)| path)
        .collect();
    let mut selected = history_paths.clone();
    selected.extend(
        paths
            .into_iter()
            .filter(|path| !history_paths.contains(path)),
    );
    selected.truncate(16);
    let mut brain = repository_brief_v1(
        store,
        workspace,
        &selected,
        &already_previewed,
        query.authorization_scope_digest,
    )?;
    let source_previewed: std::collections::BTreeSet<&str> = source_previews
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|preview| preview["path"].as_str())
        .collect();
    if let Some(files) = brain["recentCurrentFiles"].as_array_mut() {
        for file in files {
            let Some(path) = file["path"].as_str().map(str::to_owned) else {
                continue;
            };
            if history_paths.iter().any(|prior| prior == &path) {
                file["selection"] =
                    Value::String("prior task or path overlap; source rechecked".to_owned());
            }
            // A prior large-file read used to become only a path hint. Supply
            // a current excerpt when task.start did not already preview it.
            if source_previewed.contains(path.as_str())
                || file["currentCompletePreview"].as_str().is_some()
                || !source_code_path_v1(&path)
            {
                continue;
            }
            let Some((relative, absolute)) = workspace_file_v1(workspace, &path) else {
                continue;
            };
            if relative != path
                || !fs::metadata(&absolute)
                    .is_ok_and(|meta| (2049..=256 * 1024).contains(&meta.len()))
            {
                continue;
            }
            let Ok(bytes) = fs::read(&absolute) else {
                continue;
            };
            if blake3::hash(&bytes).to_hex().as_str()
                != file["currentDigest"].as_str().unwrap_or("")
            {
                continue;
            }
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            let prior_range = file["observedReadRange"]["startLine"]
                .as_u64()
                .zip(file["observedReadRange"]["endLine"].as_u64())
                .and_then(|(start, end)| {
                    prior_read_excerpt_v1(
                        &text,
                        start as usize,
                        end as usize,
                        MAX_BRAIN_PARTIAL_PREVIEW_BYTES_V1,
                    )
                });
            let (excerpt, start_line, end_line, origin) = if let Some((excerpt, start, end)) =
                prior_range
            {
                (excerpt, start, Some(end), "verified_prior_read_range")
            } else {
                let (excerpt, start, end) =
                    crate::agent_gateway_runtime::context_coordinator::source_excerpt_with_budget_v1(
                        &text,
                        query.task_text,
                        MAX_BRAIN_PARTIAL_PREVIEW_BYTES_V1,
                    );
                (excerpt, start, end, "task_anchored_current_excerpt")
            };
            if crate::task_lifecycle::screen_sensitive_text_v1(&excerpt).is_err() {
                continue;
            }
            file["currentPartialPreview"] = serde_json::json!({
                "text": excerpt,
                "startLine": start_line,
                "endLine": end_line,
                "complete": false,
                "origin": origin,
            });
        }
    }
    if serde_json::to_vec(&brain)?.len() > MAX_BRAIN_BRIEF_BYTES_V1 {
        let file_count = brain["recentCurrentFiles"].as_array().map_or(0, Vec::len);
        for index in (0..file_count).rev() {
            if serde_json::to_vec(&brain)?.len() <= MAX_BRAIN_BRIEF_BYTES_V1 {
                break;
            }
            brain["recentCurrentFiles"][index]["currentCompletePreview"] = Value::Null;
            brain["recentCurrentFiles"][index]["currentPartialPreview"] = Value::Null;
        }
        while brain["recentCurrentFiles"]
            .as_array()
            .is_some_and(|files| files.len() > 1)
            && serde_json::to_vec(&brain)?.len() > MAX_BRAIN_BRIEF_BYTES_V1
        {
            brain["recentCurrentFiles"].as_array_mut().unwrap().pop();
        }
    }
    let has_files = brain["recentCurrentFiles"]
        .as_array()
        .is_some_and(|files| !files.is_empty());
    let has_test = brain["previousSuccessfulTestCommand"].as_str().is_some();
    if (has_files || has_test) && serde_json::to_vec(&brain)?.len() <= MAX_BRAIN_BRIEF_BYTES_V1 {
        Ok(Some(brain))
    } else {
        Ok(None)
    }
}

fn prior_read_excerpt_v1(
    text: &str,
    start_line: usize,
    end_line: usize,
    budget: usize,
) -> Option<(String, usize, usize)> {
    if start_line == 0 || end_line < start_line || end_line > 8192 || end_line - start_line > 512 {
        return None;
    }
    let excerpt = text
        .split_inclusive('\n')
        .skip(start_line - 1)
        .take(end_line - start_line + 1)
        .collect::<String>();
    (!excerpt.is_empty() && excerpt.len() <= budget).then_some((excerpt, start_line, end_line))
}

fn meaningful_task_tokens_v1(text: &str) -> std::collections::BTreeSet<String> {
    const STOP: &[&str] = &[
        "about",
        "after",
        "again",
        "change",
        "code",
        "current",
        "edit",
        "existing",
        "file",
        "files",
        "find",
        "fix",
        "from",
        "implement",
        "inspect",
        "into",
        "other",
        "repair",
        "repository",
        "run",
        "source",
        "stop",
        "suite",
        "task",
        "test",
        "tests",
        "then",
        "this",
        "update",
        "with",
    ];
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| (4..=32).contains(&word.len()))
        .map(str::to_ascii_lowercase)
        .filter(|word| !STOP.contains(&word.as_str()))
        .take(48)
        .collect()
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

fn known_test_command_v1(command: &str) -> Option<String> {
    let command = command.trim();
    let command = command
        .strip_prefix("/bin/zsh -lc '")
        .and_then(|inner| inner.strip_suffix('\''))
        .unwrap_or(command);
    match command {
        "python3 -m unittest discover -s tests"
        | "python3 -m pytest"
        | "cargo test"
        | "cargo test --quiet"
        | "go test ./..."
        | "npm test"
        | "pnpm test"
        | "yarn test"
        | "bun test" => Some(command.to_owned()),
        _ if command
            .strip_prefix("node --test ")
            .is_some_and(safe_node_test_path_v1) =>
        {
            Some(command.to_owned())
        }
        _ if filtered_cargo_test_v1(command).is_some() => Some(command.to_owned()),
        _ => None,
    }
}

// A filtered Cargo test can be remembered as a suggestion only if the current
// task's candidate source still contains the selected test or module name.
fn observed_cargo_test_v1(command: &str) -> bool {
    cargo_test_selector_v1(command).is_some()
}

fn filtered_cargo_test_v1(command: &str) -> Option<String> {
    cargo_test_selector_v1(command)
        .flatten()
        .filter(|selector| {
            selector
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn cargo_test_selector_v1(command: &str) -> Option<Option<String>> {
    let command = command.trim();
    let command = command
        .strip_prefix("/bin/zsh -lc '")
        .and_then(|inner| inner.strip_suffix('\''))
        .unwrap_or(command);
    let parts = shell_words::split(command).ok()?;
    let [cargo, test, flags @ ..] = parts.as_slice() else {
        return None;
    };
    if cargo != "cargo" || test != "test" {
        return None;
    }
    let mut selector = None;
    for flag in flags {
        if matches!(flag.as_str(), "--locked" | "--lib" | "--quiet") {
            continue;
        }
        if flag.is_empty()
            || flag.len() > 128
            || !flag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':'))
            || selector.is_some()
        {
            return None;
        }
        selector = Some(flag.clone());
    }
    Some(selector)
}

fn safe_node_test_path_v1(path: &str) -> bool {
    path.starts_with("tests/test_")
        && path.len() <= 256
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
        && Path::new(path)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
        && matches!(
            Path::new(path).extension().and_then(|ext| ext.to_str()),
            Some("js" | "mjs" | "cjs")
        )
}

struct MatchedSourceReadV1 {
    path: String,
    bytes: Vec<u8>,
    range: Option<(u32, u32)>,
}

fn matching_source_reads_v1(
    item: &Value,
    workspace: &Path,
    command: &str,
) -> Vec<MatchedSourceReadV1> {
    let Some(output) = item["aggregated_output"]
        .as_str()
        .filter(|s| s.len() <= 1024 * 1024)
    else {
        return Vec::new();
    };
    let Ok(outer) = shell_words::split(command) else {
        return Vec::new();
    };
    let script = if matches!(outer.as_slice(), [shell, flag, _]
        if shell == "/bin/zsh" && flag == "-lc")
    {
        outer[2].as_str()
    } else {
        command
    };
    // Recognize only a short conjunction of read commands, optionally followed
    // by `git status --short`. Other shell syntax may change bytes or reorder
    // output, so it never creates a source observation.
    if script.bytes().any(|byte| {
        matches!(
            byte,
            b';' | b'|' | b'<' | b'>' | b'$' | b'`' | b'\n' | b'\r'
        )
    }) {
        return Vec::new();
    }
    let parts = script.split(" && ").collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 4 {
        return Vec::new();
    }
    let mut reads: Vec<MatchedSourceReadV1> = Vec::new();
    let mut expected_output = Vec::new();
    let mut has_status_suffix = false;
    for (index, part) in parts.iter().enumerate() {
        let Ok(argv) = shell_words::split(part) else {
            return Vec::new();
        };
        if argv.as_slice() == ["git", "status", "--short"] && index == parts.len() - 1 {
            has_status_suffix = true;
            continue;
        }
        let Some((read, printed)) = matched_source_read_argv_v1(workspace, &argv) else {
            return Vec::new();
        };
        expected_output.extend_from_slice(&printed);
        if let Some(existing) = reads.iter_mut().find(|existing| existing.path == read.path) {
            *existing = read;
        } else {
            reads.push(read);
        }
    }
    if reads.is_empty()
        || expected_output.is_empty()
        || (has_status_suffix && !output.as_bytes().starts_with(&expected_output))
        || (!has_status_suffix && output.as_bytes() != expected_output)
    {
        return Vec::new();
    }
    reads
}

fn matched_source_read_argv_v1(
    workspace: &Path,
    argv: &[String],
) -> Option<(MatchedSourceReadV1, Vec<u8>)> {
    let (path, lines) = match argv {
        [program, path] if program == "cat" => (path.as_str(), None),
        [program, flag, range, path] if program == "sed" && flag == "-n" => {
            let (start, end) = range.strip_suffix('p')?.split_once(',')?;
            let (start, end) = (start.parse::<usize>().ok()?, end.parse::<usize>().ok()?);
            if start == 0 || end < start || end > 8192 || end - start > 512 {
                return None;
            }
            (path.as_str(), Some((start, end)))
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
        || !fs::metadata(&absolute).is_ok_and(|meta| meta.len() <= MAX_OBSERVED_FILE_BYTES_V1)
    {
        return None;
    }
    let bytes = fs::read(&absolute).ok()?;
    let expected = if let Some((start, end)) = lines {
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .skip(start - 1)
            .take(end - start + 1)
            .flatten()
            .copied()
            .collect::<Vec<_>>()
    } else {
        bytes.clone()
    };
    let range = lines.and_then(|(start, end)| {
        let actual_end = end.min(bytes.split_inclusive(|byte| *byte == b'\n').count());
        (start <= actual_end).then_some((start as u32, actual_end as u32))
    });
    Some((
        MatchedSourceReadV1 {
            path: relative,
            bytes,
            range,
        },
        expected,
    ))
}

/// Nominate source files from a simple completed search. This verifies only
/// each reported line against current source bytes, not search completeness.
fn matching_source_search_v1(
    item: &Value,
    workspace: &Path,
    command: &str,
) -> Vec<(String, Vec<u8>)> {
    let Some(output) = item["aggregated_output"]
        .as_str()
        .filter(|output| output.len() <= 1024 * 1024)
    else {
        return Vec::new();
    };
    let Ok(outer) = shell_words::split(command) else {
        return Vec::new();
    };
    let argv = if matches!(outer.as_slice(), [shell, flag, _]
        if shell == "/bin/zsh" && flag == "-lc")
    {
        let Ok(inner) = shell_words::split(&outer[2]) else {
            return Vec::new();
        };
        inner
    } else {
        outer
    };
    if argv.first().is_none_or(|program| program != "rg")
        || argv.get(1).is_none_or(|flag| flag != "-n")
    {
        return Vec::new();
    }
    let fixed = argv.get(2).is_some_and(|flag| flag == "-F");
    let pattern_index = if fixed { 3 } else { 2 };
    let Some(pattern) = argv.get(pattern_index) else {
        return Vec::new();
    };
    if !(2..=128).contains(&pattern.len()) {
        return Vec::new();
    }
    let terms = if fixed {
        vec![pattern.as_str()]
    } else {
        pattern.split('|').collect::<Vec<_>>()
    };
    if terms.is_empty()
        || terms.len() > 8
        || terms.iter().any(|term| {
            !(2..=64).contains(&term.len())
                || !term
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    {
        return Vec::new();
    }
    let mut operands = Vec::new();
    let mut position = pattern_index + 1;
    while position < argv.len() {
        let operand = argv[position].as_str();
        if matches!(operand, "--glob" | "-g") {
            let Some(glob) = argv.get(position + 1) else {
                return Vec::new();
            };
            if glob.is_empty()
                || glob.len() > 128
                || !glob.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'*' | b'!' | b'?')
                })
            {
                return Vec::new();
            }
            position += 2;
            continue;
        }
        if operand == "2>/dev/null" && position + 1 == argv.len() {
            break;
        }
        if operands.len() == 4
            || (operand != "."
                && (operand.starts_with('-')
                    || !Path::new(operand)
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))))
        {
            return Vec::new();
        }
        let root = if operand == "." {
            match fs::canonicalize(workspace) {
                Ok(root) => root,
                Err(_) => return Vec::new(),
            }
        } else {
            let Some((_, root)) = workspace_file_v1(workspace, operand) else {
                return Vec::new();
            };
            root
        };
        operands.push((operand, root));
        position += 1;
    }
    if operands.is_empty() {
        return Vec::new();
    }
    let single_file = if operands.len() == 1 && operands[0].1.is_file() {
        Some(operands[0].0)
    } else {
        None
    };
    let mut files = Vec::new();
    for line in output.lines().take(32) {
        if files.len() == 4 {
            break;
        }
        let Some((first, rest)) = line.split_once(':') else {
            continue;
        };
        let (path, line_number, reported) =
            if let Some(single_file) = single_file.filter(|_| first.parse::<usize>().is_ok()) {
                (single_file, first, rest)
            } else {
                let Some((line_number, reported)) = rest.split_once(':') else {
                    continue;
                };
                (first, line_number, reported)
            };
        let Ok(line_number) = line_number.parse::<usize>() else {
            continue;
        };
        if !(1..=8192).contains(&line_number) {
            continue;
        }
        let Some((relative, absolute)) = workspace_file_v1(workspace, path) else {
            continue;
        };
        if !operands.iter().any(|(_, root)| absolute.starts_with(root))
            || !source_code_path_v1(&relative)
            || files.iter().any(|(selected, _)| selected == &relative)
            || !fs::metadata(&absolute).is_ok_and(|meta| meta.is_file() && meta.len() <= 8 * 1024)
        {
            continue;
        }
        let Ok(bytes) = fs::read(&absolute) else {
            continue;
        };
        let Some(actual) = bytes.split(|byte| *byte == b'\n').nth(line_number - 1) else {
            continue;
        };
        if actual == reported.as_bytes() && terms.iter().any(|term| reported.contains(term)) {
            files.push((relative, bytes));
        }
    }
    files
}

fn source_code_path_v1(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("py" | "pyi" | "rs" | "go" | "js" | "jsx" | "mjs" | "ts" | "tsx")
    )
}

fn test_hint_relevant_v1(hint: &str, workspace: &Path, candidate_paths: &[String]) -> bool {
    if let Some(selector) = filtered_cargo_test_v1(hint) {
        if !workspace.join("Cargo.toml").is_file() {
            return false;
        }
        return candidate_paths.iter().take(4).any(|path| {
            let Some((relative, absolute)) = workspace_file_v1(workspace, path) else {
                return false;
            };
            if relative != *path || !path.ends_with(".rs") {
                return false;
            }
            if !fs::metadata(&absolute)
                .is_ok_and(|metadata| metadata.len() <= MAX_TEST_SELECTOR_SCAN_BYTES_V1)
            {
                return false;
            }
            let Ok(bytes) = fs::read(&absolute) else {
                return false;
            };
            if bytes.len() > MAX_TEST_SELECTOR_SCAN_BYTES_V1 as usize {
                return false;
            }
            let tokens = bytes
                .split(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
                .filter(|token| !token.is_empty())
                .collect::<Vec<_>>();
            tokens
                .windows(2)
                .any(|pair| matches!(pair[0], b"fn" | b"mod") && pair[1] == selector.as_bytes())
        });
    }
    if matches!(hint, "npm test" | "pnpm test" | "yarn test" | "bun test") {
        return candidate_paths
            .iter()
            .any(|path| crate::validation_hint::is_javascript_source_v1(path))
            && crate::validation_hint::package_test_suggestion_v1(workspace)
                .is_some_and(|suggestion| suggestion.command == hint);
    }
    if let Some(path) = hint.strip_prefix("node --test ") {
        if !safe_node_test_path_v1(path) {
            return false;
        }
        let Ok(root) = fs::canonicalize(workspace) else {
            return false;
        };
        let Ok(test_file) = fs::canonicalize(workspace.join(path)) else {
            return false;
        };
        if !test_file.starts_with(&root) || !test_file.is_file() {
            return false;
        }
        let Some(test_stem) = Path::new(path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.strip_prefix("test_"))
        else {
            return false;
        };
        return candidate_paths.iter().any(|candidate| {
            candidate == path
                || (Path::new(candidate)
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| {
                        matches!(extension, "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx")
                    })
                    && Path::new(candidate)
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        == Some(test_stem))
        });
    }
    let (extensions, manifest): (&[&str], Option<&str>) = match hint {
        "python3 -m unittest discover -s tests" | "python3 -m pytest" => (&["py", "pyi"], None),
        "cargo test" | "cargo test --quiet" => (&["rs"], Some("Cargo.toml")),
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

pub(crate) fn current_ms_v1() -> i64 {
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

    fn task_query<'a>(task_text: &'a str, scope: &'a str) -> BrainTaskQueryV1<'a> {
        BrainTaskQueryV1 {
            task_text,
            repository_id: "repository",
            workspace_id: "workspace",
            authorization_scope_digest: scope,
        }
    }

    #[test]
    fn post_tool_hook_records_only_verified_completed_bash_work() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("helper.py"), "value = 1\n").unwrap();
        let read = serde_json::json!({
            "hook_event_name":"PostToolUse", "tool_name":"Bash",
            "session_id":"session", "tool_use_id":"read",
            "tool_input":{"command":"cat helper.py"},
            "tool_response":{"exit_code":0,"output":"value = 1\n"}
        });
        let events = codex_post_tool_event_v1(&read, dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].path.as_deref(), Some("helper.py"));
        assert_eq!(events[1].task_id, "session");

        let mut live_shape = read.clone();
        live_shape["tool_use_id"] = "live".into();
        live_shape["tool_response"] = "value = 1\n".into();
        let events = codex_post_tool_event_v1(&live_shape, dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].path.as_deref(), Some("helper.py"));
        assert_eq!(events[1].exit_code, None);
        let mut ranged = live_shape.clone();
        ranged["tool_use_id"] = "ranged".into();
        ranged["tool_input"]["command"] = "sed -n '1,1p' helper.py".into();
        let events = codex_post_tool_event_v1(&ranged, dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            (events[1].read_start_line, events[1].read_end_line),
            (Some(1), Some(1))
        );

        let mut failed = read.clone();
        failed["tool_use_id"] = "failed".into();
        failed["tool_response"]["exit_code"] = 1.into();
        assert_eq!(
            codex_post_tool_event_v1(&failed, dir.path()).unwrap().len(),
            1
        );

        let mut mismatch = read.clone();
        mismatch["tool_use_id"] = "mismatch".into();
        mismatch["tool_response"]["output"] = "different\n".into();
        assert_eq!(
            codex_post_tool_event_v1(&mismatch, dir.path())
                .unwrap()
                .len(),
            1
        );

        let mut incomplete = read.clone();
        incomplete["tool_use_id"] = "incomplete".into();
        incomplete["tool_response"] = serde_json::json!({"message":"unknown"});
        let events = codex_post_tool_event_v1(&incomplete, dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].exit_code, None);
        assert!(
            codex_post_tool_event_v1(
                &serde_json::json!({
                    "hook_event_name":"PreToolUse", "tool_name":"Bash"
                }),
                dir.path()
            )
            .is_none()
        );
    }

    #[test]
    fn completed_patch_hook_updates_and_retires_file_memory() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("helper.py"), "value = 1\n").unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let seed = serde_json::json!({"type":"item.completed","item":{
            "id":"seed","type":"file_change","status":"completed",
            "changes":[{"path":"helper.py"}]}});
        for event in codex_completed_events_v1(&seed, &workspace, "old", "old") {
            store.record_brain_event_v1(&event).unwrap();
        }
        fs::write(workspace.join("helper.py"), "value = 2\n").unwrap();
        let mut patch = serde_json::json!({
            "hook_event_name":"PostToolUse","tool_name":"apply_patch",
            "session_id":"interactive","tool_use_id":"edit-1",
            "tool_input":{"command":"*** Begin Patch\n*** Update File: helper.py\n@@\n-value = 1\n+value = 2\n*** End Patch"},
            "tool_response":"Exit code: 0\nWall time: 0 seconds\nOutput:\nSuccess. Updated the following files:\nM helper.py\n"
        });
        let events = codex_post_tool_event_v1(&patch, &workspace).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "file_change");
        store.record_brain_event_v1(&events[0]).unwrap();
        let files = store.recent_brain_files_v1(8).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].source_digest,
            blake3::hash(b"value = 2\n").to_hex().to_string()
        );

        patch["tool_use_id"] = "failed".into();
        patch["tool_response"] = "Exit code: 1\nOutput:\nPatch failed\n".into();
        assert!(
            codex_post_tool_event_v1(&patch, &workspace)
                .unwrap()
                .is_empty()
        );

        fs::remove_file(workspace.join("helper.py")).unwrap();
        patch["tool_use_id"] = "delete".into();
        patch["tool_input"]["command"] =
            "*** Begin Patch\n*** Delete File: helper.py\n*** End Patch".into();
        patch["tool_response"] = "Exit code: 0\nWall time: 0 seconds\nOutput:\nSuccess. Updated the following files:\nD helper.py\n".into();
        let events = codex_post_tool_event_v1(&patch, &workspace).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].source_digest.is_none());
        store.record_brain_event_v1(&events[0]).unwrap();
        assert!(store.recent_brain_files_v1(8).unwrap().is_empty());

        patch["tool_use_id"] = "traversal".into();
        patch["tool_input"]["command"] =
            "*** Begin Patch\n*** Update File: ../outside.py\n*** End Patch".into();
        patch["tool_response"] =
            "Exit code: 0\nOutput:\nSuccess. Updated the following files:\nM ../outside.py\n"
                .into();
        assert!(
            codex_post_tool_event_v1(&patch, &workspace)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn codex_run_observation_counts_completed_work_and_valid_usage() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("helper.py");
        fs::write(&source, "value = 1\n").unwrap();
        let mut observed = CodexRunObservationV1::default();
        let read = serde_json::json!({"type":"item.completed","item":{
            "id":"read","type":"command_execution","command":"cat helper.py",
            "aggregated_output":"value = 1\n","exit_code":0,"status":"completed"}});
        let events = codex_completed_events_v1(&read, dir.path(), "session", "task");
        observed.observe(&read, &events);
        let edit = serde_json::json!({"type":"item.completed","item":{
            "id":"edit","type":"file_change","status":"completed","changes":[{"path":"helper.py"}]}});
        observed.observe(
            &edit,
            &codex_completed_events_v1(&edit, dir.path(), "session", "task"),
        );
        let test = serde_json::json!({"type":"item.completed","item":{
            "id":"test","type":"command_execution","command":"python3 -m pytest",
            "exit_code":0,"status":"completed"}});
        observed.observe(
            &test,
            &codex_completed_events_v1(&test, dir.path(), "session", "task"),
        );
        observed.observe(
            &serde_json::json!({"type":"item.completed","item":{
            "type":"mcp_tool_call","status":"completed"}}),
            &[],
        );
        observed.observe(
            &serde_json::json!({"type":"turn.completed","usage":{
            "input_tokens":100,"cached_input_tokens":40,"output_tokens":12}}),
            &[],
        );
        let run = observed.into_run(
            "session".to_owned(),
            "task".to_owned(),
            dir.path(),
            current_ms_v1(),
            0,
        );
        assert!(run.turn_completed);
        assert_eq!(
            (
                run.completed_commands,
                run.completed_source_reads,
                run.completed_edits,
                run.completed_mcp_calls,
                run.successful_tests
            ),
            (2, 1, 1, 1, 1)
        );
        assert_eq!(
            (run.input_tokens, run.cached_input_tokens, run.output_tokens),
            (Some(100), Some(40), Some(12))
        );
        let mut invalid = CodexRunObservationV1::default();
        invalid.observe(
            &serde_json::json!({"type":"turn.completed","usage":{
            "input_tokens":5,"cached_input_tokens":6,"output_tokens":1}}),
            &[],
        );
        let run = invalid.into_run(
            "other-session".to_owned(),
            "task".to_owned(),
            dir.path(),
            current_ms_v1(),
            0,
        );
        assert!(run.turn_completed);
        assert_eq!(
            (run.input_tokens, run.cached_input_tokens, run.output_tokens),
            (None, None, None)
        );
    }

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
                read_start_line: None,
                read_end_line: None,
                command_digest: Some(blake3::hash(b"unrelated command").to_hex().to_string()),
                command_hint: None,
                exit_code: Some(0),
                created_ms: current_ms_v1() + index,
                authorization_scope_digest: Some(local_brain_scope_digest_v1(&workspace)),
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
        let scope = local_brain_scope_digest_v1(&workspace);
        let brief = repository_brief_v1(&store, &workspace, &candidates, &[], &scope).unwrap();
        assert_eq!(brief["recentCurrentFiles"].as_array().unwrap().len(), 1);
        assert_eq!(
            brief["previousSuccessfulTestCommand"],
            "python3 -m unittest discover -s tests"
        );
        let unrelated =
            repository_brief_v1(&store, &workspace, &["src/main.rs".to_owned()], &[], &scope)
                .unwrap();
        assert!(unrelated["previousSuccessfulTestCommand"].is_null());
        fs::write(workspace.join("balances.py"), "value = 2\n").unwrap();
        let stale = repository_brief_v1(&store, &workspace, &candidates, &[], &scope).unwrap();
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
        fs::create_dir(workspace.join("tests")).unwrap();
        fs::write(workspace.join("tests/test_calculator.mjs"), "export {};\n").unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        for (index, command) in [
            "cargo test --quiet",
            "go test ./...",
            "python3 -m pytest",
            "node --test tests/test_calculator.mjs",
        ]
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
        let scope = local_brain_scope_digest_v1(&workspace);
        let rust = repository_brief_v1(&store, &workspace, &["src/lib.rs".to_owned()], &[], &scope)
            .unwrap();
        assert_eq!(rust["previousSuccessfulTestCommand"], "cargo test --quiet");
        let go =
            repository_brief_v1(&store, &workspace, &["main.go".to_owned()], &[], &scope).unwrap();
        assert_eq!(go["previousSuccessfulTestCommand"], "go test ./...");
        let js = repository_brief_v1(
            &store,
            &workspace,
            &["src/calculator.mjs".to_owned()],
            &[],
            &scope,
        )
        .unwrap();
        assert_eq!(
            js["previousSuccessfulTestCommand"],
            "node --test tests/test_calculator.mjs"
        );
        fs::remove_file(workspace.join("go.mod")).unwrap();
        let stale =
            repository_brief_v1(&store, &workspace, &["main.go".to_owned()], &[], &scope).unwrap();
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
    fn filtered_cargo_test_is_only_a_current_source_checked_validation_hint() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(
            dir.path().join("src/lib.rs"),
            "#[cfg(test)] mod historical_search_oracle { #[test] fn bounded() {} }\n",
        )
        .unwrap();
        let completed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"cargo-filter","type":"command_execution",
                    "command":"/bin/zsh -lc 'cargo test --locked --lib historical_search_oracle'",
                    "exit_code":0}
        });
        let events = codex_completed_events_v1(&completed, dir.path(), "session", "task");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "test");
        assert_eq!(
            events[0].command_hint.as_deref(),
            Some("cargo test --locked --lib historical_search_oracle")
        );
        let store = Store::open(dir.path().join("state")).unwrap();
        store.record_brain_event_v1(&events[0]).unwrap();
        let scope = local_brain_scope_digest_v1(dir.path());
        let candidates = ["src/lib.rs".to_owned()];
        let brief = repository_brief_v1(&store, dir.path(), &candidates, &[], &scope).unwrap();
        assert_eq!(
            brief["previousSuccessfulTestCommand"],
            "cargo test --locked --lib historical_search_oracle"
        );
        assert_eq!(
            brief["testCommandAuthority"],
            "unverified suggestion; run required validation"
        );
        assert_eq!(
            brief["testCommandScope"],
            "filtered test only; other required validation remains unverified"
        );
        assert!(test_hint_relevant_v1(
            events[0].command_hint.as_deref().unwrap(),
            dir.path(),
            &candidates
        ));
        fs::write(dir.path().join("src/lib.rs"), "pub fn unrelated() {}\n").unwrap();
        let stale = repository_brief_v1(&store, dir.path(), &candidates, &[], &scope).unwrap();
        assert!(stale["previousSuccessfulTestCommand"].is_null());
        assert!(!test_hint_relevant_v1(
            events[0].command_hint.as_deref().unwrap(),
            dir.path(),
            &candidates
        ));
        let mut run = CodexRunObservationV1::default();
        run.observe(&completed, &events);
        assert_eq!(
            run.into_run(
                "session".to_owned(),
                "task".to_owned(),
                dir.path(),
                current_ms_v1(),
                0,
            )
            .successful_tests,
            1
        );
        for command in [
            "cargo test --locked --lib historical_search_oracle; echo done",
            "cargo test --locked --lib ../other",
            "cargo test --locked --lib first second",
        ] {
            assert!(!observed_cargo_test_v1(command));
        }
        assert!(observed_cargo_test_v1(
            "cargo test --locked --lib first::second"
        ));
        assert!(known_test_command_v1("cargo test --locked --lib first::second").is_none());
        let failed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"cargo-failed","type":"command_execution",
                    "command":"cargo test --locked --lib historical_search_oracle",
                    "exit_code":1}
        });
        assert_eq!(
            codex_completed_events_v1(&failed, dir.path(), "session", "task")[0].kind,
            "command"
        );
    }

    #[test]
    fn repository_brain_keeps_successful_package_test_as_execute_required_hint() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(
            workspace.join("package.json"),
            r#"{"packageManager":"pnpm@9.0.0","scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        fs::write(workspace.join("pnpm-lock.yaml"), "lockfileVersion: 9\n").unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let completed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"package_test","type":"command_execution",
                "command":"pnpm test","exit_code":0}
        });
        for event in codex_completed_events_v1(&completed, &workspace, "session", "old-task") {
            store.record_brain_event_v1(&event).unwrap();
        }
        let scope = local_brain_scope_digest_v1(&workspace);
        let candidate = ["src/ledger.ts".to_owned()];
        let brief = repository_brief_v1(&store, &workspace, &candidate, &[], &scope).unwrap();
        assert_eq!(brief["previousSuccessfulTestCommand"], "pnpm test");
        assert_eq!(
            brief["testCommandAuthority"],
            "unverified suggestion; run required validation"
        );
        fs::write(
            workspace.join("package.json"),
            r#"{"packageManager":"npm@10.0.0","scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        let stale = repository_brief_v1(&store, &workspace, &candidate, &[], &scope).unwrap();
        assert!(stale["previousSuccessfulTestCommand"].is_null());
        let failed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"failed_package_test","type":"command_execution",
                "command":"pnpm test","exit_code":1}
        });
        assert_eq!(
            codex_completed_events_v1(&failed, &workspace, "session", "old-task")[0].command_hint,
            None
        );
    }

    #[test]
    fn observed_node_test_is_reused_only_for_its_current_source_companion() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(workspace.join("tests")).unwrap();
        let test_path = workspace.join("tests/test_currency.mjs");
        fs::write(&test_path, "import 'node:test';\n").unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let completed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"currency_test","type":"command_execution",
                "command":"node --test tests/test_currency.mjs","exit_code":0}
        });
        for event in codex_completed_events_v1(&completed, &workspace, "session", "old-task") {
            store.record_brain_event_v1(&event).unwrap();
        }
        let scope = local_brain_scope_digest_v1(&workspace);
        let relevant = repository_brief_v1(
            &store,
            &workspace,
            &["src/currency.js".to_owned()],
            &[],
            &scope,
        )
        .unwrap();
        assert_eq!(
            relevant["previousSuccessfulTestCommand"],
            "node --test tests/test_currency.mjs"
        );
        let unrelated = repository_brief_v1(
            &store,
            &workspace,
            &["src/calculator.js".to_owned()],
            &[],
            &scope,
        )
        .unwrap();
        assert!(unrelated["previousSuccessfulTestCommand"].is_null());
        fs::remove_file(test_path).unwrap();
        let missing = repository_brief_v1(
            &store,
            &workspace,
            &["src/currency.js".to_owned()],
            &[],
            &scope,
        )
        .unwrap();
        assert!(missing["previousSuccessfulTestCommand"].is_null());
        assert!(known_test_command_v1("node --test tests/test_currency.mjs; rm -rf src").is_none());
        assert!(known_test_command_v1("node --test ../test_currency.mjs").is_none());
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
        let scope = local_brain_scope_digest_v1(&workspace);
        let brief = repository_brief_v1(&store, &workspace, &paths, &[], &scope).unwrap();
        assert_eq!(
            brief["recentCurrentFiles"][0]["currentCompletePreview"],
            "def helper():\n    return 42\n"
        );
        let previewed = repository_brief_v1(&store, &workspace, &paths, &paths, &scope).unwrap();
        assert!(previewed["recentCurrentFiles"][0]["currentCompletePreview"].is_null());
        fs::write(&source, "def helper():\n    return 0\n").unwrap();
        let stale = repository_brief_v1(&store, &workspace, &paths, &[], &scope).unwrap();
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

    #[test]
    fn compound_source_reads_require_exact_printed_prefix_and_safe_suffix() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/helper.rs"), "one\ntwo\nthree\n").unwrap();
        let mut completed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"compound-read","type":"command_execution",
                    "command":"/bin/zsh -lc \"sed -n '1,1p' src/helper.rs && sed -n '3,3p' src/helper.rs && git status --short\"",
                    "aggregated_output":"one\nthree\n M src/helper.rs\n", "exit_code":0}
        });
        let events = codex_completed_events_v1(&completed, dir.path(), "session", "task");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].path.as_deref(), Some("src/helper.rs"));
        assert_eq!(
            (events[1].read_start_line, events[1].read_end_line),
            (Some(3), Some(3))
        );
        let store = Store::open(dir.path().join("state")).unwrap();
        for event in &events {
            store.record_brain_event_v1(event).unwrap();
        }
        fs::write(dir.path().join("src/other.rs"), "other\n").unwrap();
        completed["item"]["command"] =
            "/bin/zsh -lc \"cat src/helper.rs && cat src/other.rs\"".into();
        completed["item"]["aggregated_output"] = "one\ntwo\nthree\nother\n".into();
        let two_files = codex_completed_events_v1(&completed, dir.path(), "session", "task");
        assert_eq!(two_files.len(), 3);
        assert_eq!(two_files[1].path.as_deref(), Some("src/helper.rs"));
        assert_eq!(two_files[2].path.as_deref(), Some("src/other.rs"));
        completed["item"]["command"] = "/bin/zsh -lc \"sed -n '1,1p' src/helper.rs && sed -n '3,3p' src/helper.rs && git status --short\"".into();
        completed["item"]["aggregated_output"] = "one\nWRONG\n M src/helper.rs\n".into();
        assert_eq!(
            codex_completed_events_v1(&completed, dir.path(), "session", "task").len(),
            1
        );
        completed["item"]["aggregated_output"] = "one\nthree\n M src/helper.rs\n".into();
        completed["item"]["command"] =
            "/bin/zsh -lc \"sed -n '1,1p' src/helper.rs && touch changed && git status --short\""
                .into();
        assert_eq!(
            codex_completed_events_v1(&completed, dir.path(), "session", "task").len(),
            1
        );
        fs::write(dir.path().join("src/helper.rs"), "one\ntwo\nchanged\n").unwrap();
        completed["item"]["command"] = "/bin/zsh -lc \"sed -n '1,1p' src/helper.rs && sed -n '3,3p' src/helper.rs && git status --short\"".into();
        assert_eq!(
            codex_completed_events_v1(&completed, dir.path(), "session", "task").len(),
            1
        );
    }

    #[test]
    fn bounded_sed_range_on_large_source_records_only_verified_current_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        let source = (1..=1200)
            .map(|line| format!("// source line {line}\n"))
            .collect::<String>();
        fs::write(dir.path().join("src/large.rs"), &source).unwrap();
        assert!(source.len() > 8 * 1024);
        let output = source
            .lines()
            .skip(819)
            .take(111)
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        let completed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"large-range","type":"command_execution",
                    "command":"/bin/zsh -lc \"sed -n '820,930p' src/large.rs\"",
                    "aggregated_output":output,"exit_code":0}
        });
        let events = codex_completed_events_v1(&completed, dir.path(), "session", "task");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].path.as_deref(), Some("src/large.rs"));
        assert_eq!(events[1].read_start_line, Some(820));
        assert_eq!(events[1].read_end_line, Some(930));
        let digest = blake3::hash(source.as_bytes()).to_hex().to_string();
        assert_eq!(events[1].source_digest.as_deref(), Some(digest.as_str()));
        let store = Store::open(dir.path().join("state")).unwrap();
        for event in &events {
            store.record_brain_event_v1(event).unwrap();
        }
        let scope = local_brain_scope_digest_v1(dir.path());
        let relevant = serde_json::json!({"candidates":[{"locator":{"path":"src/large.rs"}}]});
        let brief = repository_brief_for_task_v1(
            &store,
            dir.path(),
            &Value::Array(Vec::new()),
            &relevant,
            task_query("Fix unrelated source prelude", &scope),
        )
        .unwrap()
        .unwrap();
        let preview = &brief["recentCurrentFiles"][0]["currentPartialPreview"];
        assert_eq!(preview["origin"], "verified_prior_read_range");
        assert_eq!(preview["startLine"], 820);
        assert_eq!(preview["endLine"], 930);
        assert_eq!(preview["text"], output);
        assert_eq!(
            store
                .brain_file_v1("src/large.rs", &scope)
                .unwrap()
                .unwrap()
                .read_start_line,
            Some(820)
        );
        let mut run = CodexRunObservationV1::default();
        run.observe(&completed, &events);
        assert_eq!(run.completed_source_reads, 1);
        let mut wrong = completed;
        wrong["item"]["aggregated_output"] = "unverified".into();
        assert_eq!(
            codex_completed_events_v1(&wrong, dir.path(), "session", "task").len(),
            1
        );
        fs::write(
            dir.path().join("src/large.rs"),
            format!("{source}// changed\n"),
        )
        .unwrap();
        assert!(
            repository_brief_for_task_v1(
                &store,
                dir.path(),
                &Value::Array(Vec::new()),
                &relevant,
                task_query("Fix unrelated source prelude", &scope),
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn completed_literal_search_nominates_only_independently_checked_sources() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::write(
            workspace.join("src/ledger.py"),
            "def balance():\n    return 42\n",
        )
        .unwrap();
        fs::write(workspace.join("src/wrong.py"), "def unrelated():\n").unwrap();
        let completed = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"search","type":"command_execution",
                "command":"rg -n -F balance src", "exit_code":0,
                "aggregated_output":"src/ledger.py:1:def balance():\nsrc/wrong.py:1:def balance():\n"}
        });
        let events = codex_completed_events_v1(&completed, &workspace, "session", "old-task");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].path.as_deref(), Some("src/ledger.py"));
        let store = Store::open(dir.path().join("state")).unwrap();
        for event in &events {
            store.record_brain_event_v1(event).unwrap();
        }
        let scope = local_brain_scope_digest_v1(&workspace);
        let brief = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Fix ledger balance rounding", &scope),
        )
        .unwrap()
        .unwrap();
        assert_eq!(brief["recentCurrentFiles"][0]["path"], "src/ledger.py");
        fs::write(
            workspace.join("src/ledger.py"),
            "def balance():\n    return 0\n",
        )
        .unwrap();
        let stale = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Fix ledger balance rounding", &scope),
        )
        .unwrap();
        assert!(stale.is_none());

        let hook = serde_json::json!({
            "hook_event_name":"PostToolUse", "tool_name":"Bash",
            "session_id":"interactive", "tool_use_id":"search",
            "tool_input":{"command":"rg -n balance src"},
            "tool_response":"src/ledger.py:1:def balance():\n"
        });
        let hook_events = codex_post_tool_event_v1(&hook, &workspace).unwrap();
        assert_eq!(hook_events.len(), 2);
        assert_eq!(hook_events[1].path.as_deref(), Some("src/ledger.py"));
        assert_eq!(hook_events[1].exit_code, None);
        let single_file = serde_json::json!({
            "type":"item.completed", "item":{"id":"single_file","type":"command_execution",
                "command":"rg -n -F balance src/ledger.py", "exit_code":0,
                "aggregated_output":"1:def balance():\n"}
        });
        assert_eq!(
            codex_completed_events_v1(&single_file, &workspace, "session", "old-task")[1]
                .path
                .as_deref(),
            Some("src/ledger.py")
        );
        let root_search = serde_json::json!({
            "type":"item.completed", "item":{"id":"root_search","type":"command_execution",
                "command":"rg -n balance .", "exit_code":0,
                "aggregated_output":"./src/ledger.py:1:def balance():\n"}
        });
        assert_eq!(
            codex_completed_events_v1(&root_search, &workspace, "session", "old-task")[1]
                .path
                .as_deref(),
            Some("src/ledger.py")
        );
        fs::create_dir(workspace.join("tests")).unwrap();
        fs::write(
            workspace.join("tests/test_ledger.py"),
            "def test_balance():\n    pass\n",
        )
        .unwrap();
        let multi_root = serde_json::json!({
            "type":"item.completed", "item":{"id":"multi_root","type":"command_execution",
                "command":"/bin/zsh -lc 'rg -n \"balance|value\" src tests 2>/dev/null'", "exit_code":0,
                "aggregated_output":"src/ledger.py:1:def balance():\ntests/test_ledger.py:1:def test_balance():\n"}
        });
        let multi_root_events =
            codex_completed_events_v1(&multi_root, &workspace, "session", "old-task");
        assert_eq!(multi_root_events.len(), 3);
        assert_eq!(multi_root_events[1].path.as_deref(), Some("src/ledger.py"));
        assert_eq!(
            multi_root_events[2].path.as_deref(),
            Some("tests/test_ledger.py")
        );
        let globbed = serde_json::json!({
            "type":"item.completed", "item":{"id":"globbed","type":"command_execution",
                "command":"rg -n balance src --glob '!background/**'", "exit_code":0,
                "aggregated_output":"src/ledger.py:1:def balance():\n"}
        });
        assert_eq!(
            codex_completed_events_v1(&globbed, &workspace, "session", "old-task").len(),
            2
        );
        let unsafe_command = serde_json::json!({
            "type":"item.completed", "item":{"id":"unsafe","type":"command_execution",
                "command":"rg -n 'balance.*secret' src", "exit_code":0,
                "aggregated_output":"src/ledger.py:1:def balance():\n"}
        });
        assert_eq!(
            codex_completed_events_v1(&unsafe_command, &workspace, "session", "old-task").len(),
            1
        );
    }

    #[test]
    fn brain_brief_keeps_a_larger_current_preview_inside_total_budget() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let scope = local_brain_scope_digest_v1(&workspace);
        let content = "value = 1\n".repeat(200);
        for (index, name) in ["first.py", "second.py"].iter().enumerate() {
            fs::write(workspace.join(name), &content).unwrap();
            let completed = serde_json::json!({
                "type":"item.completed",
                "item":{"id":format!("edit_{index}"),"type":"file_change","status":"completed",
                        "changes":[{"path":name}]}
            });
            for event in codex_completed_events_v1(&completed, &workspace, "session", "old-task") {
                store.record_brain_event_v1(&event).unwrap();
            }
        }
        let candidates = ["first.py".to_owned(), "second.py".to_owned()];
        let brief = repository_brief_for_task_v1(
            &store, &workspace, &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":candidates.iter().map(|path| serde_json::json!({"locator":{"path":path}})).collect::<Vec<_>>() }),
            task_query("Edit both values", &scope),
        ).unwrap().unwrap();
        assert_eq!(
            brief["recentCurrentFiles"][0]["currentCompletePreview"],
            content
        );
        assert!(brief["recentCurrentFiles"][1]["currentCompletePreview"].is_null());
        assert!(serde_json::to_vec(&brief).unwrap().len() <= MAX_BRAIN_BRIEF_BYTES_V1);
        fs::write(workspace.join("first.py"), "value = 2\n").unwrap();
        let stale = repository_brief_v1(&store, &workspace, &candidates, &[], &scope).unwrap();
        assert_eq!(stale["recentCurrentFiles"][0]["path"], "second.py");
    }

    #[test]
    fn prior_task_overlap_nominates_only_current_same_scope_sources() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::write(
            workspace.join("src/ledger.py"),
            "def balance():\n    return 10\n",
        )
        .unwrap();
        fs::write(
            workspace.join("src/widget.py"),
            "def widget():\n    return 1\n",
        )
        .unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let scope = local_brain_scope_digest_v1(&workspace);
        let old_task = crate::task_lifecycle::TaskDefinitionV1::new(
            "Repair ledger balance formatting",
            Vec::new(),
            None,
            Vec::new(),
            None,
        )
        .unwrap();
        store
            .start_task_v1("repository", "workspace", &scope, "old-task", &old_task)
            .unwrap();
        let edit = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"edit_1","type":"file_change","status":"completed",
                    "changes":[{"path":"src/ledger.py"}]}
        });
        for event in codex_completed_events_v1(&edit, &workspace, "session", "old-task") {
            store.record_brain_event_v1(&event).unwrap();
        }
        let other_scope = "a".repeat(64);
        let other_task = crate::task_lifecycle::TaskDefinitionV1::new(
            "Repair widget rendering",
            Vec::new(),
            None,
            Vec::new(),
            None,
        )
        .unwrap();
        store
            .start_task_v1(
                "repository",
                "workspace",
                &other_scope,
                "other-task",
                &other_task,
            )
            .unwrap();
        let other_edit = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"edit_2","type":"file_change","status":"completed",
                    "changes":[{"path":"src/widget.py"}]}
        });
        for mut event in codex_completed_events_v1(&other_edit, &workspace, "session", "other-task")
        {
            event.authorization_scope_digest = Some(other_scope.clone());
            store.record_brain_event_v1(&event).unwrap();
        }
        let brief = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Improve ledger balance rendering", &scope),
        )
        .unwrap()
        .unwrap();
        assert_eq!(brief["recentCurrentFiles"][0]["path"], "src/ledger.py");
        assert!(
            brief["recentCurrentFiles"][0]["selection"]
                .as_str()
                .unwrap()
                .contains("prior task")
        );
        let other = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Improve widget rendering", &scope),
        )
        .unwrap();
        assert!(other.is_none());
        fs::write(
            workspace.join("src/ledger.py"),
            "def balance():\n    return 0\n",
        )
        .unwrap();
        let stale = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Improve ledger balance rendering", &scope),
        )
        .unwrap();
        assert!(stale.is_none());
    }

    #[test]
    fn interactive_hook_read_can_be_nominated_by_path_without_a_task_row() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::write(workspace.join("src/ledger_helper.py"), "value = 10\n").unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let hook = serde_json::json!({
            "hook_event_name":"PostToolUse", "tool_name":"Bash",
            "session_id":"interactive", "tool_use_id":"read",
            "tool_input":{"command":"cat src/ledger_helper.py"},
            "tool_response":"value = 10\n"
        });
        for event in codex_post_tool_event_v1(&hook, &workspace).unwrap() {
            store.record_brain_event_v1(&event).unwrap();
        }
        let scope = local_brain_scope_digest_v1(&workspace);
        let brief = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Fix ledger helper output", &scope),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            brief["recentCurrentFiles"][0]["path"],
            "src/ledger_helper.py"
        );
        assert_eq!(
            brief["recentCurrentFiles"][0]["currentCompletePreview"],
            "value = 10\n"
        );
    }

    #[test]
    fn prior_large_source_gets_current_task_anchored_partial_preview() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(workspace.join("src")).unwrap();
        let source = format!(
            "{}def balance(value):\n    return value + 1\n",
            "# ordinary source line\n".repeat(180)
        );
        fs::write(workspace.join("src/ledger.py"), &source).unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let event = serde_json::json!({
            "type":"item.completed",
            "item":{"id":"edit","type":"file_change","status":"completed",
                    "changes":[{"path":"src/ledger.py"}]}
        });
        for event in codex_completed_events_v1(&event, &workspace, "session", "prior-task") {
            store.record_brain_event_v1(&event).unwrap();
        }
        let scope = local_brain_scope_digest_v1(&workspace);
        let brief = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Fix ledger balance calculation", &scope),
        )
        .unwrap()
        .unwrap();
        let file = &brief["recentCurrentFiles"][0];
        assert_eq!(file["path"], "src/ledger.py");
        assert!(file["currentCompletePreview"].is_null());
        assert_eq!(file["currentPartialPreview"]["complete"], false);
        assert!(
            file["currentPartialPreview"]["text"]
                .as_str()
                .unwrap()
                .contains("def balance(value):")
        );
        assert!(serde_json::to_vec(&brief).unwrap().len() <= MAX_BRAIN_BRIEF_BYTES_V1);

        let existing = serde_json::json!([{"path":"src/ledger.py","complete":false}]);
        let duplicated = repository_brief_for_task_v1(
            &store,
            &workspace,
            &existing,
            &serde_json::json!({"candidates":[]}),
            task_query("Fix ledger balance calculation", &scope),
        )
        .unwrap()
        .unwrap();
        assert!(duplicated["recentCurrentFiles"][0]["currentPartialPreview"].is_null());

        fs::write(
            workspace.join("src/ledger.py"),
            format!("{source}# changed\n"),
        )
        .unwrap();
        assert!(
            repository_brief_for_task_v1(
                &store,
                &workspace,
                &Value::Array(Vec::new()),
                &serde_json::json!({"candidates":[]}),
                task_query("Fix ledger balance calculation", &scope),
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn older_relevant_file_survives_more_than_sixty_four_newer_observations() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir_all(workspace.join("src")).unwrap();
        let store = Store::open(dir.path().join("state")).unwrap();
        let scope = local_brain_scope_digest_v1(&workspace);
        let old_task = crate::task_lifecycle::TaskDefinitionV1::new(
            "Improve ledger balance calculation",
            Vec::new(),
            None,
            Vec::new(),
            None,
        )
        .unwrap();
        let decoy_task = crate::task_lifecycle::TaskDefinitionV1::new(
            "Update widget tile style",
            Vec::new(),
            None,
            Vec::new(),
            None,
        )
        .unwrap();
        store
            .start_task_v1("repository", "workspace", &scope, "ledger-task", &old_task)
            .unwrap();
        store
            .start_task_v1(
                "repository",
                "workspace",
                &scope,
                "widget-task",
                &decoy_task,
            )
            .unwrap();
        let base = current_ms_v1() - 1_000;
        for index in 0..1_000 {
            let path = if index == 0 {
                "src/ledger.py".to_owned()
            } else {
                format!("src/widget_{index:03}.py")
            };
            fs::write(workspace.join(&path), format!("value = {index}\n")).unwrap();
            let completed = serde_json::json!({
                "type":"item.completed",
                "item":{"id":format!("edit_{index}"),"type":"file_change","status":"completed",
                        "changes":[{"path":path}]}
            });
            let task_id = if index == 0 {
                "ledger-task"
            } else {
                "widget-task"
            };
            for mut event in codex_completed_events_v1(&completed, &workspace, "session", task_id) {
                event.created_ms = base + index;
                store.record_brain_event_v1(&event).unwrap();
            }
        }
        let lookup_started = std::time::Instant::now();
        let brief = repository_brief_for_task_v1(
            &store,
            &workspace,
            &Value::Array(Vec::new()),
            &serde_json::json!({"candidates":[]}),
            task_query("Fix ledger balance calculation", &scope),
        )
        .unwrap()
        .unwrap();
        eprintln!(
            "brain history lookup across 1000 observations: {:?}",
            lookup_started.elapsed()
        );
        assert_eq!(brief["recentCurrentFiles"][0]["path"], "src/ledger.py");
    }
}
