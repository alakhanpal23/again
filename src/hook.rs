//! Codex tool and compaction lifecycle JSON adapter.
//!
//! The adapter follows the documented Codex hook contract. It deliberately emits no
//! decision for commands that are not eligible: this preserves Codex's normal approval
//! and sandbox behavior.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactEvent {
    PreCompact,
    PostCompact,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodexHookInput {
    PreToolUse(Box<PreToolUseInput>),
    Compact {
        event: CompactEvent,
        session_id: String,
        cwd: String,
        context_id: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreToolUseInput {
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: Option<String>,
    pub cwd: String,
    pub hook_event_name: String,
    pub model: String,
    pub permission_mode: String,
    pub turn_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    pub tool_name: String,
    pub tool_use_id: String,
    pub tool_input: serde_json::Value,
}

impl PreToolUseInput {
    pub fn command(&self) -> Result<&str> {
        if self.hook_event_name != "PreToolUse" {
            bail!("unexpected hook event {}", self.hook_event_name);
        }
        if self.tool_name != "Bash" {
            bail!(
                "unexpected tool {}; Again v0 handles only Bash",
                self.tool_name
            );
        }
        if self.session_id.is_empty()
            || self.cwd.is_empty()
            || self.model.is_empty()
            || self.turn_id.is_empty()
            || self.tool_use_id.is_empty()
        {
            bail!("required PreToolUse identity fields must be non-empty");
        }
        if !matches!(
            self.permission_mode.as_str(),
            "default" | "acceptEdits" | "plan" | "dontAsk" | "bypassPermissions"
        ) {
            bail!("unsupported PreToolUse permission_mode");
        }
        if self.agent_id.is_some() != self.agent_type.is_some()
            || self
                .agent_id
                .as_deref()
                .is_some_and(|value| valid_context_component(value).is_none())
            || self
                .agent_type
                .as_deref()
                .is_some_and(|value| valid_context_component(value).is_none())
        {
            bail!("invalid PreToolUse subagent identity");
        }
        self.tool_input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("Bash tool_input.command must be a string"))
    }

    /// Current Codex exposes exactly `{ "command": ... }` to Bash hooks while
    /// retaining effective workdir/TTY/sandbox controls internally. Unknown
    /// hook-visible fields fail open until their semantics are audited.
    pub fn rewrite_compatible(&self) -> bool {
        self.tool_input
            .as_object()
            .is_some_and(|value| value.len() == 1 && value.contains_key("command"))
    }

    pub fn delivery_context_id(&self) -> Option<String> {
        delivery_context_id(Some(&self.turn_id), self.agent_id.as_deref())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactHookInput {
    session_id: String,
    transcript_path: Option<String>,
    cwd: String,
    hook_event_name: String,
    model: String,
    turn_id: String,
    trigger: String,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    agent_type: Option<String>,
}

fn delivery_context_id(turn_id: Option<&str>, agent_id: Option<&str>) -> Option<String> {
    let turn_id = valid_context_component(turn_id?)?;
    let (kind, agent) = match agent_id {
        Some(value) => (b"subagent".as_slice(), valid_context_component(value)?),
        None => (b"root".as_slice(), ""),
    };
    let mut hasher = Hasher::new_derive_key("again.codex.delivery-context.v1");
    put_context_field(&mut hasher, kind);
    put_context_field(&mut hasher, agent.as_bytes());
    put_context_field(&mut hasher, turn_id.as_bytes());
    Some(hasher.finalize().to_hex().to_string())
}

fn valid_context_component(value: &str) -> Option<&str> {
    (!value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control))
        .then_some(value)
}

fn put_context_field(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: &'static str,
    pub permission_decision: &'static str,
    /// Codex treats this as the rewritten tool input. Compatibility is checked
    /// before this function; replace only the exposed `command` field.
    pub updated_input: serde_json::Value,
}

pub fn parse_input(mut reader: impl Read) -> Result<PreToolUseInput> {
    match parse_hook_input(&mut reader)? {
        CodexHookInput::PreToolUse(input) => Ok(*input),
        CodexHookInput::Compact { .. } => bail!("expected a PreToolUse hook event"),
    }
}

pub fn parse_hook_input(mut reader: impl Read) -> Result<CodexHookInput> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("read Codex hook input")?;
    if bytes.len() > 1024 * 1024 {
        bail!("Codex hook input exceeds 1 MiB safety limit");
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse Codex hook JSON")?;
    let event = value
        .get("hook_event_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("hook_event_name must be a string"))?
        .to_owned();
    match event.as_str() {
        "PreToolUse" => {
            if value.get("transcript_path").is_none() {
                bail!("PreToolUse transcript_path field is required");
            }
            let input: PreToolUseInput =
                serde_json::from_value(value).context("parse Codex PreToolUse JSON")?;
            input.command()?;
            Ok(CodexHookInput::PreToolUse(Box::new(input)))
        }
        "PreCompact" | "PostCompact" => {
            if value.get("transcript_path").is_none() {
                bail!("compaction transcript_path field is required");
            }
            let compact: CompactHookInput =
                serde_json::from_value(value).context("parse Codex compact hook JSON")?;
            // The generated Codex schema types these strings but does not add
            // non-empty constraints, and agent fields are independently
            // optional. Preserve that contract. Invalid/empty optional context
            // merely disables the dormant delivery-context derivation.
            let _ = (
                &compact.transcript_path,
                &compact.model,
                &compact.agent_type,
            );
            if !matches!(compact.trigger.as_str(), "manual" | "auto") {
                bail!("compaction trigger must be manual or auto");
            }
            if compact.hook_event_name != event {
                bail!("compaction hook event changed during parsing");
            }
            let event = if event == "PreCompact" {
                CompactEvent::PreCompact
            } else {
                CompactEvent::PostCompact
            };
            let context_id =
                delivery_context_id(Some(&compact.turn_id), compact.agent_id.as_deref());
            Ok(CodexHookInput::Compact {
                event,
                session_id: compact.session_id,
                cwd: compact.cwd,
                context_id,
            })
        }
        other => bail!("unexpected hook event {other}"),
    }
}

pub fn rewrite_output(
    executable: &Path,
    call_id: &str,
    original_tool_input: &serde_json::Value,
) -> Result<PreToolUseOutput> {
    if call_id.is_empty()
        || !call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("invalid opaque call id");
    }
    let executable = executable
        .canonicalize()
        .with_context(|| format!("resolve Again executable {}", executable.display()))?;
    let executable = executable
        .to_str()
        .ok_or_else(|| anyhow!("Again executable path is not valid UTF-8"))?;
    if executable
        .chars()
        .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        bail!("Again executable path contains unsupported control characters");
    }
    let executable = format!("'{}'", executable.replace('\'', "'\\''"));
    let mut updated_input = original_tool_input
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("Bash tool_input must be an object"))?;
    updated_input.insert(
        "command".to_owned(),
        serde_json::Value::String(format!("{executable} exec --call {call_id}")),
    );
    Ok(PreToolUseOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "allow",
            updated_input: serde_json::Value::Object(updated_input),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn valid_input(command: &str) -> String {
        serde_json::json!({
            "session_id": "thr_123",
            "transcript_path": "/tmp/session.jsonl",
            "cwd": "/workspace",
            "hook_event_name": "PreToolUse",
            "model": "gpt-test",
            "permission_mode": "default",
            "turn_id": "turn_123",
            "tool_name": "Bash",
            "tool_use_id": "call_123",
            "tool_input": {"command": command}
        })
        .to_string()
    }

    #[test]
    fn parses_documented_pre_tool_use_shape() {
        let input = parse_input(valid_input("rg needle src").as_bytes()).unwrap();
        assert_eq!(input.command().unwrap(), "rg needle src");
        assert_eq!(input.session_id, "thr_123");
    }

    #[test]
    fn parses_compaction_events_without_tool_fields() {
        for (name, expected) in [
            ("PreCompact", CompactEvent::PreCompact),
            ("PostCompact", CompactEvent::PostCompact),
        ] {
            let encoded = serde_json::json!({
                "session_id": "thr_123",
                "transcript_path": null,
                "cwd": "/workspace",
                "hook_event_name": name,
                "model": "gpt-test",
                "trigger": "auto",
                "turn_id": "turn_123"
            })
            .to_string();
            assert_eq!(
                parse_hook_input(encoded.as_bytes()).unwrap(),
                CodexHookInput::Compact {
                    event: expected,
                    session_id: "thr_123".to_owned(),
                    cwd: "/workspace".to_owned(),
                    context_id: delivery_context_id(Some("turn_123"), None),
                }
            );
        }

        let schema_minimum = serde_json::json!({
            "session_id": "",
            "transcript_path": null,
            "cwd": "",
            "hook_event_name": "PostCompact",
            "model": "",
            "trigger": "manual",
            "turn_id": "",
            "agent_id": "agent-without-type"
        })
        .to_string();
        assert_eq!(
            parse_hook_input(schema_minimum.as_bytes()).unwrap(),
            CodexHookInput::Compact {
                event: CompactEvent::PostCompact,
                session_id: String::new(),
                cwd: String::new(),
                context_id: None,
            }
        );
    }

    #[test]
    fn delivery_context_separates_turns_root_and_subagents() {
        let root = delivery_context_id(Some("turn-a"), None).unwrap();
        let next_turn = delivery_context_id(Some("turn-b"), None).unwrap();
        let agent_a = delivery_context_id(Some("turn-a"), Some("agent-a")).unwrap();
        let agent_b = delivery_context_id(Some("turn-a"), Some("agent-b")).unwrap();
        assert_ne!(root, next_turn);
        assert_ne!(root, agent_a);
        assert_ne!(agent_a, agent_b);
        assert!(delivery_context_id(None, None).is_none());
        assert!(delivery_context_id(Some("turn-a"), Some("bad\nagent")).is_none());
    }

    #[test]
    fn only_the_current_exact_command_input_shape_is_rewrite_compatible() {
        let current = parse_input(valid_input("pwd").as_bytes()).unwrap();
        assert!(current.rewrite_compatible());

        let mut future: serde_json::Value = serde_json::from_str(&valid_input("pwd")).unwrap();
        future["tool_input"]["tty"] = serde_json::json!(true);
        let future = parse_input(future.to_string().as_bytes()).unwrap();
        assert!(!future.rewrite_compatible());
    }

    #[test]
    fn rejects_unknown_missing_and_incomplete_current_envelope_fields() {
        let mut unknown: serde_json::Value = serde_json::from_str(&valid_input("pwd")).unwrap();
        unknown["future_semantics"] = serde_json::json!(true);
        assert!(parse_input(unknown.to_string().as_bytes()).is_err());

        let mut missing: serde_json::Value = serde_json::from_str(&valid_input("pwd")).unwrap();
        missing.as_object_mut().unwrap().remove("turn_id");
        assert!(parse_input(missing.to_string().as_bytes()).is_err());

        let mut incomplete_agent: serde_json::Value =
            serde_json::from_str(&valid_input("pwd")).unwrap();
        incomplete_agent["agent_id"] = serde_json::json!("agent-a");
        assert!(parse_input(incomplete_agent.to_string().as_bytes()).is_err());
    }

    #[test]
    fn rejects_wrong_event_tool_and_oversized_input() {
        let wrong: serde_json::Value = serde_json::from_str(&valid_input("pwd")).unwrap();
        let mut wrong = wrong;
        wrong["tool_name"] = serde_json::json!("apply_patch");
        assert!(parse_input(wrong.to_string().as_bytes()).is_err());
        assert!(parse_input(vec![b'a'; 1024 * 1024 + 1].as_slice()).is_err());
    }

    #[test]
    fn rewrite_contains_only_executable_and_opaque_id() {
        let temp = TempDir::new().unwrap();
        let executable = temp.path().join("again executable");
        fs::write(&executable, b"binary").unwrap();
        let original = serde_json::json!({
            "command": "rg needle src",
            "yield-time_ms": 10_000,
            "max_output_chars": 20_000
        });
        let output = rewrite_output(&executable, "abc_123", &original).unwrap();
        let encoded = serde_json::to_value(output).unwrap();
        assert_eq!(encoded["hookSpecificOutput"]["permissionDecision"], "allow");
        let command = encoded["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.ends_with(" exec --call abc_123"));
        assert!(!command.contains("rg needle"));
        assert_eq!(
            encoded["hookSpecificOutput"]["updatedInput"]["yield-time_ms"],
            10_000
        );
        assert_eq!(
            encoded["hookSpecificOutput"]["updatedInput"]["max_output_chars"],
            20_000
        );
    }

    #[test]
    fn rewrite_rejects_shell_like_call_id() {
        let temp = TempDir::new().unwrap();
        let executable = temp.path().join("again");
        fs::write(&executable, b"binary").unwrap();
        assert!(
            rewrite_output(
                &executable,
                "x;curl bad",
                &serde_json::json!({"command": "pwd"})
            )
            .is_err()
        );
    }
}
