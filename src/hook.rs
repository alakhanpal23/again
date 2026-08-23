//! Codex PreToolUse JSON adapter.
//!
//! The adapter follows the documented Codex hook contract. It deliberately emits no
//! decision for commands that are not eligible: this preserves Codex's normal approval
//! and sandbox behavior.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PreToolUseInput {
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: Option<String>,
    pub cwd: String,
    pub hook_event_name: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub permission_mode: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    pub tool_name: String,
    #[serde(default)]
    pub tool_use_id: Option<String>,
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
        self.tool_input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("Bash tool_input.command must be a string"))
    }
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
    pub updated_input: UpdatedInput,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UpdatedInput {
    pub command: String,
}

pub fn parse_input(mut reader: impl Read) -> Result<PreToolUseInput> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("read Codex hook input")?;
    if bytes.len() > 1024 * 1024 {
        bail!("Codex hook input exceeds 1 MiB safety limit");
    }
    let input: PreToolUseInput =
        serde_json::from_slice(&bytes).context("parse Codex PreToolUse JSON")?;
    input.command()?;
    Ok(input)
}

pub fn rewrite_output(executable: &Path, call_id: &str) -> Result<PreToolUseOutput> {
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
    Ok(PreToolUseOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "allow",
            updated_input: UpdatedInput {
                command: format!("{executable} exec --call {call_id}"),
            },
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
        let output = rewrite_output(&executable, "abc_123").unwrap();
        let encoded = serde_json::to_value(output).unwrap();
        assert_eq!(encoded["hookSpecificOutput"]["permissionDecision"], "allow");
        let command = encoded["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(command.ends_with(" exec --call abc_123"));
        assert!(!command.contains("rg needle"));
    }

    #[test]
    fn rewrite_rejects_shell_like_call_id() {
        let temp = TempDir::new().unwrap();
        let executable = temp.path().join("again");
        fs::write(&executable, b"binary").unwrap();
        assert!(rewrite_output(&executable, "x;curl bad").is_err());
    }
}
