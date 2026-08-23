//! Idempotent Codex hook installation and removal.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

const HOOK_SENTINEL: &str = "AGAIN_CODEX_HOOK_V1=1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupScope {
    Global,
    Project,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookChange {
    pub path: PathBuf,
    pub changed: bool,
    pub backup: Option<PathBuf>,
    pub rendered: String,
}

pub fn hook_path(scope: SetupScope, project: Option<&Path>) -> Result<PathBuf> {
    match scope {
        SetupScope::Global => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or_else(|| anyhow!("HOME is unavailable"))?;
            Ok(home.join(".codex/hooks.json"))
        }
        SetupScope::Project => {
            let project =
                project.ok_or_else(|| anyhow!("project scope requires a project path"))?;
            Ok(project.join(".codex/hooks.json"))
        }
    }
}

pub fn install_codex_hook(path: &Path, executable: &Path, dry_run: bool) -> Result<HookChange> {
    let mut document = read_document(path)?;
    let original = serde_json::to_string_pretty(&document)? + "\n";
    remove_again_handlers(&mut document)?;
    add_again_handler(&mut document, executable)?;
    let rendered = serde_json::to_string_pretty(&document)? + "\n";
    let changed = original != rendered || !path.exists();

    let backup = if changed && !dry_run {
        let backup = backup_existing(path)?;
        atomic_write(path, rendered.as_bytes())?;
        backup
    } else {
        None
    };
    Ok(HookChange {
        path: path.to_path_buf(),
        changed,
        backup,
        rendered,
    })
}

pub fn remove_codex_hook(path: &Path, dry_run: bool) -> Result<HookChange> {
    let mut document = read_document(path)?;
    let original = serde_json::to_string_pretty(&document)? + "\n";
    let removed = remove_again_handlers(&mut document)?;
    let rendered = serde_json::to_string_pretty(&document)? + "\n";
    let changed = removed > 0;
    let backup = if changed && !dry_run {
        let backup = backup_existing(path)?;
        atomic_write(path, rendered.as_bytes())?;
        backup
    } else {
        None
    };
    Ok(HookChange {
        path: path.to_path_buf(),
        changed: changed && original != rendered,
        backup,
        rendered,
    })
}

pub fn is_codex_hook_installed(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let document = read_document(path)?;
    Ok(document
        .pointer("/hooks/PreToolUse")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(|handler| handler.get("command").and_then(Value::as_str))
        .any(|command| command.contains(HOOK_SENTINEL)))
}

fn read_document(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({
            "description": "Local Codex lifecycle hooks. Unrelated entries are preserved by Again.",
            "hooks": {}
        }));
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {} as JSON", path.display()))?;
    if !value.is_object() {
        bail!("{} must contain a JSON object", path.display());
    }
    Ok(value)
}

fn hooks_object(document: &mut Value) -> Result<&mut Map<String, Value>> {
    let root = document
        .as_object_mut()
        .ok_or_else(|| anyhow!("hooks document must be an object"))?;
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    hooks
        .as_object_mut()
        .ok_or_else(|| anyhow!("hooks field must be an object"))
}

fn add_again_handler(document: &mut Value, executable: &Path) -> Result<()> {
    let executable = executable
        .canonicalize()
        .with_context(|| format!("resolve Again executable {}", executable.display()))?;
    let command = format!("{HOOK_SENTINEL} {} hook", shell_quote_path(&executable)?);
    let hooks = hooks_object(document)?;
    let entries = hooks.entry("PreToolUse").or_insert_with(|| json!([]));
    let entries = entries
        .as_array_mut()
        .ok_or_else(|| anyhow!("hooks.PreToolUse must be an array"))?;
    entries.push(json!({
        "matcher": "^Bash$",
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": 5,
            "statusMessage": "Again: checking exact reuse"
        }]
    }));
    Ok(())
}

fn remove_again_handlers(document: &mut Value) -> Result<usize> {
    let hooks = hooks_object(document)?;
    let Some(entries) = hooks.get_mut("PreToolUse") else {
        return Ok(0);
    };
    let entries = entries
        .as_array_mut()
        .ok_or_else(|| anyhow!("hooks.PreToolUse must be an array"))?;
    let mut removed = 0;
    entries.retain_mut(|group| {
        let Some(handlers) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let before = handlers.len();
        handlers.retain(|handler| {
            !handler
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| command.contains(HOOK_SENTINEL))
        });
        removed += before - handlers.len();
        !handlers.is_empty()
    });
    Ok(removed)
}

fn shell_quote_path(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow!("Again executable path is not valid UTF-8"))?;
    if value
        .chars()
        .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        bail!("Again executable path contains unsupported control characters");
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn backup_existing(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let backup = path.with_extension(format!("json.again-backup-{}", Uuid::new_v4().simple()));
    fs::copy(path, &backup)
        .with_context(|| format!("back up {} to {}", path.display(), backup.display()))?;
    set_private_file(&backup)?;
    Ok(Some(backup))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("hook path has no parent"))?;
    fs::create_dir_all(parent)?;
    set_private_dir(parent)?;
    let staged = parent.join(format!(".hooks.{}.tmp", Uuid::new_v4().simple()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    set_private_file(&staged)?;
    fs::rename(&staged, path)?;
    set_private_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fake_executable(temp: &TempDir) -> PathBuf {
        let executable = temp.path().join("again binary");
        fs::write(&executable, b"binary").unwrap();
        executable
    }

    #[test]
    fn install_is_idempotent_and_preserves_unrelated_hooks() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"apply_patch","hooks":[{"type":"command","command":"other"}]}]}}"#,
        )
        .unwrap();
        let executable = fake_executable(&temp);
        let first = install_codex_hook(&path, &executable, false).unwrap();
        assert!(first.changed);
        let second = install_codex_hook(&path, &executable, false).unwrap();
        assert!(!second.changed);
        assert!(second.rendered.contains("other"));
        assert_eq!(second.rendered.matches(HOOK_SENTINEL).count(), 1);
    }

    #[test]
    fn dry_run_does_not_write() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        let executable = fake_executable(&temp);
        let change = install_codex_hook(&path, &executable, true).unwrap();
        assert!(change.changed);
        assert!(!path.exists());
        assert!(change.rendered.contains(HOOK_SENTINEL));
    }

    #[test]
    fn removal_preserves_other_handlers() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        let executable = fake_executable(&temp);
        install_codex_hook(&path, &executable, false).unwrap();
        let removed = remove_codex_hook(&path, false).unwrap();
        assert!(removed.changed);
        assert!(!removed.rendered.contains(HOOK_SENTINEL));
    }
}
