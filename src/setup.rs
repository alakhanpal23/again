//! Idempotent Codex hook installation and removal.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

const HOOK_SENTINEL: &str = "AGAIN_CODEX_HOOK_V1=1";
const SNAPSHOT_SCHEMA: &str = "again.codex-hook-snapshot.v1";

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

/// Installation state across the two Codex hook scopes. Consumers such as
/// `doctor` can surface an explicit warning when both are active.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexHookScopeStatus {
    pub global_path: PathBuf,
    pub project_path: PathBuf,
    pub global_installed: bool,
    pub project_installed: bool,
}

impl CodexHookScopeStatus {
    pub fn duplicate_again_hooks(&self) -> bool {
        self.global_path != self.project_path && self.global_installed && self.project_installed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HookSnapshot {
    schema: String,
    original: Vec<u8>,
    installed: Vec<u8>,
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

/// Inspect whether Again is active in each distinct Codex scope.
pub fn codex_hook_scope_status(
    global_path: &Path,
    project_path: &Path,
) -> Result<CodexHookScopeStatus> {
    Ok(CodexHookScopeStatus {
        global_path: global_path.to_path_buf(),
        project_path: project_path.to_path_buf(),
        global_installed: is_codex_hook_installed(global_path)?,
        project_installed: is_codex_hook_installed(project_path)?,
    })
}

pub fn install_codex_hook(path: &Path, executable: &Path, dry_run: bool) -> Result<HookChange> {
    let original_bytes = if path.exists() {
        Some(fs::read(path).with_context(|| format!("read {}", path.display()))?)
    } else {
        None
    };
    let existing_snapshot = read_snapshot(path)?;
    if original_bytes.is_none() && existing_snapshot.is_some() {
        bail!(
            "{} is missing while its Again restore snapshot remains; refusing to guess which state is authoritative",
            path.display()
        );
    }
    let mut document = read_document(path)?;
    let already_installed = document_contains_again_handler(&document);
    let original = serde_json::to_string_pretty(&document)? + "\n";
    remove_again_handlers(&mut document)?;
    add_again_handler(&mut document, executable)?;
    let rendered = serde_json::to_string_pretty(&document)? + "\n";
    let changed = original != rendered || !path.exists();
    if already_installed
        && let Some(snapshot) = existing_snapshot.as_ref()
        && original_bytes.as_deref() != Some(snapshot.installed.as_slice())
    {
        bail!(
            "{} changed since Again installed its handler; refusing to overwrite user-owned hook configuration",
            path.display()
        );
    }

    let backup = if changed && !dry_run {
        let backup = backup_existing(path)?;
        let snapshot = if !already_installed {
            original_bytes.as_ref().map(|bytes| HookSnapshot {
                schema: SNAPSHOT_SCHEMA.to_owned(),
                original: bytes.clone(),
                installed: rendered.as_bytes().to_vec(),
            })
        } else if let Some(mut snapshot) = existing_snapshot {
            snapshot.installed = rendered.as_bytes().to_vec();
            Some(snapshot)
        } else {
            None
        };
        if let Some(snapshot) = snapshot.as_ref() {
            write_snapshot(path, snapshot)?;
        }
        if let Err(error) = atomic_write(path, rendered.as_bytes()) {
            if snapshot.is_some() {
                let _ = fs::remove_file(snapshot_path(path));
            }
            return Err(error);
        }
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
    let current_bytes = if path.exists() {
        Some(fs::read(path).with_context(|| format!("read {}", path.display()))?)
    } else {
        None
    };
    let snapshot = read_snapshot(path)?;
    let mut document = read_document(path)?;
    let original = serde_json::to_string_pretty(&document)? + "\n";
    let removed = remove_again_handlers(&mut document)?;
    let delete_empty_scaffold = removed > 0 && is_empty_again_scaffold(&document);
    let restore_snapshot = if removed > 0 { snapshot.as_ref() } else { None };
    if let Some(snapshot) = restore_snapshot
        && current_bytes.as_deref() != Some(snapshot.installed.as_slice())
    {
        bail!(
            "{} changed since Again installed its handler; refusing to rewrite user-owned hook configuration",
            path.display()
        );
    }
    let rendered = if let Some(snapshot) = restore_snapshot {
        String::from_utf8(snapshot.original.clone())
            .map_err(|_| anyhow!("stored Again hook snapshot is not valid UTF-8 JSON"))?
    } else if delete_empty_scaffold {
        String::new()
    } else {
        serde_json::to_string_pretty(&document)? + "\n"
    };
    let changed = removed > 0;
    let backup = if changed && !dry_run {
        if restore_snapshot.is_some() {
            let backup = backup_existing(path)?;
            atomic_write(path, rendered.as_bytes())?;
            fs::remove_file(snapshot_path(path))
                .with_context(|| format!("remove Again hook snapshot for {}", path.display()))?;
            backup
        } else if delete_empty_scaffold {
            // This exact empty scaffold is what `read_document` creates when no
            // hooks file existed. Once Again's sole handler is gone, restoring
            // the pre-install state means removing the now-empty file.
            fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
            None
        } else {
            let backup = backup_existing(path)?;
            atomic_write(path, rendered.as_bytes())?;
            backup
        }
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

fn document_contains_again_handler(document: &Value) -> bool {
    document
        .pointer("/hooks/PreToolUse")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(|handler| handler.get("command").and_then(Value::as_str))
        .any(|command| command.contains(HOOK_SENTINEL))
}

fn is_empty_again_scaffold(document: &Value) -> bool {
    document
        == &json!({
            "description": "Local Codex lifecycle hooks. Unrelated entries are preserved by Again.",
            "hooks": { "PreToolUse": [] }
        })
}

pub fn is_codex_hook_installed(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let document = read_document(path)?;
    Ok(document_contains_again_handler(&document))
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

fn snapshot_path(path: &Path) -> PathBuf {
    path.with_extension("json.again-original-v1")
}

fn write_snapshot(path: &Path, snapshot: &HookSnapshot) -> Result<()> {
    let bytes = serde_json::to_vec(snapshot)?;
    atomic_write(&snapshot_path(path), &bytes)
}

fn read_snapshot(path: &Path) -> Result<Option<HookSnapshot>> {
    let path = snapshot_path(path);
    if !path.exists() {
        return Ok(None);
    }
    let snapshot: HookSnapshot = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    if snapshot.schema != SNAPSHOT_SCHEMA {
        bail!("{} is not an Again hook snapshot", path.display());
    }
    Ok(Some(snapshot))
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
    fn reinstalling_a_new_binary_keeps_byte_exact_restore_valid() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = b"{\n  \"description\": \"keep my formatting\",\n  \"hooks\": {}\n}\n";
        fs::write(&path, original).unwrap();
        let first = temp.path().join("again-one");
        let second = temp.path().join("again-two");
        fs::write(&first, b"one").unwrap();
        fs::write(&second, b"two").unwrap();

        install_codex_hook(&path, &first, false).unwrap();
        install_codex_hook(&path, &second, false).unwrap();
        remove_codex_hook(&path, false).unwrap();

        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!snapshot_path(&path).exists());
    }

    #[test]
    fn reinstall_refuses_user_edits_made_after_install() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, br#"{"hooks":{}}"#).unwrap();
        let executable = fake_executable(&temp);
        install_codex_hook(&path, &executable, false).unwrap();
        let mut current = fs::read_to_string(&path).unwrap();
        current.push(' ');
        fs::write(&path, current).unwrap();

        let error = install_codex_hook(&path, &executable, false).unwrap_err();
        assert!(error.to_string().contains("refusing to overwrite"));
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
        assert!(!path.exists(), "Again-only scaffold should be removed");
    }

    #[test]
    fn removal_keeps_an_existing_document_and_unrelated_hooks() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{"description":"user-owned","hooks":{"PreToolUse":[{"matcher":"apply_patch","hooks":[{"type":"command","command":"other"}]}]}}"#,
        )
        .unwrap();
        let executable = fake_executable(&temp);
        install_codex_hook(&path, &executable, false).unwrap();
        remove_codex_hook(&path, false).unwrap();
        assert!(path.exists());
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains("user-owned"));
        assert!(text.contains("other"));
        assert!(!text.contains(HOOK_SENTINEL));
    }

    #[test]
    fn removal_restores_user_hook_file_byte_for_byte() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = concat!(
            "{\n",
            "  \"hooks\" : { \"PreToolUse\" : [ { \"matcher\" : \"apply_patch\",",
            " \"hooks\" : [ { \"command\" : \"user hook\", \"type\" : \"command\" } ] } ] },\n",
            "  \"description\" : \"user-owned formatting stays intact\"\n",
            "}\n"
        )
        .as_bytes()
        .to_vec();
        fs::write(&path, &original).unwrap();

        install_codex_hook(&path, &fake_executable(&temp), false).unwrap();
        assert!(snapshot_path(&path).exists());
        remove_codex_hook(&path, false).unwrap();

        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!snapshot_path(&path).exists());
    }

    #[test]
    fn removal_of_default_again_scaffold_deletes_the_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        install_codex_hook(&path, &fake_executable(&temp), false).unwrap();
        assert!(path.exists());
        assert!(!snapshot_path(&path).exists());

        let removed = remove_codex_hook(&path, false).unwrap();
        assert!(removed.changed);
        assert!(!path.exists());
    }

    #[test]
    fn removal_refuses_to_rewrite_a_user_modified_installed_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(".codex/hooks.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\"description\":\"user-owned\",\"hooks\":{}}\n").unwrap();
        install_codex_hook(&path, &fake_executable(&temp), false).unwrap();
        let installed = fs::read(&path).unwrap();
        fs::write(&path, [installed.as_slice(), b"\n"].concat()).unwrap();

        let error = remove_codex_hook(&path, false).unwrap_err();
        assert!(error.to_string().contains("refusing to rewrite user-owned"));
        assert!(fs::read(&path).unwrap().ends_with(b"\n\n"));
        assert!(snapshot_path(&path).exists());
    }

    #[test]
    fn reports_duplicate_project_and_global_again_hooks() {
        let temp = TempDir::new().unwrap();
        let global = temp.path().join("global/hooks.json");
        let project = temp.path().join("project/.codex/hooks.json");
        let executable = fake_executable(&temp);
        install_codex_hook(&global, &executable, false).unwrap();
        install_codex_hook(&project, &executable, false).unwrap();

        let both = codex_hook_scope_status(&global, &project).unwrap();
        assert!(both.global_installed);
        assert!(both.project_installed);
        assert!(both.duplicate_again_hooks());

        remove_codex_hook(&project, false).unwrap();
        let global_only = codex_hook_scope_status(&global, &project).unwrap();
        assert!(global_only.global_installed);
        assert!(!global_only.project_installed);
        assert!(!global_only.duplicate_again_hooks());
    }

    #[test]
    fn identical_scope_paths_are_not_reported_as_duplicate() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("hooks.json");
        install_codex_hook(&path, &fake_executable(&temp), false).unwrap();
        let status = codex_hook_scope_status(&path, &path).unwrap();
        assert!(status.global_installed);
        assert!(status.project_installed);
        assert!(!status.duplicate_again_hooks());
    }
}
