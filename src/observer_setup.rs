//! Project-scoped installation of the observation-only Codex Brain hook.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

const MARKER: &str = "AGAIN_BRAIN_OBSERVER_V1=1 ";
const SNAPSHOT_SCHEMA: &str = "again.brain-observer-hook.v1";
const MAX_CONFIG_BYTES: usize = 128 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObserverHookChangeV1 {
    pub operation: &'static str,
    pub path: PathBuf,
    pub changed: bool,
    pub installed: bool,
    pub handler_preview: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverSnapshotV1 {
    schema: String,
    original: Option<String>,
    installed: String,
}

pub fn configure_codex_brain_hook_v1(
    workspace: &Path,
    executable: &Path,
    apply: bool,
    remove: bool,
) -> Result<ObserverHookChangeV1> {
    let workspace = fs::canonicalize(workspace)?;
    let codex_dir = workspace.join(".codex");
    let path = codex_dir.join("hooks.json");
    let snapshot_path = codex_dir.join(".again-brain-observer-v1.json");
    check_optional_directory(&codex_dir)?;
    let current = read_optional_text(&path, MAX_CONFIG_BYTES)?;
    let snapshot = read_optional_text(&snapshot_path, MAX_CONFIG_BYTES * 3)?
        .map(|text| serde_json::from_str::<ObserverSnapshotV1>(&text))
        .transpose()
        .context("parse Again Brain hook snapshot")?;
    if let Some(snapshot) = &snapshot {
        if snapshot.schema != SNAPSHOT_SCHEMA {
            bail!("Again Brain hook snapshot has an unknown schema");
        }
        if current.as_deref() != Some(snapshot.installed.as_str()) && current != snapshot.original {
            bail!(
                "Codex hooks changed since Again installed its observer; preserve user edits and inspect {}",
                path.display()
            );
        }
    }
    let installed = snapshot
        .as_ref()
        .is_some_and(|snapshot| current.as_deref() == Some(snapshot.installed.as_str()));
    if remove {
        let Some(snapshot) = snapshot else {
            if current.as_deref().is_some_and(contains_managed_hook) {
                bail!(
                    "Again Brain hook has no ownership snapshot; inspect {}",
                    path.display()
                );
            }
            return Ok(ObserverHookChangeV1 {
                operation: "remove",
                path,
                changed: false,
                installed: false,
                handler_preview: None,
            });
        };
        if apply {
            unreachable!("clap rejects --apply with --remove");
        }
        let changed = installed || snapshot_path.exists();
        if changed {
            match snapshot.original.as_deref() {
                Some(original) => atomic_write(&path, original.as_bytes())?,
                None => {
                    if path.exists() {
                        fs::remove_file(&path)?;
                    }
                }
            }
            fs::remove_file(&snapshot_path)?;
        }
        return Ok(ObserverHookChangeV1 {
            operation: "remove",
            path,
            changed,
            installed: false,
            handler_preview: None,
        });
    }

    if snapshot.is_none() && current.as_deref().is_some_and(contains_managed_hook) {
        bail!(
            "Again Brain hook has no ownership snapshot; inspect {}",
            path.display()
        );
    }
    let executable = fs::canonicalize(executable)
        .with_context(|| format!("resolve Again executable {}", executable.display()))?;
    let quoted = quote_shell_path(&executable)?;
    let command = format!("{MARKER}{quoted} brain observe-codex-hook");
    let mut document: Value = current
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .context("parse Codex hooks.json")?
        .unwrap_or_else(|| json!({"hooks":{}}));
    let hooks = document
        .as_object_mut()
        .ok_or_else(|| anyhow!("Codex hooks.json must be an object"))?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow!("Codex hooks must be an object"))?;
    let groups = hooks
        .entry("PostToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| anyhow!("Codex PostToolUse hooks must be an array"))?;
    for group in groups.iter_mut() {
        let handlers = group["hooks"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("Codex PostToolUse group has no handlers"))?;
        handlers.retain(|handler| !is_managed_handler(handler));
    }
    groups.retain(|group| {
        group["hooks"]
            .as_array()
            .is_some_and(|hooks| !hooks.is_empty())
    });
    let handler = json!({
        "matcher":"^(Bash|apply_patch)$",
        "hooks":[{"type":"command","command":command,"async":true,"timeout":30}]
    });
    groups.push(handler.clone());
    let rendered = serde_json::to_string_pretty(&document)? + "\n";
    if rendered.len() > MAX_CONFIG_BYTES {
        bail!("Codex hooks.json exceeds the Again setup size limit");
    }
    let changed = current.as_deref() != Some(rendered.as_str());
    if apply && changed {
        let original = snapshot.map_or_else(|| current.clone(), |snapshot| snapshot.original);
        let new_snapshot = ObserverSnapshotV1 {
            schema: SNAPSHOT_SCHEMA.to_owned(),
            original,
            installed: rendered.clone(),
        };
        fs::create_dir_all(&codex_dir)?;
        check_optional_directory(&codex_dir)?;
        atomic_write(&snapshot_path, &serde_json::to_vec(&new_snapshot)?)?;
        atomic_write(&path, rendered.as_bytes())?;
    }
    Ok(ObserverHookChangeV1 {
        operation: if apply { "apply" } else { "preview" },
        path,
        changed,
        installed: apply || installed,
        handler_preview: (!apply).then(|| handler.to_string()),
    })
}

fn is_managed_handler(value: &Value) -> bool {
    value["command"]
        .as_str()
        .is_some_and(|command| command.starts_with(MARKER))
}

fn contains_managed_hook(text: &str) -> bool {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|document| document["hooks"]["PostToolUse"].as_array().cloned())
        .is_some_and(|groups| {
            groups.iter().any(|group| {
                group["hooks"]
                    .as_array()
                    .is_some_and(|hooks| hooks.iter().any(is_managed_handler))
            })
        })
}

fn quote_shell_path(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow!("Again executable path is not valid UTF-8"))?;
    if value.chars().any(char::is_control) {
        bail!("Again executable path contains a control character");
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn check_optional_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            bail!(
                "Codex configuration directory is not a real directory: {}",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn read_optional_text(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            bail!(
                "Codex configuration is not a regular file: {}",
                path.display()
            )
        }
        Ok(meta) if meta.len() > max_bytes as u64 => {
            bail!("Codex configuration exceeds the Again setup size limit")
        }
        Ok(_) => fs::read_to_string(path)
            .map(Some)
            .with_context(|| format!("read {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("hook path has no parent"))?;
    check_optional_directory(parent)?;
    let staged = parent.join(format!(".again-brain-{}.tmp", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&staged, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(staged);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_apply_and_remove_restore_existing_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let codex = dir.path().join(".codex");
        fs::create_dir(&codex).unwrap();
        let path = codex.join("hooks.json");
        let original = "{\"hooks\":{\"PostToolUse\":[{\"matcher\":\"^Bash$\",\"hooks\":[{\"type\":\"command\",\"command\":\"other\"}]}]}}\n";
        fs::write(&path, original).unwrap();
        let executable = dir.path().join("again");
        fs::write(&executable, "binary").unwrap();

        let preview = configure_codex_brain_hook_v1(dir.path(), &executable, false, false).unwrap();
        assert_eq!(preview.operation, "preview");
        assert!(preview.changed);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(!codex.join(".again-brain-observer-v1.json").exists());

        let applied = configure_codex_brain_hook_v1(dir.path(), &executable, true, false).unwrap();
        assert!(applied.installed);
        let installed = fs::read_to_string(&path).unwrap();
        let document: Value = serde_json::from_str(&installed).unwrap();
        let groups = document["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["hooks"][0]["command"], "other");
        assert_eq!(groups[1]["matcher"], "^(Bash|apply_patch)$");
        assert_eq!(groups[1]["hooks"][0]["async"], true);
        assert!(
            !configure_codex_brain_hook_v1(dir.path(), &executable, true, false)
                .unwrap()
                .changed
        );

        let removed = configure_codex_brain_hook_v1(dir.path(), &executable, false, true).unwrap();
        assert!(removed.changed);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(!codex.join(".again-brain-observer-v1.json").exists());
    }

    #[test]
    fn refuses_modified_hook_and_symlinked_directory() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("again");
        fs::write(&executable, "binary").unwrap();
        configure_codex_brain_hook_v1(dir.path(), &executable, true, false).unwrap();
        let path = dir.path().join(".codex/hooks.json");
        fs::write(&path, "{\"hooks\":{}}\n").unwrap();
        assert!(configure_codex_brain_hook_v1(dir.path(), &executable, false, true).is_err());
        assert!(configure_codex_brain_hook_v1(dir.path(), &executable, true, false).is_err());

        let other = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path().join(".codex"), other.path().join(".codex"))
                .unwrap();
            assert!(
                configure_codex_brain_hook_v1(other.path(), &executable, false, false).is_err()
            );
        }
    }
}
