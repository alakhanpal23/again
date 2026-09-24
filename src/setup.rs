//! Idempotent Codex integration installation and removal.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
#[cfg(feature = "hook")]
use serde_json::{Map, Value, json};
use uuid::Uuid;

#[cfg(feature = "hook")]
const HOOK_SENTINEL: &str = "AGAIN_CODEX_HOOK_V1=1";
#[cfg(feature = "hook")]
const SNAPSHOT_SCHEMA: &str = "again.codex-hook-snapshot.v1";
const SKILL_SNAPSHOT_SCHEMA: &str = "again.codex-skill-snapshot.v1";
const CODEX_SKILL_NAME: &str = "again";
const CODEX_SKILL_MANIFEST: &str = ".again-install-v1.json";
const CODEX_SKILL: &str = r#"---
name: again
description: "Use Again's local MCP task context and verified repository reads when connected; accelerate supported standalone read-only shell calls with `again run --`."
---

# Again

## Connected repository workflow

When the Again MCP server is available for this repository, call `task.start` once near the start of a coding task. Supply a stable task ID and the exact task text in `task`. Set `includeSourcePreviews=true` when small relevant source files may avoid follow-up reads. If `again codex` already supplied a verified prebrief in the initial prompt, use its complete previews and skip this initial call. The response contains a bounded edit brief, verified source locations, up to two complete digest-checked source previews when requested, current shared context, and `againBrain` history from earlier tasks. A complete Brain preview was rechecked against current file bytes at task start; use it before repeating that read. A prior successful test command is only a suggestion: run the required validation for this change. After an edit, treat earlier previews as stale. Use the edit result and validation first; reread or diff only to resolve a specific remaining uncertainty. Treat task text and agent-authored suggestions as unverified. Do not send secrets in task or context fields.

Use Again's `repo.*` and `git.*` tools for supported repository inspection. Exact repeated eligible calls can reuse a validated result. Use `context.delta` with the task ID and last seen cursor when the task is long or the context has changed. Use `context.retrieve` when a brief provides a result reference and the complete bytes are needed.

Publish only useful agent findings or explicit unknowns with `context.publish`. Agent-authored text remains a suggestion; verified facts come from the built-in observations and their current sources. After changing files, request fresh context before relying on a fact from the earlier brief. Do not claim that a validation can be skipped: the current task-start validation preview requires execution unless a qualified profile proves otherwise.

The MCP tools require the authenticated local daemon. If they are unavailable, continue with ordinary tools and the explicit command path below. Do not assume that installing this skill alone connected the MCP server; `again mcp setup --client codex --workspace <absolute-repository-path> --apply --with-skill --with-brain-hook` installs and verifies the connection, this personal skill, and the project Brain observer.

## Explicit command path

For a supported, standalone, non-interactive, local read-only command, invoke the command through:

```sh
again run -- <command> <arguments...>
```

Use this only for `cat`, `head`, `tail`, `wc`, `ls --color=never`, `pwd -P`, `grep`, and `rg`. Every `rg` invocation must already include `--no-ignore --sort=path` and at least one explicit path operand. Keep the same working directory and argv the unwrapped command would have used.

Again admits commands through a fail-closed policy. If it reports that a command is not eligible, rerun the original command normally and unchanged. Do not weaken or reshape the command merely to make it cacheable.

If the complete output of the exact command is already visible in this same active context and you only need to prove that its inputs and stored result are unchanged, invoke:

```sh
again reference -- <command> <arguments...>
```

This emits a small content-addressed JSON reference after the same input, runtime, executable, proof, and blob checks. It never executes the command on a miss. If it misses, use `again run --` to obtain the real output. Do not use a reference after context compaction, across agents or conversations, or whenever you need the output bytes again; use `again show <result_id>` to retrieve the exact stored streams explicitly.

Never wrap shell composition or expansion, including pipes, redirects, `&&`, substitutions, globs, or environment assignments. Never wrap a command that mutates state, uses the network, consumes stdin, needs a TTY, or reads outside the current repository. Never invoke Again's hidden `hook` or `exec` subcommands.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupScope {
    Global,
    Project,
}

#[cfg(feature = "hook")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookChange {
    pub path: PathBuf,
    pub changed: bool,
    pub backup: Option<PathBuf>,
    pub rendered: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillChange {
    /// The `SKILL.md` file managed by this operation.
    pub path: PathBuf,
    pub changed: bool,
    /// The skill text that would remain after the operation. Empty on removal.
    pub rendered: String,
}

/// Installation state across the personal and repository Codex skill scopes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexSkillScopeStatus {
    pub personal_dir: PathBuf,
    pub project_dir: PathBuf,
    pub personal_installed: bool,
    pub project_installed: bool,
}

impl CodexSkillScopeStatus {
    pub fn duplicate_again_skills(&self) -> bool {
        self.personal_dir != self.project_dir && self.personal_installed && self.project_installed
    }
}

#[cfg(feature = "hook")]
/// Installation state across the two Codex hook scopes. Consumers such as
/// `doctor` can surface an explicit warning when both are active.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexHookScopeStatus {
    pub global_path: PathBuf,
    pub project_path: PathBuf,
    pub global_installed: bool,
    pub project_installed: bool,
}

#[cfg(feature = "hook")]
impl CodexHookScopeStatus {
    pub fn duplicate_again_hooks(&self) -> bool {
        self.global_path != self.project_path && self.global_installed && self.project_installed
    }
}

#[cfg(feature = "hook")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HookSnapshot {
    schema: String,
    original: Vec<u8>,
    installed: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillSnapshot {
    schema: String,
    skill_name: String,
    installed: String,
}

/// Return the documented Codex skill directory for one setup scope.
///
/// `SetupScope::Global` means the current user's personal skill scope. Project
/// callers should pass the repository root rather than an arbitrary child
/// working directory.
pub fn codex_skill_dir(scope: SetupScope, project: Option<&Path>) -> Result<PathBuf> {
    match scope {
        SetupScope::Global => {
            let home = std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| anyhow!("HOME is unavailable"))?;
            Ok(codex_personal_skill_dir(&home))
        }
        SetupScope::Project => {
            let project =
                project.ok_or_else(|| anyhow!("project scope requires a repository path"))?;
            Ok(project
                .join(".agents")
                .join("skills")
                .join(CODEX_SKILL_NAME))
        }
    }
}

/// Pure path helper used by callers that already resolved a user's home.
pub fn codex_personal_skill_dir(home: &Path) -> PathBuf {
    home.join(".agents").join("skills").join(CODEX_SKILL_NAME)
}

pub fn codex_skill_scope_status(
    personal_dir: &Path,
    project_dir: &Path,
) -> Result<CodexSkillScopeStatus> {
    Ok(CodexSkillScopeStatus {
        personal_dir: personal_dir.to_path_buf(),
        project_dir: project_dir.to_path_buf(),
        personal_installed: is_codex_skill_installed(personal_dir)?,
        project_installed: is_codex_skill_installed(project_dir)?,
    })
}

/// Install the instruction-only Again skill without changing Codex hooks or
/// configuration. Existing unowned `SKILL.md` files are never overwritten.
pub fn install_codex_skill(skill_dir: &Path, dry_run: bool) -> Result<SkillChange> {
    validate_skill_location(skill_dir)?;
    let skill_path = skill_dir.join("SKILL.md");
    let manifest_path = skill_dir.join(CODEX_SKILL_MANIFEST);
    let current = read_optional_regular_file(&skill_path, "Codex skill")?;
    let manifest_bytes = read_optional_regular_file(&manifest_path, "Again skill snapshot")?;
    let snapshot = manifest_bytes
        .as_deref()
        .map(|bytes| parse_skill_snapshot(&manifest_path, bytes))
        .transpose()?;

    match (&current, &snapshot) {
        (Some(_), None) => bail!(
            "{} is not owned by Again; refusing to overwrite it",
            skill_path.display()
        ),
        (None, Some(_)) => bail!(
            "{} is missing while its Again ownership snapshot remains; refusing to guess which state is authoritative",
            skill_path.display()
        ),
        (Some(current), Some(snapshot)) if current.as_slice() != snapshot.installed.as_bytes() => {
            bail!(
                "{} changed since Again installed it; refusing to overwrite user-owned changes",
                skill_path.display()
            )
        }
        _ => {}
    }

    let rendered = CODEX_SKILL.to_owned();
    let changed = current.as_deref() != Some(rendered.as_bytes());
    if !changed || dry_run {
        return Ok(SkillChange {
            path: skill_path,
            changed,
            rendered,
        });
    }

    let directory_existed = skill_dir.exists();
    fs::create_dir_all(skill_dir)
        .with_context(|| format!("create Codex skill directory {}", skill_dir.display()))?;
    validate_skill_location(skill_dir)?;

    let previous_skill = current;
    let previous_manifest = manifest_bytes;
    let new_snapshot = SkillSnapshot {
        schema: SKILL_SNAPSHOT_SCHEMA.to_owned(),
        skill_name: CODEX_SKILL_NAME.to_owned(),
        installed: rendered.clone(),
    };
    let new_manifest = serde_json::to_vec_pretty(&new_snapshot)?;

    atomic_write_skill_file(&skill_path, rendered.as_bytes())?;
    if let Err(error) = atomic_write_skill_file(&manifest_path, &new_manifest) {
        rollback_skill_install(
            &skill_path,
            &manifest_path,
            previous_skill.as_deref(),
            previous_manifest.as_deref(),
        );
        if !directory_existed {
            let _ = fs::remove_dir(skill_dir);
        }
        return Err(error).context("write Again skill ownership snapshot");
    }

    Ok(SkillChange {
        path: skill_path,
        changed: true,
        rendered,
    })
}

/// Remove only a byte-identical skill previously installed by Again.
/// Unrelated files in the skill directory are preserved.
pub fn remove_codex_skill(skill_dir: &Path, dry_run: bool) -> Result<SkillChange> {
    validate_skill_location(skill_dir)?;
    let skill_path = skill_dir.join("SKILL.md");
    let manifest_path = skill_dir.join(CODEX_SKILL_MANIFEST);
    let current = read_optional_regular_file(&skill_path, "Codex skill")?;
    let manifest_bytes = read_optional_regular_file(&manifest_path, "Again skill snapshot")?;

    match (current.as_ref(), manifest_bytes.as_ref()) {
        (None, None) => {
            return Ok(SkillChange {
                path: skill_path,
                changed: false,
                rendered: String::new(),
            });
        }
        (Some(_), None) => bail!(
            "{} is not owned by Again; refusing to remove it",
            skill_path.display()
        ),
        (None, Some(_)) => bail!(
            "{} is missing while its Again ownership snapshot remains; refusing to remove partial state",
            skill_path.display()
        ),
        (Some(_), Some(_)) => {}
    }

    let current = current.expect("checked above");
    let manifest_bytes = manifest_bytes.expect("checked above");
    let snapshot = parse_skill_snapshot(&manifest_path, &manifest_bytes)?;
    if current.as_slice() != snapshot.installed.as_bytes() {
        bail!(
            "{} changed since Again installed it; refusing to remove user-owned changes",
            skill_path.display()
        );
    }
    let rendered = String::new();
    if dry_run {
        return Ok(SkillChange {
            path: skill_path,
            changed: true,
            rendered,
        });
    }

    transactional_remove_skill(&skill_path, &manifest_path)?;
    let _ = fs::remove_dir(skill_dir);

    Ok(SkillChange {
        path: skill_path,
        changed: true,
        rendered,
    })
}

pub fn is_codex_skill_installed(skill_dir: &Path) -> Result<bool> {
    validate_skill_location(skill_dir)?;
    let skill_path = skill_dir.join("SKILL.md");
    let manifest_path = skill_dir.join(CODEX_SKILL_MANIFEST);
    let current = read_optional_regular_file(&skill_path, "Codex skill")?;
    let manifest = read_optional_regular_file(&manifest_path, "Again skill snapshot")?;
    match (current, manifest) {
        (None, None) | (Some(_), None) => Ok(false),
        (None, Some(_)) => bail!(
            "{} is missing while its Again ownership snapshot remains",
            skill_path.display()
        ),
        (Some(current), Some(manifest)) => {
            let snapshot = parse_skill_snapshot(&manifest_path, &manifest)?;
            if current.as_slice() != snapshot.installed.as_bytes() {
                bail!("{} differs from its Again snapshot", skill_path.display());
            }
            Ok(true)
        }
    }
}

fn validate_skill_location(skill_dir: &Path) -> Result<()> {
    // The managed layout is `<scope-root>/.agents/skills/again`. Refuse
    // symlinks or non-directories in its three installer-owned components so
    // a repository cannot redirect setup outside its selected scope.
    for component in skill_dir.ancestors().take(3) {
        match fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => bail!(
                "{} is a symlink; refusing to manage an indirect Codex skill directory",
                component.display()
            ),
            Ok(metadata) if !metadata.is_dir() => {
                bail!("{} is not a directory", component.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", component.display()));
            }
        }
    }
    Ok(())
}

fn read_optional_regular_file(path: &Path, description: &str) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("{} {} is a symlink", description, path.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("{} {} is not a regular file", description, path.display())
        }
        Ok(_) => fs::read(path)
            .with_context(|| format!("read {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn parse_skill_snapshot(path: &Path, bytes: &[u8]) -> Result<SkillSnapshot> {
    let snapshot: SkillSnapshot =
        serde_json::from_slice(bytes).with_context(|| format!("parse {}", path.display()))?;
    if snapshot.schema != SKILL_SNAPSHOT_SCHEMA || snapshot.skill_name != CODEX_SKILL_NAME {
        bail!(
            "{} is not an Again skill ownership snapshot",
            path.display()
        );
    }
    Ok(snapshot)
}

fn rollback_skill_install(
    skill_path: &Path,
    manifest_path: &Path,
    previous_skill: Option<&[u8]>,
    previous_manifest: Option<&[u8]>,
) {
    match previous_skill {
        Some(bytes) => {
            let _ = atomic_write_skill_file(skill_path, bytes);
        }
        None => {
            let _ = fs::remove_file(skill_path);
        }
    }
    match previous_manifest {
        Some(bytes) => {
            let _ = atomic_write_skill_file(manifest_path, bytes);
        }
        None => {
            let _ = fs::remove_file(manifest_path);
        }
    }
}

fn transactional_remove_skill(skill_path: &Path, manifest_path: &Path) -> Result<()> {
    let parent = skill_path
        .parent()
        .ok_or_else(|| anyhow!("Codex skill path has no parent"))?;
    let nonce = Uuid::new_v4().simple();
    let staged_skill = parent.join(format!(".again-remove-skill-{nonce}"));
    let staged_manifest = parent.join(format!(".again-remove-manifest-{nonce}"));

    fs::rename(skill_path, &staged_skill).with_context(|| {
        format!(
            "stage {} for ownership-checked removal",
            skill_path.display()
        )
    })?;
    if let Err(error) = fs::rename(manifest_path, &staged_manifest) {
        fs::rename(&staged_skill, skill_path).with_context(|| {
            format!(
                "restore {} after removal staging failed: {error}",
                skill_path.display()
            )
        })?;
        return Err(error).with_context(|| format!("stage {}", manifest_path.display()));
    }

    fs::remove_file(&staged_manifest)
        .with_context(|| format!("remove {}", staged_manifest.display()))?;
    fs::remove_file(&staged_skill).with_context(|| format!("remove {}", staged_skill.display()))?;
    Ok(())
}

fn atomic_write_skill_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Codex skill path has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create Codex skill directory {}", parent.display()))?;
    let staged = parent.join(format!(".again-skill-{}.tmp", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .with_context(|| format!("create {}", staged.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        set_skill_file_permissions(&staged)?;
        fs::rename(&staged, path)
            .with_context(|| format!("install Codex skill file {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

#[cfg(unix)]
fn set_skill_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_skill_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(feature = "hook")]
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
#[cfg(feature = "hook")]
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

#[cfg(feature = "hook")]
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
    let already_installed = document_contains_any_again_handler(&document);
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

#[cfg(feature = "hook")]
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

#[cfg(feature = "hook")]
fn event_contains_again_handler(document: &Value, event: &str) -> bool {
    document
        .pointer(&format!("/hooks/{event}"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(|handler| handler.get("command").and_then(Value::as_str))
        .any(|command| command.contains(HOOK_SENTINEL))
}

#[cfg(feature = "hook")]
fn document_contains_any_again_handler(document: &Value) -> bool {
    ["PreToolUse", "PreCompact", "PostCompact"]
        .iter()
        .any(|event| event_contains_again_handler(document, event))
}

#[cfg(feature = "hook")]
fn document_contains_complete_again_hook(document: &Value) -> bool {
    ["PreToolUse", "PreCompact", "PostCompact"]
        .iter()
        .all(|event| event_contains_again_handler(document, event))
}

#[cfg(feature = "hook")]
fn is_empty_again_scaffold(document: &Value) -> bool {
    document
        == &json!({
            "description": "Local Codex lifecycle hooks. Unrelated entries are preserved by Again.",
            "hooks": {}
        })
}

#[cfg(feature = "hook")]
pub fn is_codex_hook_installed(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let document = read_document(path)?;
    Ok(document_contains_complete_again_hook(&document))
}

#[cfg(feature = "hook")]
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

#[cfg(feature = "hook")]
fn hooks_object(document: &mut Value) -> Result<&mut Map<String, Value>> {
    let root = document
        .as_object_mut()
        .ok_or_else(|| anyhow!("hooks document must be an object"))?;
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    hooks
        .as_object_mut()
        .ok_or_else(|| anyhow!("hooks field must be an object"))
}

#[cfg(feature = "hook")]
fn add_again_handler(document: &mut Value, executable: &Path) -> Result<()> {
    let executable = executable
        .canonicalize()
        .with_context(|| format!("resolve Again executable {}", executable.display()))?;
    let command = format!("{HOOK_SENTINEL} {} hook", shell_quote_path(&executable)?);
    let hooks = hooks_object(document)?;
    add_again_event_handler(
        hooks,
        "PreToolUse",
        "^Bash$",
        &command,
        "Again: checking exact reuse",
    )?;
    for event in ["PreCompact", "PostCompact"] {
        add_again_event_handler(
            hooks,
            event,
            "^(manual|auto)$",
            &command,
            "Again: inactive lifecycle compatibility no-op",
        )?;
    }
    Ok(())
}

#[cfg(feature = "hook")]
fn add_again_event_handler(
    hooks: &mut Map<String, Value>,
    event: &str,
    matcher: &str,
    command: &str,
    status_message: &str,
) -> Result<()> {
    let entries = hooks.entry(event).or_insert_with(|| json!([]));
    let entries = entries
        .as_array_mut()
        .ok_or_else(|| anyhow!("hooks.{event} must be an array"))?;
    entries.push(json!({
        "matcher": matcher,
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": 5,
            "statusMessage": status_message
        }]
    }));
    Ok(())
}

#[cfg(feature = "hook")]
fn remove_again_handlers(document: &mut Value) -> Result<usize> {
    let hooks = hooks_object(document)?;
    let mut removed = 0;
    for event in ["PreToolUse", "PreCompact", "PostCompact"] {
        let remove_event = if let Some(entries) = hooks.get_mut(event) {
            let entries = entries
                .as_array_mut()
                .ok_or_else(|| anyhow!("hooks.{event} must be an array"))?;
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
            entries.is_empty()
        } else {
            false
        };
        if remove_event {
            hooks.remove(event);
        }
    }
    Ok(removed)
}

#[cfg(feature = "hook")]
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

#[cfg(feature = "hook")]
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

#[cfg(feature = "hook")]
fn snapshot_path(path: &Path) -> PathBuf {
    path.with_extension("json.again-original-v1")
}

#[cfg(feature = "hook")]
fn write_snapshot(path: &Path, snapshot: &HookSnapshot) -> Result<()> {
    let bytes = serde_json::to_vec(snapshot)?;
    atomic_write(&snapshot_path(path), &bytes)
}

#[cfg(feature = "hook")]
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

#[cfg(feature = "hook")]
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

#[cfg(all(feature = "hook", unix))]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(all(feature = "hook", not(unix)))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(feature = "hook", unix))]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(all(feature = "hook", not(unix)))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}
#[cfg(all(test, feature = "hook"))]
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
        assert_eq!(second.rendered.matches(HOOK_SENTINEL).count(), 3);
        assert!(second.rendered.contains("PreCompact"));
        assert!(second.rendered.contains("PostCompact"));
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
