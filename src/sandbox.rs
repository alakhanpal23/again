//! macOS Seatbelt confinement planning for admitted read-only commands.
//!
//! This module never falls back to unconfined execution. Callers must inspect
//! [`preflight`] (or handle [`SandboxError::Unavailable`]) before using a plan.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use blake3::Hasher;
use thiserror::Error;

use crate::policy::{AccessPlan, AccessScope};

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
pub const SYSTEM_PROFILE: &str = "/System/Library/Sandbox/Profiles/system.sb";

/// Runtime support for Apple's private Seatbelt profile interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxAvailability {
    Available {
        sandbox_exec: PathBuf,
        system_profile: PathBuf,
    },
    UnsupportedPlatform {
        target_os: &'static str,
    },
    MissingSandboxExec {
        path: PathBuf,
    },
    MissingSystemProfile {
        path: PathBuf,
    },
}

impl SandboxAvailability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

impl fmt::Display for SandboxAvailability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available { .. } => formatter.write_str("available"),
            Self::UnsupportedPlatform { target_os } => {
                write!(formatter, "unsupported platform `{target_os}`")
            }
            Self::MissingSandboxExec { path } => {
                write!(formatter, "missing sandbox-exec at `{}`", path.display())
            }
            Self::MissingSystemProfile { path } => {
                write!(formatter, "missing system.sb at `{}`", path.display())
            }
        }
    }
}

/// Check whether the host has the private macOS interfaces required by v0.
///
/// Availability is intentionally explicit because Apple may move or remove
/// `system.sb`; absence must disable reuse rather than silently run unconfined.
pub fn preflight() -> SandboxAvailability {
    #[cfg(not(target_os = "macos"))]
    {
        SandboxAvailability::UnsupportedPlatform {
            target_os: std::env::consts::OS,
        }
    }

    #[cfg(target_os = "macos")]
    {
        let sandbox_exec = PathBuf::from(SANDBOX_EXEC);
        let system_profile = PathBuf::from(SYSTEM_PROFILE);
        if !is_regular_executable(&sandbox_exec) {
            return SandboxAvailability::MissingSandboxExec { path: sandbox_exec };
        }
        if !fs::metadata(&system_profile).is_ok_and(|metadata| metadata.is_file())
            || File::open(&system_profile).is_err()
        {
            return SandboxAvailability::MissingSystemProfile {
                path: system_profile,
            };
        }
        SandboxAvailability::Available {
            sandbox_exec,
            system_profile,
        }
    }
}

/// A failure to apply Seatbelt even though its private files are installed.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SandboxProbeError {
    #[error("macOS sandbox is unavailable: {0}")]
    Unavailable(SandboxAvailability),

    #[error("failed to launch sandbox-exec ({kind}): {message}")]
    LaunchFailed {
        kind: io::ErrorKind,
        message: String,
    },

    #[error("sandbox-exec rejected the profile (status {status:?}): {stderr}")]
    Rejected { status: Option<i32>, stderr: String },
}

/// Prove that this process can apply a minimal Seatbelt profile at runtime.
///
/// This is deliberately separate from [`preflight`]: the binaries and private
/// profile may exist while a parent sandbox prevents nested Seatbelt application.
/// Callers should probe once per runtime environment and disable confined reuse on
/// any error. The probe executes only `/usr/bin/true`, with no workspace access.
pub fn probe_apply() -> Result<(), SandboxProbeError> {
    let availability = preflight();
    let sandbox_exec = match availability {
        SandboxAvailability::Available { sandbox_exec, .. } => sandbox_exec,
        unavailable => return Err(SandboxProbeError::Unavailable(unavailable)),
    };
    let rules = ReadRules::default();
    let profile = render_profile(Path::new("/usr/bin/true"), &rules).map_err(|error| {
        SandboxProbeError::LaunchFailed {
            kind: io::ErrorKind::InvalidInput,
            message: error.to_string(),
        }
    })?;
    let output = Command::new(sandbox_exec)
        .arg("-p")
        .arg(profile)
        .arg("/usr/bin/true")
        .output()
        .map_err(|source| SandboxProbeError::LaunchFailed {
            kind: source.kind(),
            message: source.to_string(),
        })?;
    classify_probe_output(
        output.status.success(),
        output.status.code(),
        &output.stderr,
    )
}

fn classify_probe_output(
    success: bool,
    status: Option<i32>,
    stderr: &[u8],
) -> Result<(), SandboxProbeError> {
    if success {
        Ok(())
    } else {
        Err(SandboxProbeError::Rejected {
            status,
            stderr: String::from_utf8_lossy(stderr).into_owned(),
        })
    }
}

/// A fully validated, deterministic invocation of `sandbox-exec`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPlan {
    sandbox_exec: PathBuf,
    executable: PathBuf,
    cwd: PathBuf,
    workspace: PathBuf,
    profile: String,
    profile_digest: String,
}

impl SandboxPlan {
    pub fn sandbox_exec(&self) -> &Path {
        &self.sandbox_exec
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Lower-case BLAKE3 hex over the exact profile passed to `sandbox-exec`.
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    /// Construct, but do not execute, the confined command.
    ///
    /// `args` excludes argv[0]. No shell is involved, and each original argument is
    /// passed as one opaque `OsString` after the canonical executable path.
    pub fn command(&self, args: &[OsString]) -> Command {
        let mut command = Command::new(&self.sandbox_exec);
        command
            .arg("-p")
            .arg(&self.profile)
            .arg(&self.executable)
            .args(args)
            .current_dir(&self.cwd);
        command
    }
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("macOS sandbox is unavailable: {0}")]
    Unavailable(SandboxAvailability),

    #[error("access plan must contain at least one scope")]
    EmptyAccessPlan,

    #[error("{kind} path is not canonical: supplied `{supplied}`, canonical `{canonical}`")]
    NonCanonicalPath {
        kind: &'static str,
        supplied: PathBuf,
        canonical: PathBuf,
    },

    #[error("workspace is not a directory: {0}")]
    WorkspaceNotDirectory(PathBuf),

    #[error("working directory is not a directory: {0}")]
    WorkingDirectoryNotDirectory(PathBuf),

    #[error("executable is not an executable regular file: {0}")]
    ExecutableNotRegular(PathBuf),

    #[error("scope path must be relative to the workspace: {0}")]
    AbsoluteScopePath(PathBuf),

    #[error("{kind} escapes workspace `{workspace}`: {path}")]
    PathEscapesWorkspace {
        kind: &'static str,
        path: PathBuf,
        workspace: PathBuf,
    },

    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(PathBuf),

    #[error("path contains a control character: {0:?}")]
    ControlCharacter(PathBuf),

    #[error("special filesystem entry cannot be confined safely: {0}")]
    SpecialFile(PathBuf),

    #[error("symlink cycle encountered while validating: {0}")]
    SymlinkCycle(PathBuf),

    #[error("cannot {operation} `{path}`")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Compile a policy access plan into a fail-closed macOS confinement plan.
pub fn plan_read_only(
    canonical_executable: &Path,
    canonical_cwd: &Path,
    canonical_workspace: &Path,
    access_plan: &AccessPlan,
) -> Result<SandboxPlan, SandboxError> {
    let availability = preflight();
    let sandbox_exec = match &availability {
        SandboxAvailability::Available { sandbox_exec, .. } => sandbox_exec.clone(),
        _ => return Err(SandboxError::Unavailable(availability)),
    };
    if access_plan.scopes.is_empty() {
        return Err(SandboxError::EmptyAccessPlan);
    }

    let workspace = require_canonical(canonical_workspace, "workspace")?;
    let workspace_metadata = metadata(&workspace, "inspect workspace")?;
    if !workspace_metadata.is_dir() {
        return Err(SandboxError::WorkspaceNotDirectory(workspace));
    }
    validate_profile_path(&workspace)?;

    let cwd = require_canonical(canonical_cwd, "working directory")?;
    let cwd_metadata = metadata(&cwd, "inspect working directory")?;
    if !cwd_metadata.is_dir() {
        return Err(SandboxError::WorkingDirectoryNotDirectory(cwd));
    }
    ensure_within(&cwd, &workspace, "working directory")?;
    validate_profile_path(&cwd)?;

    let executable = require_canonical(canonical_executable, "executable")?;
    let executable_metadata = metadata(&executable, "inspect executable")?;
    if !executable_metadata.is_file() || executable_metadata.mode() & 0o111 == 0 {
        return Err(SandboxError::ExecutableNotRegular(executable));
    }
    File::open(&executable).map_err(|source| io_error("read executable", &executable, source))?;
    validate_profile_path(&executable)?;

    let mut rules = ReadRules::default();
    let mut scopes = access_plan.scopes.clone();
    scopes.sort_by_key(scope_sort_key);
    scopes.dedup();

    if scopes
        .iter()
        .any(|scope| matches!(scope, AccessScope::WholeWorkspace))
    {
        let mut active = HashSet::new();
        validate_content_tree(&workspace, &workspace, &mut rules, &mut active)?;
        rules.metadata_subpaths.insert(workspace.clone());
        rules.data_subpaths.insert(workspace.clone());
    } else {
        for scope in &scopes {
            match scope {
                AccessScope::IdentityOnly => {}
                AccessScope::ContentPath(relative) => {
                    add_content_scope(&workspace, relative, &mut rules)?;
                }
                AccessScope::RecursiveContentTree(relative) => {
                    add_recursive_scope(&workspace, relative, &mut rules)?;
                }
                AccessScope::DirectoryListing(relative) => {
                    add_listing_scope(&workspace, relative, &mut rules)?;
                }
                AccessScope::WholeWorkspace => unreachable!("handled above"),
            }
        }
    }

    let profile = render_profile(&executable, &rules)?;
    let mut digest = Hasher::new_derive_key("again macos sandbox profile v1");
    digest.update(profile.as_bytes());
    let profile_digest = digest.finalize().to_hex().to_string();

    Ok(SandboxPlan {
        sandbox_exec,
        executable,
        cwd,
        workspace,
        profile,
        profile_digest,
    })
}

#[derive(Default)]
struct ReadRules {
    metadata_literals: BTreeSet<PathBuf>,
    metadata_subpaths: BTreeSet<PathBuf>,
    data_literals: BTreeSet<PathBuf>,
    data_subpaths: BTreeSet<PathBuf>,
}

fn add_content_scope(
    workspace: &Path,
    relative: &Path,
    rules: &mut ReadRules,
) -> Result<(), SandboxError> {
    let operand = resolve_operand(workspace, relative)?;
    match fs::symlink_metadata(&operand) {
        Ok(metadata) => {
            ensure_supported(&operand, &metadata)?;
            if metadata.file_type().is_symlink() {
                rules.metadata_literals.insert(operand.clone());
                rules.data_literals.insert(operand.clone());
                let target = resolve_symlink(&operand, workspace)?;
                return add_resolved_content(&target, workspace, rules);
            }
            add_resolved_content(&operand, workspace, rules)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            validate_missing_ancestor(&operand, workspace)?;
            rules.metadata_literals.insert(operand.clone());
            rules.data_literals.insert(operand);
            Ok(())
        }
        Err(source) => Err(io_error("inspect content scope", &operand, source)),
    }
}

fn add_recursive_scope(
    workspace: &Path,
    relative: &Path,
    rules: &mut ReadRules,
) -> Result<(), SandboxError> {
    let operand = resolve_operand(workspace, relative)?;
    match fs::symlink_metadata(&operand) {
        Ok(metadata) => {
            ensure_supported(&operand, &metadata)?;
            let resolved = if metadata.file_type().is_symlink() {
                rules.metadata_literals.insert(operand.clone());
                rules.data_literals.insert(operand.clone());
                resolve_symlink(&operand, workspace)?
            } else {
                operand
            };
            add_resolved_content(&resolved, workspace, rules)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            validate_missing_ancestor(&operand, workspace)?;
            rules.metadata_literals.insert(operand.clone());
            rules.data_literals.insert(operand);
            Ok(())
        }
        Err(source) => Err(io_error("inspect recursive scope", &operand, source)),
    }
}

fn add_resolved_content(
    path: &Path,
    workspace: &Path,
    rules: &mut ReadRules,
) -> Result<(), SandboxError> {
    let metadata = metadata(path, "inspect content operand")?;
    ensure_supported(path, &metadata)?;
    if metadata.is_file() {
        File::open(path).map_err(|source| io_error("read content operand", path, source))?;
        rules.metadata_literals.insert(path.to_path_buf());
        rules.data_literals.insert(path.to_path_buf());
        return Ok(());
    }

    let mut active = HashSet::new();
    validate_content_tree(path, workspace, rules, &mut active)?;
    rules.metadata_subpaths.insert(path.to_path_buf());
    rules.data_subpaths.insert(path.to_path_buf());
    Ok(())
}

fn validate_content_tree(
    directory: &Path,
    workspace: &Path,
    rules: &mut ReadRules,
    active: &mut HashSet<PathBuf>,
) -> Result<(), SandboxError> {
    let canonical = canonicalize(directory, "canonicalize content tree")?;
    ensure_within(&canonical, workspace, "content tree")?;
    if !active.insert(canonical.clone()) {
        return Err(SandboxError::SymlinkCycle(canonical));
    }

    let result = (|| {
        let iterator = fs::read_dir(directory)
            .map_err(|source| io_error("read content tree", directory, source))?;
        let mut names = Vec::new();
        for entry in iterator {
            let entry =
                entry.map_err(|source| io_error("read content tree entry", directory, source))?;
            names.push(entry.file_name());
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

        for name in names {
            let child = directory.join(name);
            validate_profile_path(&child)?;
            let child_metadata = symlink_metadata(&child, "inspect content tree entry")?;
            ensure_supported(&child, &child_metadata)?;
            if child_metadata.file_type().is_symlink() {
                let target = resolve_symlink(&child, workspace)?;
                let target_metadata = metadata(&target, "inspect symlink target")?;
                ensure_supported(&target, &target_metadata)?;
                if target_metadata.is_dir() {
                    validate_content_tree(&target, workspace, rules, active)?;
                    rules.metadata_subpaths.insert(target.clone());
                    rules.data_subpaths.insert(target);
                } else {
                    File::open(&target)
                        .map_err(|source| io_error("read symlink target", &target, source))?;
                    rules.metadata_literals.insert(target.clone());
                    rules.data_literals.insert(target);
                }
            } else if child_metadata.is_dir() {
                validate_content_tree(&child, workspace, rules, active)?;
            } else {
                File::open(&child)
                    .map_err(|source| io_error("read content tree file", &child, source))?;
            }
        }
        Ok(())
    })();
    active.remove(&canonical);
    result
}

fn add_listing_scope(
    workspace: &Path,
    relative: &Path,
    rules: &mut ReadRules,
) -> Result<(), SandboxError> {
    let operand = resolve_operand(workspace, relative)?;
    match fs::symlink_metadata(&operand) {
        Ok(metadata) => {
            ensure_supported(&operand, &metadata)?;
            rules.metadata_literals.insert(operand.clone());
            if metadata.file_type().is_symlink() {
                // `ls -l` observes link metadata/target text, not target contents.
                fs::read_link(&operand)
                    .map_err(|source| io_error("read listing symlink", &operand, source))?;
                resolve_symlink(&operand, workspace)?;
                return Ok(());
            }
            if metadata.is_file() {
                return Ok(());
            }

            rules.data_literals.insert(operand.clone());
            let iterator = fs::read_dir(&operand)
                .map_err(|source| io_error("read directory listing", &operand, source))?;
            let mut names = Vec::new();
            for entry in iterator {
                let entry =
                    entry.map_err(|source| io_error("read directory entry", &operand, source))?;
                names.push(entry.file_name());
            }
            names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            for name in names {
                let child = operand.join(name);
                validate_profile_path(&child)?;
                let child_metadata = symlink_metadata(&child, "inspect listing entry")?;
                ensure_supported(&child, &child_metadata)?;
                if child_metadata.file_type().is_symlink() {
                    fs::read_link(&child)
                        .map_err(|source| io_error("read listing symlink", &child, source))?;
                    resolve_symlink(&child, workspace)?;
                }
                rules.metadata_literals.insert(child);
            }
            Ok(())
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            validate_missing_ancestor(&operand, workspace)?;
            rules.metadata_literals.insert(operand);
            Ok(())
        }
        Err(source) => Err(io_error("inspect listing scope", &operand, source)),
    }
}

fn resolve_operand(workspace: &Path, relative: &Path) -> Result<PathBuf, SandboxError> {
    validate_profile_path(relative)?;
    if relative.is_absolute() {
        return Err(SandboxError::AbsoluteScopePath(relative.to_path_buf()));
    }
    let candidate = workspace.join(relative);
    let normalized =
        lexical_normalize(&candidate).ok_or_else(|| SandboxError::PathEscapesWorkspace {
            kind: "scope",
            path: candidate.clone(),
            workspace: workspace.to_path_buf(),
        })?;
    ensure_within(&normalized, workspace, "scope")?;
    validate_profile_path(&normalized)?;

    match fs::canonicalize(&normalized) {
        Ok(canonical) => ensure_within(&canonical, workspace, "scope")?,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            validate_missing_ancestor(&normalized, workspace)?;
        }
        Err(source) => return Err(io_error("resolve scope", &normalized, source)),
    }
    Ok(normalized)
}

fn resolve_symlink(path: &Path, workspace: &Path) -> Result<PathBuf, SandboxError> {
    fs::read_link(path).map_err(|source| io_error("read symlink", path, source))?;
    let canonical = canonicalize(path, "resolve symlink")?;
    ensure_within(&canonical, workspace, "symlink target")?;
    validate_profile_path(&canonical)?;
    Ok(canonical)
}

fn validate_missing_ancestor(path: &Path, workspace: &Path) -> Result<(), SandboxError> {
    let mut probe = path.to_path_buf();
    loop {
        match fs::canonicalize(&probe) {
            Ok(canonical) => {
                ensure_within(&canonical, workspace, "scope ancestor")?;
                validate_profile_path(&canonical)?;
                return Ok(());
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                if !probe.pop() {
                    return Err(io_error("resolve scope ancestor", path, source));
                }
            }
            Err(source) => return Err(io_error("resolve scope ancestor", &probe, source)),
        }
    }
}

fn render_profile(executable: &Path, rules: &ReadRules) -> Result<String, SandboxError> {
    let executable = scheme_string(executable)?;
    let mut profile = String::from(
        "(version 1)\n\
         (deny default)\n\
         (import \"system.sb\")\n\
         (deny process-exec)\n",
    );
    profile.push_str("(allow process-exec (literal ");
    profile.push_str(&executable);
    profile.push_str("))\n");
    profile.push_str("(deny file-write*)\n");
    profile.push_str("(deny network*)\n");
    profile.push_str(
        "(deny network-outbound (literal \"/private/var/run/syslog\"))\n\
         (deny file-read*\n\
           (subpath \"/dev\")\n\
           (subpath \"/private/dev\")\n\
           (literal \"/private/etc/passwd\")\n\
           (literal \"/private/etc/master.passwd\")\n\
           (literal \"/etc/passwd\")\n\
           (literal \"/etc/master.passwd\")\n\
           (literal \"/private/var/run/syslog\"))\n",
    );

    render_read_operation(
        &mut profile,
        "file-read-metadata",
        &rules.metadata_literals,
        &rules.metadata_subpaths,
    )?;
    render_read_operation(
        &mut profile,
        "file-read-data",
        &rules.data_literals,
        &rules.data_subpaths,
    )?;
    Ok(profile)
}

fn render_read_operation(
    output: &mut String,
    operation: &str,
    literals: &BTreeSet<PathBuf>,
    subpaths: &BTreeSet<PathBuf>,
) -> Result<(), SandboxError> {
    if literals.is_empty() && subpaths.is_empty() {
        return Ok(());
    }
    output.push_str("(allow ");
    output.push_str(operation);
    output.push('\n');
    for path in literals {
        output.push_str("  (literal ");
        output.push_str(&scheme_string(path)?);
        output.push_str(")\n");
    }
    for path in subpaths {
        output.push_str("  (subpath ");
        output.push_str(&scheme_string(path)?);
        output.push_str(")\n");
    }
    output.push_str(")\n");
    Ok(())
}

fn scheme_string(path: &Path) -> Result<String, SandboxError> {
    let value = validated_utf8(path)?;
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            _ => escaped.push(character),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

fn validated_utf8(path: &Path) -> Result<&str, SandboxError> {
    let value = path
        .to_str()
        .ok_or_else(|| SandboxError::NonUtf8Path(path.to_path_buf()))?;
    if value.chars().any(char::is_control) {
        return Err(SandboxError::ControlCharacter(path.to_path_buf()));
    }
    Ok(value)
}

fn validate_profile_path(path: &Path) -> Result<(), SandboxError> {
    validated_utf8(path).map(|_| ())
}

fn ensure_supported(path: &Path, metadata: &Metadata) -> Result<(), SandboxError> {
    let file_type = metadata.file_type();
    if file_type.is_file() || file_type.is_dir() || file_type.is_symlink() {
        Ok(())
    } else {
        Err(SandboxError::SpecialFile(path.to_path_buf()))
    }
}

fn require_canonical(path: &Path, kind: &'static str) -> Result<PathBuf, SandboxError> {
    let canonical = canonicalize(path, "canonicalize path")?;
    if canonical != path {
        return Err(SandboxError::NonCanonicalPath {
            kind,
            supplied: path.to_path_buf(),
            canonical,
        });
    }
    Ok(path.to_path_buf())
}

fn ensure_within(path: &Path, workspace: &Path, kind: &'static str) -> Result<(), SandboxError> {
    if path.starts_with(workspace) {
        Ok(())
    } else {
        Err(SandboxError::PathEscapesWorkspace {
            kind,
            path: path.to_path_buf(),
            workspace: workspace.to_path_buf(),
        })
    }
}

fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn scope_sort_key(scope: &AccessScope) -> (u8, Vec<u8>) {
    match scope {
        AccessScope::IdentityOnly => (0, Vec::new()),
        AccessScope::ContentPath(path) => (1, path.as_os_str().as_bytes().to_vec()),
        AccessScope::RecursiveContentTree(path) => (2, path.as_os_str().as_bytes().to_vec()),
        AccessScope::DirectoryListing(path) => (3, path.as_os_str().as_bytes().to_vec()),
        AccessScope::WholeWorkspace => (4, Vec::new()),
    }
}

fn canonicalize(path: &Path, operation: &'static str) -> Result<PathBuf, SandboxError> {
    fs::canonicalize(path).map_err(|source| io_error(operation, path, source))
}

fn metadata(path: &Path, operation: &'static str) -> Result<Metadata, SandboxError> {
    fs::metadata(path).map_err(|source| io_error(operation, path, source))
}

fn symlink_metadata(path: &Path, operation: &'static str) -> Result<Metadata, SandboxError> {
    fs::symlink_metadata(path).map_err(|source| io_error(operation, path, source))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> SandboxError {
    SandboxError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(target_os = "macos")]
fn is_regular_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        _temp: TempDir,
        workspace: PathBuf,
        executable: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let workspace = temp.path().join("workspace");
            fs::create_dir(&workspace).expect("workspace");
            fs::create_dir(workspace.join("src")).expect("src");
            fs::write(workspace.join("src/main.rs"), b"fn main() {}\n").expect("source");
            fs::write(workspace.join("README.md"), b"read me\n").expect("readme");

            let executable = temp.path().join("tool");
            fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("tool");
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("tool mode");
            Self {
                _temp: temp,
                workspace: fs::canonicalize(workspace).expect("canonical workspace"),
                executable: fs::canonicalize(executable).expect("canonical tool"),
            }
        }

        fn plan(&self, scopes: Vec<AccessScope>) -> SandboxPlan {
            plan_read_only(
                &self.executable,
                &self.workspace,
                &self.workspace,
                &AccessPlan { scopes },
            )
            .expect("sandbox plan")
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn profile_denies_ambient_authority_and_command_preserves_arguments() {
        let fixture = Fixture::new();
        let plan = fixture.plan(vec![AccessScope::ContentPath(PathBuf::from("README.md"))]);
        let profile = plan.profile();
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(import \"system.sb\")"));
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains("(deny file-write*)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("/private/var/run/syslog"));
        assert!(profile.contains("/dev"));
        assert!(profile.contains("/private/etc/passwd"));
        assert!(profile.contains(&format!(
            "(allow process-exec (literal {}))",
            scheme_string(&fixture.executable).unwrap()
        )));
        assert_eq!(plan.profile_digest().len(), 64);

        let args = vec![OsString::from("value with spaces"), OsString::from("--")];
        let command = plan.command(&args);
        assert_eq!(command.get_program(), OsStr::new(SANDBOX_EXEC));
        let actual: Vec<_> = command.get_args().collect();
        assert_eq!(actual[0], OsStr::new("-p"));
        assert_eq!(actual[1], OsStr::new(plan.profile()));
        assert_eq!(actual[2], fixture.executable.as_os_str());
        assert_eq!(actual[3], OsStr::new("value with spaces"));
        assert_eq!(actual[4], OsStr::new("--"));
        assert_eq!(command.get_current_dir(), Some(fixture.workspace.as_path()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn scope_kinds_emit_distinct_minimal_read_rules() {
        let fixture = Fixture::new();
        let identity = fixture.plan(vec![AccessScope::IdentityOnly]);
        assert!(
            !identity
                .profile()
                .contains(fixture.workspace.to_str().unwrap())
        );

        let file = fixture.plan(vec![AccessScope::ContentPath(PathBuf::from("README.md"))]);
        let readme = scheme_string(&fixture.workspace.join("README.md")).unwrap();
        assert!(file.profile().contains(&format!("(literal {readme})")));
        assert!(!file.profile().contains(&format!("(subpath {readme})")));

        let tree = fixture.plan(vec![AccessScope::RecursiveContentTree(PathBuf::from(
            "src",
        ))]);
        let src = scheme_string(&fixture.workspace.join("src")).unwrap();
        assert!(tree.profile().contains(&format!("(subpath {src})")));

        let listing = fixture.plan(vec![AccessScope::DirectoryListing(PathBuf::from("src"))]);
        let source = scheme_string(&fixture.workspace.join("src/main.rs")).unwrap();
        let data_section = listing
            .profile()
            .split("(allow file-read-data")
            .nth(1)
            .expect("data section");
        assert!(listing.profile().contains(&format!("(literal {source})")));
        assert!(!data_section.contains(&format!("(literal {source})")));
        assert!(data_section.contains(&format!("(literal {src})")));

        let whole = fixture.plan(vec![AccessScope::WholeWorkspace]);
        let workspace = scheme_string(&fixture.workspace).unwrap();
        assert!(whole.profile().contains(&format!("(subpath {workspace})")));
        assert_ne!(identity.profile_digest(), whole.profile_digest());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn profile_and_digest_are_stable_across_scope_order() {
        let fixture = Fixture::new();
        let first = fixture.plan(vec![
            AccessScope::ContentPath(PathBuf::from("README.md")),
            AccessScope::DirectoryListing(PathBuf::from("src")),
        ]);
        let second = fixture.plan(vec![
            AccessScope::DirectoryListing(PathBuf::from("src")),
            AccessScope::ContentPath(PathBuf::from("README.md")),
            AccessScope::ContentPath(PathBuf::from("README.md")),
        ]);
        assert_eq!(first.profile(), second.profile());
        assert_eq!(first.profile_digest(), second.profile_digest());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn symlink_escape_is_rejected_for_file_and_tree_scopes() {
        let fixture = Fixture::new();
        symlink("../tool", fixture.workspace.join("escape")).expect("escape symlink");
        for scope in [
            AccessScope::ContentPath(PathBuf::from("escape")),
            AccessScope::RecursiveContentTree(PathBuf::from(".")),
        ] {
            let error = plan_read_only(
                &fixture.executable,
                &fixture.workspace,
                &fixture.workspace,
                &AccessPlan {
                    scopes: vec![scope],
                },
            )
            .expect_err("escaping symlink must fail");
            assert!(matches!(error, SandboxError::PathEscapesWorkspace { .. }));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn scheme_quoting_escapes_quotes_and_backslashes() {
        let fixture = Fixture::new();
        let name = "a\\b\"c";
        fs::write(fixture.workspace.join(name), b"quoted\n").expect("quoted path");
        let plan = fixture.plan(vec![AccessScope::ContentPath(PathBuf::from(name))]);
        assert!(plan.profile().contains("a\\\\b\\\"c"));
        assert!(!plan.profile().contains("a\\b\"c"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn control_and_non_utf8_paths_are_rejected_before_profile_generation() {
        let fixture = Fixture::new();
        let control = plan_read_only(
            &fixture.executable,
            &fixture.workspace,
            &fixture.workspace,
            &AccessPlan {
                scopes: vec![AccessScope::ContentPath(PathBuf::from("bad\npath"))],
            },
        )
        .expect_err("control path");
        assert!(matches!(control, SandboxError::ControlCharacter(_)));

        let non_utf8 = PathBuf::from(OsStr::from_bytes(b"bad\xffpath"));
        let error = plan_read_only(
            &fixture.executable,
            &fixture.workspace,
            &fixture.workspace,
            &AccessPlan {
                scopes: vec![AccessScope::ContentPath(non_utf8)],
            },
        )
        .expect_err("non-UTF8 path");
        assert!(matches!(error, SandboxError::NonUtf8Path(_)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn preflight_reports_private_profile_availability() {
        assert!(matches!(preflight(), SandboxAvailability::Available { .. }));
    }

    #[test]
    fn probe_failure_shape_preserves_status_and_stderr_without_running_seatbelt() {
        let failure = classify_probe_output(false, Some(71), b"sandbox_apply: denied\xff")
            .expect_err("synthetic rejection");
        assert_eq!(
            failure,
            SandboxProbeError::Rejected {
                status: Some(71),
                stderr: "sandbox_apply: denied\u{fffd}".to_owned(),
            }
        );
        assert!(classify_probe_output(true, Some(0), b"").is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_is_explicitly_unsupported() {
        let availability = preflight();
        assert!(matches!(
            availability,
            SandboxAvailability::UnsupportedPlatform { .. }
        ));
        let plan = AccessPlan {
            scopes: vec![AccessScope::IdentityOnly],
        };
        assert!(matches!(
            plan_read_only(
                Path::new("/bin/echo"),
                Path::new("/tmp"),
                Path::new("/tmp"),
                &plan
            ),
            Err(SandboxError::Unavailable(
                SandboxAvailability::UnsupportedPlatform { .. }
            ))
        ));
    }
}
