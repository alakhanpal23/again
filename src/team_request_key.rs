//! Portable request descriptors for the deliberately narrow team-cache alpha.
//!
//! This module is separate from the native local fingerprint. It never weakens
//! that fingerprint and is not an execution boundary: callers must execute an
//! admitted request inside the exact policy/profile/platform/image identities
//! bound here and must independently prevent filesystem mutation between key
//! construction and execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use blake3::Hasher;
use thiserror::Error;

use crate::fingerprint::{
    FileDigestCache, FileIdentity, NoFileDigestCache, portable_file_content_hasher,
};
use crate::runtime_attestation::{RuntimeAttestationError, TeamRuntimeAttestationV1};
use crate::team::Digest;

pub const TEAM_REQUEST_KEY_SCHEMA_VERSION: u16 = 1;
pub const TEAM_ALPHA_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
pub const TEAM_ALPHA_MAX_TREE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const TEAM_ALPHA_MAX_TREE_ENTRIES: u64 = 100_000;
/// Maximum entries read from one directory before sorting. This bounds the
/// largest allocation made by the deterministic walker, including hidden
/// entries that are excluded from the request observation.
pub const TEAM_ALPHA_MAX_DIRECTORY_ENTRIES: u64 = 16_384;
/// Maximum directory entries discovered over a complete traversal, including
/// hidden entries. The descriptor's `entries` field still counts only visible
/// files and directories, preserving its existing meaning.
pub const TEAM_ALPHA_MAX_DISCOVERED_TREE_ENTRIES: u64 = 100_000;
/// Maximum visible directory nesting below the selected tree root. The root is
/// depth zero, so a value of 256 admits at most 256 nested directory components.
pub const TEAM_ALPHA_MAX_TREE_DEPTH: usize = 256;

const REQUEST_DOMAIN: &[u8] = b"again.team-request-key.v1";
const TREE_DOMAIN: &[u8] = b"again.team-request-tree.v1";
const ENVIRONMENT_DOMAIN: &[u8] = b"again.team-request-environment.v1";
const MODELED_ENVIRONMENT: &[&str] = &["LANG", "LC_ALL", "LC_CTYPE", "TZ"];

/// Complete inputs for the portable team-alpha request key.
///
/// `environment` must be the complete environment exposed to the command, not
/// an overlay on the parent environment. Only the explicitly modeled names are
/// accepted. A future executor must therefore start from a cleared environment.
pub struct TeamRequestKeyInput<'a> {
    pub tenant_id: &'a str,
    pub repository_id: &'a str,
    pub generation_id: &'a str,
    pub workspace: &'a Path,
    pub cwd: &'a Path,
    pub argv: &'a [OsString],
    pub environment: &'a [(OsString, OsString)],
    pub stdin_is_tty: bool,
    pub stdout_is_tty: bool,
    pub stderr_is_tty: bool,
    pub policy_digest: Digest,
    pub execution_profile_digest: Digest,
    #[cfg(not(test))]
    platform_digest: Digest,
    #[cfg(test)]
    pub(crate) platform_digest: Digest,
    #[cfg(not(test))]
    image_digest: Digest,
    #[cfg(test)]
    pub(crate) image_digest: Digest,
}

/// All caller-controlled request fields before runtime identity is attached.
/// This type is crate-private so the team CLI can collect inputs without
/// exposing an unchecked portable-key constructor to library consumers.
pub(crate) struct UnboundTeamRequestKeyInput<'a> {
    pub(crate) tenant_id: &'a str,
    pub(crate) repository_id: &'a str,
    pub(crate) generation_id: &'a str,
    pub(crate) workspace: &'a Path,
    pub(crate) cwd: &'a Path,
    pub(crate) argv: &'a [OsString],
    pub(crate) environment: &'a [(OsString, OsString)],
    pub(crate) stdin_is_tty: bool,
    pub(crate) stdout_is_tty: bool,
    pub(crate) stderr_is_tty: bool,
    pub(crate) policy_digest: Digest,
    pub(crate) execution_profile_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub(crate) enum RuntimeBindingError {
    #[error("request argv[0] is not the attested executable")]
    CommandMismatch,
    #[error("team execution requires the exact cleared locale environment LANG=C, LC_ALL=C")]
    EnvironmentMismatch,
    #[error("runtime attestation is no longer current: {0}")]
    Attestation(#[from] RuntimeAttestationError),
}

impl<'a> TeamRequestKeyInput<'a> {
    /// Attach only digests derived from a live, sealed runtime capability.
    /// The capability is revalidated here so a path replacement between
    /// attestation and request construction fails closed.
    pub(crate) fn new_attested(
        input: UnboundTeamRequestKeyInput<'a>,
        runtime: &TeamRuntimeAttestationV1,
    ) -> Result<Self, RuntimeBindingError> {
        let command = input
            .argv
            .first()
            .and_then(|value| value.to_str())
            .ok_or(RuntimeBindingError::CommandMismatch)?;
        if !runtime.binds_command(command) {
            return Err(RuntimeBindingError::CommandMismatch);
        }
        if !is_exact_team_environment(input.environment) {
            return Err(RuntimeBindingError::EnvironmentMismatch);
        }
        runtime.verify_executable_current()?;
        Ok(Self {
            tenant_id: input.tenant_id,
            repository_id: input.repository_id,
            generation_id: input.generation_id,
            workspace: input.workspace,
            cwd: input.cwd,
            argv: input.argv,
            environment: input.environment,
            stdin_is_tty: input.stdin_is_tty,
            stdout_is_tty: input.stdout_is_tty,
            stderr_is_tty: input.stderr_is_tty,
            policy_digest: input.policy_digest,
            execution_profile_digest: input.execution_profile_digest,
            platform_digest: runtime.platform_digest(),
            image_digest: runtime.image_digest(),
        })
    }

    /// Reconstruct an already sealed descriptor against an immutable snapshot.
    /// Callers cannot forge `descriptor`: all of its fields are private and it
    /// can only be obtained from a built [`TeamRequestKeyV1`].
    pub(crate) fn new_for_verified_descriptor(
        descriptor: &'a TeamRequestDescriptorV1,
        workspace: &'a Path,
        cwd: &'a Path,
        argv: &'a [OsString],
        environment: &'a [(OsString, OsString)],
    ) -> Self {
        Self {
            tenant_id: descriptor.tenant_id(),
            repository_id: descriptor.repository_id(),
            generation_id: descriptor.generation_id(),
            workspace,
            cwd,
            argv,
            environment,
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: descriptor.policy_digest(),
            execution_profile_digest: descriptor.execution_profile_digest(),
            platform_digest: descriptor.platform_digest(),
            image_digest: descriptor.image_digest(),
        }
    }
}

fn is_exact_team_environment(environment: &[(OsString, OsString)]) -> bool {
    if environment.len() != 2 {
        return false;
    }
    let mut lang = false;
    let mut lc_all = false;
    for (name, value) in environment {
        match (name.to_str(), value.to_str()) {
            (Some("LANG"), Some("C")) if !lang => lang = true,
            (Some("LC_ALL"), Some("C")) if !lc_all => lc_all = true,
            _ => return false,
        }
    }
    lang && lc_all
}

/// A portable, inspectable descriptor. It contains no absolute checkout path,
/// inode, owner, or timestamp. Environment values are represented only by
/// domain-separated digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamRequestDescriptorV1 {
    schema_version: u16,
    tenant_id: String,
    repository_id: String,
    generation_id: String,
    repository_relative_cwd: String,
    normalized_argv: Vec<String>,
    modeled_environment: Vec<ModeledEnvironmentV1>,
    observations: Vec<TeamObservationV1>,
    policy_digest: Digest,
    execution_profile_digest: Digest,
    platform_digest: Digest,
    image_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeledEnvironmentV1 {
    name: String,
    value_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeamObservationKindV1 {
    File,
    RecursiveTree,
}

/// One content-derived filesystem observation. `repository_path` is always a
/// normalized UTF-8 path relative to the repository root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamObservationV1 {
    kind: TeamObservationKindV1,
    repository_path: String,
    content_digest: Digest,
    entries: u64,
    bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamRequestKeyV1 {
    digest: Digest,
    descriptor: TeamRequestDescriptorV1,
}

impl TeamRequestKeyV1 {
    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn descriptor(&self) -> &TeamRequestDescriptorV1 {
        &self.descriptor
    }
}

impl TeamRequestDescriptorV1 {
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    pub fn repository_relative_cwd(&self) -> &str {
        &self.repository_relative_cwd
    }

    pub fn normalized_argv(&self) -> &[String] {
        &self.normalized_argv
    }

    pub fn modeled_environment(&self) -> &[ModeledEnvironmentV1] {
        &self.modeled_environment
    }

    pub fn observations(&self) -> &[TeamObservationV1] {
        &self.observations
    }

    pub fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    pub fn execution_profile_digest(&self) -> Digest {
        self.execution_profile_digest
    }

    pub fn platform_digest(&self) -> Digest {
        self.platform_digest
    }

    pub fn image_digest(&self) -> Digest {
        self.image_digest
    }
}

impl ModeledEnvironmentV1 {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value_digest(&self) -> Digest {
        self.value_digest
    }
}

impl TeamObservationV1 {
    pub fn kind(&self) -> TeamObservationKindV1 {
        self.kind
    }

    pub fn repository_path(&self) -> &str {
        &self.repository_path
    }

    pub fn content_digest(&self) -> Digest {
        self.content_digest
    }

    pub fn entries(&self) -> u64 {
        self.entries
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// A typed explanation for keeping a request local. No error from this module
/// should be converted into a team-cache hit or upload attempt.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TeamLocalOnlyReason {
    #[error("{field} is not a valid team-cache namespace")]
    InvalidNamespace { field: &'static str },

    #[error("generation_id must be exactly 32 lower-case hexadecimal characters")]
    InvalidGenerationId,

    #[error("team-cache argv is empty")]
    EmptyArgv,

    #[error("team-cache argv[{index}] is not portable UTF-8")]
    NonUtf8Argument { index: usize },

    #[error("team-cache argv[{index}] contains a control character")]
    ControlCharacterArgument { index: usize },

    #[error("absolute executables are local-only")]
    AbsoluteExecutable,

    #[error("command `{command}` is outside the team-alpha subset")]
    UnsupportedCommand { command: String },

    #[error("argument {index} is unsupported for `{command}`")]
    UnsupportedArgument { command: String, index: usize },

    #[error("`{command}` requires an explicit file or tree operand")]
    MissingOperand { command: String },

    #[error("TTY-dependent requests are local-only")]
    TtyDependent,

    #[error("environment name at index {index} is not portable UTF-8")]
    NonUtf8EnvironmentName { index: usize },

    #[error("environment value for `{name}` is not portable UTF-8")]
    NonUtf8EnvironmentValue { name: String },

    #[error("environment variable `{name}` is not modeled by the team-alpha profile")]
    UnsupportedEnvironment { name: String },

    #[error("environment variable `{name}` is duplicated")]
    DuplicateEnvironment { name: String },

    #[error("environment value for `{name}` is not portable")]
    UnsupportedEnvironmentValue { name: String },

    #[error("workspace is not a directory")]
    WorkspaceNotDirectory,

    #[error("working directory is not a directory")]
    WorkingDirectoryNotDirectory,

    #[error("working directory is outside the repository")]
    WorkingDirectoryOutsideRepository,

    #[error("path at argv[{index}] is absolute")]
    AbsolutePath { index: usize },

    #[error("path at argv[{index}] escapes the repository")]
    OutsideRepository { index: usize },

    #[error("path at argv[{index}] is not in canonical portable form")]
    NonCanonicalPath { index: usize },

    #[error("path at argv[{index}] enters a hidden or runtime namespace")]
    ExcludedPath { index: usize },

    #[error("path at argv[{index}] contains a symlink")]
    SymlinkPath { index: usize },

    #[error("path at argv[{index}] does not exist")]
    MissingPath { index: usize },

    #[error("path at argv[{index}] selects stdin")]
    StdinDependent { index: usize },

    #[error("path at argv[{index}] has an unsupported filesystem type")]
    UnsupportedFileType { index: usize },

    #[error("filesystem path is not portable UTF-8")]
    NonPortableFilesystemPath,

    #[error("filesystem changed while constructing the portable request key")]
    ConcurrentFilesystemMutation,

    #[error("team-alpha observation exceeds the {limit} resource limit")]
    ResourceLimit { limit: &'static str },

    #[error("cannot {operation} `{path}` ({kind:?})")]
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
    },
}

#[derive(Clone, Copy)]
enum OperandKind {
    File,
    FileOrTree,
}

#[derive(Clone, Copy)]
struct Operand {
    argv_index: usize,
    kind: OperandKind,
}

struct ResolvedOperand {
    absolute: PathBuf,
    repository_path: String,
    metadata: Metadata,
}

struct TreeSummary {
    digest: Digest,
    entries: u64,
    bytes: u64,
}

#[derive(Clone, Copy)]
struct TreeTraversalLimits {
    max_depth: usize,
    max_directory_entries: u64,
    max_discovered_entries: u64,
    max_observed_entries: u64,
    max_tree_bytes: u64,
}

impl Default for TreeTraversalLimits {
    fn default() -> Self {
        Self {
            max_depth: TEAM_ALPHA_MAX_TREE_DEPTH,
            max_directory_entries: TEAM_ALPHA_MAX_DIRECTORY_ENTRIES,
            max_discovered_entries: TEAM_ALPHA_MAX_DISCOVERED_TREE_ENTRIES,
            max_observed_entries: TEAM_ALPHA_MAX_TREE_ENTRIES,
            max_tree_bytes: TEAM_ALPHA_MAX_TREE_BYTES,
        }
    }
}

#[derive(Default)]
struct KeyBuildStats {
    cache_hits: u64,
    files_hashed: u64,
    bytes_hashed: u64,
}

/// Construct a content-derived request key for the conservative team-alpha
/// command subset. Any uncertainty produces a typed local-only result.
pub fn build_team_request_key_v1(
    input: &TeamRequestKeyInput<'_>,
) -> Result<TeamRequestKeyV1, TeamLocalOnlyReason> {
    let mut cache = NoFileDigestCache;
    build_team_request_key_v1_with_cache(input, &mut cache)
}

/// Construct a portable request key while reusing strongly validated file
/// content digests. A cache hit still opens and fstats the file and compares
/// its complete identity/change epoch with the path before returning bytes.
/// Cache misses and backend errors merely fall back to hashing.
pub fn build_team_request_key_v1_with_cache(
    input: &TeamRequestKeyInput<'_>,
    cache: &mut dyn FileDigestCache,
) -> Result<TeamRequestKeyV1, TeamLocalOnlyReason> {
    let mut stats = KeyBuildStats::default();
    build_team_request_key_v1_with_options(input, cache, TreeTraversalLimits::default(), &mut stats)
}

/// Cheap, non-authorizing admission pass for the team CLI.
///
/// This deliberately mints no descriptor and accepts no platform/image
/// digests. It rejects unsupported argv, environment, cwd, and immediate
/// operand shapes before the comparatively expensive runtime audit. The full
/// builder must still run after a sealed runtime is attached; this preflight is
/// only an early failure optimization and is never reuse evidence.
pub(crate) fn preflight_team_request_v1(
    workspace: &Path,
    cwd: &Path,
    argv: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<(), TeamLocalOnlyReason> {
    let argv = portable_argv(argv)?;
    let operands = parse_command(&argv)?;
    modeled_environment(environment)?;
    let (workspace, cwd, _) = resolve_workspace_and_cwd(workspace, cwd)?;
    for operand in operands {
        let resolved = resolve_operand(
            &workspace,
            &cwd,
            &argv[operand.argv_index],
            operand.argv_index,
        )?;
        match (
            operand.kind,
            resolved.metadata.is_file(),
            resolved.metadata.is_dir(),
        ) {
            (OperandKind::File, true, _) | (OperandKind::FileOrTree, true, _) => {
                if resolved.metadata.len() > TEAM_ALPHA_MAX_FILE_BYTES {
                    return Err(TeamLocalOnlyReason::ResourceLimit {
                        limit: "file_bytes",
                    });
                }
            }
            (OperandKind::FileOrTree, _, true) => {}
            _ => {
                return Err(TeamLocalOnlyReason::UnsupportedFileType {
                    index: operand.argv_index,
                });
            }
        }
    }
    Ok(())
}

fn build_team_request_key_v1_with_options(
    input: &TeamRequestKeyInput<'_>,
    cache: &mut dyn FileDigestCache,
    limits: TreeTraversalLimits,
    stats: &mut KeyBuildStats,
) -> Result<TeamRequestKeyV1, TeamLocalOnlyReason> {
    validate_namespace(input.tenant_id, "tenant_id")?;
    validate_namespace(input.repository_id, "repository_id")?;
    validate_generation_id(input.generation_id)?;
    if input.stdin_is_tty || input.stdout_is_tty || input.stderr_is_tty {
        return Err(TeamLocalOnlyReason::TtyDependent);
    }

    let argv = portable_argv(input.argv)?;
    let operands = parse_command(&argv)?;
    let modeled_environment = modeled_environment(input.environment)?;
    let (workspace, cwd, relative_cwd) = resolve_workspace_and_cwd(input.workspace, input.cwd)?;

    let mut observations = Vec::with_capacity(operands.len());
    for operand in operands {
        let resolved = resolve_operand(
            &workspace,
            &cwd,
            &argv[operand.argv_index],
            operand.argv_index,
        )?;
        let observation = match operand.kind {
            OperandKind::File => observe_file(&resolved, operand.argv_index, cache, stats)?,
            OperandKind::FileOrTree if resolved.metadata.is_file() => {
                observe_file(&resolved, operand.argv_index, cache, stats)?
            }
            OperandKind::FileOrTree if resolved.metadata.is_dir() => {
                let summary =
                    observe_tree(&resolved.absolute, operand.argv_index, cache, limits, stats)?;
                TeamObservationV1 {
                    kind: TeamObservationKindV1::RecursiveTree,
                    repository_path: resolved.repository_path,
                    content_digest: summary.digest,
                    entries: summary.entries,
                    bytes: summary.bytes,
                }
            }
            OperandKind::FileOrTree => {
                return Err(TeamLocalOnlyReason::UnsupportedFileType {
                    index: operand.argv_index,
                });
            }
        };
        observations.push(observation);
    }

    let descriptor = TeamRequestDescriptorV1 {
        schema_version: TEAM_REQUEST_KEY_SCHEMA_VERSION,
        tenant_id: input.tenant_id.to_owned(),
        repository_id: input.repository_id.to_owned(),
        generation_id: input.generation_id.to_owned(),
        repository_relative_cwd: relative_cwd,
        normalized_argv: argv,
        modeled_environment,
        observations,
        policy_digest: input.policy_digest,
        execution_profile_digest: input.execution_profile_digest,
        platform_digest: input.platform_digest,
        image_digest: input.image_digest,
    };
    let digest = digest_descriptor(&descriptor);
    Ok(TeamRequestKeyV1 { digest, descriptor })
}

fn validate_namespace(value: &str, field: &'static str) -> Result<(), TeamLocalOnlyReason> {
    let mut bytes = value.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !valid_first
        || value.len() > 128
        || !bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(TeamLocalOnlyReason::InvalidNamespace { field });
    }
    Ok(())
}

fn validate_generation_id(value: &str) -> Result<(), TeamLocalOnlyReason> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(TeamLocalOnlyReason::InvalidGenerationId);
    }
    Ok(())
}

fn portable_argv(argv: &[OsString]) -> Result<Vec<String>, TeamLocalOnlyReason> {
    if argv.is_empty() {
        return Err(TeamLocalOnlyReason::EmptyArgv);
    }
    argv.iter()
        .enumerate()
        .map(|(index, value)| {
            let value = value
                .to_str()
                .ok_or(TeamLocalOnlyReason::NonUtf8Argument { index })?;
            if value.chars().any(char::is_control) {
                return Err(TeamLocalOnlyReason::ControlCharacterArgument { index });
            }
            Ok(value.to_owned())
        })
        .collect()
}

fn parse_command(argv: &[String]) -> Result<Vec<Operand>, TeamLocalOnlyReason> {
    let command = &argv[0];
    if Path::new(command).is_absolute() {
        return Err(TeamLocalOnlyReason::AbsoluteExecutable);
    }
    match command.as_str() {
        "cat" => parse_cat(argv),
        "head" | "tail" => parse_head_tail(argv),
        "wc" => parse_wc(argv),
        "grep" => parse_search(argv, false),
        "rg" => parse_search(argv, true),
        _ => Err(TeamLocalOnlyReason::UnsupportedCommand {
            command: command.clone(),
        }),
    }
}

fn parse_cat(argv: &[String]) -> Result<Vec<Operand>, TeamLocalOnlyReason> {
    let mut index = 1;
    if argv.get(index).is_some_and(|value| value == "--") {
        index += 1;
    }
    let first = index;
    let mut operands = Vec::new();
    while index < argv.len() {
        if argv[index].starts_with('-') && first == 1 {
            return unsupported_argument(argv, index);
        }
        operands.push(Operand {
            argv_index: index,
            kind: OperandKind::File,
        });
        index += 1;
    }
    require_operands(argv, operands)
}

fn parse_head_tail(argv: &[String]) -> Result<Vec<Operand>, TeamLocalOnlyReason> {
    let mut index = 1;
    let mut selector_seen = false;
    let mut options_done = false;
    while index < argv.len() {
        let value = &argv[index];
        if value == "--" {
            options_done = true;
            index += 1;
            break;
        }
        if matches!(value.as_str(), "-n" | "--lines" | "-c" | "--bytes") {
            if selector_seen {
                return unsupported_argument(argv, index);
            }
            let count_index = index + 1;
            let count = argv
                .get(count_index)
                .ok_or_else(|| unsupported_argument_value(argv, index))?;
            validate_count(count).map_err(|()| unsupported_argument_value(argv, count_index))?;
            selector_seen = true;
            index += 2;
            continue;
        }
        if let Some(count) = value
            .strip_prefix("--lines=")
            .or_else(|| value.strip_prefix("--bytes="))
        {
            if selector_seen || validate_count(count).is_err() {
                return unsupported_argument(argv, index);
            }
            selector_seen = true;
            index += 1;
            continue;
        }
        if value.starts_with('-') {
            return unsupported_argument(argv, index);
        }
        if argv[0] == "tail" && value.starts_with('+') {
            return unsupported_argument(argv, index);
        }
        break;
    }
    file_operands_from(argv, index, options_done)
}

fn parse_wc(argv: &[String]) -> Result<Vec<Operand>, TeamLocalOnlyReason> {
    let mode = argv
        .get(1)
        .ok_or_else(|| TeamLocalOnlyReason::MissingOperand {
            command: argv[0].clone(),
        })?;
    if !matches!(mode.as_str(), "-c" | "--bytes" | "-l" | "--lines") {
        return unsupported_argument(argv, 1);
    }
    let mut index = 2;
    let options_done = argv.get(index).is_some_and(|value| value == "--");
    if options_done {
        index += 1;
    }
    file_operands_from(argv, index, options_done)
}

fn parse_search(argv: &[String], is_rg: bool) -> Result<Vec<Operand>, TeamLocalOnlyReason> {
    let mut index = 1;
    let mut options_done = false;
    let mut no_ignore = false;
    let mut sort_path = false;
    while index < argv.len() {
        let value = &argv[index];
        if value == "--" {
            options_done = true;
            index += 1;
            break;
        }
        if !value.starts_with('-') {
            break;
        }
        if !safe_search_flag(value, is_rg) {
            return unsupported_argument(argv, index);
        }
        no_ignore |= value == "--no-ignore";
        sort_path |= value == "--sort=path";
        index += 1;
    }
    if is_rg && (!no_ignore || !sort_path) {
        return Err(TeamLocalOnlyReason::UnsupportedArgument {
            command: argv[0].clone(),
            index: 0,
        });
    }
    let pattern_index = index;
    if argv.get(pattern_index).is_none() {
        return Err(TeamLocalOnlyReason::MissingOperand {
            command: argv[0].clone(),
        });
    }
    index += 1;
    let first_path = index;
    let mut operands = Vec::new();
    while index < argv.len() {
        if !options_done && argv[index].starts_with('-') {
            return unsupported_argument(argv, index);
        }
        operands.push(Operand {
            argv_index: index,
            kind: if is_rg {
                OperandKind::FileOrTree
            } else {
                OperandKind::File
            },
        });
        index += 1;
    }
    if first_path == argv.len() {
        return Err(TeamLocalOnlyReason::MissingOperand {
            command: argv[0].clone(),
        });
    }
    Ok(operands)
}

fn safe_search_flag(value: &str, is_rg: bool) -> bool {
    let common = matches!(
        value,
        "-F" | "--fixed-strings"
            | "-i"
            | "--ignore-case"
            | "-n"
            | "--line-number"
            | "--with-filename"
            | "--no-filename"
            | "-v"
            | "--invert-match"
            | "-w"
            | "--word-regexp"
            | "-x"
            | "--line-regexp"
    );
    common
        || (!is_rg && matches!(value, "-E" | "-h" | "-H"))
        || (is_rg
            && matches!(
                value,
                "--no-ignore" | "--no-messages" | "--count" | "-c" | "--sort=path"
            ))
}

fn file_operands_from(
    argv: &[String],
    index: usize,
    options_done: bool,
) -> Result<Vec<Operand>, TeamLocalOnlyReason> {
    let mut operands = Vec::new();
    for argv_index in index..argv.len() {
        if !options_done
            && (argv[argv_index].starts_with('-')
                || (argv[0] == "tail" && argv[argv_index].starts_with('+')))
        {
            return unsupported_argument(argv, argv_index);
        }
        operands.push(Operand {
            argv_index,
            kind: OperandKind::File,
        });
    }
    require_operands(argv, operands)
}

fn require_operands(
    argv: &[String],
    operands: Vec<Operand>,
) -> Result<Vec<Operand>, TeamLocalOnlyReason> {
    if operands.is_empty() {
        Err(TeamLocalOnlyReason::MissingOperand {
            command: argv[0].clone(),
        })
    } else {
        Ok(operands)
    }
}

fn unsupported_argument<T>(argv: &[String], index: usize) -> Result<T, TeamLocalOnlyReason> {
    Err(unsupported_argument_value(argv, index))
}

fn unsupported_argument_value(argv: &[String], index: usize) -> TeamLocalOnlyReason {
    TeamLocalOnlyReason::UnsupportedArgument {
        command: argv[0].clone(),
        index,
    }
}

fn validate_count(value: &str) -> Result<(), ()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    value.parse::<u64>().map(|_| ()).map_err(|_| ())
}

fn modeled_environment(
    environment: &[(OsString, OsString)],
) -> Result<Vec<ModeledEnvironmentV1>, TeamLocalOnlyReason> {
    let mut values = BTreeMap::new();
    for (index, (name, value)) in environment.iter().enumerate() {
        let name = name
            .to_str()
            .ok_or(TeamLocalOnlyReason::NonUtf8EnvironmentName { index })?;
        if !MODELED_ENVIRONMENT.contains(&name) {
            return Err(TeamLocalOnlyReason::UnsupportedEnvironment {
                name: name.to_owned(),
            });
        }
        if values.contains_key(name) {
            return Err(TeamLocalOnlyReason::DuplicateEnvironment {
                name: name.to_owned(),
            });
        }
        let value = value
            .to_str()
            .ok_or_else(|| TeamLocalOnlyReason::NonUtf8EnvironmentValue {
                name: name.to_owned(),
            })?;
        if value.len() > 4096
            || value
                .chars()
                .any(|character| character == '\0' || character == '\n' || character == '\r')
        {
            return Err(TeamLocalOnlyReason::UnsupportedEnvironmentValue {
                name: name.to_owned(),
            });
        }
        values.insert(
            name.to_owned(),
            digest_bytes(ENVIRONMENT_DOMAIN, value.as_bytes()),
        );
    }
    Ok(values
        .into_iter()
        .map(|(name, value_digest)| ModeledEnvironmentV1 { name, value_digest })
        .collect())
}

fn resolve_workspace_and_cwd(
    workspace: &Path,
    cwd: &Path,
) -> Result<(PathBuf, PathBuf, String), TeamLocalOnlyReason> {
    let workspace = fs::canonicalize(workspace)
        .map_err(|error| io_reason("canonicalize workspace", workspace, error))?;
    if !metadata(&workspace, "inspect workspace")?.is_dir() {
        return Err(TeamLocalOnlyReason::WorkspaceNotDirectory);
    }
    let cwd = fs::canonicalize(cwd)
        .map_err(|error| io_reason("canonicalize working directory", cwd, error))?;
    if !metadata(&cwd, "inspect working directory")?.is_dir() {
        return Err(TeamLocalOnlyReason::WorkingDirectoryNotDirectory);
    }
    let relative = cwd
        .strip_prefix(&workspace)
        .map_err(|_| TeamLocalOnlyReason::WorkingDirectoryOutsideRepository)?;
    let relative = portable_repository_path(relative, true)?;
    Ok((workspace, cwd, relative))
}

fn resolve_operand(
    workspace: &Path,
    cwd: &Path,
    spelling: &str,
    argv_index: usize,
) -> Result<ResolvedOperand, TeamLocalOnlyReason> {
    let relative_operand = Path::new(spelling);
    if spelling == "-" {
        return Err(TeamLocalOnlyReason::StdinDependent { index: argv_index });
    }
    if relative_operand.is_absolute() {
        return Err(TeamLocalOnlyReason::AbsolutePath { index: argv_index });
    }
    if relative_operand.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(TeamLocalOnlyReason::OutsideRepository { index: argv_index });
    }
    let normalized_spelling = portable_repository_path(relative_operand, false)
        .map_err(|reason| path_reason(reason, argv_index))?;
    if normalized_spelling != spelling {
        return Err(TeamLocalOnlyReason::NonCanonicalPath { index: argv_index });
    }

    let cwd_relative = cwd
        .strip_prefix(workspace)
        .map_err(|_| TeamLocalOnlyReason::WorkingDirectoryOutsideRepository)?;
    let repository_relative = if relative_operand == Path::new(".") {
        cwd_relative.to_path_buf()
    } else {
        cwd_relative.join(relative_operand)
    };
    let repository_path = portable_repository_path(&repository_relative, true)
        .map_err(|reason| path_reason(reason, argv_index))?;
    if path_is_excluded(&repository_relative) {
        return Err(TeamLocalOnlyReason::ExcludedPath { index: argv_index });
    }

    let absolute = if repository_relative.as_os_str().is_empty() {
        workspace.to_path_buf()
    } else {
        workspace.join(&repository_relative)
    };
    reject_symlink_components(workspace, &repository_relative, argv_index)?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => TeamLocalOnlyReason::MissingPath { index: argv_index },
        _ => io_reason("inspect operand", &absolute, error),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(TeamLocalOnlyReason::SymlinkPath { index: argv_index });
    }
    Ok(ResolvedOperand {
        absolute,
        repository_path,
        metadata,
    })
}

fn reject_symlink_components(
    workspace: &Path,
    relative: &Path,
    argv_index: usize,
) -> Result<(), TeamLocalOnlyReason> {
    let mut candidate = workspace.to_path_buf();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        candidate.push(value);
        let metadata = fs::symlink_metadata(&candidate).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => TeamLocalOnlyReason::MissingPath { index: argv_index },
            _ => io_reason("inspect path component", &candidate, error),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(TeamLocalOnlyReason::SymlinkPath { index: argv_index });
        }
    }
    Ok(())
}

fn portable_repository_path(path: &Path, allow_empty: bool) -> Result<String, TeamLocalOnlyReason> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or(TeamLocalOnlyReason::NonPortableFilesystemPath)?;
                if value.is_empty() || value.contains('\\') || value.chars().any(char::is_control) {
                    return Err(TeamLocalOnlyReason::NonPortableFilesystemPath);
                }
                parts.push(value);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(TeamLocalOnlyReason::WorkingDirectoryOutsideRepository);
            }
        }
    }
    if parts.is_empty() {
        if allow_empty || path == Path::new(".") {
            Ok(".".to_owned())
        } else {
            Err(TeamLocalOnlyReason::NonPortableFilesystemPath)
        }
    } else {
        Ok(parts.join("/"))
    }
}

fn path_reason(reason: TeamLocalOnlyReason, index: usize) -> TeamLocalOnlyReason {
    match reason {
        TeamLocalOnlyReason::WorkingDirectoryOutsideRepository => {
            TeamLocalOnlyReason::OutsideRepository { index }
        }
        TeamLocalOnlyReason::NonPortableFilesystemPath => {
            TeamLocalOnlyReason::NonCanonicalPath { index }
        }
        other => other,
    }
}

fn path_is_excluded(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(value) => value
            .to_str()
            .is_none_or(|value| value.starts_with('.') || value == ".again" || value == ".git"),
        _ => false,
    })
}

fn observe_file(
    resolved: &ResolvedOperand,
    argv_index: usize,
    cache: &mut dyn FileDigestCache,
    stats: &mut KeyBuildStats,
) -> Result<TeamObservationV1, TeamLocalOnlyReason> {
    if !resolved.metadata.is_file() {
        return Err(TeamLocalOnlyReason::UnsupportedFileType { index: argv_index });
    }
    let (content_digest, bytes) =
        stable_file_digest(&resolved.absolute, &resolved.metadata, cache, stats)?;
    Ok(TeamObservationV1 {
        kind: TeamObservationKindV1::File,
        repository_path: resolved.repository_path.clone(),
        content_digest: digest_from_bytes(content_digest),
        entries: 1,
        bytes,
    })
}

fn stable_file_digest(
    path: &Path,
    before: &Metadata,
    cache: &mut dyn FileDigestCache,
    stats: &mut KeyBuildStats,
) -> Result<([u8; 32], u64), TeamLocalOnlyReason> {
    if before.len() > TEAM_ALPHA_MAX_FILE_BYTES {
        return Err(TeamLocalOnlyReason::ResourceLimit {
            limit: "file_bytes",
        });
    }
    let identity = FileIdentity::from_metadata(before);
    if identity.is_valid()
        && let Some(bytes) = cache.lookup(&identity)
    {
        // A memoized digest proves a prior stable read, not current authority.
        // Re-open and compare both the descriptor and path epochs on every hit.
        let file = File::open(path).map_err(|error| io_reason("open cached file", path, error))?;
        let opened = file
            .metadata()
            .map_err(|error| io_reason("inspect open cached file", path, error))?;
        let path_after = fs::symlink_metadata(path)
            .map_err(|error| io_reason("reinspect cached file path", path, error))?;
        if !opened.is_file()
            || !same_epoch(before, &opened)
            || !same_epoch(before, &path_after)
            || !same_epoch(&opened, &path_after)
        {
            return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
        }
        stats.cache_hits = stats.cache_hits.saturating_add(1);
        return Ok((bytes, before.len()));
    }

    let mut file = File::open(path).map_err(|error| io_reason("open file", path, error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_reason("inspect open file", path, error))?;
    if !same_epoch(before, &opened) || !opened.is_file() {
        return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
    }

    let mut hasher = portable_file_content_hasher();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_reason("read file", path, error))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or(TeamLocalOnlyReason::ResourceLimit {
                limit: "file_bytes",
            })?;
        if bytes > TEAM_ALPHA_MAX_FILE_BYTES {
            return Err(TeamLocalOnlyReason::ResourceLimit {
                limit: "file_bytes",
            });
        }
        hasher.update(&buffer[..read]);
    }

    let opened_after = file
        .metadata()
        .map_err(|error| io_reason("reinspect open file", path, error))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|error| io_reason("reinspect file path", path, error))?;
    if bytes != before.len()
        || !same_epoch(before, &opened_after)
        || !same_epoch(before, &path_after)
    {
        return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
    }
    let digest = hasher.finalize();
    if identity.is_valid() {
        cache.record(&identity, *digest.as_bytes());
    }
    stats.files_hashed = stats.files_hashed.saturating_add(1);
    stats.bytes_hashed = stats.bytes_hashed.saturating_add(bytes);
    Ok((*digest.as_bytes(), bytes))
}

fn observe_tree(
    root: &Path,
    argv_index: usize,
    cache: &mut dyn FileDigestCache,
    limits: TreeTraversalLimits,
    stats: &mut KeyBuildStats,
) -> Result<TreeSummary, TeamLocalOnlyReason> {
    let before = metadata(root, "inspect tree root")?;
    if !before.is_dir() {
        return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
    }
    let mut hasher = domain_hasher(TREE_DOMAIN);
    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    walk_tree_iterative(
        root,
        argv_index,
        &mut hasher,
        &mut entries,
        &mut bytes,
        cache,
        limits,
        stats,
    )?;
    let after = metadata(root, "reinspect tree root")?;
    if !same_epoch(&before, &after) {
        return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
    }
    Ok(TreeSummary {
        digest: digest_from_hasher(hasher),
        entries,
        bytes,
    })
}

struct TreeChild {
    path: PathBuf,
    relative: String,
}

enum TreeAction {
    Visit { child: TreeChild, depth: usize },
    ExitDirectory { path: PathBuf, before: Metadata },
}

#[allow(clippy::too_many_arguments)]
fn walk_tree_iterative(
    root: &Path,
    argv_index: usize,
    hasher: &mut Hasher,
    entries: &mut u64,
    bytes: &mut u64,
    cache: &mut dyn FileDigestCache,
    limits: TreeTraversalLimits,
    stats: &mut KeyBuildStats,
) -> Result<(), TeamLocalOnlyReason> {
    let mut discovered = 0_u64;
    let root_before = metadata(root, "inspect tree directory")?;
    if !root_before.is_dir() {
        return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
    }
    let root_children = read_bounded_children(root, root, &mut discovered, limits)?;
    let mut actions = Vec::with_capacity(root_children.len().saturating_add(1));
    actions.push(TreeAction::ExitDirectory {
        path: root.to_path_buf(),
        before: root_before,
    });
    push_children_in_reverse(&mut actions, root_children, 1);

    while let Some(action) = actions.pop() {
        match action {
            TreeAction::Visit { child, depth } => {
                let child_metadata = fs::symlink_metadata(&child.path)
                    .map_err(|error| io_reason("inspect tree entry", &child.path, error))?;
                if child_metadata.file_type().is_symlink() {
                    return Err(TeamLocalOnlyReason::SymlinkPath { index: argv_index });
                }
                *entries = entries
                    .checked_add(1)
                    .ok_or(TeamLocalOnlyReason::ResourceLimit {
                        limit: "tree_entries",
                    })?;
                if *entries > limits.max_observed_entries {
                    return Err(TeamLocalOnlyReason::ResourceLimit {
                        limit: "tree_entries",
                    });
                }

                if child_metadata.is_dir() {
                    if depth > limits.max_depth {
                        return Err(TeamLocalOnlyReason::ResourceLimit {
                            limit: "tree_depth",
                        });
                    }
                    put_u8(hasher, 1);
                    put_bytes(hasher, child.relative.as_bytes());
                    let before = metadata(&child.path, "inspect tree directory")?;
                    if !before.is_dir() {
                        return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
                    }
                    let children =
                        read_bounded_children(root, &child.path, &mut discovered, limits)?;
                    actions.push(TreeAction::ExitDirectory {
                        path: child.path,
                        before,
                    });
                    push_children_in_reverse(&mut actions, children, depth.saturating_add(1));
                } else if child_metadata.is_file() {
                    let projected_bytes = bytes.checked_add(child_metadata.len()).ok_or(
                        TeamLocalOnlyReason::ResourceLimit {
                            limit: "tree_bytes",
                        },
                    )?;
                    if projected_bytes > limits.max_tree_bytes {
                        return Err(TeamLocalOnlyReason::ResourceLimit {
                            limit: "tree_bytes",
                        });
                    }
                    let (digest, size) =
                        stable_file_digest(&child.path, &child_metadata, cache, stats)?;
                    if size != child_metadata.len() {
                        return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
                    }
                    *bytes = projected_bytes;
                    put_u8(hasher, 3);
                    put_bytes(hasher, child.relative.as_bytes());
                    hasher.update(&digest);
                    put_u64(hasher, size);
                } else {
                    return Err(TeamLocalOnlyReason::UnsupportedFileType { index: argv_index });
                }
            }
            TreeAction::ExitDirectory { path, before } => {
                let after = metadata(&path, "reinspect tree directory")?;
                if !same_epoch(&before, &after) {
                    return Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation);
                }
                if path != root {
                    put_u8(hasher, 2);
                }
            }
        }
    }
    Ok(())
}

fn read_bounded_children(
    root: &Path,
    directory: &Path,
    discovered: &mut u64,
    limits: TreeTraversalLimits,
) -> Result<Vec<TreeChild>, TeamLocalOnlyReason> {
    let reader = fs::read_dir(directory)
        .map_err(|error| io_reason("read tree directory", directory, error))?;
    let mut directory_entries = 0_u64;
    let initial_capacity = limits.max_directory_entries.min(256) as usize;
    let mut names = Vec::with_capacity(initial_capacity);
    for entry in reader {
        let entry = entry.map_err(|error| io_reason("read tree entry", directory, error))?;
        directory_entries =
            directory_entries
                .checked_add(1)
                .ok_or(TeamLocalOnlyReason::ResourceLimit {
                    limit: "directory_entries",
                })?;
        if directory_entries > limits.max_directory_entries {
            return Err(TeamLocalOnlyReason::ResourceLimit {
                limit: "directory_entries",
            });
        }
        *discovered = discovered
            .checked_add(1)
            .ok_or(TeamLocalOnlyReason::ResourceLimit {
                limit: "discovered_tree_entries",
            })?;
        if *discovered > limits.max_discovered_entries {
            return Err(TeamLocalOnlyReason::ResourceLimit {
                limit: "discovered_tree_entries",
            });
        }
        names.push(entry.file_name());
    }
    // Sort raw names before UTF-8/type validation, preserving the recursive
    // walker's deterministic path and error order for every admitted tree.
    names.sort_unstable();
    let mut children = Vec::with_capacity(names.len());
    for name in names {
        let name = name
            .into_string()
            .map_err(|_| TeamLocalOnlyReason::NonPortableFilesystemPath)?;
        // `rg --no-ignore` still excludes hidden paths unless `--hidden` is
        // supplied; that flag is intentionally outside this alpha subset.
        if name.starts_with('.') {
            continue;
        }
        if name.contains('\\') || name.chars().any(char::is_control) {
            return Err(TeamLocalOnlyReason::NonPortableFilesystemPath);
        }
        let path = directory.join(&name);
        let relative = path
            .strip_prefix(root)
            .map_err(|_| TeamLocalOnlyReason::ConcurrentFilesystemMutation)?;
        let relative = portable_repository_path(relative, false)?;
        children.push(TreeChild { path, relative });
    }
    Ok(children)
}

fn push_children_in_reverse(actions: &mut Vec<TreeAction>, children: Vec<TreeChild>, depth: usize) {
    actions.extend(
        children
            .into_iter()
            .rev()
            .map(|child| TreeAction::Visit { child, depth }),
    );
}

fn same_epoch(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn metadata(path: &Path, operation: &'static str) -> Result<Metadata, TeamLocalOnlyReason> {
    fs::metadata(path).map_err(|error| io_reason(operation, path, error))
}

fn io_reason(operation: &'static str, path: &Path, error: io::Error) -> TeamLocalOnlyReason {
    TeamLocalOnlyReason::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

fn digest_descriptor(descriptor: &TeamRequestDescriptorV1) -> Digest {
    let mut hasher = domain_hasher(REQUEST_DOMAIN);
    put_u16(&mut hasher, descriptor.schema_version);
    put_bytes(&mut hasher, descriptor.tenant_id.as_bytes());
    put_bytes(&mut hasher, descriptor.repository_id.as_bytes());
    put_bytes(&mut hasher, descriptor.generation_id.as_bytes());
    put_bytes(&mut hasher, descriptor.repository_relative_cwd.as_bytes());
    put_u64(&mut hasher, descriptor.normalized_argv.len() as u64);
    for value in &descriptor.normalized_argv {
        put_bytes(&mut hasher, value.as_bytes());
    }
    put_u64(&mut hasher, descriptor.modeled_environment.len() as u64);
    for value in &descriptor.modeled_environment {
        put_bytes(&mut hasher, value.name.as_bytes());
        hasher.update(value.value_digest.as_bytes());
    }
    put_u64(&mut hasher, descriptor.observations.len() as u64);
    for observation in &descriptor.observations {
        put_u8(
            &mut hasher,
            match observation.kind {
                TeamObservationKindV1::File => 1,
                TeamObservationKindV1::RecursiveTree => 2,
            },
        );
        put_bytes(&mut hasher, observation.repository_path.as_bytes());
        hasher.update(observation.content_digest.as_bytes());
        put_u64(&mut hasher, observation.entries);
        put_u64(&mut hasher, observation.bytes);
    }
    hasher.update(descriptor.policy_digest.as_bytes());
    hasher.update(descriptor.execution_profile_digest.as_bytes());
    hasher.update(descriptor.platform_digest.as_bytes());
    hasher.update(descriptor.image_digest.as_bytes());
    digest_from_hasher(hasher)
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = domain_hasher(domain);
    put_bytes(&mut hasher, bytes);
    digest_from_hasher(hasher)
}

fn domain_hasher(domain: &[u8]) -> Hasher {
    let mut hasher = Hasher::new();
    put_bytes(&mut hasher, domain);
    hasher
}

fn digest_from_hasher(hasher: Hasher) -> Digest {
    digest_from_bytes(*hasher.finalize().as_bytes())
}

fn digest_from_bytes(bytes: [u8; 32]) -> Digest {
    Digest::from_hex(blake3::Hash::from_bytes(bytes).to_hex().as_ref())
        .expect("BLAKE3 always produces a lower-case 32-byte digest")
}

fn put_u8(hasher: &mut Hasher, value: u8) {
    hasher.update(&[value]);
}

fn put_u16(hasher: &mut Hasher, value: u16) {
    hasher.update(&value.to_le_bytes());
}

fn put_u64(hasher: &mut Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn put_bytes(hasher: &mut Hasher, value: &[u8]) {
    put_u64(hasher, value.len() as u64);
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::{FileTimes, OpenOptions};
    use std::time::Instant;

    use super::*;
    use crate::fingerprint::SessionFileDigestCache;
    use crate::store::Store;
    use tempfile::TempDir;

    const GENERATION: &str = "0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct CountingCache {
        digests: HashMap<FileIdentity, [u8; 32]>,
        lookups: u64,
        hits: u64,
        records: u64,
        recorded_bytes: u64,
    }

    impl FileDigestCache for CountingCache {
        fn lookup(&mut self, identity: &FileIdentity) -> Option<[u8; 32]> {
            self.lookups = self.lookups.saturating_add(1);
            let result = self.digests.get(identity).copied();
            if result.is_some() {
                self.hits = self.hits.saturating_add(1);
            }
            result
        }

        fn record(&mut self, identity: &FileIdentity, digest: [u8; 32]) {
            self.records = self.records.saturating_add(1);
            self.recorded_bytes = self.recorded_bytes.saturating_add(identity.size);
            self.digests.insert(*identity, digest);
        }
    }

    fn digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn environment(values: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        values
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    fn fixture() -> TempDir {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("src/nested")).unwrap();
        fs::write(temp.path().join("README.md"), "portable\n").unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        fs::write(temp.path().join("src/nested/data.txt"), "alpha\nbeta\n").unwrap();
        fs::create_dir(temp.path().join(".git")).unwrap();
        fs::write(temp.path().join(".git/index"), "ignored hidden state").unwrap();
        temp
    }

    fn key(
        root: &Path,
        cwd: &Path,
        argv: &[OsString],
        env: &[(OsString, OsString)],
        profile: Digest,
    ) -> Result<TeamRequestKeyV1, TeamLocalOnlyReason> {
        build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: "tenant-a",
            repository_id: "repo-a",
            generation_id: GENERATION,
            workspace: root,
            cwd,
            argv,
            environment: env,
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: digest(1),
            execution_profile_digest: profile,
            platform_digest: digest(3),
            image_digest: digest(4),
        })
    }

    fn attested_input_for_environment<'a>(
        root: &'a Path,
        argv: &'a [OsString],
        environment: &'a [(OsString, OsString)],
    ) -> Result<TeamRequestKeyInput<'a>, RuntimeBindingError> {
        let (runtime, _invalidator) =
            TeamRuntimeAttestationV1::new_for_test("cat", digest(3), digest(4));
        TeamRequestKeyInput::new_attested(
            UnboundTeamRequestKeyInput {
                tenant_id: "tenant-a",
                repository_id: "repo-a",
                generation_id: GENERATION,
                workspace: root,
                cwd: root,
                argv,
                environment,
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
                policy_digest: digest(1),
                execution_profile_digest: digest(2),
            },
            &runtime,
        )
    }

    fn key_with_cache_and_limits(
        root: &Path,
        cwd: &Path,
        argv: &[OsString],
        cache: &mut dyn FileDigestCache,
        limits: TreeTraversalLimits,
    ) -> (Result<TeamRequestKeyV1, TeamLocalOnlyReason>, KeyBuildStats) {
        let mut stats = KeyBuildStats::default();
        let result = build_team_request_key_v1_with_options(
            &TeamRequestKeyInput {
                tenant_id: "tenant-a",
                repository_id: "repo-a",
                generation_id: GENERATION,
                workspace: root,
                cwd,
                argv,
                environment: &[],
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
                policy_digest: digest(1),
                execution_profile_digest: digest(2),
                platform_digest: digest(3),
                image_digest: digest(4),
            },
            cache,
            limits,
            &mut stats,
        );
        (result, stats)
    }

    #[test]
    fn equivalent_copies_at_different_roots_have_the_same_key() {
        let left = fixture();
        let right = fixture();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let env = environment(&[("TZ", "UTC"), ("LC_ALL", "C")]);

        let left_key = key(left.path(), left.path(), &argv, &env, digest(2)).unwrap();
        let right_key = key(right.path(), right.path(), &argv, &env, digest(2)).unwrap();

        assert_eq!(left_key.digest, right_key.digest);
        assert_eq!(left_key.descriptor, right_key.descriptor);
        assert_eq!(left_key.descriptor.repository_relative_cwd, ".");
        assert!(!format!("{:?}", left_key.descriptor).contains(left.path().to_str().unwrap()));
    }

    #[test]
    fn cached_uncached_and_equivalent_roots_have_identical_keys() {
        let left = fixture();
        let right = fixture();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let uncached_left = key(left.path(), left.path(), &argv, &[], digest(2)).unwrap();
        let uncached_right = key(right.path(), right.path(), &argv, &[], digest(2)).unwrap();

        let mut cache = CountingCache::default();
        let (cold, cold_stats) = key_with_cache_and_limits(
            left.path(),
            left.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );
        let (warm, warm_stats) = key_with_cache_and_limits(
            left.path(),
            left.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );

        assert_eq!(uncached_left, uncached_right);
        assert_eq!(uncached_left, cold.unwrap());
        assert_eq!(uncached_left, warm.unwrap());
        assert_eq!(cold_stats.files_hashed, 3);
        assert_eq!(cold_stats.bytes_hashed, 38);
        assert_eq!(cold_stats.cache_hits, 0);
        assert_eq!(
            warm_stats.files_hashed, 0,
            "warm files must not be byte-read"
        );
        assert_eq!(
            warm_stats.bytes_hashed, 0,
            "warm files must not be byte-read"
        );
        assert_eq!(warm_stats.cache_hits, 3);
        assert_eq!(cache.records, 3);
        assert_eq!(cache.hits, 3);
        assert_eq!(cache.lookups, 6);
        assert_eq!(cache.recorded_bytes, 38);
    }

    #[test]
    fn portable_key_reuses_the_persistent_store_digest_cache_after_reopen() {
        use crate::store::Store;

        let workspace = fixture();
        let state = TempDir::new().unwrap();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let state_root = state.path().join("state");
        let mut store = Store::open(&state_root).unwrap();
        let (cold, cold_stats) = key_with_cache_and_limits(
            workspace.path(),
            workspace.path(),
            &argv,
            &mut store,
            TreeTraversalLimits::default(),
        );
        assert_eq!(cold_stats.files_hashed, 3);
        drop(store);

        let mut reopened = Store::open(&state_root).unwrap();
        let (warm, warm_stats) = key_with_cache_and_limits(
            workspace.path(),
            workspace.path(),
            &argv,
            &mut reopened,
            TreeTraversalLimits::default(),
        );
        assert_eq!(cold.unwrap(), warm.unwrap());
        assert_eq!(warm_stats.files_hashed, 0);
        assert_eq!(warm_stats.bytes_hashed, 0);
        assert_eq!(warm_stats.cache_hits, 3);
    }

    #[test]
    fn cached_file_digest_is_the_native_portable_content_hash() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("selected"), b"portable bytes").unwrap();
        let argv = os(&["cat", "selected"]);
        let result = key(temp.path(), temp.path(), &argv, &[], digest(2)).unwrap();
        let mut expected = portable_file_content_hasher();
        expected.update(b"portable bytes");
        assert_eq!(
            result.descriptor().observations()[0].content_digest(),
            digest_from_bytes(*expected.finalize().as_bytes())
        );
        assert_eq!(result.descriptor().observations()[0].bytes(), 14);
        assert_eq!(
            result.descriptor().observations()[0].repository_path(),
            "selected"
        );
    }

    #[test]
    fn cached_hit_rechecks_opened_and_path_identity() {
        struct ReplacingCache {
            identity: FileIdentity,
            digest: [u8; 32],
            path: PathBuf,
            replacement: Option<PathBuf>,
        }

        impl FileDigestCache for ReplacingCache {
            fn lookup(&mut self, identity: &FileIdentity) -> Option<[u8; 32]> {
                if *identity != self.identity {
                    return None;
                }
                fs::rename(self.replacement.take().unwrap(), &self.path).unwrap();
                Some(self.digest)
            }

            fn record(&mut self, _identity: &FileIdentity, _digest: [u8; 32]) {}
        }

        let temp = TempDir::new().unwrap();
        let selected = temp.path().join("selected");
        let replacement = temp.path().join("replacement");
        fs::write(&selected, b"before").unwrap();
        fs::write(&replacement, b"after!").unwrap();
        let identity = FileIdentity::from_metadata(&fs::metadata(&selected).unwrap());
        let mut content = portable_file_content_hasher();
        content.update(b"before");
        let mut cache = ReplacingCache {
            identity,
            digest: *content.finalize().as_bytes(),
            path: selected,
            replacement: Some(replacement),
        };
        let argv = os(&["cat", "selected"]);
        let (result, _) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );
        assert_eq!(
            result,
            Err(TeamLocalOnlyReason::ConcurrentFilesystemMutation)
        );
    }

    #[test]
    fn iterative_tree_refuses_excessive_depth_before_descending() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("a/b/c")).unwrap();
        fs::write(temp.path().join("a/b/c/value.txt"), "value\n").unwrap();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let limits = TreeTraversalLimits {
            max_depth: 2,
            ..TreeTraversalLimits::default()
        };
        let (result, _) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut CountingCache::default(),
            limits,
        );
        assert_eq!(
            result,
            Err(TeamLocalOnlyReason::ResourceLimit {
                limit: "tree_depth"
            })
        );
    }

    #[test]
    fn iterative_tree_caps_one_directory_before_collecting_it() {
        let temp = TempDir::new().unwrap();
        for index in 0..3 {
            fs::write(temp.path().join(format!("{index}.txt")), "value\n").unwrap();
        }
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let limits = TreeTraversalLimits {
            max_directory_entries: 2,
            ..TreeTraversalLimits::default()
        };
        let (result, _) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut CountingCache::default(),
            limits,
        );
        assert_eq!(
            result,
            Err(TeamLocalOnlyReason::ResourceLimit {
                limit: "directory_entries"
            })
        );
    }

    #[test]
    fn iterative_tree_caps_total_discovered_entries() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("a")).unwrap();
        fs::create_dir_all(temp.path().join("b")).unwrap();
        fs::write(temp.path().join("a/one"), "one").unwrap();
        fs::write(temp.path().join("b/two"), "two").unwrap();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let limits = TreeTraversalLimits {
            max_discovered_entries: 3,
            ..TreeTraversalLimits::default()
        };
        let (result, _) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut CountingCache::default(),
            limits,
        );
        assert_eq!(
            result,
            Err(TeamLocalOnlyReason::ResourceLimit {
                limit: "discovered_tree_entries"
            })
        );
    }

    #[test]
    fn iterative_tree_preserves_sorted_enter_exit_encoding() {
        let temp = fixture();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let result = key(temp.path(), temp.path(), &argv, &[], digest(2)).unwrap();

        fn content(bytes: &[u8]) -> Digest {
            let mut hasher = portable_file_content_hasher();
            hasher.update(bytes);
            digest_from_bytes(*hasher.finalize().as_bytes())
        }

        let mut expected = domain_hasher(TREE_DOMAIN);
        put_u8(&mut expected, 3);
        put_bytes(&mut expected, b"README.md");
        expected.update(content(b"portable\n").as_bytes());
        put_u64(&mut expected, 9);
        put_u8(&mut expected, 1);
        put_bytes(&mut expected, b"src");
        put_u8(&mut expected, 3);
        put_bytes(&mut expected, b"src/lib.rs");
        expected.update(content(b"pub fn value() {}\n").as_bytes());
        put_u64(&mut expected, 18);
        put_u8(&mut expected, 1);
        put_bytes(&mut expected, b"src/nested");
        put_u8(&mut expected, 3);
        put_bytes(&mut expected, b"src/nested/data.txt");
        expected.update(content(b"alpha\nbeta\n").as_bytes());
        put_u64(&mut expected, 11);
        put_u8(&mut expected, 2);
        put_u8(&mut expected, 2);

        let observation = &result.descriptor().observations()[0];
        assert_eq!(observation.content_digest(), digest_from_hasher(expected));
        assert_eq!(observation.entries(), 5);
        assert_eq!(observation.bytes(), 38);
    }

    #[cfg(unix)]
    #[test]
    fn iterative_tree_rejects_visible_symlink_and_special_entries() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);

        let symlink_tree = TempDir::new().unwrap();
        fs::write(symlink_tree.path().join("target"), "value").unwrap();
        symlink("target", symlink_tree.path().join("link")).unwrap();
        assert_eq!(
            key(
                symlink_tree.path(),
                symlink_tree.path(),
                &argv,
                &[],
                digest(2)
            ),
            Err(TeamLocalOnlyReason::SymlinkPath { index: 4 })
        );

        let special_tree = TempDir::new().unwrap();
        let _listener = UnixListener::bind(special_tree.path().join("socket")).unwrap();
        assert_eq!(
            key(
                special_tree.path(),
                special_tree.path(),
                &argv,
                &[],
                digest(2)
            ),
            Err(TeamLocalOnlyReason::UnsupportedFileType { index: 4 })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn iterative_tree_rejects_non_utf8_entries_even_when_hidden() {
        use std::os::unix::ffi::OsStringExt;

        let tree = TempDir::new().unwrap();
        fs::write(
            tree.path().join(OsString::from_vec(vec![b'.', 0xff])),
            "hidden but non-portable",
        )
        .unwrap();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        assert_eq!(
            key(tree.path(), tree.path(), &argv, &[], digest(2)),
            Err(TeamLocalOnlyReason::NonPortableFilesystemPath)
        );
    }

    #[test]
    fn ctime_change_forces_rehash_and_content_change_changes_key() {
        let temp = TempDir::new().unwrap();
        let selected = temp.path().join("selected.txt");
        fs::write(&selected, b"before").unwrap();
        let argv = os(&["cat", "selected.txt"]);
        let mut cache = CountingCache::default();
        let original = fs::metadata(&selected).unwrap();
        let (first, first_stats) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );
        assert_eq!(first_stats.files_hashed, 1);

        fs::write(&selected, b"after!").unwrap();
        OpenOptions::new()
            .write(true)
            .open(&selected)
            .unwrap()
            .set_times(FileTimes::new().set_modified(original.modified().unwrap()))
            .unwrap();
        let changed = fs::metadata(&selected).unwrap();
        assert_eq!(original.len(), changed.len());
        assert_eq!(original.mtime(), changed.mtime());
        assert_eq!(original.mtime_nsec(), changed.mtime_nsec());
        assert_ne!(
            (original.ctime(), original.ctime_nsec()),
            (changed.ctime(), changed.ctime_nsec())
        );

        let (second, second_stats) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );
        assert_ne!(first.unwrap().digest(), second.unwrap().digest());
        assert_eq!(second_stats.cache_hits, 0);
        assert_eq!(second_stats.files_hashed, 1);
        assert_eq!(second_stats.bytes_hashed, 6);
        assert_eq!(cache.records, 2);
    }

    #[test]
    fn inode_replacement_is_rehashed_even_when_portable_content_is_equal() {
        let temp = TempDir::new().unwrap();
        let selected = temp.path().join("selected.txt");
        let replacement = temp.path().join("replacement");
        fs::write(&selected, b"stable").unwrap();
        let argv = os(&["cat", "selected.txt"]);
        let mut cache = CountingCache::default();
        let original = fs::metadata(&selected).unwrap();
        let (first, _) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );

        fs::write(&replacement, b"stable").unwrap();
        OpenOptions::new()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(FileTimes::new().set_modified(original.modified().unwrap()))
            .unwrap();
        fs::rename(&replacement, &selected).unwrap();
        let replaced = fs::metadata(&selected).unwrap();
        assert_ne!(original.ino(), replaced.ino());

        let (second, stats) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );
        assert_eq!(first.unwrap(), second.unwrap());
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.files_hashed, 1);
        assert_eq!(stats.bytes_hashed, 6);
        assert_eq!(cache.records, 2);
    }

    #[test]
    #[ignore = "diagnostic cold/warm portable-key benchmark"]
    fn benchmark_cold_and_warm_portable_key_construction() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        let body = vec![b'x'; 16 * 1024];
        for index in 0..256 {
            fs::write(temp.path().join(format!("src/{index:04}.txt")), &body).unwrap();
        }
        let argv = os(&["rg", "--no-ignore", "--sort=path", "x", "src"]);
        let mut cache = CountingCache::default();

        let cold_start = Instant::now();
        let (cold, cold_stats) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );
        let cold_elapsed = cold_start.elapsed();
        let warm_start = Instant::now();
        let (warm, warm_stats) = key_with_cache_and_limits(
            temp.path(),
            temp.path(),
            &argv,
            &mut cache,
            TreeTraversalLimits::default(),
        );
        let warm_elapsed = warm_start.elapsed();

        assert_eq!(cold.unwrap(), warm.unwrap());
        assert_eq!(cold_stats.bytes_hashed, 4 * 1024 * 1024);
        assert_eq!(warm_stats.bytes_hashed, 0);
        assert_eq!(warm_stats.cache_hits, 256);
        eprintln!(
            "portable_key_benchmark cold_us={} warm_us={} cold_bytes_hashed={} warm_bytes_hashed={} warm_cache_hits={}",
            cold_elapsed.as_micros(),
            warm_elapsed.as_micros(),
            cold_stats.bytes_hashed,
            warm_stats.bytes_hashed,
            warm_stats.cache_hits,
        );
    }

    #[test]
    #[ignore = "diagnostic 1k/10k Store-backed session digest-cache benchmark"]
    fn benchmark_store_backed_session_cache_at_team_scale() {
        for file_count in [1_000_usize, 10_000] {
            let workspace = TempDir::new().unwrap();
            let state = TempDir::new().unwrap();
            fs::create_dir(workspace.path().join("src")).unwrap();
            for index in 0..file_count {
                let shard = workspace.path().join(format!("src/{:03}", index / 100));
                fs::create_dir_all(&shard).unwrap();
                fs::write(
                    shard.join(format!("{index:05}.txt")),
                    format!("stable benchmark payload {index:05}\n"),
                )
                .unwrap();
            }
            let argv = os(&["rg", "--no-ignore", "--sort=path", "payload", "src"]);
            let mut store = Store::open(state.path().join("store")).unwrap();
            let mut session = SessionFileDigestCache::new(&mut store);

            let cold_started = Instant::now();
            let (cold, cold_stats) = key_with_cache_and_limits(
                workspace.path(),
                workspace.path(),
                &argv,
                &mut session,
                TreeTraversalLimits::default(),
            );
            let cold_micros = cold_started.elapsed().as_micros();
            let same_session_started = Instant::now();
            let (same_session, same_session_stats) = key_with_cache_and_limits(
                workspace.path(),
                workspace.path(),
                &argv,
                &mut session,
                TreeTraversalLimits::default(),
            );
            let same_session_micros = same_session_started.elapsed().as_micros();
            drop(session);

            let mut reopened_session = SessionFileDigestCache::new(&mut store);
            let persistent_started = Instant::now();
            let (persistent, persistent_stats) = key_with_cache_and_limits(
                workspace.path(),
                workspace.path(),
                &argv,
                &mut reopened_session,
                TreeTraversalLimits::default(),
            );
            let persistent_micros = persistent_started.elapsed().as_micros();

            assert_eq!(cold.as_ref().unwrap(), same_session.as_ref().unwrap());
            assert_eq!(cold.as_ref().unwrap(), persistent.as_ref().unwrap());
            assert_eq!(cold_stats.files_hashed, file_count as u64);
            assert_eq!(same_session_stats.files_hashed, 0);
            assert_eq!(same_session_stats.cache_hits, file_count as u64);
            assert_eq!(persistent_stats.files_hashed, 0);
            assert_eq!(persistent_stats.cache_hits, file_count as u64);
            eprintln!(
                "team_session_cache_benchmark files={file_count} cold_us={cold_micros} same_session_us={same_session_micros} reopened_store_us={persistent_micros} cold_bytes_hashed={} same_session_cache_hits={} reopened_store_cache_hits={}",
                cold_stats.bytes_hashed, same_session_stats.cache_hits, persistent_stats.cache_hits,
            );
        }
    }

    #[test]
    fn every_relevant_request_dimension_changes_the_key() {
        let temp = fixture();
        let env = environment(&[("LC_ALL", "C"), ("TZ", "UTC")]);
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "src"]);
        let baseline = key(temp.path(), temp.path(), &argv, &env, digest(2))
            .unwrap()
            .digest;

        fs::write(temp.path().join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        let changed_content = key(temp.path(), temp.path(), &argv, &env, digest(2))
            .unwrap()
            .digest;
        assert_ne!(baseline, changed_content);

        fs::write(temp.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        fs::rename(
            temp.path().join("src/nested/data.txt"),
            temp.path().join("src/nested/renamed.txt"),
        )
        .unwrap();
        let changed_tree_path = key(temp.path(), temp.path(), &argv, &env, digest(2))
            .unwrap()
            .digest;
        assert_ne!(baseline, changed_tree_path);

        fs::rename(
            temp.path().join("src/nested/renamed.txt"),
            temp.path().join("src/nested/data.txt"),
        )
        .unwrap();
        let changed_argv = os(&["rg", "--no-ignore", "--sort=path", "changed", "src"]);
        assert_ne!(
            baseline,
            key(temp.path(), temp.path(), &changed_argv, &env, digest(2))
                .unwrap()
                .digest
        );

        let changed_env = environment(&[("LC_ALL", "C"), ("TZ", "GMT")]);
        assert_ne!(
            baseline,
            key(temp.path(), temp.path(), &argv, &changed_env, digest(2))
                .unwrap()
                .digest
        );
        assert_ne!(
            baseline,
            key(temp.path(), temp.path(), &argv, &env, digest(9))
                .unwrap()
                .digest
        );
    }

    #[test]
    fn namespace_and_every_policy_identity_are_bound() {
        let temp = fixture();
        let argv = os(&["cat", "README.md"]);
        let baseline = key(temp.path(), temp.path(), &argv, &[], digest(2)).unwrap();
        let baseline_digest = baseline.digest;

        let mut variants = Vec::new();
        let mut descriptor = baseline.descriptor.clone();
        descriptor.tenant_id = "tenant-b".to_owned();
        variants.push(descriptor);
        let mut descriptor = baseline.descriptor.clone();
        descriptor.repository_id = "repo-b".to_owned();
        variants.push(descriptor);
        let mut descriptor = baseline.descriptor.clone();
        descriptor.policy_digest = digest(8);
        variants.push(descriptor);
        let mut descriptor = baseline.descriptor.clone();
        descriptor.execution_profile_digest = digest(8);
        variants.push(descriptor);
        let mut descriptor = baseline.descriptor.clone();
        descriptor.platform_digest = digest(8);
        variants.push(descriptor);
        let mut descriptor = baseline.descriptor;
        descriptor.image_digest = digest(8);
        variants.push(descriptor);

        for descriptor in variants {
            assert_ne!(baseline_digest, digest_descriptor(&descriptor));
        }

        let long_namespace = "a".repeat(129);
        for invalid in [
            "",
            "-leading",
            ".leading",
            "tenant/repository",
            "tenant@example",
            long_namespace.as_str(),
        ] {
            assert_eq!(
                validate_namespace(invalid, "tenant_id"),
                Err(TeamLocalOnlyReason::InvalidNamespace { field: "tenant_id" })
            );
        }
        for valid in ["a", "tenant-a", "tenant_a", "tenant.a", "tenant:a"] {
            validate_namespace(valid, "tenant_id").unwrap();
        }
    }

    #[test]
    fn repository_relative_cwd_and_file_path_are_bound() {
        let temp = fixture();
        let env = environment(&[("LC_ALL", "C")]);
        let argv = os(&["cat", "nested/data.txt"]);
        let result = key(
            temp.path(),
            &temp.path().join("src"),
            &argv,
            &env,
            digest(2),
        )
        .unwrap();
        assert_eq!(result.descriptor.repository_relative_cwd, "src");
        assert_eq!(
            result.descriptor.observations[0].repository_path,
            "src/nested/data.txt"
        );
    }

    #[test]
    fn admits_each_narrow_command_family() {
        let temp = fixture();
        let env = environment(&[("LC_ALL", "C")]);
        let cases = [
            os(&["cat", "README.md"]),
            os(&["head", "--lines=2", "README.md"]),
            os(&["tail", "-c", "4", "README.md"]),
            os(&["wc", "--bytes", "README.md"]),
            os(&["grep", "-F", "portable", "README.md"]),
            os(&["rg", "--no-ignore", "--sort=path", "value", "src"]),
        ];
        for argv in cases {
            key(temp.path(), temp.path(), &argv, &env, digest(2)).unwrap();
        }
    }

    #[test]
    fn unsupported_commands_and_ambient_inputs_are_typed_local_only() {
        let temp = fixture();
        let empty_env = Vec::new();
        for command in ["pwd", "ls", "cargo"] {
            let argv = os(&[command]);
            assert!(matches!(
                key(temp.path(), temp.path(), &argv, &empty_env, digest(2)),
                Err(TeamLocalOnlyReason::UnsupportedCommand { .. })
            ));
        }

        let argv = os(&["cat", "README.md"]);
        let unsupported_env = environment(&[("PATH", "/bin")]);
        assert_eq!(
            key(temp.path(), temp.path(), &argv, &unsupported_env, digest(2)),
            Err(TeamLocalOnlyReason::UnsupportedEnvironment {
                name: "PATH".to_owned()
            })
        );
        let tty = build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: "tenant-a",
            repository_id: "repo-a",
            generation_id: GENERATION,
            workspace: temp.path(),
            cwd: temp.path(),
            argv: &argv,
            environment: &empty_env,
            stdin_is_tty: false,
            stdout_is_tty: true,
            stderr_is_tty: false,
            policy_digest: digest(1),
            execution_profile_digest: digest(2),
            platform_digest: digest(3),
            image_digest: digest(4),
        });
        assert_eq!(tty, Err(TeamLocalOnlyReason::TtyDependent));

        let duplicate_env = environment(&[("LC_ALL", "C"), ("LC_ALL", "C")]);
        assert_eq!(
            key(temp.path(), temp.path(), &argv, &duplicate_env, digest(2)),
            Err(TeamLocalOnlyReason::DuplicateEnvironment {
                name: "LC_ALL".to_owned()
            })
        );
        let control_env = environment(&[("TZ", "UTC\nBAD")]);
        assert_eq!(
            key(temp.path(), temp.path(), &argv, &control_env, digest(2)),
            Err(TeamLocalOnlyReason::UnsupportedEnvironmentValue {
                name: "TZ".to_owned()
            })
        );
    }

    #[test]
    fn absolute_parent_hidden_and_nondeterministic_rg_paths_are_local_only() {
        let temp = fixture();
        let env = Vec::new();
        let absolute = os(&["cat", temp.path().join("README.md").to_str().unwrap()]);
        assert!(matches!(
            key(temp.path(), temp.path(), &absolute, &env, digest(2)),
            Err(TeamLocalOnlyReason::AbsolutePath { index: 1 })
        ));
        for argv in [
            os(&["cat", "../outside"]),
            os(&["cat", ".git/index"]),
            os(&["cat", "./README.md"]),
            os(&["rg", "needle", "src"]),
            os(&["rg", "-H", "--no-ignore", "--sort=path", "needle", "."]),
            os(&["tail", "+2", "README.md"]),
            os(&["head", "README.md", "-n"]),
        ] {
            assert!(key(temp.path(), temp.path(), &argv, &env, digest(2)).is_err());
        }
    }

    #[test]
    fn stdin_sentinel_is_rejected_even_after_option_delimiter() {
        let temp = fixture();
        for argv in [
            os(&["cat", "--", "-"]),
            os(&["head", "--", "-"]),
            os(&["wc", "-c", "--", "-"]),
            os(&["grep", "--", "needle", "-"]),
            os(&["rg", "--no-ignore", "--sort=path", "--", "needle", "-"]),
        ] {
            let index = argv.len() - 1;
            assert_eq!(
                key(temp.path(), temp.path(), &argv, &[], digest(2)),
                Err(TeamLocalOnlyReason::StdinDependent { index })
            );
        }
    }

    #[test]
    fn dash_patterns_and_filenames_require_an_explicit_delimiter() {
        let temp = fixture();
        fs::write(temp.path().join("-data.txt"), "-needle\n").unwrap();

        for argv in [
            os(&["grep", "--", "-needle", "README.md"]),
            os(&["rg", "--no-ignore", "--sort=path", "--", "-needle", "src"]),
            os(&["cat", "--", "-data.txt"]),
            os(&["head", "--", "-data.txt"]),
            os(&["wc", "-c", "--", "-data.txt"]),
            os(&["grep", "--", "needle", "-data.txt"]),
            os(&[
                "rg",
                "--no-ignore",
                "--sort=path",
                "--",
                "needle",
                "-data.txt",
            ]),
        ] {
            key(temp.path(), temp.path(), &argv, &[], digest(2)).unwrap();
        }

        for argv in [
            os(&["grep", "-needle", "README.md"]),
            os(&["rg", "--no-ignore", "--sort=path", "-needle", "src"]),
            os(&["cat", "-data.txt"]),
            os(&["head", "-data.txt"]),
            os(&["wc", "-c", "-data.txt"]),
            os(&["grep", "needle", "-data.txt"]),
        ] {
            assert!(matches!(
                key(temp.path(), temp.path(), &argv, &[], digest(2)),
                Err(TeamLocalOnlyReason::UnsupportedArgument { .. })
            ));
        }
    }

    #[test]
    fn deterministic_rg_excludes_hidden_tree_state() {
        let temp = fixture();
        let argv = os(&["rg", "--no-ignore", "--sort=path", "value", "."]);
        let baseline = key(temp.path(), temp.path(), &argv, &[], digest(2))
            .unwrap()
            .digest;

        fs::write(temp.path().join(".secret"), "hidden value\n").unwrap();
        fs::write(temp.path().join(".git/index"), "changed hidden state").unwrap();
        assert_eq!(
            baseline,
            key(temp.path(), temp.path(), &argv, &[], digest(2))
                .unwrap()
                .digest
        );

        fs::write(temp.path().join("visible.txt"), "visible value\n").unwrap();
        assert_ne!(
            baseline,
            key(temp.path(), temp.path(), &argv, &[], digest(2))
                .unwrap()
                .digest
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_typed_local_only() {
        use std::os::unix::fs::symlink;

        let temp = fixture();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret"), "do not share").unwrap();
        symlink(outside.path(), temp.path().join("escape")).unwrap();
        let argv = os(&["cat", "escape/secret"]);
        assert_eq!(
            key(temp.path(), temp.path(), &argv, &[], digest(2)),
            Err(TeamLocalOnlyReason::SymlinkPath { index: 1 })
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argv_and_environment_are_typed_local_only() {
        use std::os::unix::ffi::OsStringExt;

        let temp = fixture();
        let argv = vec![OsString::from("cat"), OsString::from_vec(vec![0xff])];
        assert_eq!(
            key(temp.path(), temp.path(), &argv, &[], digest(2)),
            Err(TeamLocalOnlyReason::NonUtf8Argument { index: 1 })
        );

        let argv = os(&["cat", "README.md"]);
        let environment = vec![(OsString::from_vec(vec![0xff]), OsString::from("C"))];
        assert_eq!(
            key(temp.path(), temp.path(), &argv, &environment, digest(2)),
            Err(TeamLocalOnlyReason::NonUtf8EnvironmentName { index: 0 })
        );
        let environment = vec![(OsString::from("LC_ALL"), OsString::from_vec(vec![0xff]))];
        assert_eq!(
            key(temp.path(), temp.path(), &argv, &environment, digest(2)),
            Err(TeamLocalOnlyReason::NonUtf8EnvironmentValue {
                name: "LC_ALL".to_owned()
            })
        );
    }

    #[test]
    fn environment_order_is_canonical_but_values_are_not_retained() {
        let temp = fixture();
        let argv = os(&["cat", "README.md"]);
        let sentinel = "DO_NOT_RETAIN_THIS_ENVIRONMENT_VALUE";
        let left = environment(&[("TZ", sentinel), ("LC_ALL", "C")]);
        let right = environment(&[("LC_ALL", "C"), ("TZ", sentinel)]);
        let left = key(temp.path(), temp.path(), &argv, &left, digest(2)).unwrap();
        let right = key(temp.path(), temp.path(), &argv, &right, digest(2)).unwrap();
        assert_eq!(left.digest, right.digest);
        let debug = format!("{:?}", left.descriptor.modeled_environment);
        assert!(!debug.contains(sentinel));
    }

    #[test]
    fn production_runtime_binding_requires_only_the_exact_c_locale() {
        let temp = fixture();
        let argv = os(&["cat", "README.md"]);
        for accepted in [
            environment(&[("LANG", "C"), ("LC_ALL", "C")]),
            environment(&[("LC_ALL", "C"), ("LANG", "C")]),
        ] {
            assert!(attested_input_for_environment(temp.path(), &argv, &accepted).is_ok());
        }

        for rejected in [
            environment(&[]),
            environment(&[("LANG", "C")]),
            environment(&[("LANG", "C"), ("LC_ALL", "C"), ("TZ", "UTC")]),
            environment(&[("LANG", "en_US.UTF-8"), ("LC_ALL", "C")]),
            environment(&[("LANG", "C"), ("LC_ALL", "C"), ("LC_CTYPE", "C")]),
            environment(&[("LANG", "C"), ("LANG", "C")]),
        ] {
            assert_eq!(
                attested_input_for_environment(temp.path(), &argv, &rejected).err(),
                Some(RuntimeBindingError::EnvironmentMismatch)
            );
        }
    }
}
