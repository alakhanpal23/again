//! Conservative, local-only publication admission for a future team cache.
//!
//! This module does not upload anything and is deliberately disconnected from
//! the execution engine.  A successful scan is evidence only that this exact
//! classifier did not recognize a reviewed risk shape in the supplied facts;
//! it is **not** proof that an output contains no secret.  Callers must retain
//! the classifier and policy digests with any future publication decision.
//! This pure gate also does not authenticate capture provenance, resolve
//! symlinks, establish filesystem identity, or attest that scoped paths are
//! complete; those are separate execution-boundary responsibilities.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::team::{Digest, PrivacyClass, PrivacyMetadata, Shareability};
use crate::team_request_key::{TEAM_REQUEST_KEY_SCHEMA_VERSION, TeamRequestKeyV1};

/// Hard ceiling for a repository policy. Individual policies may be stricter.
pub const MAX_POLICY_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ARGUMENT_COUNT: usize = 256;
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_POLICY_PREFIXES: usize = 256;
const MAX_REPOSITORY_PATH_BYTES: usize = 4096;

const POLICY_SCHEMA_VERSION: u16 = 1;
const CLASSIFIER_VERSION: &str = "again-publication-classifier-v1";
const CLASSIFIER_DOMAIN: &[u8] = b"again.publication-classifier.v1";
const POLICY_DOMAIN: &[u8] = b"again.repository-sharing-policy.v1";

// This manifest is part of the classifier identity. Any rule change must
// update this text and the pinned digest test below.
const CLASSIFIER_RULE_MANIFEST: &str = concat!(
    "utf8-required;binary-controls-denied;complete-pipe-capture-only;",
    "zero-exit;empty-stderr;bounded-output;relative-repository-paths;",
    "sealed-team-request-v1;exact-policy-binding;",
    "explicit-include-exclude;builtin-sensitive-paths-v2;",
    "pem-private-key;aws-access-key-v1;github-token-v1;bearer-v1;",
    "jwt-like-v1;secret-assignment-v2;high-entropy-v2;",
    "obvious-hash-exceptions-v2"
);

/// A validated, versioned repository sharing policy.
///
/// Prefixes use repository-relative paths. `.` is the repository root. Both
/// lists are required so publication cannot silently inherit an implicit
/// allow-all or no-exclusions policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositorySharingPolicy {
    version: String,
    include_prefixes: Vec<NormalizedRepoPath>,
    exclude_prefixes: Vec<NormalizedRepoPath>,
    max_output_bytes: u64,
    digest: Digest,
}

impl RepositorySharingPolicy {
    pub fn new(
        version: impl Into<String>,
        include_prefixes: Vec<PathBuf>,
        exclude_prefixes: Vec<PathBuf>,
        max_output_bytes: u64,
    ) -> Result<Self, SharingPolicyError> {
        let version = version.into();
        validate_policy_version(&version)?;
        if include_prefixes.is_empty() {
            return Err(SharingPolicyError::MissingIncludePrefixes);
        }
        if exclude_prefixes.is_empty() {
            return Err(SharingPolicyError::MissingExcludePrefixes);
        }
        if max_output_bytes == 0 || max_output_bytes > MAX_POLICY_OUTPUT_BYTES {
            return Err(SharingPolicyError::InvalidOutputLimit);
        }

        let include_prefixes = normalize_policy_prefixes(include_prefixes, PrefixKind::Include)?;
        let exclude_prefixes = normalize_policy_prefixes(exclude_prefixes, PrefixKind::Exclude)?;
        if include_prefixes.iter().any(path_has_sensitive_component) {
            return Err(SharingPolicyError::SensitiveIncludePrefix);
        }

        let digest = policy_digest(
            &version,
            &include_prefixes,
            &exclude_prefixes,
            max_output_bytes,
        );
        Ok(Self {
            version,
            include_prefixes,
            exclude_prefixes,
            max_output_bytes,
            digest,
        })
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixKind {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SharingPolicyError {
    #[error("sharing policy version must be 1-64 portable ASCII identifier characters")]
    InvalidVersion,
    #[error("sharing policy must configure at least one include prefix")]
    MissingIncludePrefixes,
    #[error("sharing policy must configure at least one exclude prefix")]
    MissingExcludePrefixes,
    #[error("sharing policy output limit must be within the hard publication ceiling")]
    InvalidOutputLimit,
    #[error("sharing policy prefix {index} in {kind:?} is not a canonical relative path")]
    InvalidPrefix { kind: PrefixKind, index: usize },
    #[error("a built-in sensitive path cannot be an include prefix")]
    SensitiveIncludePrefix,
}

/// How stdin was connected for the captured execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedStdin {
    Closed,
    Pipe,
    Terminal,
    Unknown,
}

/// A stream fact from a capture layer. `ScannerError` exists so an upstream
/// inspection failure cannot be converted into permission to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedStream<'a> {
    CompletePipe(&'a [u8]),
    Terminal,
    Unknown,
    ScannerError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedExit {
    Code(i32),
    Signal,
    Unknown,
}

/// Exact capture facts required by the publication classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedExecution<'a> {
    stdin: CapturedStdin,
    stdout: CapturedStream<'a>,
    stderr: CapturedStream<'a>,
    exit: CapturedExit,
}

impl<'a> CapturedExecution<'a> {
    pub fn new(
        stdin: CapturedStdin,
        stdout: CapturedStream<'a>,
        stderr: CapturedStream<'a>,
        exit: CapturedExit,
    ) -> Self {
        Self {
            stdin,
            stdout,
            stderr,
            exit,
        }
    }
}

/// Opaque permission evidence for future repository-scoped publication.
///
/// The fields are private and there is no unchecked constructor. This type
/// intentionally retains no output, argv, or path bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishableResult {
    privacy: PrivacyMetadata,
    classifier_digest: Digest,
    policy_digest: Digest,
}

/// Output-independent evidence that a sealed request's cwd, argv, and observed
/// repository paths passed the exact local sharing policy. Holding this private-
/// field capability is required before any team bearer token or request key may
/// leave the machine; output scanning remains a separate post-capture/decrypt
/// requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteRequestAdmissionV1 {
    request_key: Digest,
    policy_digest: Digest,
    classifier_digest: Digest,
}

impl RemoteRequestAdmissionV1 {
    pub(crate) fn matches(
        &self,
        policy: &RepositorySharingPolicy,
        request: &TeamRequestKeyV1,
    ) -> bool {
        self.request_key == request.digest()
            && self.policy_digest == policy.digest()
            && self.classifier_digest == publication_classifier_digest_v1()
    }
}

/// Reject sensitive/excluded paths and credential-shaped argv before remote
/// lookup, trust fetch, or immutable execution begins.
pub(crate) fn admit_remote_request_v1(
    policy: &RepositorySharingPolicy,
    request: &TeamRequestKeyV1,
) -> Result<RemoteRequestAdmissionV1, LocalOnlyReason> {
    let descriptor = request.descriptor();
    if descriptor.schema_version() != TEAM_REQUEST_KEY_SCHEMA_VERSION {
        return Err(LocalOnlyReason::RequestSchemaMismatch);
    }
    if descriptor.policy_digest() != policy.digest {
        return Err(LocalOnlyReason::PolicyDigestMismatch);
    }
    let argv = descriptor
        .normalized_argv()
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let scoped_paths = descriptor
        .observations()
        .iter()
        .map(|observation| PathBuf::from(observation.repository_path()))
        .collect::<Vec<_>>();
    evaluate_paths(
        policy,
        Path::new(descriptor.repository_relative_cwd()),
        &scoped_paths,
    )?;
    evaluate_argv(&argv)?;
    Ok(RemoteRequestAdmissionV1 {
        request_key: request.digest(),
        policy_digest: policy.digest(),
        classifier_digest: publication_classifier_digest_v1(),
    })
}

impl PublishableResult {
    /// Evaluate capture facts only for a sealed portable request key. The cwd,
    /// argv, and observed repository paths are derived from that capability;
    /// callers cannot substitute an unrelated "safe" scope list. Any
    /// uncertainty produces a typed [`LocalOnlyReason`]. Successful
    /// classification does not prove secret absence and is meaningful only
    /// with the returned digests. This API still relies on a future execution
    /// boundary to attest that `execution` was captured from this exact
    /// request; it does not establish that provenance itself.
    pub fn evaluate(
        policy: &RepositorySharingPolicy,
        request: &TeamRequestKeyV1,
        execution: CapturedExecution<'_>,
    ) -> Result<Self, LocalOnlyReason> {
        let descriptor = request.descriptor();
        if descriptor.schema_version() != TEAM_REQUEST_KEY_SCHEMA_VERSION {
            return Err(LocalOnlyReason::RequestSchemaMismatch);
        }
        if descriptor.policy_digest() != policy.digest {
            return Err(LocalOnlyReason::PolicyDigestMismatch);
        }
        let argv = descriptor
            .normalized_argv()
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let scoped_paths = descriptor
            .observations()
            .iter()
            .map(|observation| PathBuf::from(observation.repository_path()))
            .collect::<Vec<_>>();
        evaluate_derived_facts(
            policy,
            Path::new(descriptor.repository_relative_cwd()),
            &argv,
            &scoped_paths,
            execution,
        )
    }

    pub fn privacy(&self) -> &PrivacyMetadata {
        &self.privacy
    }

    pub fn classifier_digest(&self) -> Digest {
        self.classifier_digest
    }

    pub fn policy_digest(&self) -> Digest {
        self.policy_digest
    }
}

fn evaluate_derived_facts(
    policy: &RepositorySharingPolicy,
    cwd: &Path,
    argv: &[OsString],
    scoped_paths: &[PathBuf],
    execution: CapturedExecution<'_>,
) -> Result<PublishableResult, LocalOnlyReason> {
    evaluate_execution(policy, &execution)?;
    evaluate_paths(policy, cwd, scoped_paths)?;
    evaluate_argv(argv)?;

    let stdout = complete_stream_bytes(execution.stdout, StreamKind::Stdout)?;
    inspect_text(stdout, InspectionSource::Stdout)?;

    Ok(PublishableResult {
        privacy: PrivacyMetadata {
            classification: PrivacyClass::Internal,
            shareability: Shareability::Repository,
            // This means only "not recognized by this classifier", not
            // that secret absence has been proven.
            secret_tainted: false,
        },
        classifier_digest: classifier_digest(),
        policy_digest: policy.digest,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionSource {
    Stdin,
    Stdout,
    Stderr,
    ExitStatus,
    Cwd,
    Argv(usize),
    ScopedPath(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativePathProblem {
    Absolute,
    ParentTraversal,
    NonCanonical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    PemPrivateKey,
    AwsAccessKey,
    GitHubToken,
    BearerToken,
    JwtLike,
    SecretAssignment,
    HighEntropyToken,
}

/// Stable local-only outcomes. Values intentionally identify locations by
/// index/type rather than retaining potentially sensitive source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LocalOnlyReason {
    #[error("portable request schema does not match the publication classifier")]
    RequestSchemaMismatch,
    #[error("validated capture does not belong to the sealed portable request")]
    RequestDigestMismatch,
    #[error("portable request and repository sharing policy digests differ")]
    PolicyDigestMismatch,
    #[error("required publication input is unknown: {input:?}")]
    Unknown { input: InspectionSource },
    #[error("scanner failed for required publication input: {input:?}")]
    ScannerError { input: InspectionSource },
    #[error("publication input is not UTF-8: {input:?}")]
    NonUtf8 { input: InspectionSource },
    #[error("captured stream is binary: {stream:?}")]
    Binary { stream: StreamKind },
    #[error("a terminal participated in the execution: {stream:?}")]
    Tty { stream: StreamKind },
    #[error("execution consumed piped stdin")]
    StdinDependent,
    #[error("execution did not have a normal exit code")]
    UnknownExit,
    #[error("execution exited unsuccessfully with code {code}")]
    NonZeroExit { code: i32 },
    #[error("captured stderr was non-empty ({bytes} bytes)")]
    NonEmptyStderr { bytes: u64 },
    #[error("captured stream exceeds policy limit: {stream:?}")]
    Oversize {
        stream: StreamKind,
        bytes: u64,
        limit: u64,
    },
    #[error("argv is empty")]
    EmptyArgv,
    #[error("argv exceeds the strict argument count or byte limit")]
    OversizeArgv,
    #[error("repository path is not strict and relative: {input:?}")]
    InvalidRelativePath {
        input: InspectionSource,
        problem: RelativePathProblem,
    },
    #[error("path is denied by the built-in sensitive path rules: {input:?}")]
    SensitivePath { input: InspectionSource },
    #[error("path is denied by a configured exclude prefix: {input:?}")]
    ExcludedPath { input: InspectionSource },
    #[error("path is outside configured include prefixes: {input:?}")]
    OutsideIncludePrefixes { input: InspectionSource },
    #[error("reviewed credential shape was detected: {kind:?} in {input:?}")]
    CredentialShape {
        input: InspectionSource,
        kind: CredentialKind,
    },
}

fn evaluate_execution(
    policy: &RepositorySharingPolicy,
    execution: &CapturedExecution<'_>,
) -> Result<(), LocalOnlyReason> {
    match execution.stdin {
        CapturedStdin::Closed => {}
        CapturedStdin::Pipe => return Err(LocalOnlyReason::StdinDependent),
        CapturedStdin::Terminal => {
            return Err(LocalOnlyReason::Tty {
                stream: StreamKind::Stdin,
            });
        }
        CapturedStdin::Unknown => {
            return Err(LocalOnlyReason::Unknown {
                input: InspectionSource::Stdin,
            });
        }
    }
    match execution.exit {
        CapturedExit::Code(0) => {}
        CapturedExit::Code(code) => return Err(LocalOnlyReason::NonZeroExit { code }),
        CapturedExit::Signal | CapturedExit::Unknown => return Err(LocalOnlyReason::UnknownExit),
    }

    let stdout = complete_stream_bytes(execution.stdout, StreamKind::Stdout)?;
    let stderr = complete_stream_bytes(execution.stderr, StreamKind::Stderr)?;
    check_output_size(stdout, StreamKind::Stdout, policy.max_output_bytes)?;
    check_output_size(stderr, StreamKind::Stderr, policy.max_output_bytes)?;
    if !stderr.is_empty() {
        return Err(LocalOnlyReason::NonEmptyStderr {
            bytes: stderr.len() as u64,
        });
    }
    Ok(())
}

fn complete_stream_bytes(
    stream: CapturedStream<'_>,
    kind: StreamKind,
) -> Result<&[u8], LocalOnlyReason> {
    let input = match kind {
        StreamKind::Stdin => InspectionSource::Stdin,
        StreamKind::Stdout => InspectionSource::Stdout,
        StreamKind::Stderr => InspectionSource::Stderr,
    };
    match stream {
        CapturedStream::CompletePipe(bytes) => Ok(bytes),
        CapturedStream::Terminal => Err(LocalOnlyReason::Tty { stream: kind }),
        CapturedStream::Unknown => Err(LocalOnlyReason::Unknown { input }),
        CapturedStream::ScannerError => Err(LocalOnlyReason::ScannerError { input }),
    }
}

fn check_output_size(bytes: &[u8], stream: StreamKind, limit: u64) -> Result<(), LocalOnlyReason> {
    let bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if bytes > limit {
        return Err(LocalOnlyReason::Oversize {
            stream,
            bytes,
            limit,
        });
    }
    Ok(())
}

fn evaluate_paths(
    policy: &RepositorySharingPolicy,
    cwd: &Path,
    scoped_paths: &[PathBuf],
) -> Result<(), LocalOnlyReason> {
    let cwd = normalize_candidate_path(cwd, InspectionSource::Cwd)?;
    check_path_safety(policy, &cwd, InspectionSource::Cwd, cwd.is_root())?;
    for (index, path) in scoped_paths.iter().enumerate() {
        let source = InspectionSource::ScopedPath(index);
        let path = normalize_candidate_path(path, source)?;
        check_path_safety(policy, &path, source, false)?;
    }
    Ok(())
}

fn evaluate_argv(argv: &[OsString]) -> Result<(), LocalOnlyReason> {
    if argv.is_empty() {
        return Err(LocalOnlyReason::EmptyArgv);
    }
    if argv.len() > MAX_ARGUMENT_COUNT {
        return Err(LocalOnlyReason::OversizeArgv);
    }

    let mut total_bytes = 0usize;
    let mut values = Vec::with_capacity(argv.len());
    for (index, value) in argv.iter().enumerate() {
        let value = value.to_str().ok_or(LocalOnlyReason::NonUtf8 {
            input: InspectionSource::Argv(index),
        })?;
        total_bytes = total_bytes
            .checked_add(value.len())
            .ok_or(LocalOnlyReason::OversizeArgv)?;
        if total_bytes > MAX_ARGUMENT_BYTES || value.contains('\0') {
            return Err(LocalOnlyReason::OversizeArgv);
        }
        values.push(value);
    }

    for index in 0..values.len().saturating_sub(1) {
        if is_secret_flag(values[index]) && !is_placeholder(values[index + 1]) {
            return Err(LocalOnlyReason::CredentialShape {
                input: InspectionSource::Argv(index),
                kind: CredentialKind::SecretAssignment,
            });
        }
    }
    for (index, value) in values.iter().enumerate() {
        if let Some((flag, assigned)) = value.split_once('=')
            && is_secret_flag(flag)
            && !is_placeholder(assigned)
        {
            return Err(LocalOnlyReason::CredentialShape {
                input: InspectionSource::Argv(index),
                kind: CredentialKind::SecretAssignment,
            });
        }
    }

    for (index, value) in values.iter().enumerate() {
        let input = InspectionSource::Argv(index);
        inspect_text(value.as_bytes(), input)?;
    }

    // Adjacent argv elements may form `Bearer TOKEN` or a spaced assignment.
    // The count/byte limits above bound this allocation.
    let joined = values.join(" ");
    if let Some(kind) = detect_credential_shape(&joined) {
        return Err(LocalOnlyReason::CredentialShape {
            input: InspectionSource::Argv(0),
            kind,
        });
    }
    Ok(())
}

fn inspect_text(bytes: &[u8], input: InspectionSource) -> Result<(), LocalOnlyReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| LocalOnlyReason::NonUtf8 { input })?;
    if text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        let stream = match input {
            InspectionSource::Stderr => StreamKind::Stderr,
            _ => StreamKind::Stdout,
        };
        return Err(LocalOnlyReason::Binary { stream });
    }
    if let Some(kind) = detect_credential_shape(text) {
        return Err(LocalOnlyReason::CredentialShape { input, kind });
    }
    Ok(())
}

fn normalize_policy_prefixes(
    prefixes: Vec<PathBuf>,
    kind: PrefixKind,
) -> Result<Vec<NormalizedRepoPath>, SharingPolicyError> {
    if prefixes.len() > MAX_POLICY_PREFIXES {
        return Err(SharingPolicyError::InvalidPrefix { kind, index: 0 });
    }
    let mut normalized = BTreeSet::new();
    for (index, prefix) in prefixes.into_iter().enumerate() {
        let path = NormalizedRepoPath::parse(&prefix)
            .map_err(|_| SharingPolicyError::InvalidPrefix { kind, index })?;
        normalized.insert(path);
    }
    Ok(normalized.into_iter().collect())
}

fn validate_policy_version(version: &str) -> Result<(), SharingPolicyError> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SharingPolicyError::InvalidVersion);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedRepoPath(Vec<String>);

impl NormalizedRepoPath {
    fn parse(path: &Path) -> Result<Self, PathParseError> {
        if path.as_os_str().is_empty() {
            return Err(PathParseError::NonCanonical);
        }
        if path.is_absolute() {
            return Err(PathParseError::Absolute);
        }
        let raw = path.to_str().ok_or(PathParseError::NonUtf8)?;
        if raw.len() > MAX_REPOSITORY_PATH_BYTES
            || raw.contains('\\')
            || raw.contains('\0')
            || raw.contains(['*', '?', '[', ']', '{', '}'])
            || (raw.len() >= 2
                && raw.as_bytes()[0].is_ascii_alphabetic()
                && raw.as_bytes()[1] == b':')
        {
            return Err(PathParseError::NonCanonical);
        }

        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(value) => {
                    let value = value.to_str().ok_or(PathParseError::NonUtf8)?;
                    if value.is_empty() {
                        return Err(PathParseError::NonCanonical);
                    }
                    components.push(value.to_owned());
                }
                Component::ParentDir => return Err(PathParseError::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => return Err(PathParseError::Absolute),
            }
        }
        Ok(Self(components))
    }

    fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    fn starts_with(&self, prefix: &Self) -> bool {
        self.0.starts_with(&prefix.0)
    }

    fn canonical(&self) -> String {
        if self.is_root() {
            ".".to_owned()
        } else {
            self.0.join("/")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathParseError {
    NonUtf8,
    Absolute,
    ParentTraversal,
    NonCanonical,
}

fn normalize_candidate_path(
    path: &Path,
    input: InspectionSource,
) -> Result<NormalizedRepoPath, LocalOnlyReason> {
    NormalizedRepoPath::parse(path).map_err(|error| match error {
        PathParseError::NonUtf8 => LocalOnlyReason::NonUtf8 { input },
        PathParseError::Absolute => LocalOnlyReason::InvalidRelativePath {
            input,
            problem: RelativePathProblem::Absolute,
        },
        PathParseError::ParentTraversal => LocalOnlyReason::InvalidRelativePath {
            input,
            problem: RelativePathProblem::ParentTraversal,
        },
        PathParseError::NonCanonical => LocalOnlyReason::InvalidRelativePath {
            input,
            problem: RelativePathProblem::NonCanonical,
        },
    })
}

fn check_path_safety(
    policy: &RepositorySharingPolicy,
    path: &NormalizedRepoPath,
    input: InspectionSource,
    allow_root_context: bool,
) -> Result<(), LocalOnlyReason> {
    if path_has_sensitive_component(path) {
        return Err(LocalOnlyReason::SensitivePath { input });
    }
    if policy
        .exclude_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return Err(LocalOnlyReason::ExcludedPath { input });
    }
    if !allow_root_context
        && !policy
            .include_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    {
        return Err(LocalOnlyReason::OutsideIncludePrefixes { input });
    }
    Ok(())
}

fn path_has_sensitive_component(path: &NormalizedRepoPath) -> bool {
    path.0
        .iter()
        .any(|component| is_sensitive_component(component))
}

fn is_sensitive_component(component: &str) -> bool {
    let lower = component.to_ascii_lowercase();
    if lower.starts_with(".env") {
        return true;
    }
    if matches!(
        lower.as_str(),
        ".netrc" | ".npmrc" | ".pypirc" | "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519"
    ) {
        return true;
    }

    let stem = lower.trim_start_matches('.');
    const SENSITIVE_STEMS: &[&str] = &[
        "credential",
        "credentials",
        "key",
        "keys",
        "auth",
        "authorization",
        "secret",
        "secrets",
    ];
    SENSITIVE_STEMS.iter().any(|word| {
        stem == *word
            || stem
                .strip_prefix(word)
                .is_some_and(|suffix| matches!(suffix.as_bytes().first(), Some(b'.' | b'-' | b'_')))
    }) || stem
        .split(['.', '-', '_'])
        .any(|word| SENSITIVE_STEMS.contains(&word) || word == "oauth")
}

fn is_secret_flag(argument: &str) -> bool {
    if !argument.starts_with('-') {
        return false;
    }
    let flag = argument
        .trim_start_matches('-')
        .split_once('=')
        .map_or(argument.trim_start_matches('-'), |(name, _)| name)
        .replace('-', "_")
        .to_ascii_lowercase();
    matches!(
        flag.as_str(),
        "password"
            | "passwd"
            | "secret"
            | "token"
            | "api_key"
            | "apikey"
            | "access_key"
            | "private_key"
            | "client_secret"
            | "authorization"
            | "auth"
            | "credential"
            | "credentials"
            | "key"
            | "keys"
    ) || [
        "_password",
        "_passwd",
        "_secret",
        "_token",
        "_api_key",
        "_access_key",
        "_private_key",
        "_client_secret",
        "_authorization",
        "_auth",
        "_credential",
        "_credentials",
        "_key",
        "_keys",
    ]
    .iter()
    .any(|suffix| flag.ends_with(suffix))
}

fn detect_credential_shape(text: &str) -> Option<CredentialKind> {
    if contains_pem_private_key(text) {
        return Some(CredentialKind::PemPrivateKey);
    }
    if contains_aws_access_key(text) {
        return Some(CredentialKind::AwsAccessKey);
    }
    if contains_github_token(text) {
        return Some(CredentialKind::GitHubToken);
    }
    if contains_bearer_token(text) {
        return Some(CredentialKind::BearerToken);
    }
    if contains_jwt_like(text) {
        return Some(CredentialKind::JwtLike);
    }
    if contains_secret_assignment(text) {
        return Some(CredentialKind::SecretAssignment);
    }
    if contains_high_entropy_token(text) {
        return Some(CredentialKind::HighEntropyToken);
    }
    None
}

fn contains_pem_private_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let begin = b"-----BEGIN ";
    for offset in find_all(bytes, begin) {
        let remaining = &bytes[offset + begin.len()..];
        let line_end = remaining
            .iter()
            .position(|byte| matches!(byte, b'\n' | b'\r'))
            .unwrap_or(remaining.len())
            .min(80);
        if find_subslice(&remaining[..line_end], b"PRIVATE KEY-----").is_some() {
            return true;
        }
    }
    false
}

fn contains_aws_access_key(text: &str) -> bool {
    const PREFIXES: &[&[u8; 4]] = &[
        b"AKIA", b"ASIA", b"AIDA", b"AROA", b"AIPA", b"ANPA", b"ANVA", b"ASCA",
    ];
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    (0..=bytes.len() - 20).any(|start| {
        let token = &bytes[start..start + 20];
        PREFIXES.iter().any(|prefix| token.starts_with(*prefix))
            && token.iter().all(u8::is_ascii_uppercase_or_digit)
            && has_token_boundaries(bytes, start, start + 20)
    })
}

trait AsciiUpperOrDigit {
    fn is_ascii_uppercase_or_digit(&self) -> bool;
}

impl AsciiUpperOrDigit for u8 {
    fn is_ascii_uppercase_or_digit(&self) -> bool {
        self.is_ascii_uppercase() || self.is_ascii_digit()
    }
}

fn contains_github_token(text: &str) -> bool {
    const PREFIXES: &[(&str, usize)] = &[
        ("ghp_", 30),
        ("gho_", 30),
        ("ghu_", 30),
        ("ghs_", 30),
        ("ghr_", 30),
        ("github_pat_", 20),
    ];
    let bytes = text.as_bytes();
    PREFIXES.iter().any(|(prefix, minimum_tail)| {
        find_all(bytes, prefix.as_bytes()).any(|start| {
            let end = bytes[start + prefix.len()..]
                .iter()
                .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
                .map_or(bytes.len(), |length| start + prefix.len() + length);
            end - start - prefix.len() >= *minimum_tail && has_token_boundaries(bytes, start, end)
        })
    })
}

fn contains_bearer_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    find_all(lower.as_bytes(), b"bearer").any(|start| {
        if start > 0 && lower.as_bytes()[start - 1].is_ascii_alphanumeric() {
            return false;
        }
        let mut cursor = start + "bearer".len();
        if cursor >= bytes.len() || !bytes[cursor].is_ascii_whitespace() {
            return false;
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let token_len = bytes[cursor..]
            .iter()
            .take_while(|byte| is_token_byte(**byte))
            .count();
        token_len >= 8
    })
}

fn contains_jwt_like(text: &str) -> bool {
    token_ranges(text.as_bytes()).any(|(start, end)| {
        let token = &text.as_bytes()[start..end];
        let mut segments = token.split(|byte| *byte == b'.');
        let Some(header) = segments.next() else {
            return false;
        };
        let Some(payload) = segments.next() else {
            return false;
        };
        let Some(signature) = segments.next() else {
            return false;
        };
        segments.next().is_none()
            && header.starts_with(b"eyJ")
            && header.len() >= 8
            && payload.len() >= 8
            && signature.len() >= 8
            && [header, payload, signature].iter().all(|segment| {
                segment
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
    })
}

fn contains_secret_assignment(text: &str) -> bool {
    const KEYS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "client_secret",
        "authorization",
        "aws_secret_access_key",
    ];
    let lower = text.to_ascii_lowercase();
    let lower_bytes = lower.as_bytes();
    let bytes = text.as_bytes();
    KEYS.iter().any(|key| {
        find_all(lower_bytes, key.as_bytes()).any(|start| {
            if start > 0 && lower_bytes[start - 1].is_ascii_alphanumeric() {
                return false;
            }
            let mut cursor = start + key.len();
            if cursor < lower_bytes.len() && lower_bytes[cursor].is_ascii_alphanumeric() {
                return false;
            }
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_whitespace() || matches!(bytes[cursor], b'\'' | b'"'))
            {
                cursor += 1;
            }
            if cursor >= bytes.len() || !matches!(bytes[cursor], b'=' | b':') {
                return false;
            }
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_whitespace() || matches!(bytes[cursor], b'\'' | b'"'))
            {
                cursor += 1;
            }
            let end = bytes[cursor..]
                .iter()
                .position(|byte| {
                    byte.is_ascii_whitespace() || matches!(byte, b'\'' | b'"' | b',' | b';')
                })
                .map_or(bytes.len(), |length| cursor + length);
            end.saturating_sub(cursor) >= 4 && !is_placeholder(&text[cursor..end])
        })
    })
}

fn contains_high_entropy_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    token_ranges(bytes).any(|(start, end)| {
        let token = &bytes[start..end];
        if token.len() < 32 || token.len() > 512 || is_obvious_hash(bytes, start, token) {
            return false;
        }
        let entropy = shannon_entropy(token);
        if token.iter().all(u8::is_ascii_hexdigit) {
            // Unlabelled random hex is also a common credential/private-key
            // representation. Only an algorithm-labelled value is exempted
            // by `is_obvious_hash` above.
            entropy >= 3.2
        } else {
            entropy_classes(token) >= 3 && entropy >= 4.2
        }
    })
}

fn token_ranges(bytes: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut cursor = 0usize;
    std::iter::from_fn(move || {
        while cursor < bytes.len() && !is_token_byte(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == bytes.len() {
            return None;
        }
        let start = cursor;
        while cursor < bytes.len() && is_token_byte(bytes[cursor]) {
            cursor += 1;
        }
        Some((start, cursor))
    })
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'/' | b'=')
}

fn is_obvious_hash(all: &[u8], start: usize, token: &[u8]) -> bool {
    let lower = token.to_ascii_lowercase();
    if [b"sha256-".as_slice(), b"sha384-", b"sha512-", b"blake3-"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }
    if looks_like_uuid(token) {
        return true;
    }
    let prior = &all[start.saturating_sub(8)..start];
    [
        b"sha256:".as_slice(),
        b"sha384:",
        b"sha512:",
        b"blake3:",
        b"h1:",
    ]
    .iter()
    .any(|prefix| prior.ends_with(prefix))
}

fn looks_like_uuid(token: &[u8]) -> bool {
    token.len() == 36
        && [8, 13, 18, 23].iter().all(|index| token[*index] == b'-')
        && token
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn entropy_classes(token: &[u8]) -> usize {
    usize::from(token.iter().any(u8::is_ascii_lowercase))
        + usize::from(token.iter().any(u8::is_ascii_uppercase))
        + usize::from(token.iter().any(u8::is_ascii_digit))
        + usize::from(token.iter().any(|byte| !byte.is_ascii_alphanumeric()))
}

fn shannon_entropy(token: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for byte in token {
        counts[*byte as usize] += 1;
    }
    let length = token.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn is_placeholder(value: &str) -> bool {
    let value = value
        .trim_matches(['\'', '"', '<', '>', '[', ']'])
        .to_ascii_lowercase();
    value.is_empty()
        || matches!(
            value.as_str(),
            "none" | "null" | "redacted" | "masked" | "placeholder" | "changeme"
        )
        || value.starts_with("${")
        || value.starts_with("{{")
}

fn has_token_boundaries(bytes: &[u8], start: usize, end: usize) -> bool {
    (start == 0 || !is_identifier_byte(bytes[start - 1]))
        && (end == bytes.len() || !is_identifier_byte(bytes[end]))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn find_all<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    (0..=haystack.len().saturating_sub(needle.len())).filter(move |start| {
        !needle.is_empty()
            && haystack.len() >= needle.len()
            && haystack[*start..].starts_with(needle)
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_all(haystack, needle).next()
}

/// Stable identity of the exact publication classifier used by producer and
/// consumer admission. Bootstrap inspection may expose this digest, but never
/// the captured bytes or any private policy input from which it was derived.
pub(crate) fn publication_classifier_digest_v1() -> Digest {
    let mut hasher = blake3::Hasher::new();
    put_bytes(&mut hasher, CLASSIFIER_DOMAIN);
    put_bytes(&mut hasher, CLASSIFIER_VERSION.as_bytes());
    put_bytes(&mut hasher, CLASSIFIER_RULE_MANIFEST.as_bytes());
    digest_from_hash(hasher.finalize())
}

fn classifier_digest() -> Digest {
    publication_classifier_digest_v1()
}

fn policy_digest(
    version: &str,
    includes: &[NormalizedRepoPath],
    excludes: &[NormalizedRepoPath],
    max_output_bytes: u64,
) -> Digest {
    let mut hasher = blake3::Hasher::new();
    put_bytes(&mut hasher, POLICY_DOMAIN);
    hasher.update(&POLICY_SCHEMA_VERSION.to_be_bytes());
    hasher.update(classifier_digest().as_bytes());
    put_bytes(&mut hasher, version.as_bytes());
    hasher.update(&max_output_bytes.to_be_bytes());
    put_paths(&mut hasher, includes);
    put_paths(&mut hasher, excludes);
    digest_from_hash(hasher.finalize())
}

fn put_paths(hasher: &mut blake3::Hasher, paths: &[NormalizedRepoPath]) {
    hasher.update(&(paths.len() as u64).to_be_bytes());
    for path in paths {
        put_bytes(hasher, path.canonical().as_bytes());
    }
}

fn put_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn digest_from_hash(hash: blake3::Hash) -> Digest {
    Digest::from_hex(&hash.to_hex()).expect("BLAKE3 always produces canonical lower-case hex")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::team_request_key::{TeamRequestKeyInput, build_team_request_key_v1};
    use tempfile::TempDir;

    fn fixed_digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn sealed_key(root: &Path, argv: &[OsString], policy_digest: Digest) -> TeamRequestKeyV1 {
        build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: "tenant-a",
            repository_id: "repo-a",
            generation_id: "0123456789abcdef0123456789abcdef",
            workspace: root,
            cwd: root,
            argv,
            environment: &[],
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest,
            execution_profile_digest: fixed_digest(2),
            platform_digest: fixed_digest(3),
            image_digest: fixed_digest(4),
        })
        .unwrap()
    }

    fn policy() -> RepositorySharingPolicy {
        RepositorySharingPolicy::new(
            "repo-policy-7",
            vec![PathBuf::from("src"), PathBuf::from("tests")],
            vec![PathBuf::from("target"), PathBuf::from("fixtures/private")],
            1024,
        )
        .unwrap()
    }

    fn execution(stdout: &[u8]) -> CapturedExecution<'_> {
        CapturedExecution::new(
            CapturedStdin::Closed,
            CapturedStream::CompletePipe(stdout),
            CapturedStream::CompletePipe(b""),
            CapturedExit::Code(0),
        )
    }

    fn evaluate<'a>(
        policy: &RepositorySharingPolicy,
        stdout: &'a [u8],
        argv: &'a [OsString],
        scopes: &'a [PathBuf],
    ) -> Result<PublishableResult, LocalOnlyReason> {
        evaluate_derived_facts(policy, Path::new("."), argv, scopes, execution(stdout))
    }

    #[test]
    fn benign_text_produces_only_repository_metadata_and_digests() {
        let policy = policy();
        let argv = [OsString::from("rg"), OsString::from("needle")];
        let scopes = [PathBuf::from("src")];
        let result = evaluate(
            &policy,
            b"src/main.rs:42: ordinary compiler output\n",
            &argv,
            &scopes,
        )
        .unwrap();

        assert_eq!(result.privacy().classification, PrivacyClass::Internal);
        assert_eq!(result.privacy().shareability, Shareability::Repository);
        assert!(!result.privacy().secret_tainted);
        assert_eq!(result.policy_digest(), policy.digest());
        assert_ne!(result.classifier_digest(), result.policy_digest());
    }

    #[test]
    fn remote_request_admission_rejects_sensitive_paths_before_output_exists() {
        let workspace = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        fs::write(workspace.path().join("src/value.txt"), b"safe").unwrap();
        fs::write(workspace.path().join("src/credentials.json"), b"private").unwrap();
        let policy = policy();

        let safe_argv = [OsString::from("cat"), OsString::from("src/value.txt")];
        let safe_request = sealed_key(workspace.path(), &safe_argv, policy.digest());
        let admitted = admit_remote_request_v1(&policy, &safe_request).unwrap();
        assert!(admitted.matches(&policy, &safe_request));

        let sensitive_argv = [
            OsString::from("cat"),
            OsString::from("src/credentials.json"),
        ];
        let sensitive_request = sealed_key(workspace.path(), &sensitive_argv, policy.digest());
        assert_eq!(
            admit_remote_request_v1(&policy, &sensitive_request),
            Err(LocalOnlyReason::SensitivePath {
                input: InspectionSource::ScopedPath(0),
            })
        );
    }

    #[test]
    fn policy_is_strict_canonical_and_order_independent() {
        assert_eq!(
            RepositorySharingPolicy::new(
                "bad version",
                vec![PathBuf::from("src")],
                vec![PathBuf::from("target")],
                1,
            ),
            Err(SharingPolicyError::InvalidVersion)
        );
        assert_eq!(
            RepositorySharingPolicy::new("v1", vec![], vec![PathBuf::from("target")], 1,),
            Err(SharingPolicyError::MissingIncludePrefixes)
        );
        assert_eq!(
            RepositorySharingPolicy::new("v1", vec![PathBuf::from("src")], vec![], 1,),
            Err(SharingPolicyError::MissingExcludePrefixes)
        );
        assert_eq!(
            RepositorySharingPolicy::new(
                "v1",
                vec![PathBuf::from("src")],
                vec![PathBuf::from("target")],
                0,
            ),
            Err(SharingPolicyError::InvalidOutputLimit)
        );
        assert_eq!(
            RepositorySharingPolicy::new(
                "v1",
                vec![PathBuf::from("secrets")],
                vec![PathBuf::from("target")],
                1,
            ),
            Err(SharingPolicyError::SensitiveIncludePrefix)
        );

        let first = RepositorySharingPolicy::new(
            "v1",
            vec![PathBuf::from("tests"), PathBuf::from("src")],
            vec![PathBuf::from("tmp"), PathBuf::from("target")],
            20,
        )
        .unwrap();
        let second = RepositorySharingPolicy::new(
            "v1",
            vec![PathBuf::from("src"), PathBuf::from("tests")],
            vec![PathBuf::from("target"), PathBuf::from("tmp")],
            20,
        )
        .unwrap();
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn capture_uncertainty_and_failures_are_typed_local_only() {
        let policy = policy();
        let argv = [OsString::from("rg")];
        let scopes = [PathBuf::from("src")];
        let classify =
            |execution| evaluate_derived_facts(&policy, Path::new("."), &argv, &scopes, execution);

        for (execution, expected) in [
            (
                CapturedExecution::new(
                    CapturedStdin::Unknown,
                    CapturedStream::CompletePipe(b"ok"),
                    CapturedStream::CompletePipe(b""),
                    CapturedExit::Code(0),
                ),
                LocalOnlyReason::Unknown {
                    input: InspectionSource::Stdin,
                },
            ),
            (
                CapturedExecution::new(
                    CapturedStdin::Closed,
                    CapturedStream::Unknown,
                    CapturedStream::CompletePipe(b""),
                    CapturedExit::Code(0),
                ),
                LocalOnlyReason::Unknown {
                    input: InspectionSource::Stdout,
                },
            ),
            (
                CapturedExecution::new(
                    CapturedStdin::Closed,
                    CapturedStream::ScannerError,
                    CapturedStream::CompletePipe(b""),
                    CapturedExit::Code(0),
                ),
                LocalOnlyReason::ScannerError {
                    input: InspectionSource::Stdout,
                },
            ),
            (
                CapturedExecution::new(
                    CapturedStdin::Terminal,
                    CapturedStream::CompletePipe(b"ok"),
                    CapturedStream::CompletePipe(b""),
                    CapturedExit::Code(0),
                ),
                LocalOnlyReason::Tty {
                    stream: StreamKind::Stdin,
                },
            ),
            (
                CapturedExecution::new(
                    CapturedStdin::Closed,
                    CapturedStream::Terminal,
                    CapturedStream::CompletePipe(b""),
                    CapturedExit::Code(0),
                ),
                LocalOnlyReason::Tty {
                    stream: StreamKind::Stdout,
                },
            ),
        ] {
            assert_eq!(classify(execution), Err(expected));
        }
    }

    #[test]
    fn result_constraints_fail_closed() {
        let policy = policy();
        let argv = [OsString::from("rg")];
        let scopes = [PathBuf::from("src")];
        let classify =
            |execution| evaluate_derived_facts(&policy, Path::new("."), &argv, &scopes, execution);

        let piped = CapturedExecution::new(
            CapturedStdin::Pipe,
            CapturedStream::CompletePipe(b"ok"),
            CapturedStream::CompletePipe(b""),
            CapturedExit::Code(0),
        );
        assert_eq!(classify(piped), Err(LocalOnlyReason::StdinDependent));

        let failed = CapturedExecution::new(
            CapturedStdin::Closed,
            CapturedStream::CompletePipe(b"ok"),
            CapturedStream::CompletePipe(b""),
            CapturedExit::Code(2),
        );
        assert_eq!(
            classify(failed),
            Err(LocalOnlyReason::NonZeroExit { code: 2 })
        );

        let signaled = CapturedExecution::new(
            CapturedStdin::Closed,
            CapturedStream::CompletePipe(b"ok"),
            CapturedStream::CompletePipe(b""),
            CapturedExit::Signal,
        );
        assert_eq!(classify(signaled), Err(LocalOnlyReason::UnknownExit));

        let noisy = CapturedExecution::new(
            CapturedStdin::Closed,
            CapturedStream::CompletePipe(b"ok"),
            CapturedStream::CompletePipe(b"warning"),
            CapturedExit::Code(0),
        );
        assert_eq!(
            classify(noisy),
            Err(LocalOnlyReason::NonEmptyStderr { bytes: 7 })
        );

        let large = vec![b'a'; 1025];
        assert_eq!(
            evaluate(&policy, &large, &argv, &scopes),
            Err(LocalOnlyReason::Oversize {
                stream: StreamKind::Stdout,
                bytes: 1025,
                limit: 1024,
            })
        );
    }

    #[test]
    fn non_utf8_and_binary_never_publish() {
        let policy = policy();
        let argv = [OsString::from("rg")];
        let scopes = [PathBuf::from("src")];
        assert_eq!(
            evaluate(&policy, b"bad \xff", &argv, &scopes),
            Err(LocalOnlyReason::NonUtf8 {
                input: InspectionSource::Stdout,
            })
        );
        assert_eq!(
            evaluate(&policy, b"bad\0bytes", &argv, &scopes),
            Err(LocalOnlyReason::Binary {
                stream: StreamKind::Stdout,
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argv_and_paths_never_publish() {
        use std::os::unix::ffi::OsStringExt;

        let policy = policy();
        let scopes = [PathBuf::from("src")];
        let argv = [OsString::from_vec(vec![b'r', b'g', 0xff])];
        assert_eq!(
            evaluate(&policy, b"ok", &argv, &scopes),
            Err(LocalOnlyReason::NonUtf8 {
                input: InspectionSource::Argv(0),
            })
        );

        let argv = [OsString::from("rg")];
        let bad_scope = [PathBuf::from(OsString::from_vec(vec![b's', 0xff]))];
        assert_eq!(
            evaluate(&policy, b"ok", &argv, &bad_scope),
            Err(LocalOnlyReason::NonUtf8 {
                input: InspectionSource::ScopedPath(0),
            })
        );
    }

    #[test]
    fn relative_include_exclude_and_builtin_sensitive_paths_are_enforced() {
        let policy = policy();
        let argv = [OsString::from("rg")];
        for (scope, expected) in [
            (
                PathBuf::from("../src"),
                LocalOnlyReason::InvalidRelativePath {
                    input: InspectionSource::ScopedPath(0),
                    problem: RelativePathProblem::ParentTraversal,
                },
            ),
            (
                PathBuf::from("docs"),
                LocalOnlyReason::OutsideIncludePrefixes {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("target/report.txt"),
                LocalOnlyReason::ExcludedPath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/.env.production"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/.envrc"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/credentials.json"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/keys.toml"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/auth.rs"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/oauth.rs"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/api_keys/cache.txt"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
            (
                PathBuf::from("src/secrets.yaml"),
                LocalOnlyReason::SensitivePath {
                    input: InspectionSource::ScopedPath(0),
                },
            ),
        ] {
            assert_eq!(evaluate(&policy, b"ok", &argv, &[scope]), Err(expected));
        }

        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\src")
        } else {
            PathBuf::from("/src")
        };
        assert_eq!(
            evaluate(&policy, b"ok", &argv, &[absolute]),
            Err(LocalOnlyReason::InvalidRelativePath {
                input: InspectionSource::ScopedPath(0),
                problem: RelativePathProblem::Absolute,
            })
        );
    }

    #[test]
    fn sealed_request_prevents_argv_scope_substitution_and_safe_request_works() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/public.txt"), "public\n").unwrap();
        fs::write(temp.path().join("private.txt"), "private\n").unwrap();
        let policy = policy();

        let private_argv = [OsString::from("cat"), OsString::from("private.txt")];
        let private_key = sealed_key(temp.path(), &private_argv, policy.digest());
        assert_eq!(
            private_key.descriptor().observations()[0].repository_path(),
            "private.txt"
        );
        // There is intentionally no scope argument to `evaluate`; the old
        // exploit could pair this argv with a fake `src` scope.
        assert_eq!(
            PublishableResult::evaluate(&policy, &private_key, execution(b"private\n")),
            Err(LocalOnlyReason::OutsideIncludePrefixes {
                input: InspectionSource::ScopedPath(0),
            })
        );

        let safe_argv = [OsString::from("cat"), OsString::from("src/public.txt")];
        let safe_key = sealed_key(temp.path(), &safe_argv, policy.digest());
        PublishableResult::evaluate(&policy, &safe_key, execution(b"public\n")).unwrap();

        let mismatched_key = sealed_key(temp.path(), &safe_argv, fixed_digest(9));
        assert_eq!(
            PublishableResult::evaluate(&policy, &mismatched_key, execution(b"public\n")),
            Err(LocalOnlyReason::PolicyDigestMismatch)
        );
    }

    #[test]
    fn reviewed_credential_shapes_are_refused_at_buffer_edges() {
        let policy = policy();
        let argv = [OsString::from("rg")];
        let scopes = [PathBuf::from("src")];
        let fixtures = [
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc",
                CredentialKind::PemPrivateKey,
            ),
            ("prefix AKIAIOSFODNN7EXAMPLE", CredentialKind::AwsAccessKey),
            (
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234",
                CredentialKind::GitHubToken,
            ),
            (
                "Authorization: Bearer abcDEFGH12345678_-",
                CredentialKind::BearerToken,
            ),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz",
                CredentialKind::JwtLike,
            ),
            ("DB_PASSWORD = hunter2", CredentialKind::SecretAssignment),
            (
                "mF8zQ1vN7pR2sL9xK4dH6wY3uC5bT0aE+JqZ",
                CredentialKind::HighEntropyToken,
            ),
        ];
        for (fixture, kind) in fixtures {
            assert_eq!(
                evaluate(&policy, fixture.as_bytes(), &argv, &scopes),
                Err(LocalOnlyReason::CredentialShape {
                    input: InspectionSource::Stdout,
                    kind,
                }),
                "fixture: {fixture}"
            );
        }

        // Start the prefix immediately before a typical scanner chunk edge.
        // The implementation scans the complete bounded capture, so no
        // credential may disappear across an internal buffer boundary.
        let mut crossing = "x".repeat(509);
        crossing.push('\n');
        crossing.push_str("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234");
        assert_eq!(
            evaluate(&policy, crossing.as_bytes(), &argv, &scopes),
            Err(LocalOnlyReason::CredentialShape {
                input: InspectionSource::Stdout,
                kind: CredentialKind::GitHubToken,
            })
        );
    }

    #[test]
    fn secret_argv_pairs_are_refused() {
        let policy = policy();
        let scopes = [PathBuf::from("src")];
        let argv = [
            OsString::from("tool"),
            OsString::from("--db-password"),
            OsString::from("ordinary-looking-value"),
        ];
        assert_eq!(
            evaluate(&policy, b"ok", &argv, &scopes),
            Err(LocalOnlyReason::CredentialShape {
                input: InspectionSource::Argv(1),
                kind: CredentialKind::SecretAssignment,
            })
        );

        let inline = [OsString::from("tool"), OsString::from("--auth=hunter2")];
        assert_eq!(
            evaluate(&policy, b"ok", &inline, &scopes),
            Err(LocalOnlyReason::CredentialShape {
                input: InspectionSource::Argv(1),
                kind: CredentialKind::SecretAssignment,
            })
        );
    }

    #[test]
    fn obvious_hashes_uuids_and_non_secret_identifiers_remain_benign() {
        let policy = policy();
        let argv = [
            OsString::from("rg"),
            OsString::from("secret"),
            OsString::from("auth"),
            OsString::from("src"),
        ];
        let scopes = [PathBuf::from("src")];
        let output = concat!(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "550e8400-e29b-41d4-a716-446655440000\n",
            "authorization middleware enabled\n",
            "token_count = 42\n"
        );
        evaluate(&policy, output.as_bytes(), &argv, &scopes).unwrap();
    }

    #[test]
    fn unlabelled_high_entropy_hex_is_not_assumed_to_be_a_hash() {
        let policy = policy();
        let argv = [OsString::from("rg")];
        let scopes = [PathBuf::from("src")];
        let bare_hex = "a91f04bc73d28e5601fa9c347db825e6012ec934ab7d85f6903c81be7f5a204d";
        assert_eq!(
            evaluate(&policy, bare_hex.as_bytes(), &argv, &scopes),
            Err(LocalOnlyReason::CredentialShape {
                input: InspectionSource::Stdout,
                kind: CredentialKind::HighEntropyToken,
            })
        );
    }

    #[test]
    fn classifier_identity_is_pinned() {
        // Deliberately update this value whenever the reviewed rule manifest
        // changes so stored decisions cannot silently change meaning.
        assert_eq!(
            classifier_digest().to_hex(),
            "4049854d5204339a60e087e6a393a4d2e8808717f857392549ff60813cd1f0a6"
        );
    }
}
