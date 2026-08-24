//! Immutable source capture for the deliberately narrow team-cache alpha.
//!
//! This module is intentionally a private child of `team_manifest_v2`.  That
//! placement lets it call the private two-execution validator while preventing
//! another crate module from minting [`super::ValidatedLocalResultV1`] from
//! caller-asserted bytes.
//!
//! The boundary pins the repository with directory file descriptors, opens
//! every selected component with `openat(O_NOFOLLOW)`, copies only regular
//! files into an owner-private snapshot, and reopens/revalidates each source
//! entry after reading it.  The portable request key is re-derived from the
//! snapshot before and after each child.  Snapshot files and directories are
//! read-only while the two executions run.
//!
//! The explicit team-alpha CLI reaches this boundary only through the sealed
//! publisher and supplies a non-forgeable runtime attestation. The execution-
//! profile digest binds the exact copied executable bytes and capture
//! mechanics; the separate runtime authority binds the reviewed dynamic loader
//! and shared-cache image.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use blake3::Hasher;
use thiserror::Error;
use uuid::Uuid;

use super::{
    CompleteLocalExecutionV1, LocalResultValidationError, MAX_V2_PLAINTEXT_STREAM_BYTES,
    ValidatedLocalResultV1, validate_two_complete_executions_v1,
};
use crate::executable::{ExecutableIdentity, VerifyError, verify_executable};
use crate::fingerprint::{FileDigestCache, NoFileDigestCache, portable_file_content_hasher};
use crate::runtime_attestation::{RuntimeAttestationError, TeamRuntimeAttestationV1};
use crate::team::Digest;
#[cfg(test)]
use crate::team_request_key::build_team_request_key_v1;
use crate::team_request_key::{
    TEAM_ALPHA_MAX_DIRECTORY_ENTRIES, TEAM_ALPHA_MAX_DISCOVERED_TREE_ENTRIES,
    TEAM_ALPHA_MAX_FILE_BYTES, TEAM_ALPHA_MAX_TREE_BYTES, TEAM_ALPHA_MAX_TREE_DEPTH,
    TEAM_ALPHA_MAX_TREE_ENTRIES, TeamLocalOnlyReason, TeamObservationKindV1, TeamRequestKeyInput,
    TeamRequestKeyV1, build_team_request_key_v1_with_cache,
};

const CAPTURE_PROFILE_DOMAIN: &[u8] = b"again.immutable-team-capture-profile.v1";
const CAPTURE_PROFILE_SCHEMA_VERSION: u16 = 1;
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);
const INTERRUPTION_GRACE: Duration = Duration::from_millis(250);
const INTERRUPTION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const STREAM_STDOUT: &str = "stdout";
const STREAM_STDERR: &str = "stderr";
const FORWARDED_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

// Signal dispositions are process-global, so immutable capture scopes must
// not overlap even when tests invoke the private boundary from several
// threads. Production uses a fresh, current-thread runtime, but serializing
// here makes that lifecycle invariant explicit rather than incidental.
static SIGNAL_FORWARDING_LOCK: Mutex<()> = Mutex::new(());
static FORWARDED_PROCESS_GROUP: AtomicI32 = AtomicI32::new(0);
static FIRST_INTERRUPTION_SIGNAL: AtomicI32 = AtomicI32::new(0);
static INTERRUPTION_ESCALATED: AtomicBool = AtomicBool::new(false);

/// Content-bound executable identity for immutable capture.
///
/// Construction performs a stable, no-follow read. Capture repeats that read,
/// copies the bytes into its private runtime directory, and requires the same
/// digest, so this value cannot authorize a later replacement at the source
/// path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImmutableExecutionProfileV1 {
    command_name: String,
    canonical_executable: PathBuf,
    attestation: ProfileAttestation,
    executable_digest: Digest,
    digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProfileAttestation {
    Audited(ExecutableIdentity),
    #[cfg(test)]
    TestOnly,
}

impl ImmutableExecutionProfileV1 {
    pub(crate) fn inspect(
        command_name: impl Into<String>,
        executable: &Path,
    ) -> Result<Self, ImmutableCaptureError> {
        let command_name = command_name.into();
        validate_supported_command_name(&command_name)?;
        let stable = read_stable_absolute_regular_file(
            executable,
            MAX_EXECUTABLE_BYTES,
            "inspect capture executable",
        )?;
        if stable.metadata.mode() & 0o111 == 0 {
            return Err(ImmutableCaptureError::ExecutableNotExecutable);
        }
        let file_name = stable
            .canonical_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ImmutableCaptureError::ExecutableNameMismatch)?;
        if file_name != command_name {
            return Err(ImmutableCaptureError::ExecutableNameMismatch);
        }
        let identity = verify_executable(&command_name, &stable.canonical_path)
            .map_err(ImmutableCaptureError::ExecutableNotAudited)?;
        let executable_digest = digest_from_hash(blake3::hash(&stable.bytes));
        let digest =
            capture_profile_digest(&command_name, &stable.bytes, &identity.semantic_profile);
        Ok(Self {
            command_name,
            canonical_executable: stable.canonical_path,
            attestation: ProfileAttestation::Audited(identity),
            executable_digest,
            digest,
        })
    }

    pub(crate) fn digest(&self) -> Digest {
        self.digest
    }

    #[cfg(test)]
    fn inspect_for_boundary_test(
        command_name: impl Into<String>,
        executable: &Path,
    ) -> Result<Self, ImmutableCaptureError> {
        let command_name = command_name.into();
        validate_supported_command_name(&command_name)?;
        let stable = read_stable_absolute_regular_file(
            executable,
            MAX_EXECUTABLE_BYTES,
            "inspect test capture executable",
        )?;
        if stable.metadata.mode() & 0o111 == 0 {
            return Err(ImmutableCaptureError::ExecutableNotExecutable);
        }
        if stable
            .canonical_path
            .file_name()
            .and_then(|value| value.to_str())
            != Some(command_name.as_str())
        {
            return Err(ImmutableCaptureError::ExecutableNameMismatch);
        }
        let executable_digest = digest_from_hash(blake3::hash(&stable.bytes));
        let digest =
            capture_profile_digest(&command_name, &stable.bytes, "test-only-unattested-runtime");
        Ok(Self {
            command_name,
            canonical_executable: stable.canonical_path,
            attestation: ProfileAttestation::TestOnly,
            executable_digest,
            digest,
        })
    }
}

/// Complete inputs for one disconnected immutable team capture.
pub(crate) struct ImmutableCaptureInputV1<'a> {
    request: &'a TeamRequestKeyV1,
    workspace: &'a Path,
    snapshot_parent: &'a Path,
    environment: &'a [(OsString, OsString)],
    execution_profile: &'a ImmutableExecutionProfileV1,
    runtime: RuntimeAuthority<'a>,
    producer_version: &'a str,
}

enum RuntimeAuthority<'a> {
    Attested(&'a TeamRuntimeAttestationV1),
    #[cfg(test)]
    TestOnly,
}

impl<'a> ImmutableCaptureInputV1<'a> {
    pub(crate) fn new(
        request: &'a TeamRequestKeyV1,
        workspace: &'a Path,
        snapshot_parent: &'a Path,
        environment: &'a [(OsString, OsString)],
        execution_profile: &'a ImmutableExecutionProfileV1,
        runtime: &'a TeamRuntimeAttestationV1,
        producer_version: &'a str,
    ) -> Self {
        Self {
            request,
            workspace,
            snapshot_parent,
            environment,
            execution_profile,
            runtime: RuntimeAuthority::Attested(runtime),
            producer_version,
        }
    }

    #[cfg(test)]
    fn new_for_boundary_test(
        request: &'a TeamRequestKeyV1,
        workspace: &'a Path,
        snapshot_parent: &'a Path,
        environment: &'a [(OsString, OsString)],
        execution_profile: &'a ImmutableExecutionProfileV1,
        producer_version: &'a str,
    ) -> Self {
        Self {
            request,
            workspace,
            snapshot_parent,
            environment,
            execution_profile,
            runtime: RuntimeAuthority::TestOnly,
            producer_version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParityPhase {
    Before,
    AfterFirst,
    AfterSecond,
}

#[derive(Debug, Error)]
pub(crate) enum ImmutableCaptureError {
    #[error("snapshot parent is not an owner-private directory")]
    UnsafeSnapshotParent,
    #[error("workspace is not a regular, no-follow directory")]
    InvalidWorkspace,
    #[error("capture path is not a strict repository-relative path")]
    InvalidRepositoryPath,
    #[error("capture source path contains a symlink")]
    SymlinkSource,
    #[error("capture source path contains a special filesystem entry")]
    SpecialSource,
    #[error("capture source crosses a filesystem boundary")]
    CrossDeviceSource,
    #[error("capture source changed while it was being materialized")]
    ConcurrentSourceMutation,
    #[error("snapshot destination conflicts with another sealed observation")]
    SnapshotConflict,
    #[error("capture resource limit exceeded: {limit}")]
    ResourceLimit { limit: &'static str },
    #[error("unsupported immutable-capture command `{command}`")]
    UnsupportedCommand { command: String },
    #[error("capture executable name does not exactly match argv[0]")]
    ExecutableNameMismatch,
    #[error("capture executable is not executable")]
    ExecutableNotExecutable,
    #[error("capture executable is outside the audited Again allowlist: {0}")]
    ExecutableNotAudited(VerifyError),
    #[error("capture executable attestation changed after profile inspection")]
    ExecutableAttestationChanged,
    #[error("capture executable changed after its profile was inspected")]
    ExecutableChanged,
    #[error("request execution-profile digest does not match the copied executable")]
    ExecutionProfileMismatch,
    #[error("capture runtime attestation is invalid: {0}")]
    RuntimeAttestation(#[from] RuntimeAttestationError),
    #[error("snapshot request reconstruction failed during {phase:?}")]
    RequestReconstruction {
        phase: ParityPhase,
        #[source]
        source: TeamLocalOnlyReason,
    },
    #[error("snapshot request digest/descriptor mismatch during {phase:?}")]
    RequestParityMismatch { phase: ParityPhase },
    #[error("execution {run} exceeded the immutable-capture timeout")]
    ExecutionTimeout { run: u8 },
    #[error("immutable capture was interrupted by signal {signal}")]
    ExecutionInterrupted { signal: libc::c_int },
    #[error("execution {run} {stream} exceeded {limit} bytes")]
    OversizeStream {
        run: u8,
        stream: &'static str,
        limit: u64,
    },
    #[error("execution {run} {stream} capture failed ({kind:?})")]
    StreamCapture {
        run: u8,
        stream: &'static str,
        kind: io::ErrorKind,
    },
    #[error("cannot {operation} `{path}` ({kind:?})")]
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
    },
    #[error(transparent)]
    LocalValidation(#[from] LocalResultValidationError),
}

/// The first child execution that reached a terminal status.
///
/// This stays local-only and owns the exact bytes so an orchestration failure
/// after the child starts never needs to execute the user's command a third
/// time merely to recover its observable result.
#[derive(Debug)]
pub(crate) struct CompleteImmutableExecutionV1 {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_micros: u64,
}

impl CompleteImmutableExecutionV1 {
    pub(crate) fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub(crate) fn status_code(&self) -> Option<i32> {
        self.status.code()
    }

    pub(crate) fn exit_code(&self) -> i32 {
        self.status
            .code()
            .or_else(|| {
                self.status
                    .signal()
                    .map(|signal| 128_i32.saturating_add(signal))
            })
            .unwrap_or(1)
            .clamp(0, 255)
    }

    pub(crate) fn duration_micros(&self) -> u64 {
        self.duration_micros
    }
}

/// A typed capture failure preserves whether launching a local fallback is
/// still safe. `BeforeStart` proves no child was created. `AfterStart` forbids
/// another execution and retains the first complete result whenever one
/// exists. `Interrupted` is explicit even before spawn: it forbids fallback,
/// carries the received signal, and retains only a genuine completed execution.
#[derive(Debug, Error)]
pub(crate) enum ImmutableCaptureFailureV1 {
    #[error("immutable capture failed before the command started: {source}")]
    BeforeStart {
        #[source]
        source: ImmutableCaptureError,
    },
    #[error("immutable capture failed after the command started: {source}")]
    AfterStart {
        first_complete: Option<CompleteImmutableExecutionV1>,
        #[source]
        source: ImmutableCaptureError,
    },
    #[error("immutable capture was interrupted by signal {signal}")]
    Interrupted {
        signal: libc::c_int,
        retained_execution: Option<CompleteImmutableExecutionV1>,
    },
}

impl ImmutableCaptureFailureV1 {
    pub(crate) fn before_start(source: ImmutableCaptureError) -> Self {
        Self::BeforeStart { source }
    }

    pub(crate) fn after_start(
        first_complete: Option<CompleteImmutableExecutionV1>,
        source: ImmutableCaptureError,
    ) -> Self {
        Self::AfterStart {
            first_complete,
            source,
        }
    }

    fn interrupted(
        signal: libc::c_int,
        retained_execution: Option<CompleteImmutableExecutionV1>,
    ) -> Self {
        Self::Interrupted {
            signal,
            retained_execution,
        }
    }

    fn prioritize_interruption(self, signal: libc::c_int) -> Self {
        let retained_execution = match self {
            Self::BeforeStart { .. } => None,
            Self::AfterStart { first_complete, .. } => first_complete,
            Self::Interrupted {
                retained_execution, ..
            } => retained_execution,
        };
        Self::interrupted(signal, retained_execution)
    }

    pub(crate) fn first_complete(&self) -> Option<&CompleteImmutableExecutionV1> {
        match self {
            Self::BeforeStart { .. } => None,
            Self::AfterStart { first_complete, .. } => first_complete.as_ref(),
            Self::Interrupted {
                retained_execution, ..
            } => retained_execution.as_ref(),
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<CompleteImmutableExecutionV1>,
        ImmutableCaptureError,
        bool,
    ) {
        match self {
            Self::BeforeStart { source } => (None, source, false),
            Self::AfterStart {
                first_complete,
                source,
            } => (first_complete, source, true),
            Self::Interrupted {
                signal,
                retained_execution,
            } => (
                retained_execution,
                ImmutableCaptureError::ExecutionInterrupted { signal },
                true,
            ),
        }
    }
}

/// Materialize, seal, execute at most twice, and mint the only result
/// capability accepted by the encrypted-manifest builder.
pub(crate) fn capture_immutable_team_attempt_v1(
    input: ImmutableCaptureInputV1<'_>,
    digest_cache: &mut dyn FileDigestCache,
) -> Result<ValidatedLocalResultV1, ImmutableCaptureFailureV1> {
    capture_immutable_team_attempt_with_v1(input, digest_cache, &NoCaptureHooks, EXECUTION_TIMEOUT)
}

fn capture_immutable_team_attempt_with_v1<H: CaptureHooks>(
    input: ImmutableCaptureInputV1<'_>,
    digest_cache: &mut dyn FileDigestCache,
    hooks: &H,
    execution_timeout: Duration,
) -> Result<ValidatedLocalResultV1, ImmutableCaptureFailureV1> {
    let mut signals = SignalForwardingScope::install().map_err(|error| {
        ImmutableCaptureFailureV1::before_start(capture_io(
            "install immutable capture signal forwarding",
            Path::new("<capture-signals>"),
            error,
        ))
    })?;
    let outcome = capture_immutable_team_attempt_guarded_v1(
        input,
        digest_cache,
        hooks,
        execution_timeout,
        &signals,
    );
    let (interrupted, restore_result) = signals.finish();
    if let Some(signal) = interrupted {
        return Err(match outcome {
            Ok((_, first)) => ImmutableCaptureFailureV1::interrupted(signal, Some(first)),
            Err(failure) => failure.prioritize_interruption(signal),
        });
    }
    if let Err(error) = restore_result {
        let source = capture_io(
            "restore immutable capture signal forwarding",
            Path::new("<capture-signals>"),
            error,
        );
        return Err(match outcome {
            Ok((_, first)) => ImmutableCaptureFailureV1::after_start(Some(first), source),
            Err(ImmutableCaptureFailureV1::BeforeStart { .. }) => {
                ImmutableCaptureFailureV1::after_start(None, source)
            }
            Err(ImmutableCaptureFailureV1::AfterStart { first_complete, .. }) => {
                ImmutableCaptureFailureV1::after_start(first_complete, source)
            }
            Err(ImmutableCaptureFailureV1::Interrupted {
                signal,
                retained_execution,
            }) => ImmutableCaptureFailureV1::interrupted(signal, retained_execution),
        });
    }
    outcome.map(|(validated, _)| validated)
}

fn capture_immutable_team_attempt_guarded_v1<H: CaptureHooks>(
    input: ImmutableCaptureInputV1<'_>,
    digest_cache: &mut dyn FileDigestCache,
    hooks: &H,
    execution_timeout: Duration,
    signals: &SignalForwardingScope,
) -> Result<(ValidatedLocalResultV1, CompleteImmutableExecutionV1), ImmutableCaptureFailureV1> {
    verify_runtime_authority(&input).map_err(ImmutableCaptureFailureV1::before_start)?;
    let prepared =
        prepare_snapshot(&input, hooks).map_err(ImmutableCaptureFailureV1::before_start)?;
    verify_runtime_authority(&input).map_err(ImmutableCaptureFailureV1::before_start)?;
    verify_snapshot_request(
        &prepared,
        &input,
        input.environment,
        ParityPhase::Before,
        digest_cache,
    )
    .map_err(ImmutableCaptureFailureV1::before_start)?;
    // The child receives only this owned copy after its exact names/value
    // digests have re-derived the sealed request. It never consumes the
    // caller's slice directly.
    let execution_environment = VerifiedModeledEnvironment(input.environment.to_vec());

    if let Some(signal) = signals.interrupted_signal() {
        return Err(ImmutableCaptureFailureV1::interrupted(signal, None));
    }

    let first = match run_once(
        &prepared,
        input.request,
        &execution_environment,
        1,
        hooks.execution_timeout(1, execution_timeout),
        hooks,
        signals,
    ) {
        Ok(first) => first,
        Err(RunOnceFailure::BeforeStart(source)) => {
            return Err(ImmutableCaptureFailureV1::before_start(source));
        }
        Err(RunOnceFailure::AfterStart(source)) => {
            return Err(ImmutableCaptureFailureV1::after_start(None, source));
        }
        Err(RunOnceFailure::Interrupted {
            signal,
            retained_execution,
        }) => {
            return Err(ImmutableCaptureFailureV1::interrupted(
                signal,
                retained_execution,
            ));
        }
    };
    hooks.after_execution(&prepared, 1);
    if let Err(source) = verify_runtime_authority(&input) {
        return Err(ImmutableCaptureFailureV1::after_start(Some(first), source));
    }
    if let Err(source) = verify_execution_profile_current(input.execution_profile) {
        return Err(ImmutableCaptureFailureV1::after_start(Some(first), source));
    }
    if let Err(source) = verify_snapshot_request(
        &prepared,
        &input,
        &execution_environment.0,
        ParityPhase::AfterFirst,
        digest_cache,
    ) {
        return Err(ImmutableCaptureFailureV1::after_start(Some(first), source));
    }
    if let Some(signal) = signals.interrupted_signal() {
        return Err(ImmutableCaptureFailureV1::interrupted(signal, Some(first)));
    }
    let second = match run_once(
        &prepared,
        input.request,
        &execution_environment,
        2,
        hooks.execution_timeout(2, execution_timeout),
        hooks,
        signals,
    ) {
        Ok(second) => second,
        Err(RunOnceFailure::BeforeStart(source) | RunOnceFailure::AfterStart(source)) => {
            return Err(ImmutableCaptureFailureV1::after_start(Some(first), source));
        }
        Err(RunOnceFailure::Interrupted { signal, .. }) => {
            return Err(ImmutableCaptureFailureV1::interrupted(signal, Some(first)));
        }
    };
    hooks.after_execution(&prepared, 2);
    if let Err(source) = verify_runtime_authority(&input) {
        return Err(ImmutableCaptureFailureV1::after_start(Some(first), source));
    }
    if let Err(source) = verify_execution_profile_current(input.execution_profile) {
        return Err(ImmutableCaptureFailureV1::after_start(Some(first), source));
    }
    if let Err(source) = verify_snapshot_request(
        &prepared,
        &input,
        &execution_environment.0,
        ParityPhase::AfterSecond,
        digest_cache,
    ) {
        return Err(ImmutableCaptureFailureV1::after_start(Some(first), source));
    }

    if let Some(signal) = signals.interrupted_signal() {
        return Err(ImmutableCaptureFailureV1::interrupted(signal, Some(first)));
    }

    let validated = match validate_two_complete_executions_v1(
        input.request,
        CompleteLocalExecutionV1::from_complete_capture(
            first.status_code(),
            first.stdout(),
            first.stderr(),
            first.duration_micros(),
        ),
        CompleteLocalExecutionV1::from_complete_capture(
            second.status_code(),
            second.stdout(),
            second.stderr(),
            second.duration_micros(),
        ),
        input.producer_version,
    ) {
        Ok(validated) => validated,
        Err(source) => {
            return Err(ImmutableCaptureFailureV1::after_start(
                Some(first),
                ImmutableCaptureError::from(source),
            ));
        }
    };
    Ok((validated, first))
}

/// Compatibility helper for focused boundary tests. Production orchestration
/// must use [`capture_immutable_team_attempt_v1`] so execution state is never
/// discarded and converted into a third local run.
#[allow(dead_code)]
pub(crate) fn capture_immutable_team_result_v1(
    input: ImmutableCaptureInputV1<'_>,
) -> Result<ValidatedLocalResultV1, ImmutableCaptureError> {
    let mut digest_cache = NoFileDigestCache;
    capture_immutable_team_attempt_v1(input, &mut digest_cache).map_err(|failure| {
        let (_, source, _) = failure.into_parts();
        source
    })
}

fn verify_runtime_authority(
    input: &ImmutableCaptureInputV1<'_>,
) -> Result<(), ImmutableCaptureError> {
    match input.runtime {
        RuntimeAuthority::Attested(runtime) => {
            runtime.verify_request_binding(input.request)?;
            if runtime.command_name() != input.execution_profile.command_name
                || runtime.executable_identity()
                    != match &input.execution_profile.attestation {
                        ProfileAttestation::Audited(identity) => identity,
                        #[cfg(test)]
                        ProfileAttestation::TestOnly => {
                            return Err(ImmutableCaptureError::ExecutionProfileMismatch);
                        }
                    }
                || runtime.executable_digest() != input.execution_profile.executable_digest
                || input.request.descriptor().execution_profile_digest()
                    != input.execution_profile.digest
            {
                return Err(ImmutableCaptureError::ExecutionProfileMismatch);
            }
            Ok(())
        }
        #[cfg(test)]
        RuntimeAuthority::TestOnly => Ok(()),
    }
}

struct StableAbsoluteFile {
    canonical_path: PathBuf,
    metadata: Metadata,
    bytes: Vec<u8>,
}

fn read_stable_absolute_regular_file(
    supplied: &Path,
    limit: u64,
    operation: &'static str,
) -> Result<StableAbsoluteFile, ImmutableCaptureError> {
    if fs::symlink_metadata(supplied)
        .map_err(|error| capture_io(operation, supplied, error))?
        .file_type()
        .is_symlink()
    {
        return Err(ImmutableCaptureError::SymlinkSource);
    }
    let canonical =
        fs::canonicalize(supplied).map_err(|error| capture_io(operation, supplied, error))?;
    if !canonical.is_absolute() {
        return Err(ImmutableCaptureError::InvalidRepositoryPath);
    }
    let mut opened = open_absolute_no_follow(&canonical, false, operation)?;
    let before = opened
        .metadata()
        .map_err(|error| capture_io(operation, &canonical, error))?;
    if !before.is_file() {
        return Err(ImmutableCaptureError::SpecialSource);
    }
    if before.len() > limit {
        return Err(ImmutableCaptureError::ResourceLimit {
            limit: "executable_bytes",
        });
    }
    let mut bytes = Vec::with_capacity(before.len().min(limit) as usize);
    opened
        .read_to_end(&mut bytes)
        .map_err(|error| capture_io(operation, &canonical, error))?;
    if bytes.len() as u64 > limit {
        return Err(ImmutableCaptureError::ResourceLimit {
            limit: "executable_bytes",
        });
    }
    let after = opened
        .metadata()
        .map_err(|error| capture_io(operation, &canonical, error))?;
    let reopened = open_absolute_no_follow(&canonical, false, operation)?;
    let path_after = reopened
        .metadata()
        .map_err(|error| capture_io(operation, &canonical, error))?;
    if bytes.len() as u64 != before.len()
        || !same_epoch(&before, &after)
        || !same_epoch(&before, &path_after)
    {
        return Err(ImmutableCaptureError::ConcurrentSourceMutation);
    }
    Ok(StableAbsoluteFile {
        canonical_path: canonical,
        metadata: before,
        bytes,
    })
}

fn validate_supported_command_name(command: &str) -> Result<(), ImmutableCaptureError> {
    if matches!(command, "cat" | "head" | "tail" | "wc" | "grep" | "rg") {
        Ok(())
    } else {
        Err(ImmutableCaptureError::UnsupportedCommand {
            command: command.to_owned(),
        })
    }
}

fn capture_profile_digest(command: &str, executable: &[u8], semantic_profile: &str) -> Digest {
    let mut hasher = Hasher::new();
    put_bytes(&mut hasher, CAPTURE_PROFILE_DOMAIN);
    hasher.update(&CAPTURE_PROFILE_SCHEMA_VERSION.to_le_bytes());
    put_bytes(&mut hasher, command.as_bytes());
    put_bytes(&mut hasher, blake3::hash(executable).as_bytes());
    put_bytes(&mut hasher, semantic_profile.as_bytes());
    put_bytes(&mut hasher, b"private-no-follow-snapshot-v1");
    put_bytes(&mut hasher, b"environment-clear-exact-modeled-values");
    put_bytes(&mut hasher, b"stdin-null-stdout-stderr-complete-pipes");
    put_bytes(&mut hasher, b"two-exact-successful-read-only-runs");
    put_bytes(
        &mut hasher,
        b"sigint-sigterm-sighup-forwarded-to-retained-group-with-bounded-grace",
    );
    hasher.update(&MAX_V2_PLAINTEXT_STREAM_BYTES.to_le_bytes());
    hasher.update(&(EXECUTION_TIMEOUT.as_micros() as u64).to_le_bytes());
    digest_from_hash(hasher.finalize())
}

struct PrivateCaptureRoot {
    path: PathBuf,
}

impl PrivateCaptureRoot {
    fn create(parent: &Path) -> Result<Self, ImmutableCaptureError> {
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|error| capture_io("canonicalize snapshot parent", parent, error))?;
        let metadata = fs::symlink_metadata(&canonical_parent)
            .map_err(|error| capture_io("inspect snapshot parent", &canonical_parent, error))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(ImmutableCaptureError::UnsafeSnapshotParent);
        }

        for _ in 0..32 {
            let path = canonical_parent.join(format!(
                ".again-immutable-capture-{}",
                Uuid::new_v4().simple()
            ));
            let encoded = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| ImmutableCaptureError::InvalidRepositoryPath)?;
            // SAFETY: `encoded` is a NUL-terminated path and mkdir copies it.
            let result = unsafe { libc::mkdir(encoded.as_ptr(), 0o700) };
            if result == 0 {
                return Ok(Self { path });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(capture_io("create private snapshot", &path, error));
            }
        }
        Err(ImmutableCaptureError::ResourceLimit {
            limit: "snapshot_name_attempts",
        })
    }
}

impl Drop for PrivateCaptureRoot {
    fn drop(&mut self) {
        restore_directory_write_permissions(&self.path);
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn restore_directory_write_permissions(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return;
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if fs::symlink_metadata(&child).is_ok_and(|value| value.is_dir()) {
            restore_directory_write_permissions(&child);
        }
    }
}

struct PreparedSnapshot {
    _root: PrivateCaptureRoot,
    repository: PathBuf,
    cwd: PathBuf,
    executable: PathBuf,
}

trait CaptureHooks {
    fn after_file_read(&self, _repository_path: &Path) {}
    fn after_directory_listed(&self, _repository_path: &Path) {}
    fn after_child_started(&self, _prepared: &PreparedSnapshot, _run: u8) {}
    fn execution_timeout(&self, _run: u8, default: Duration) -> Duration {
        default
    }
    fn try_wait_child(&self, child: &mut Child, _run: u8) -> io::Result<Option<ExitStatus>> {
        child.try_wait()
    }
    fn after_execution(&self, _prepared: &PreparedSnapshot, _run: u8) {}
}

struct NoCaptureHooks;
impl CaptureHooks for NoCaptureHooks {}

struct SnapshotMaterializer<'a, H: CaptureHooks> {
    source_root_path: PathBuf,
    source_root: File,
    source_root_metadata: Metadata,
    repository: PathBuf,
    hooks: &'a H,
    copied_files: BTreeMap<PathBuf, (Digest, u64)>,
    created_directories: BTreeSet<PathBuf>,
    unique_bytes: u64,
    source_bytes_read: u64,
    observed_entries: u64,
    discovered_entries: u64,
}

fn prepare_snapshot<H: CaptureHooks>(
    input: &ImmutableCaptureInputV1<'_>,
    hooks: &H,
) -> Result<PreparedSnapshot, ImmutableCaptureError> {
    let descriptor = input.request.descriptor();
    let command = descriptor.normalized_argv().first().ok_or_else(|| {
        ImmutableCaptureError::UnsupportedCommand {
            command: String::new(),
        }
    })?;
    validate_supported_command_name(command)?;
    if input.execution_profile.command_name != *command {
        return Err(ImmutableCaptureError::ExecutableNameMismatch);
    }
    if descriptor.execution_profile_digest() != input.execution_profile.digest {
        return Err(ImmutableCaptureError::ExecutionProfileMismatch);
    }

    let root = PrivateCaptureRoot::create(input.snapshot_parent)?;
    let repository = root.path.join("repository");
    let runtime = root.path.join("runtime");
    create_private_directory(&repository)?;
    create_private_directory(&runtime)?;

    let (source_root_path, source_root, source_root_metadata) =
        open_workspace_root(input.workspace)?;
    let mut materializer = SnapshotMaterializer {
        source_root_path,
        source_root,
        source_root_metadata,
        repository: repository.clone(),
        hooks,
        copied_files: BTreeMap::new(),
        created_directories: BTreeSet::new(),
        unique_bytes: 0,
        source_bytes_read: 0,
        observed_entries: 0,
        discovered_entries: 0,
    };
    materializer.created_directories.insert(PathBuf::from("."));

    let cwd_relative = strict_relative_path(descriptor.repository_relative_cwd(), true)?;
    materializer.ensure_destination_directory(&cwd_relative)?;
    for observation in descriptor.observations() {
        let relative = strict_relative_path(observation.repository_path(), true)?;
        match observation.kind() {
            TeamObservationKindV1::File => {
                let opened = materializer.open_source_path(&relative)?;
                if !opened.metadata.is_file() {
                    return Err(ImmutableCaptureError::SpecialSource);
                }
                let (digest, bytes) =
                    materializer.copy_open_file(&opened.file, &opened.metadata, &relative)?;
                materializer.validate_opened_path(&opened)?;
                if digest != observation.content_digest()
                    || bytes != observation.bytes()
                    || observation.entries() != 1
                {
                    return Err(ImmutableCaptureError::RequestParityMismatch {
                        phase: ParityPhase::Before,
                    });
                }
            }
            TeamObservationKindV1::RecursiveTree => {
                let opened = materializer.open_source_path(&relative)?;
                if !opened.metadata.is_dir() {
                    return Err(ImmutableCaptureError::SpecialSource);
                }
                materializer.ensure_destination_directory(&relative)?;
                materializer.copy_tree(&opened.file, &opened.metadata, &relative, 0)?;
                materializer.validate_opened_path(&opened)?;
            }
        }
    }
    materializer.validate_source_root()?;

    let stable_executable = read_stable_absolute_regular_file(
        &input.execution_profile.canonical_executable,
        MAX_EXECUTABLE_BYTES,
        "copy capture executable",
    )?;
    if stable_executable.metadata.mode() & 0o111 == 0 {
        return Err(ImmutableCaptureError::ExecutableNotExecutable);
    }
    let semantic_profile = match &input.execution_profile.attestation {
        ProfileAttestation::Audited(expected) => {
            let current = verify_executable(command, &stable_executable.canonical_path)
                .map_err(ImmutableCaptureError::ExecutableNotAudited)?;
            if &current != expected {
                return Err(ImmutableCaptureError::ExecutableAttestationChanged);
            }
            current.semantic_profile
        }
        #[cfg(test)]
        ProfileAttestation::TestOnly => "test-only-unattested-runtime".to_owned(),
    };
    let current_profile_digest =
        capture_profile_digest(command, &stable_executable.bytes, &semantic_profile);
    if current_profile_digest != input.execution_profile.digest {
        return Err(ImmutableCaptureError::ExecutableChanged);
    }
    let executable = match &input.execution_profile.attestation {
        // Audited platform binaries are executed at the exact canonical path
        // accepted by `verify_executable`; copying an Apple platform binary
        // can discard filesystem provenance the kernel uses at exec time. The
        // verifier and content profile are checked before and after each run.
        ProfileAttestation::Audited(_) => stable_executable.canonical_path,
        #[cfg(test)]
        ProfileAttestation::TestOnly => {
            let copied = runtime.join(command);
            write_new_file(&copied, &stable_executable.bytes, 0o500)?;
            copied
        }
    };

    seal_snapshot_tree(&repository)?;
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o500))
        .map_err(|error| capture_io("seal capture runtime directory", &runtime, error))?;
    fs::set_permissions(&root.path, fs::Permissions::from_mode(0o500))
        .map_err(|error| capture_io("seal snapshot root", &root.path, error))?;

    let cwd = if cwd_relative == Path::new(".") {
        repository.clone()
    } else {
        repository.join(cwd_relative)
    };
    Ok(PreparedSnapshot {
        _root: root,
        repository,
        cwd,
        executable,
    })
}

fn verify_execution_profile_current(
    profile: &ImmutableExecutionProfileV1,
) -> Result<(), ImmutableCaptureError> {
    let stable = read_stable_absolute_regular_file(
        &profile.canonical_executable,
        MAX_EXECUTABLE_BYTES,
        "reverify capture executable",
    )?;
    let semantic_profile = match &profile.attestation {
        ProfileAttestation::Audited(expected) => {
            let current = verify_executable(&profile.command_name, &stable.canonical_path)
                .map_err(ImmutableCaptureError::ExecutableNotAudited)?;
            if &current != expected {
                return Err(ImmutableCaptureError::ExecutableAttestationChanged);
            }
            current.semantic_profile
        }
        #[cfg(test)]
        ProfileAttestation::TestOnly => "test-only-unattested-runtime".to_owned(),
    };
    if capture_profile_digest(&profile.command_name, &stable.bytes, &semantic_profile)
        != profile.digest
    {
        return Err(ImmutableCaptureError::ExecutableChanged);
    }
    Ok(())
}

fn open_workspace_root(
    supplied: &Path,
) -> Result<(PathBuf, File, Metadata), ImmutableCaptureError> {
    if fs::symlink_metadata(supplied)
        .map_err(|error| capture_io("inspect workspace", supplied, error))?
        .file_type()
        .is_symlink()
    {
        return Err(ImmutableCaptureError::InvalidWorkspace);
    }
    let canonical = fs::canonicalize(supplied)
        .map_err(|error| capture_io("canonicalize workspace", supplied, error))?;
    let opened = open_absolute_no_follow(&canonical, true, "open workspace")?;
    let metadata = opened
        .metadata()
        .map_err(|error| capture_io("inspect open workspace", &canonical, error))?;
    if !metadata.is_dir() {
        return Err(ImmutableCaptureError::InvalidWorkspace);
    }
    Ok((canonical, opened, metadata))
}

struct OpenedSourcePath {
    file: File,
    metadata: Metadata,
    links: Vec<OpenedLink>,
}

struct OpenedLink {
    parent: File,
    name: CString,
    expected: Metadata,
}

impl<H: CaptureHooks> SnapshotMaterializer<'_, H> {
    fn open_source_path(&self, relative: &Path) -> Result<OpenedSourcePath, ImmutableCaptureError> {
        if relative == Path::new(".") {
            return Ok(OpenedSourcePath {
                file: self.source_root.try_clone().map_err(|error| {
                    capture_io("clone workspace descriptor", &self.source_root_path, error)
                })?,
                metadata: self.source_root_metadata.clone(),
                links: Vec::new(),
            });
        }
        let mut current = self.source_root.try_clone().map_err(|error| {
            capture_io("clone workspace descriptor", &self.source_root_path, error)
        })?;
        let mut links = Vec::new();
        let components = strict_components(relative)?;
        for (index, component) in components.iter().enumerate() {
            let name = CString::new(component.as_bytes())
                .map_err(|_| ImmutableCaptureError::InvalidRepositoryPath)?;
            let child =
                open_child_no_follow(&current, &name, false).map_err(map_open_source_error)?;
            let metadata = child
                .metadata()
                .map_err(|error| capture_io("inspect capture source", relative, error))?;
            if metadata.dev() != self.source_root_metadata.dev() {
                return Err(ImmutableCaptureError::CrossDeviceSource);
            }
            if index + 1 < components.len() && !metadata.is_dir() {
                return Err(ImmutableCaptureError::SpecialSource);
            }
            links.push(OpenedLink {
                parent: current,
                name,
                expected: metadata.clone(),
            });
            current = child;
        }
        let metadata = current
            .metadata()
            .map_err(|error| capture_io("inspect capture source", relative, error))?;
        Ok(OpenedSourcePath {
            file: current,
            metadata,
            links,
        })
    }

    fn validate_opened_path(&self, opened: &OpenedSourcePath) -> Result<(), ImmutableCaptureError> {
        let after = opened
            .file
            .metadata()
            .map_err(|error| capture_io("reinspect open source", &self.source_root_path, error))?;
        if !same_epoch(&opened.metadata, &after) {
            return Err(ImmutableCaptureError::ConcurrentSourceMutation);
        }
        for link in opened.links.iter().rev() {
            let reopened = open_child_no_follow(&link.parent, &link.name, false)
                .map_err(map_open_source_error)?;
            let metadata = reopened.metadata().map_err(|error| {
                capture_io("reopen capture source", &self.source_root_path, error)
            })?;
            if !same_epoch(&link.expected, &metadata) {
                return Err(ImmutableCaptureError::ConcurrentSourceMutation);
            }
        }
        Ok(())
    }

    fn validate_source_root(&self) -> Result<(), ImmutableCaptureError> {
        let after = self
            .source_root
            .metadata()
            .map_err(|error| capture_io("reinspect workspace", &self.source_root_path, error))?;
        let reopened = open_absolute_no_follow(&self.source_root_path, true, "reopen workspace")?;
        let path_after = reopened.metadata().map_err(|error| {
            capture_io("reinspect workspace path", &self.source_root_path, error)
        })?;
        if !same_epoch(&self.source_root_metadata, &after)
            || !same_epoch(&self.source_root_metadata, &path_after)
        {
            return Err(ImmutableCaptureError::ConcurrentSourceMutation);
        }
        Ok(())
    }

    fn copy_tree(
        &mut self,
        source: &File,
        expected: &Metadata,
        relative: &Path,
        depth: usize,
    ) -> Result<(), ImmutableCaptureError> {
        if depth > TEAM_ALPHA_MAX_TREE_DEPTH {
            return Err(ImmutableCaptureError::ResourceLimit {
                limit: "tree_depth",
            });
        }
        let names = read_directory_names(source, &mut self.discovered_entries, relative)?;
        self.hooks.after_directory_listed(relative);
        for name in names {
            self.observed_entries = self.observed_entries.checked_add(1).ok_or(
                ImmutableCaptureError::ResourceLimit {
                    limit: "tree_entries",
                },
            )?;
            if self.observed_entries > TEAM_ALPHA_MAX_TREE_ENTRIES {
                return Err(ImmutableCaptureError::ResourceLimit {
                    limit: "tree_entries",
                });
            }
            let encoded = CString::new(name.as_bytes())
                .map_err(|_| ImmutableCaptureError::InvalidRepositoryPath)?;
            let child =
                open_child_no_follow(source, &encoded, false).map_err(map_open_source_error)?;
            let child_before = child
                .metadata()
                .map_err(|error| capture_io("inspect tree child", relative, error))?;
            if child_before.dev() != self.source_root_metadata.dev() {
                return Err(ImmutableCaptureError::CrossDeviceSource);
            }
            let child_relative = relative.join(&name);
            if child_before.is_dir() {
                self.ensure_destination_directory(&child_relative)?;
                self.copy_tree(
                    &child,
                    &child_before,
                    &child_relative,
                    depth.saturating_add(1),
                )?;
            } else if child_before.is_file() {
                self.copy_open_file(&child, &child_before, &child_relative)?;
            } else {
                return Err(ImmutableCaptureError::SpecialSource);
            }
            let child_after = child
                .metadata()
                .map_err(|error| capture_io("reinspect tree child", &child_relative, error))?;
            let reopened =
                open_child_no_follow(source, &encoded, false).map_err(map_open_source_error)?;
            let path_after = reopened
                .metadata()
                .map_err(|error| capture_io("reopen tree child", &child_relative, error))?;
            if !same_epoch(&child_before, &child_after) || !same_epoch(&child_before, &path_after) {
                return Err(ImmutableCaptureError::ConcurrentSourceMutation);
            }
        }
        let after = source
            .metadata()
            .map_err(|error| capture_io("reinspect source directory", relative, error))?;
        if !same_epoch(expected, &after) {
            return Err(ImmutableCaptureError::ConcurrentSourceMutation);
        }
        Ok(())
    }

    fn copy_open_file(
        &mut self,
        source: &File,
        expected: &Metadata,
        relative: &Path,
    ) -> Result<(Digest, u64), ImmutableCaptureError> {
        if !expected.is_file() {
            return Err(ImmutableCaptureError::SpecialSource);
        }
        if expected.len() > TEAM_ALPHA_MAX_FILE_BYTES {
            return Err(ImmutableCaptureError::ResourceLimit {
                limit: "file_bytes",
            });
        }
        let destination = self.repository.join(relative);
        if let Some(parent) = relative
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            self.ensure_destination_directory(parent)?;
        }
        let existing = self.copied_files.get(relative).copied();
        let mut output = if existing.is_none() {
            Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&destination)
                    .map_err(|error| capture_io("create snapshot file", &destination, error))?,
            )
        } else {
            None
        };
        let mut reader = source
            .try_clone()
            .map_err(|error| capture_io("clone source file", relative, error))?;
        let mut hasher = portable_file_content_hasher();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|error| capture_io("read capture source", relative, error))?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or(ImmutableCaptureError::ResourceLimit {
                    limit: "file_bytes",
                })?;
            self.source_bytes_read = self.source_bytes_read.checked_add(read as u64).ok_or(
                ImmutableCaptureError::ResourceLimit {
                    limit: "capture_source_bytes",
                },
            )?;
            if bytes > TEAM_ALPHA_MAX_FILE_BYTES
                || self.source_bytes_read > TEAM_ALPHA_MAX_TREE_BYTES
            {
                return Err(ImmutableCaptureError::ResourceLimit {
                    limit: "capture_source_bytes",
                });
            }
            hasher.update(&buffer[..read]);
            if let Some(file) = output.as_mut() {
                file.write_all(&buffer[..read])
                    .map_err(|error| capture_io("write snapshot file", &destination, error))?;
            }
        }
        self.hooks.after_file_read(relative);
        let after = reader
            .metadata()
            .map_err(|error| capture_io("reinspect source file", relative, error))?;
        if bytes != expected.len() || !same_epoch(expected, &after) {
            return Err(ImmutableCaptureError::ConcurrentSourceMutation);
        }
        let digest = digest_from_hash(hasher.finalize());
        if let Some((prior_digest, prior_bytes)) = existing {
            if prior_digest != digest || prior_bytes != bytes {
                return Err(ImmutableCaptureError::SnapshotConflict);
            }
        } else {
            let mut file = output.expect("new destination retains its output handle");
            file.flush()
                .map_err(|error| capture_io("flush snapshot file", &destination, error))?;
            drop(file);
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o400))
                .map_err(|error| capture_io("seal snapshot file", &destination, error))?;
            self.unique_bytes = self.unique_bytes.checked_add(bytes).ok_or(
                ImmutableCaptureError::ResourceLimit {
                    limit: "snapshot_bytes",
                },
            )?;
            if self.unique_bytes > TEAM_ALPHA_MAX_TREE_BYTES {
                return Err(ImmutableCaptureError::ResourceLimit {
                    limit: "snapshot_bytes",
                });
            }
            self.copied_files
                .insert(relative.to_path_buf(), (digest, bytes));
        }
        Ok((digest, bytes))
    }

    fn ensure_destination_directory(
        &mut self,
        relative: &Path,
    ) -> Result<(), ImmutableCaptureError> {
        let mut current_relative = PathBuf::new();
        for component in strict_path_components(relative)? {
            current_relative.push(component);
            if self.created_directories.contains(&current_relative) {
                continue;
            }
            let destination = self.repository.join(&current_relative);
            match fs::symlink_metadata(&destination) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => return Err(ImmutableCaptureError::SnapshotConflict),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    create_private_directory(&destination)?;
                }
                Err(error) => {
                    return Err(capture_io(
                        "inspect snapshot directory",
                        &destination,
                        error,
                    ));
                }
            }
            self.created_directories.insert(current_relative.clone());
            if self.created_directories.len() as u64 > TEAM_ALPHA_MAX_TREE_ENTRIES {
                return Err(ImmutableCaptureError::ResourceLimit {
                    limit: "snapshot_directories",
                });
            }
        }
        Ok(())
    }
}

fn verify_snapshot_request(
    prepared: &PreparedSnapshot,
    input: &ImmutableCaptureInputV1<'_>,
    environment: &[(OsString, OsString)],
    phase: ParityPhase,
    digest_cache: &mut dyn FileDigestCache,
) -> Result<(), ImmutableCaptureError> {
    let descriptor = input.request.descriptor();
    let argv = descriptor
        .normalized_argv()
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let reconstructed = build_team_request_key_v1_with_cache(
        &TeamRequestKeyInput::new_for_verified_descriptor(
            descriptor,
            &prepared.repository,
            &prepared.cwd,
            &argv,
            environment,
        ),
        digest_cache,
    )
    .map_err(|source| ImmutableCaptureError::RequestReconstruction { phase, source })?;
    if reconstructed != *input.request {
        return Err(ImmutableCaptureError::RequestParityMismatch { phase });
    }
    Ok(())
}

struct VerifiedModeledEnvironment(Vec<(OsString, OsString)>);

/// Owns the temporary process-wide signal dispositions used only while an
/// immutable capture is active. The CLI is a fresh, single-threaded process at
/// this boundary. The mutex also serializes private boundary tests because
/// `sigaction` state cannot safely be scoped independently by thread.
struct SignalForwardingScope {
    _exclusive: MutexGuard<'static, ()>,
    previous_actions: [libc::sigaction; FORWARDED_SIGNALS.len()],
    previous_mask: libc::sigset_t,
    active: bool,
}

impl SignalForwardingScope {
    fn install() -> io::Result<Self> {
        let exclusive = SIGNAL_FORWARDING_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let signal_set = forwarded_signal_set()?;
        let mut previous_mask = unsafe { std::mem::zeroed() };
        set_thread_signal_mask(libc::SIG_BLOCK, &signal_set, Some(&mut previous_mask))?;

        FIRST_INTERRUPTION_SIGNAL.store(0, Ordering::SeqCst);
        INTERRUPTION_ESCALATED.store(false, Ordering::SeqCst);
        FORWARDED_PROCESS_GROUP.store(0, Ordering::SeqCst);

        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = immutable_capture_signal_handler as libc::sighandler_t;
        action.sa_mask = signal_set;
        action.sa_flags = libc::SA_RESTART;
        let mut previous_actions: [libc::sigaction; FORWARDED_SIGNALS.len()] =
            unsafe { std::mem::zeroed() };
        let mut installed = 0;
        for (index, signal) in FORWARDED_SIGNALS.into_iter().enumerate() {
            // SAFETY: action and the writable old-action slot are initialized
            // for this supported signal number.
            if unsafe { libc::sigaction(signal, &action, &mut previous_actions[index]) } != 0 {
                let error = io::Error::last_os_error();
                restore_signal_actions(&previous_actions, installed);
                let _ = set_thread_signal_mask(libc::SIG_SETMASK, &previous_mask, None);
                return Err(error);
            }
            installed += 1;
        }

        // The child inherits this unblocked mask across fork/exec. Save the
        // exact caller mask above and restore it when capture finishes.
        let mut capture_mask = previous_mask;
        for signal in FORWARDED_SIGNALS {
            // SAFETY: capture_mask is initialized and signal is supported.
            if unsafe { libc::sigdelset(&mut capture_mask, signal) } == -1 {
                let error = io::Error::last_os_error();
                restore_signal_actions(&previous_actions, installed);
                let _ = set_thread_signal_mask(libc::SIG_SETMASK, &previous_mask, None);
                return Err(error);
            }
        }
        if let Err(error) = set_thread_signal_mask(libc::SIG_SETMASK, &capture_mask, None) {
            restore_signal_actions(&previous_actions, installed);
            let _ = set_thread_signal_mask(libc::SIG_SETMASK, &previous_mask, None);
            return Err(error);
        }

        Ok(Self {
            _exclusive: exclusive,
            previous_actions,
            previous_mask,
            active: true,
        })
    }

    fn interrupted_signal(&self) -> Option<libc::c_int> {
        let signal = FIRST_INTERRUPTION_SIGNAL.load(Ordering::SeqCst);
        (signal != 0).then_some(signal)
    }

    fn interruption_escalated(&self) -> bool {
        INTERRUPTION_ESCALATED.load(Ordering::SeqCst)
    }

    fn retain_process_group(
        &self,
        process_group: libc::pid_t,
    ) -> io::Result<RetainedProcessGroup<'_>> {
        debug_assert!(process_group > 0);
        self.with_forwarded_signals_blocked(|| {
            FORWARDED_PROCESS_GROUP
                .compare_exchange(0, process_group, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| {
                    io::Error::other("immutable capture process group already retained")
                })?;
            if let Some(signal) = self.interrupted_signal() {
                if let Err(error) = signal_process_group(process_group, signal) {
                    FORWARDED_PROCESS_GROUP.store(0, Ordering::SeqCst);
                    return Err(error);
                }
                if self.interruption_escalated() {
                    let _ = signal_process_group(process_group, libc::SIGKILL);
                }
            }
            Ok(())
        })?;
        Ok(RetainedProcessGroup {
            signals: self,
            process_group,
            active: true,
        })
    }

    fn release_process_group(&self, process_group: libc::pid_t) -> io::Result<()> {
        self.with_forwarded_signals_blocked(|| {
            FORWARDED_PROCESS_GROUP
                .compare_exchange(process_group, 0, Ordering::SeqCst, Ordering::SeqCst)
                .map(|_| ())
                .map_err(|_| io::Error::other("immutable capture process group was not retained"))
        })
    }

    fn with_forwarded_signals_blocked<T>(
        &self,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let signal_set = forwarded_signal_set()?;
        let mut prior_mask = unsafe { std::mem::zeroed() };
        set_thread_signal_mask(libc::SIG_BLOCK, &signal_set, Some(&mut prior_mask))?;
        let result = operation();
        let restore = set_thread_signal_mask(libc::SIG_SETMASK, &prior_mask, None);
        match (result, restore) {
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    /// Block forwarding signals, clear the published PGID, restore all prior
    /// dispositions, then restore the exact caller mask. A signal arriving
    /// after the PGID is cleared can no longer target a recycled group.
    fn finish(&mut self) -> (Option<libc::c_int>, io::Result<()>) {
        self.restore()
    }

    fn restore(&mut self) -> (Option<libc::c_int>, io::Result<()>) {
        if !self.active {
            return (None, Ok(()));
        }
        let mut first_error = None;
        match forwarded_signal_set() {
            Ok(signal_set) => {
                if let Err(error) = set_thread_signal_mask(libc::SIG_BLOCK, &signal_set, None) {
                    first_error = Some(error);
                }
            }
            Err(error) => first_error = Some(error),
        }
        FORWARDED_PROCESS_GROUP.store(0, Ordering::SeqCst);
        let interrupted = self.interrupted_signal();
        for (index, signal) in FORWARDED_SIGNALS.into_iter().enumerate() {
            // SAFETY: each old action was populated by a successful sigaction
            // call during installation and remains live here.
            if unsafe {
                libc::sigaction(signal, &self.previous_actions[index], std::ptr::null_mut())
            } != 0
                && first_error.is_none()
            {
                first_error = Some(io::Error::last_os_error());
            }
        }
        FIRST_INTERRUPTION_SIGNAL.store(0, Ordering::SeqCst);
        INTERRUPTION_ESCALATED.store(false, Ordering::SeqCst);
        if let Err(error) = set_thread_signal_mask(libc::SIG_SETMASK, &self.previous_mask, None)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        self.active = false;
        (interrupted, first_error.map_or(Ok(()), Err))
    }
}

impl Drop for SignalForwardingScope {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct RetainedProcessGroup<'a> {
    signals: &'a SignalForwardingScope,
    process_group: libc::pid_t,
    active: bool,
}

impl RetainedProcessGroup<'_> {
    fn release(mut self) -> io::Result<()> {
        let result = self.signals.release_process_group(self.process_group);
        self.active = false;
        result
    }
}

impl Drop for RetainedProcessGroup<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.signals.release_process_group(self.process_group);
        }
    }
}

fn forwarded_signal_set() -> io::Result<libc::sigset_t> {
    let mut signal_set = unsafe { std::mem::zeroed() };
    // SAFETY: signal_set is valid writable storage.
    if unsafe { libc::sigemptyset(&mut signal_set) } == -1 {
        return Err(io::Error::last_os_error());
    }
    for signal in FORWARDED_SIGNALS {
        // SAFETY: signal_set stays initialized and signal is supported.
        if unsafe { libc::sigaddset(&mut signal_set, signal) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(signal_set)
}

fn set_thread_signal_mask(
    how: libc::c_int,
    signal_set: &libc::sigset_t,
    previous: Option<&mut libc::sigset_t>,
) -> io::Result<()> {
    let previous = previous.map_or(std::ptr::null_mut(), std::ptr::from_mut);
    // SAFETY: signal_set and the optional writable previous mask are valid for
    // this call; pthread_sigmask returns an errno value directly.
    let status = unsafe { libc::pthread_sigmask(how, signal_set, previous) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

fn restore_signal_actions(
    previous_actions: &[libc::sigaction; FORWARDED_SIGNALS.len()],
    installed: usize,
) {
    for index in (0..installed).rev() {
        // SAFETY: only slots populated by successful installation calls are
        // visited during rollback.
        unsafe {
            libc::sigaction(
                FORWARDED_SIGNALS[index],
                &previous_actions[index],
                std::ptr::null_mut(),
            );
        }
    }
}

extern "C" fn immutable_capture_signal_handler(signal: libc::c_int) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let saved_errno = unsafe { *signal_errno_location() };
    if !FORWARDED_SIGNALS.contains(&signal) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        unsafe {
            *signal_errno_location() = saved_errno;
        }
        return;
    }
    let first = FIRST_INTERRUPTION_SIGNAL
        .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    if !first {
        INTERRUPTION_ESCALATED.store(true, Ordering::SeqCst);
    }
    let process_group = FORWARDED_PROCESS_GROUP.load(Ordering::SeqCst);
    if process_group > 0 {
        // SAFETY: the handler performs only a lock-free atomic transition and
        // POSIX async-signal-safe kill. The published value is always a
        // retained positive child PGID, so negation cannot address Again's
        // own process group.
        unsafe {
            libc::kill(-process_group, if first { signal } else { libc::SIGKILL });
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unsafe {
        *signal_errno_location() = saved_errno;
    }
}

#[cfg(target_os = "macos")]
unsafe fn signal_errno_location() -> *mut libc::c_int {
    // SAFETY: Darwin exposes the calling thread's live errno slot.
    unsafe { libc::__error() }
}

#[cfg(target_os = "linux")]
unsafe fn signal_errno_location() -> *mut libc::c_int {
    // SAFETY: libc exposes the calling thread's live errno slot.
    unsafe { libc::__errno_location() }
}

fn signal_process_group(process_group: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    debug_assert!(process_group > 0);
    // SAFETY: process_group is a retained positive child PGID; negation
    // targets that disposable group only.
    if unsafe { libc::kill(-process_group, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

enum RunOnceFailure {
    BeforeStart(ImmutableCaptureError),
    AfterStart(ImmutableCaptureError),
    Interrupted {
        signal: libc::c_int,
        retained_execution: Option<CompleteImmutableExecutionV1>,
    },
}

fn run_once<H: CaptureHooks>(
    prepared: &PreparedSnapshot,
    request: &TeamRequestKeyV1,
    environment: &VerifiedModeledEnvironment,
    run: u8,
    execution_timeout: Duration,
    hooks: &H,
    signals: &SignalForwardingScope,
) -> Result<CompleteImmutableExecutionV1, RunOnceFailure> {
    if let Some(signal) = signals.interrupted_signal() {
        return Err(RunOnceFailure::Interrupted {
            signal,
            retained_execution: None,
        });
    }
    let argv = request.descriptor().normalized_argv();
    let mut command = Command::new(&prepared.executable);
    command
        .arg0(&argv[0])
        .args(&argv[1..])
        .current_dir(&prepared.cwd)
        .env_clear()
        .envs(environment.0.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: this closure invokes only async-signal-safe libc/syscall
    // operations. It creates a new process group and closes descriptors other
    // than the already-installed standard streams before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            close_extra_child_fds();
            Ok(())
        });
    }
    let started = Instant::now();
    let mut child = command.spawn().map_err(|error| {
        RunOnceFailure::BeforeStart(capture_io(
            "spawn immutable command",
            &prepared.executable,
            error,
        ))
    })?;
    let process_group = match libc::pid_t::try_from(child.id()) {
        Ok(process_group) if process_group > 0 => process_group,
        _ => {
            let source = capture_io(
                "retain immutable process group",
                Path::new("<child>"),
                io::Error::new(io::ErrorKind::InvalidData, "child PID does not fit pid_t"),
            );
            let _ = terminate_and_reap(&mut child, None, false, interruption_cleanup_deadline());
            return Err(RunOnceFailure::AfterStart(source));
        }
    };
    let retained_group = match signals.retain_process_group(process_group) {
        Ok(retained_group) => retained_group,
        Err(error) => {
            let source = capture_io(
                "publish immutable process group",
                Path::new("<child-process-group>"),
                error,
            );
            let _ = terminate_and_reap(
                &mut child,
                Some(process_group),
                false,
                interruption_cleanup_deadline(),
            );
            return Err(RunOnceFailure::AfterStart(source));
        }
    };
    let deadline = started
        .checked_add(execution_timeout)
        .expect("the fixed immutable execution timeout fits Instant");
    // Tests use this post-spawn barrier to make timeout boundaries independent
    // of host scheduling. Production's hook is a no-op.
    hooks.after_child_started(prepared, run);
    let stdout = child
        .stdout
        .take()
        .expect("piped immutable stdout is always present");
    let stderr = child
        .stderr
        .take()
        .expect("piped immutable stderr is always present");
    let mut stdout = match NonblockingStreamCapture::new(stdout) {
        Ok(stdout) => stdout,
        Err(error) => {
            let _ = terminate_and_reap(
                &mut child,
                Some(process_group),
                false,
                interruption_cleanup_deadline(),
            );
            let _ = retained_group.release();
            return Err(RunOnceFailure::AfterStart(
                StreamFailure::Io(error.kind()).into_capture_error(run, STREAM_STDOUT),
            ));
        }
    };
    let mut stderr = match NonblockingStreamCapture::new(stderr) {
        Ok(stderr) => stderr,
        Err(error) => {
            let _ = terminate_and_reap(
                &mut child,
                Some(process_group),
                false,
                interruption_cleanup_deadline(),
            );
            let _ = retained_group.release();
            return Err(RunOnceFailure::AfterStart(
                StreamFailure::Io(error.kind()).into_capture_error(run, STREAM_STDERR),
            ));
        }
    };
    let mut status = None;
    let mut group_alive = true;
    let mut interruption = None;
    loop {
        let now = Instant::now();
        if interruption.is_none()
            && let Some(signal) = signals.interrupted_signal()
        {
            interruption = Some((signal, now + INTERRUPTION_GRACE));
        }
        if let Some((signal, grace_deadline)) = interruption
            && (signals.interruption_escalated() || now >= grace_deadline)
        {
            let cleanup_deadline = interruption_cleanup_deadline();
            let reaped = terminate_and_reap(
                &mut child,
                group_alive.then_some(process_group),
                status.is_some(),
                cleanup_deadline,
            );
            status = status.or(reaped);
            let streams_complete =
                drain_terminated_streams(&mut stdout, &mut stderr, cleanup_deadline);
            let _ = retained_group.release();
            let retained_execution =
                status
                    .filter(|_| streams_complete)
                    .map(|status| CompleteImmutableExecutionV1 {
                        status,
                        stdout: stdout.into_bytes(),
                        stderr: stderr.into_bytes(),
                        duration_micros: started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                    });
            return Err(RunOnceFailure::Interrupted {
                signal,
                retained_execution,
            });
        }
        if interruption.is_none() && now >= deadline {
            let _ = terminate_and_reap(
                &mut child,
                group_alive.then_some(process_group),
                status.is_some(),
                interruption_cleanup_deadline(),
            );
            let _ = retained_group.release();
            return Err(RunOnceFailure::AfterStart(
                ImmutableCaptureError::ExecutionTimeout { run },
            ));
        }

        let stdout_progress = match stdout.read_available() {
            Ok(progress) => progress,
            Err(failure) => {
                let _ = terminate_and_reap(
                    &mut child,
                    (status.is_none() || group_alive).then_some(process_group),
                    status.is_some(),
                    interruption_cleanup_deadline(),
                );
                let _ = retained_group.release();
                return Err(RunOnceFailure::AfterStart(
                    failure.into_capture_error(run, STREAM_STDOUT),
                ));
            }
        };
        let stderr_progress = match stderr.read_available() {
            Ok(progress) => progress,
            Err(failure) => {
                let _ = terminate_and_reap(
                    &mut child,
                    (status.is_none() || group_alive).then_some(process_group),
                    status.is_some(),
                    interruption_cleanup_deadline(),
                );
                let _ = retained_group.release();
                return Err(RunOnceFailure::AfterStart(
                    failure.into_capture_error(run, STREAM_STDERR),
                ));
            }
        };

        if status.is_none() {
            status = match hooks.try_wait_child(&mut child, run) {
                Ok(status) => status,
                Err(error) => {
                    let source =
                        capture_io("wait for immutable command", Path::new("<child>"), error);
                    let _ = terminate_and_reap(
                        &mut child,
                        Some(process_group),
                        false,
                        interruption_cleanup_deadline(),
                    );
                    let _ = retained_group.release();
                    return Err(RunOnceFailure::AfterStart(source));
                }
            };
        }
        if status.is_some() {
            group_alive = match process_group_exists(process_group) {
                Ok(group_alive) => group_alive,
                Err(error) => {
                    let source = capture_io(
                        "inspect immutable process group",
                        Path::new("<child-process-group>"),
                        error,
                    );
                    let _ = terminate_and_reap(
                        &mut child,
                        Some(process_group),
                        true,
                        interruption_cleanup_deadline(),
                    );
                    let _ = retained_group.release();
                    return Err(RunOnceFailure::AfterStart(source));
                }
            };
            if !group_alive && stdout.is_complete() && stderr.is_complete() {
                break;
            }
        }

        if !stdout_progress && !stderr_progress {
            let active_deadline = interruption
                .map(|(_, grace_deadline)| grace_deadline)
                .unwrap_or(deadline);
            let remaining = active_deadline.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                thread::sleep(CHILD_POLL_INTERVAL.min(remaining));
            }
        }
    }
    let status = status.expect("a completed lifecycle has reaped its process-group leader");
    let stdout = stdout.into_bytes();
    let stderr = stderr.into_bytes();
    let duration_micros = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
    let complete = CompleteImmutableExecutionV1 {
        status,
        stdout,
        stderr,
        duration_micros,
    };
    if let Err(error) = retained_group.release() {
        return Err(RunOnceFailure::AfterStart(capture_io(
            "release immutable process group",
            Path::new("<child-process-group>"),
            error,
        )));
    }
    if let Some(signal) = signals.interrupted_signal() {
        return Err(RunOnceFailure::Interrupted {
            signal,
            retained_execution: Some(complete),
        });
    }
    Ok(complete)
}

enum StreamFailure {
    Oversize,
    Io(io::ErrorKind),
}

impl StreamFailure {
    fn into_capture_error(self, run: u8, stream: &'static str) -> ImmutableCaptureError {
        match self {
            Self::Oversize => ImmutableCaptureError::OversizeStream {
                run,
                stream,
                limit: MAX_V2_PLAINTEXT_STREAM_BYTES,
            },
            Self::Io(kind) => ImmutableCaptureError::StreamCapture { run, stream, kind },
        }
    }
}

struct NonblockingStreamCapture<R> {
    reader: Option<R>,
    bytes: Vec<u8>,
}

impl<R: Read + AsRawFd> NonblockingStreamCapture<R> {
    fn new(reader: R) -> io::Result<Self> {
        set_nonblocking(reader.as_raw_fd())?;
        let limit = MAX_V2_PLAINTEXT_STREAM_BYTES as usize;
        Ok(Self {
            reader: Some(reader),
            bytes: Vec::with_capacity(limit.min(64 * 1024)),
        })
    }

    /// Read at most one pipe-sized chunk so stdout and stderr, child polling,
    /// and deadline enforcement all continue to make progress together.
    fn read_available(&mut self) -> Result<bool, StreamFailure> {
        let Some(reader) = self.reader.as_mut() else {
            return Ok(false);
        };
        let limit = MAX_V2_PLAINTEXT_STREAM_BYTES as usize;
        let mut buffer = [0_u8; 64 * 1024];
        match reader.read(&mut buffer) {
            Ok(0) => {
                self.reader = None;
                Ok(true)
            }
            Ok(read) => {
                if self.bytes.len().saturating_add(read) > limit {
                    return Err(StreamFailure::Oversize);
                }
                self.bytes.extend_from_slice(&buffer[..read]);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(true),
            Err(error) => Err(StreamFailure::Io(error.kind())),
        }
    }

    fn is_complete(&self) -> bool {
        self.reader.is_none()
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn set_nonblocking(descriptor: RawFd) -> io::Result<()> {
    // SAFETY: fcntl reads and updates flags on an owned pipe descriptor. It
    // does not access memory or alter the child's distinct write endpoint.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor remains owned by the stream capture and flags came
    // from F_GETFL for that same descriptor.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn process_group_exists(process_group: libc::pid_t) -> io::Result<bool> {
    debug_assert!(process_group > 0);
    // SAFETY: a negative, retained child PGID targets only the disposable
    // process group established by setsid; signal zero performs no mutation.
    if unsafe { libc::kill(-process_group, 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error),
    }
}

fn interruption_cleanup_deadline() -> Instant {
    Instant::now()
        .checked_add(INTERRUPTION_CLEANUP_TIMEOUT)
        .expect("the fixed interruption cleanup timeout fits Instant")
}

fn drain_terminated_streams<Out, Err>(
    stdout: &mut NonblockingStreamCapture<Out>,
    stderr: &mut NonblockingStreamCapture<Err>,
    deadline: Instant,
) -> bool
where
    Out: Read + AsRawFd,
    Err: Read + AsRawFd,
{
    loop {
        if stdout.read_available().is_err() || stderr.read_available().is_err() {
            return false;
        }
        if stdout.is_complete() && stderr.is_complete() {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(CHILD_POLL_INTERVAL.min(remaining));
    }
}

fn terminate_and_reap(
    child: &mut Child,
    process_group: Option<libc::pid_t>,
    leader_reaped: bool,
    deadline: Instant,
) -> Option<ExitStatus> {
    let mut status = None;
    if let Some(process_group) = process_group {
        // SAFETY: the positive PGID was retained immediately after a child
        // successfully ran setsid. Negating it addresses that process group,
        // never the parent's process group or the caller's PID.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    if !leader_reaped {
        // Group signaling is the containment primitive; direct kill is a
        // defensive fallback if group signaling raced an unusual OS error.
        let _ = child.kill();
        status = child.wait().ok();
    }
    let Some(process_group) = process_group else {
        return status;
    };
    loop {
        match process_group_exists(process_group) {
            Ok(false) | Err(_) => return status,
            Ok(true) => {
                // The leader can fork between the first group signal and
                // reaping. Re-signal a still-live retained group so such a
                // late descendant cannot escape cleanup by missing one kill.
                // SAFETY: process_group is the same positive retained PGID.
                unsafe {
                    libc::kill(-process_group, libc::SIGKILL);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return status;
                }
                thread::sleep(CHILD_POLL_INTERVAL.min(remaining));
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn close_extra_child_fds() {
    // SAFETY: direct syscall with scalar arguments; failures fall back to a
    // bounded close loop suitable for this pre-exec child.
    let result = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
    if result == -1 {
        for descriptor in 3..65_536 {
            // SAFETY: close on an arbitrary descriptor is async-signal-safe.
            unsafe { libc::close(descriptor) };
        }
    }
}

#[cfg(target_os = "macos")]
unsafe fn close_extra_child_fds() {
    for descriptor in 3..65_536 {
        // SAFETY: close on an arbitrary descriptor is async-signal-safe.
        unsafe { libc::close(descriptor) };
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
unsafe fn close_extra_child_fds() {
    for descriptor in 3..65_536 {
        // SAFETY: close on an arbitrary descriptor is async-signal-safe.
        unsafe { libc::close(descriptor) };
    }
}

fn read_directory_names(
    directory: &File,
    discovered: &mut u64,
    repository_path: &Path,
) -> Result<Vec<String>, ImmutableCaptureError> {
    // Opening `.` relative to the pinned directory creates an independent
    // open-file description. `dup` would share the directory offset, causing
    // overlapping observations to see an already-consumed stream.
    // SAFETY: directory is valid and the static component is NUL-terminated.
    let stream_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if stream_fd < 0 {
        return Err(capture_io(
            "reopen source directory",
            repository_path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fdopendir takes ownership of the new descriptor.
    let stream = unsafe { libc::fdopendir(stream_fd) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        unsafe { libc::close(stream_fd) };
        return Err(capture_io(
            "open source directory stream",
            repository_path,
            io::Error::last_os_error(),
        ));
    }
    let guard = DirectoryStream(stream);
    let mut names = Vec::new();
    let mut directory_entries = 0_u64;
    loop {
        set_errno_zero();
        // SAFETY: guard retains a valid DIR pointer for the loop.
        let entry = unsafe { libc::readdir(guard.0) };
        if entry.is_null() {
            if current_errno() != 0 {
                return Err(capture_io(
                    "read source directory",
                    repository_path,
                    io::Error::last_os_error(),
                ));
            }
            break;
        }
        // SAFETY: d_name is NUL-terminated for every successful readdir.
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        directory_entries =
            directory_entries
                .checked_add(1)
                .ok_or(ImmutableCaptureError::ResourceLimit {
                    limit: "directory_entries",
                })?;
        if directory_entries > TEAM_ALPHA_MAX_DIRECTORY_ENTRIES {
            return Err(ImmutableCaptureError::ResourceLimit {
                limit: "directory_entries",
            });
        }
        *discovered = discovered
            .checked_add(1)
            .ok_or(ImmutableCaptureError::ResourceLimit {
                limit: "discovered_tree_entries",
            })?;
        if *discovered > TEAM_ALPHA_MAX_DISCOVERED_TREE_ENTRIES {
            return Err(ImmutableCaptureError::ResourceLimit {
                limit: "discovered_tree_entries",
            });
        }
        let name =
            std::str::from_utf8(raw).map_err(|_| ImmutableCaptureError::InvalidRepositoryPath)?;
        if name.contains('\\') || name.chars().any(char::is_control) {
            return Err(ImmutableCaptureError::InvalidRepositoryPath);
        }
        if name.starts_with('.') {
            continue;
        }
        names.push(name.to_owned());
    }
    names.sort_unstable();
    Ok(names)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the DIR pointer.
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(target_os = "linux")]
fn set_errno_zero() {
    // SAFETY: thread-local errno pointer is valid for this thread.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn set_errno_zero() {
    // SAFETY: thread-local errno pointer is valid for this thread.
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn current_errno() -> i32 {
    // SAFETY: thread-local errno pointer is valid for this thread.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn current_errno() -> i32 {
    // SAFETY: thread-local errno pointer is valid for this thread.
    unsafe { *libc::__error() }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn set_errno_zero() {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_errno() -> i32 {
    0
}

fn strict_relative_path(value: &str, allow_dot: bool) -> Result<PathBuf, ImmutableCaptureError> {
    let path = Path::new(value);
    if allow_dot && path == Path::new(".") {
        return Ok(PathBuf::from("."));
    }
    let components = strict_components(path)?;
    if components.join("/") != value {
        return Err(ImmutableCaptureError::InvalidRepositoryPath);
    }
    Ok(components.iter().collect())
}

fn strict_components(path: &Path) -> Result<Vec<String>, ImmutableCaptureError> {
    let mut output = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or(ImmutableCaptureError::InvalidRepositoryPath)?;
                if value.is_empty()
                    || value.starts_with('.')
                    || value.contains('\\')
                    || value.chars().any(char::is_control)
                {
                    return Err(ImmutableCaptureError::InvalidRepositoryPath);
                }
                output.push(value.to_owned());
            }
            Component::CurDir if path == Path::new(".") => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(ImmutableCaptureError::InvalidRepositoryPath);
            }
        }
    }
    if output.is_empty() && path != Path::new(".") {
        return Err(ImmutableCaptureError::InvalidRepositoryPath);
    }
    Ok(output)
}

fn strict_path_components(path: &Path) -> Result<Vec<String>, ImmutableCaptureError> {
    if path == Path::new(".") {
        Ok(Vec::new())
    } else {
        strict_components(path)
    }
}

fn open_absolute_no_follow(
    path: &Path,
    final_directory: bool,
    operation: &'static str,
) -> Result<File, ImmutableCaptureError> {
    if !path.is_absolute() {
        return Err(ImmutableCaptureError::InvalidRepositoryPath);
    }
    let mut current =
        open_root_directory().map_err(|error| capture_io(operation, Path::new("/"), error))?;
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_owned()),
            Component::RootDir => None,
            _ => Some(OsString::new()),
        })
        .collect::<Vec<_>>();
    if components.iter().any(|value| value.is_empty()) {
        return Err(ImmutableCaptureError::InvalidRepositoryPath);
    }
    if components.is_empty() {
        if final_directory {
            return Ok(current);
        }
        return Err(ImmutableCaptureError::SpecialSource);
    }
    for (index, component) in components.iter().enumerate() {
        let encoded = CString::new(component.as_bytes())
            .map_err(|_| ImmutableCaptureError::InvalidRepositoryPath)?;
        let directory = index + 1 < components.len() || final_directory;
        current =
            open_child_no_follow(&current, &encoded, directory).map_err(map_open_source_error)?;
    }
    Ok(current)
}

fn open_root_directory() -> io::Result<File> {
    let descriptor = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: open returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn open_child_no_follow(parent: &File, name: &CStr, directory: bool) -> io::Result<File> {
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: parent is valid and name is one NUL-terminated path component.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn map_open_source_error(error: io::Error) -> ImmutableCaptureError {
    match error.raw_os_error() {
        Some(libc::ELOOP) => ImmutableCaptureError::SymlinkSource,
        Some(libc::ENOTDIR) => ImmutableCaptureError::SpecialSource,
        _ if error.kind() == io::ErrorKind::NotFound => {
            ImmutableCaptureError::ConcurrentSourceMutation
        }
        _ => ImmutableCaptureError::Io {
            operation: "open capture source",
            path: PathBuf::from("<sealed-relative-path>"),
            kind: error.kind(),
        },
    }
}

fn create_private_directory(path: &Path) -> Result<(), ImmutableCaptureError> {
    fs::create_dir(path).map_err(|error| capture_io("create snapshot directory", path, error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| capture_io("protect snapshot directory", path, error))
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ImmutableCaptureError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| capture_io("create capture runtime file", path, error))?;
    file.write_all(bytes)
        .map_err(|error| capture_io("write capture runtime file", path, error))?;
    file.flush()
        .map_err(|error| capture_io("flush capture runtime file", path, error))?;
    drop(file);
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| capture_io("seal capture runtime file", path, error))
}

fn seal_snapshot_tree(path: &Path) -> Result<(), ImmutableCaptureError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| capture_io("inspect snapshot before seal", path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(ImmutableCaptureError::SnapshotConflict);
    }
    if metadata.is_file() {
        return fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .map_err(|error| capture_io("seal snapshot file", path, error));
    }
    if !metadata.is_dir() {
        return Err(ImmutableCaptureError::SnapshotConflict);
    }
    for entry in fs::read_dir(path)
        .map_err(|error| capture_io("enumerate snapshot before seal", path, error))?
    {
        let entry = entry.map_err(|error| capture_io("read snapshot entry", path, error))?;
        seal_snapshot_tree(&entry.path())?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))
        .map_err(|error| capture_io("seal snapshot directory", path, error))
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

fn capture_io(operation: &'static str, path: &Path, error: io::Error) -> ImmutableCaptureError {
    ImmutableCaptureError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

fn digest_from_hash(hash: blake3::Hash) -> Digest {
    Digest::from_hex(hash.to_hex().as_ref())
        .expect("BLAKE3 always emits a lower-case 32-byte digest")
}

fn put_bytes(hasher: &mut Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use tempfile::TempDir;

    use super::*;

    const SIGNAL_HELPER_DIRECTORY: &str = "AGAIN_IMMUTABLE_SIGNAL_HELPER_DIRECTORY";
    const SIGNAL_HELPER_SIGNAL: &str = "AGAIN_IMMUTABLE_SIGNAL_HELPER_SIGNAL";
    const SIGNAL_HELPER_IGNORE_FIRST: &str = "AGAIN_IMMUTABLE_SIGNAL_HELPER_IGNORE_FIRST";

    fn digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn environment(values: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        values
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    fn write_executable(directory: &Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn request(
        workspace: &Path,
        argv: &[&str],
        environment: &[(OsString, OsString)],
        profile: &ImmutableExecutionProfileV1,
    ) -> TeamRequestKeyV1 {
        let argv = argv.iter().map(OsString::from).collect::<Vec<_>>();
        build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: "tenant-a",
            repository_id: "repo-a",
            generation_id: "0123456789abcdef0123456789abcdef",
            workspace,
            cwd: workspace,
            argv: &argv,
            environment,
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: digest(1),
            execution_profile_digest: profile.digest(),
            platform_digest: digest(3),
            image_digest: digest(4),
        })
        .unwrap()
    }

    fn system_cat() -> PathBuf {
        [Path::new("/bin/cat"), Path::new("/usr/bin/cat")]
            .into_iter()
            .find(|path| path.is_file())
            .unwrap()
            .to_path_buf()
    }

    fn boundary_attempt<H: CaptureHooks>(
        executable_body: &str,
        hooks: &H,
        execution_timeout: Duration,
    ) -> Result<ValidatedLocalResultV1, ImmutableCaptureFailureV1> {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        fs::write(workspace.path().join("selected.txt"), b"value\n").unwrap();
        let executable = write_executable(executables.path(), "cat", executable_body);
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("cat", &executable).unwrap();
        let request = request(workspace.path(), &["cat", "selected.txt"], &[], &profile);
        let mut digest_cache = NoFileDigestCache;
        capture_immutable_team_attempt_with_v1(
            ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &[],
                &profile,
                "again-test-v1",
            ),
            &mut digest_cache,
            hooks,
            execution_timeout,
        )
    }

    fn execution_count(path: &Path) -> usize {
        fs::read(path).unwrap_or_default().len()
    }

    fn wait_for_process_group_exit(process_group: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_group_exists(process_group).unwrap() {
            assert!(
                Instant::now() < deadline,
                "process group {process_group} survived cleanup"
            );
            thread::sleep(CHILD_POLL_INTERVAL);
        }
    }

    fn assert_child_reaped(pid: libc::pid_t) {
        let mut status = 0;
        // SAFETY: WNOHANG only queries the test process's former direct child
        // and writes to this live stack integer.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(
            result, -1,
            "child {pid} was left waitable (result {result})"
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    struct MutateSnapshotAfterRun {
        run: u8,
    }

    impl CaptureHooks for MutateSnapshotAfterRun {
        fn after_execution(&self, prepared: &PreparedSnapshot, run: u8) {
            if run != self.run {
                return;
            }
            let selected = prepared.repository.join("selected.txt");
            fs::set_permissions(&selected, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(selected, b"changed\n").unwrap();
        }
    }

    struct WaitForChildMarker {
        counter: PathBuf,
        first_timeout: Duration,
        second_timeout: Duration,
    }

    struct InjectFirstTryWaitError {
        counter: PathBuf,
        leader_pid: AtomicU32,
        fired: AtomicBool,
    }

    impl CaptureHooks for InjectFirstTryWaitError {
        fn after_child_started(&self, _prepared: &PreparedSnapshot, _run: u8) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while execution_count(&self.counter) < 1 {
                assert!(
                    Instant::now() < deadline,
                    "child never crossed its execution marker"
                );
                thread::yield_now();
            }
        }

        fn try_wait_child(&self, child: &mut Child, _run: u8) -> io::Result<Option<ExitStatus>> {
            self.leader_pid.store(child.id(), Ordering::SeqCst);
            if !self.fired.swap(true, Ordering::SeqCst) {
                Err(io::Error::other("injected try_wait failure"))
            } else {
                child.try_wait()
            }
        }
    }

    impl CaptureHooks for WaitForChildMarker {
        fn after_child_started(&self, _prepared: &PreparedSnapshot, run: u8) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while execution_count(&self.counter) < usize::from(run) {
                assert!(
                    Instant::now() < deadline,
                    "child {run} never crossed its execution marker"
                );
                thread::yield_now();
            }
        }

        fn execution_timeout(&self, run: u8, _default: Duration) -> Duration {
            if run == 1 {
                self.first_timeout
            } else {
                self.second_timeout
            }
        }
    }

    struct RaiseOnFirstFileRead {
        signal: libc::c_int,
        fired: AtomicBool,
    }

    impl CaptureHooks for RaiseOnFirstFileRead {
        fn after_file_read(&self, _repository_path: &Path) {
            if !self.fired.swap(true, Ordering::SeqCst) {
                // SAFETY: the capture scope has installed a handler for this
                // supported signal and raise targets this exact test thread.
                assert_eq!(unsafe { libc::raise(self.signal) }, 0);
            }
        }
    }

    struct RaiseAfterFirstExecution {
        signal: libc::c_int,
    }

    impl CaptureHooks for RaiseAfterFirstExecution {
        fn after_execution(&self, _prepared: &PreparedSnapshot, run: u8) {
            if run == 1 {
                // SAFETY: the capture scope has installed a handler for this
                // supported signal and raise targets this exact test thread.
                assert_eq!(unsafe { libc::raise(self.signal) }, 0);
            }
        }
    }

    #[test]
    fn production_profile_is_exactly_gated_by_the_audited_executable_verifier() {
        let canonical = fs::canonicalize(system_cat()).unwrap();
        let expected = verify_executable("cat", &canonical);
        let actual = ImmutableExecutionProfileV1::inspect("cat", &canonical);
        match (expected, actual) {
            (Ok(identity), Ok(profile)) => {
                assert_eq!(profile.attestation, ProfileAttestation::Audited(identity));
            }
            (Err(expected), Err(ImmutableCaptureError::ExecutableNotAudited(actual))) => {
                assert_eq!(actual, expected);
            }
            (expected, actual) => {
                panic!("profile/verifier disagreement: verifier={expected:?}, profile={actual:?}")
            }
        }
    }

    #[test]
    fn same_name_script_cannot_construct_a_production_profile() {
        let executables = TempDir::new().unwrap();
        let executable =
            write_executable(executables.path(), "cat", "#!/bin/sh\nprintf malicious\n");
        assert!(matches!(
            ImmutableExecutionProfileV1::inspect("cat", &executable),
            Err(ImmutableCaptureError::ExecutableNotAudited(_))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn production_capture_requires_the_same_live_runtime_and_profile() {
        if crate::executable::host_audited_apple_profile().is_err() {
            return;
        }
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        fs::write(workspace.path().join("selected.txt"), b"sealed bytes\n").unwrap();
        let canonical = fs::canonicalize(system_cat()).unwrap();
        let profile = ImmutableExecutionProfileV1::inspect("cat", &canonical).unwrap();
        let runtime =
            crate::runtime_attestation::attest_team_runtime_v1("cat", &canonical).unwrap();
        let argv = [OsString::from("cat"), OsString::from("selected.txt")];
        let modeled_environment = environment(&[("LANG", "C"), ("LC_ALL", "C")]);
        let request_input = TeamRequestKeyInput::new_attested(
            crate::team_request_key::UnboundTeamRequestKeyInput {
                tenant_id: "tenant-a",
                repository_id: "repo-a",
                generation_id: "0123456789abcdef0123456789abcdef",
                workspace: workspace.path(),
                cwd: workspace.path(),
                argv: &argv,
                environment: &modeled_environment,
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
                policy_digest: digest(1),
                execution_profile_digest: profile.digest(),
            },
            &runtime,
        )
        .unwrap();
        let request = build_team_request_key_v1(&request_input).unwrap();
        let captured = capture_immutable_team_result_v1(ImmutableCaptureInputV1::new(
            &request,
            workspace.path(),
            snapshots.path(),
            &modeled_environment,
            &profile,
            &runtime,
            "again-test-v1",
        ))
        .unwrap();
        assert_eq!(captured.stdout, b"sealed bytes\n");

        let wrong_profile_input = TeamRequestKeyInput::new_attested(
            crate::team_request_key::UnboundTeamRequestKeyInput {
                tenant_id: "tenant-a",
                repository_id: "repo-a",
                generation_id: "0123456789abcdef0123456789abcdef",
                workspace: workspace.path(),
                cwd: workspace.path(),
                argv: &argv,
                environment: &modeled_environment,
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
                policy_digest: digest(1),
                execution_profile_digest: digest(99),
            },
            &runtime,
        )
        .unwrap();
        let wrong_profile_request = build_team_request_key_v1(&wrong_profile_input).unwrap();
        assert!(matches!(
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new(
                &wrong_profile_request,
                workspace.path(),
                snapshots.path(),
                &modeled_environment,
                &profile,
                &runtime,
                "again-test-v1",
            )),
            Err(ImmutableCaptureError::ExecutionProfileMismatch)
        ));
    }

    #[test]
    fn exact_cat_is_captured_twice_from_private_snapshot() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        fs::write(workspace.path().join("selected.txt"), b"sealed bytes\n").unwrap();
        let executable = write_executable(
            executables.path(),
            "cat",
            "#!/bin/sh\nIFS= read -r line < \"$1\"\nprintf '%s\\n' \"$line\"\n",
        );
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("cat", &executable).unwrap();
        let request = request(workspace.path(), &["cat", "selected.txt"], &[], &profile);
        let before = fs::read_dir(snapshots.path()).unwrap().count();
        let captured =
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &[],
                &profile,
                "again-test-v1",
            ))
            .unwrap();
        assert_eq!(captured.request_key, request.digest());
        assert_eq!(captured.stdout, b"sealed bytes\n");
        assert_eq!(fs::read_dir(snapshots.path()).unwrap().count(), before);
    }

    #[test]
    fn exact_modeled_environment_is_required_for_snapshot_parity() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        fs::write(workspace.path().join("selected.txt"), b"value\n").unwrap();
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("cat", &system_cat()).unwrap();
        let keyed_environment = environment(&[("LC_ALL", "C")]);
        let wrong_environment = environment(&[("LC_ALL", "C.UTF-8")]);
        let request = request(
            workspace.path(),
            &["cat", "selected.txt"],
            &keyed_environment,
            &profile,
        );
        assert!(matches!(
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &wrong_environment,
                &profile,
                "again-test-v1",
            )),
            Err(ImmutableCaptureError::RequestParityMismatch { .. })
        ));
    }

    struct ReplaceAfterRead {
        selected: PathBuf,
        replacement: PathBuf,
        fired: AtomicBool,
    }

    struct RemoveAfterDirectoryList {
        directory: PathBuf,
        fired: AtomicBool,
    }

    impl CaptureHooks for RemoveAfterDirectoryList {
        fn after_directory_listed(&self, repository_path: &Path) {
            if repository_path == Path::new("src") && !self.fired.swap(true, Ordering::SeqCst) {
                fs::remove_file(self.directory.join("value.txt")).unwrap();
            }
        }
    }

    impl CaptureHooks for ReplaceAfterRead {
        fn after_file_read(&self, repository_path: &Path) {
            if repository_path == Path::new("selected.txt")
                && !self.fired.swap(true, Ordering::SeqCst)
            {
                fs::rename(&self.replacement, &self.selected).unwrap();
            }
        }
    }

    #[test]
    fn inode_replacement_after_open_is_rejected_before_execution() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        let selected = workspace.path().join("selected.txt");
        let replacement = workspace.path().join("replacement.txt");
        fs::write(&selected, b"before").unwrap();
        let executable = write_executable(executables.path(), "cat", "#!/bin/sh\nprintf before\n");
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("cat", &executable).unwrap();
        let request = request(workspace.path(), &["cat", "selected.txt"], &[], &profile);
        fs::write(&replacement, b"after!").unwrap();
        let input = ImmutableCaptureInputV1::new_for_boundary_test(
            &request,
            workspace.path(),
            snapshots.path(),
            &[],
            &profile,
            "again-test-v1",
        );
        let result = prepare_snapshot(
            &input,
            &ReplaceAfterRead {
                selected,
                replacement,
                fired: AtomicBool::new(false),
            },
        );
        assert!(matches!(
            result,
            Err(ImmutableCaptureError::ConcurrentSourceMutation)
        ));
    }

    #[test]
    fn tree_entry_removed_after_enumeration_is_rejected_as_a_race() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        fs::write(workspace.path().join("src/value.txt"), b"needle\n").unwrap();
        let executable = write_executable(executables.path(), "rg", "#!/bin/sh\nprintf ok\n");
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("rg", &executable).unwrap();
        let request = request(
            workspace.path(),
            &["rg", "--no-ignore", "--sort=path", "needle", "src"],
            &[],
            &profile,
        );
        let input = ImmutableCaptureInputV1::new_for_boundary_test(
            &request,
            workspace.path(),
            snapshots.path(),
            &[],
            &profile,
            "again-test-v1",
        );
        let result = prepare_snapshot(
            &input,
            &RemoveAfterDirectoryList {
                directory: workspace.path().join("src"),
                fired: AtomicBool::new(false),
            },
        );
        assert!(matches!(
            result,
            Err(ImmutableCaptureError::ConcurrentSourceMutation)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn source_replaced_by_symlink_after_keying_is_rejected() {
        use std::os::unix::fs::symlink;

        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        fs::write(workspace.path().join("selected.txt"), b"before").unwrap();
        fs::write(workspace.path().join("target.txt"), b"target").unwrap();
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("cat", &system_cat()).unwrap();
        let request = request(workspace.path(), &["cat", "selected.txt"], &[], &profile);
        fs::remove_file(workspace.path().join("selected.txt")).unwrap();
        symlink("target.txt", workspace.path().join("selected.txt")).unwrap();
        assert!(matches!(
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &[],
                &profile,
                "again-test-v1",
            )),
            Err(ImmutableCaptureError::SymlinkSource)
        ));
    }

    #[test]
    fn executable_replacement_after_profile_inspection_is_rejected() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        fs::write(workspace.path().join("selected.txt"), b"value").unwrap();
        let executable = write_executable(executables.path(), "cat", "#!/bin/sh\nprintf first\n");
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("cat", &executable).unwrap();
        let request = request(workspace.path(), &["cat", "selected.txt"], &[], &profile);
        fs::write(&executable, "#!/bin/sh\nprintf second\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &[],
                &profile,
                "again-test-v1",
            )),
            Err(ImmutableCaptureError::ExecutableChanged)
        ));
    }

    #[test]
    fn nondeterministic_two_run_output_cannot_mint_result() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        fs::write(workspace.path().join("selected.txt"), b"value").unwrap();
        let executable =
            write_executable(executables.path(), "cat", "#!/bin/sh\nprintf '%s' \"$$\"\n");
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("cat", &executable).unwrap();
        let request = request(workspace.path(), &["cat", "selected.txt"], &[], &profile);
        assert!(matches!(
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &[],
                &profile,
                "again-test-v1",
            )),
            Err(ImmutableCaptureError::LocalValidation(
                LocalResultValidationError::ExecutionMismatch
            ))
        ));
    }

    #[test]
    fn nonzero_capture_retains_first_complete_execution_and_starts_only_twice() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf exact-out\nexit 7\n",
            counter.display()
        );
        let failure = boundary_attempt(&body, &NoCaptureHooks, EXECUTION_TIMEOUT).unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: Some(first),
                source:
                    ImmutableCaptureError::LocalValidation(LocalResultValidationError::NonZeroExit {
                        run: 1,
                        code: 7,
                    }),
            } => {
                assert_eq!(first.stdout(), b"exact-out");
                assert_eq!(first.stderr(), b"");
                assert_eq!(first.exit_code(), 7);
            }
            other => panic!("unexpected capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 2);
    }

    #[test]
    fn stderr_capture_retains_exact_first_streams_and_starts_only_twice() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf exact-out\nprintf exact-err >&2\n",
            counter.display()
        );
        let failure = boundary_attempt(&body, &NoCaptureHooks, EXECUTION_TIMEOUT).unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: Some(first),
                source:
                    ImmutableCaptureError::LocalValidation(LocalResultValidationError::NonEmptyStderr {
                        run: 1,
                        ..
                    }),
            } => {
                assert_eq!(first.stdout(), b"exact-out");
                assert_eq!(first.stderr(), b"exact-err");
                assert_eq!(first.exit_code(), 0);
            }
            other => panic!("unexpected capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 2);
    }

    #[test]
    fn divergent_second_run_returns_first_complete_without_a_third_start() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let marker = state.path().join("marker");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nif [ -e '{}' ]; then printf second; else : > '{}'; printf first; fi\n",
            counter.display(),
            marker.display(),
            marker.display()
        );
        let failure = boundary_attempt(&body, &NoCaptureHooks, EXECUTION_TIMEOUT).unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: Some(first),
                source:
                    ImmutableCaptureError::LocalValidation(
                        LocalResultValidationError::ExecutionMismatch,
                    ),
            } => assert_eq!(first.stdout(), b"first"),
            other => panic!("unexpected capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 2);
    }

    #[test]
    fn second_run_failure_returns_first_complete_without_a_third_start() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let marker = state.path().join("marker");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nif [ -e '{}' ]; then exit 9; else : > '{}'; printf first; fi\n",
            counter.display(),
            marker.display(),
            marker.display()
        );
        let failure = boundary_attempt(&body, &NoCaptureHooks, EXECUTION_TIMEOUT).unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: Some(first),
                source:
                    ImmutableCaptureError::LocalValidation(LocalResultValidationError::NonZeroExit {
                        run: 2,
                        code: 9,
                    }),
            } => assert_eq!(first.stdout(), b"first"),
            other => panic!("unexpected capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 2);
    }

    #[test]
    fn parity_failure_after_first_run_starts_once_and_retains_first_complete() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf first\n",
            counter.display()
        );
        let failure =
            boundary_attempt(&body, &MutateSnapshotAfterRun { run: 1 }, EXECUTION_TIMEOUT)
                .unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: Some(first),
                source:
                    ImmutableCaptureError::RequestParityMismatch {
                        phase: ParityPhase::AfterFirst,
                    },
            } => assert_eq!(first.stdout(), b"first"),
            other => panic!("unexpected capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 1);
    }

    #[test]
    fn interruption_during_snapshot_never_starts_a_command() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf should-not-run\n",
            counter.display()
        );
        let failure = boundary_attempt(
            &body,
            &RaiseOnFirstFileRead {
                signal: libc::SIGTERM,
                fired: AtomicBool::new(false),
            },
            EXECUTION_TIMEOUT,
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            ImmutableCaptureFailureV1::Interrupted {
                signal: libc::SIGTERM,
                retained_execution: None,
            }
        ));
        assert_eq!(execution_count(&counter), 0);
    }

    #[test]
    fn interruption_between_runs_retains_first_and_never_starts_shadow() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf exact-first\n",
            counter.display()
        );
        let failure = boundary_attempt(
            &body,
            &RaiseAfterFirstExecution {
                signal: libc::SIGINT,
            },
            EXECUTION_TIMEOUT,
        )
        .unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::Interrupted {
                signal: libc::SIGINT,
                retained_execution: Some(first),
            } => {
                assert_eq!(first.stdout(), b"exact-first");
                assert_eq!(first.stderr(), b"");
                assert_eq!(first.exit_code(), 0);
            }
            other => panic!("unexpected capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 1);
    }

    #[test]
    fn first_run_timeout_is_post_start_and_never_launches_a_fallback_candidate() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\n/bin/sleep 1\n",
            counter.display()
        );
        let hooks = WaitForChildMarker {
            counter: counter.clone(),
            first_timeout: Duration::from_millis(25),
            second_timeout: Duration::from_secs(2),
        };
        let failure = boundary_attempt(&body, &hooks, EXECUTION_TIMEOUT).unwrap_err();
        assert!(matches!(
            failure,
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: None,
                source: ImmutableCaptureError::ExecutionTimeout { run: 1 },
            }
        ));
        assert_eq!(execution_count(&counter), 1);
    }

    #[test]
    fn exited_leader_with_pipe_holding_descendant_times_out_and_cleans_group() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let process_group_file = state.path().join("process-group");
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\n/bin/sleep 3600 &\nprintf x >> '{}'\n",
            process_group_file.display(),
            counter.display()
        );
        let hooks = WaitForChildMarker {
            counter: counter.clone(),
            first_timeout: Duration::from_millis(100),
            second_timeout: Duration::from_secs(2),
        };
        let started = Instant::now();
        let failure = boundary_attempt(&body, &hooks, EXECUTION_TIMEOUT).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "capture exceeded its bounded lifecycle"
        );
        assert!(matches!(
            failure,
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: None,
                source: ImmutableCaptureError::ExecutionTimeout { run: 1 },
            }
        ));
        assert_eq!(execution_count(&counter), 1);
        let process_group = fs::read_to_string(process_group_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        wait_for_process_group_exit(process_group);
    }

    #[test]
    fn injected_try_wait_error_terminates_group_and_reaps_leader() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\n/bin/sleep 3600 &\nprintf x >> '{}'\nwait\n",
            counter.display()
        );
        let hooks = InjectFirstTryWaitError {
            counter: counter.clone(),
            leader_pid: AtomicU32::new(0),
            fired: AtomicBool::new(false),
        };
        let failure = boundary_attempt(&body, &hooks, Duration::from_secs(2)).unwrap_err();
        assert!(matches!(
            failure,
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: None,
                source: ImmutableCaptureError::Io {
                    operation: "wait for immutable command",
                    kind: io::ErrorKind::Other,
                    ..
                },
            }
        ));
        assert_eq!(execution_count(&counter), 1);
        let leader_pid = hooks.leader_pid.load(Ordering::SeqCst) as libc::pid_t;
        assert!(leader_pid > 0);
        wait_for_process_group_exit(leader_pid);
        assert_child_reaped(leader_pid);
    }

    #[test]
    #[ignore = "spawned in isolation by forwards_parent_signals_to_retained_process_group"]
    fn immutable_signal_subprocess_helper() {
        let directory = PathBuf::from(
            std::env::var_os(SIGNAL_HELPER_DIRECTORY)
                .expect("isolated signal helper directory is required"),
        );
        let signal = std::env::var(SIGNAL_HELPER_SIGNAL)
            .expect("isolated signal helper number is required")
            .parse::<libc::c_int>()
            .unwrap();
        assert!(FORWARDED_SIGNALS.contains(&signal));

        let counter = directory.join("runs");
        let process_group_file = directory.join("process-group");
        let forwarded_file = directory.join("forwarded");
        let ignore_first = std::env::var_os(SIGNAL_HELPER_IGNORE_FIRST).is_some();
        let trap = if ignore_first {
            "trap '' HUP INT TERM".to_owned()
        } else {
            format!(
                "trap 'printf forwarded > \"{}\"; exit 0' HUP INT TERM",
                forwarded_file.display()
            )
        };
        let body = format!(
            "#!/bin/sh\n{trap}\nprintf x >> '{}'\nprintf '%s\\n' \"$$\" > '{}'\nprintf before-signal\n/bin/sleep 3600 &\nwait\n",
            counter.display(),
            process_group_file.display(),
        );
        let failure = boundary_attempt(&body, &NoCaptureHooks, Duration::from_secs(5)).unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::Interrupted {
                signal: actual,
                retained_execution,
            } => {
                assert_eq!(actual, signal);
                if let Some(retained) = retained_execution {
                    assert!(retained.stdout().starts_with(b"before-signal"));
                }
            }
            other => panic!("unexpected isolated capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 1);
        if ignore_first {
            assert!(!forwarded_file.exists());
        } else {
            assert_eq!(fs::read(&forwarded_file).unwrap(), b"forwarded");
        }
        let process_group = fs::read_to_string(process_group_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        wait_for_process_group_exit(process_group);
    }

    #[test]
    fn forwards_parent_signals_to_retained_process_group() {
        const HELPER_TEST: &str =
            "team_manifest_v2::immutable_capture::tests::immutable_signal_subprocess_helper";

        for signal in FORWARDED_SIGNALS {
            let state = TempDir::new().unwrap();
            let process_group_file = state.path().join("process-group");
            let mut helper = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(HELPER_TEST)
                .arg("--ignored")
                .arg("--nocapture")
                .env(SIGNAL_HELPER_DIRECTORY, state.path())
                .env(SIGNAL_HELPER_SIGNAL, signal.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();

            let ready_deadline = Instant::now() + Duration::from_secs(5);
            while fs::read_to_string(&process_group_file)
                .ok()
                .is_none_or(|value| value.trim().is_empty())
            {
                if Instant::now() >= ready_deadline {
                    let _ = helper.kill();
                    let output = helper.wait_with_output().unwrap();
                    panic!(
                        "signal helper never retained its group for {signal}: stdout={} stderr={}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                    );
                }
                thread::sleep(CHILD_POLL_INTERVAL);
            }

            let helper_pid = libc::pid_t::try_from(helper.id()).unwrap();
            // SAFETY: helper_pid names the live isolated test subprocess and
            // signal is one of the three supported forwarding signals.
            assert_eq!(unsafe { libc::kill(helper_pid, signal) }, 0);
            let output = helper.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "isolated forwarding test failed for signal {signal}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[test]
    fn single_parent_signal_forces_cleanup_after_bounded_grace() {
        const HELPER_TEST: &str =
            "team_manifest_v2::immutable_capture::tests::immutable_signal_subprocess_helper";

        let state = TempDir::new().unwrap();
        let process_group_file = state.path().join("process-group");
        let helper = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(HELPER_TEST)
            .arg("--ignored")
            .arg("--nocapture")
            .env(SIGNAL_HELPER_DIRECTORY, state.path())
            .env(SIGNAL_HELPER_SIGNAL, libc::SIGTERM.to_string())
            .env(SIGNAL_HELPER_IGNORE_FIRST, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while fs::read_to_string(&process_group_file)
            .ok()
            .is_none_or(|value| value.trim().is_empty())
        {
            assert!(
                Instant::now() < ready_deadline,
                "bounded-grace helper never retained its process group"
            );
            thread::sleep(CHILD_POLL_INTERVAL);
        }
        let helper_pid = libc::pid_t::try_from(helper.id()).unwrap();
        let interrupted_at = Instant::now();
        // SAFETY: helper_pid names the live isolated test subprocess.
        assert_eq!(unsafe { libc::kill(helper_pid, libc::SIGTERM) }, 0);
        let output = helper.wait_with_output().unwrap();
        let elapsed = interrupted_at.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200),
            "the ignored signal was escalated before the documented grace: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "forced interruption cleanup exceeded its bound: {elapsed:?}"
        );
        assert!(
            output.status.success(),
            "isolated bounded-grace test failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn second_parent_signal_escalates_immediately() {
        const HELPER_TEST: &str =
            "team_manifest_v2::immutable_capture::tests::immutable_signal_subprocess_helper";

        let state = TempDir::new().unwrap();
        let process_group_file = state.path().join("process-group");
        let helper = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(HELPER_TEST)
            .arg("--ignored")
            .arg("--nocapture")
            .env(SIGNAL_HELPER_DIRECTORY, state.path())
            .env(SIGNAL_HELPER_SIGNAL, libc::SIGTERM.to_string())
            .env(SIGNAL_HELPER_IGNORE_FIRST, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let ready_deadline = Instant::now() + Duration::from_secs(5);
        while fs::read_to_string(&process_group_file)
            .ok()
            .is_none_or(|value| value.trim().is_empty())
        {
            assert!(
                Instant::now() < ready_deadline,
                "escalation helper never retained its process group"
            );
            thread::sleep(CHILD_POLL_INTERVAL);
        }
        let helper_pid = libc::pid_t::try_from(helper.id()).unwrap();
        // SAFETY: helper_pid names the live isolated test subprocess.
        assert_eq!(unsafe { libc::kill(helper_pid, libc::SIGTERM) }, 0);
        thread::sleep(Duration::from_millis(25));
        // SAFETY: the same live helper receives a second supported signal,
        // which must escalate its retained child group immediately.
        assert_eq!(unsafe { libc::kill(helper_pid, libc::SIGTERM) }, 0);

        let output = helper.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "isolated escalation test failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn short_lived_background_descendants_are_captured_exactly_twice() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf parent-\n( /bin/sleep 0.025; printf descendant ) &\nwait\n",
            counter.display()
        );
        let captured = boundary_attempt(&body, &NoCaptureHooks, Duration::from_secs(2)).unwrap();
        assert_eq!(captured.stdout, b"parent-descendant");
        assert_eq!(execution_count(&counter), 2);
    }

    #[test]
    fn second_run_timeout_retains_first_complete_and_starts_only_twice() {
        let state = TempDir::new().unwrap();
        let counter = state.path().join("runs");
        let marker = state.path().join("marker");
        let body = format!(
            "#!/bin/sh\nprintf x >> '{}'\nif [ -e '{}' ]; then /bin/sleep 1; else : > '{}'; printf first; fi\n",
            counter.display(),
            marker.display(),
            marker.display()
        );
        let hooks = WaitForChildMarker {
            counter: counter.clone(),
            first_timeout: Duration::from_secs(2),
            second_timeout: Duration::from_millis(25),
        };
        let failure = boundary_attempt(&body, &hooks, EXECUTION_TIMEOUT).unwrap_err();
        match failure {
            ImmutableCaptureFailureV1::AfterStart {
                first_complete: Some(first),
                source: ImmutableCaptureError::ExecutionTimeout { run: 2 },
            } => assert_eq!(first.stdout(), b"first"),
            other => panic!("unexpected capture result: {other:?}"),
        }
        assert_eq!(execution_count(&counter), 2);
    }

    #[test]
    fn tree_snapshot_preserves_visible_layout_and_empty_directories() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        fs::create_dir_all(workspace.path().join("src/empty")).unwrap();
        fs::write(workspace.path().join("src/value.txt"), b"needle\n").unwrap();
        fs::create_dir(workspace.path().join("src/.hidden")).unwrap();
        fs::write(workspace.path().join("src/.hidden/secret"), b"not observed").unwrap();
        let executable = write_executable(
            executables.path(),
            "rg",
            "#!/bin/sh\nprintf 'src/value.txt:needle\\n'\n",
        );
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("rg", &executable).unwrap();
        let request = request(
            workspace.path(),
            &["rg", "--no-ignore", "--sort=path", "needle", "src"],
            &[],
            &profile,
        );
        let captured =
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &[],
                &profile,
                "again-test-v1",
            ))
            .unwrap();
        assert_eq!(captured.stdout, b"src/value.txt:needle\n");
    }

    #[test]
    fn overlapping_tree_observations_reopen_independent_directory_streams() {
        let workspace = TempDir::new().unwrap();
        let snapshots = TempDir::new().unwrap();
        let executables = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        fs::write(workspace.path().join("src/value.txt"), b"needle\n").unwrap();
        let executable = write_executable(executables.path(), "rg", "#!/bin/sh\nprintf ok\n");
        let profile =
            ImmutableExecutionProfileV1::inspect_for_boundary_test("rg", &executable).unwrap();
        let request = request(
            workspace.path(),
            &["rg", "--no-ignore", "--sort=path", "needle", "src", "src"],
            &[],
            &profile,
        );
        let captured =
            capture_immutable_team_result_v1(ImmutableCaptureInputV1::new_for_boundary_test(
                &request,
                workspace.path(),
                snapshots.path(),
                &[],
                &profile,
                "again-test-v1",
            ))
            .unwrap();
        assert_eq!(captured.stdout, b"ok");
    }
}
