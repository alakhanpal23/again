//! Opt-in user-facing orchestration for the sealed team-cache protocol.
//!
//! `again team run` is deliberately a fresh-process, no-daemon path. A result
//! is presented as a hit only after the pull layer returns its unforgeable
//! verified-plaintext capability. The sole miss signal is
//! [`TeamPullError::CacheMiss`]; every other remote/trust/manifest failure is
//! quarantined locally and falls back to exactly one audited local execution.

use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use tokio::runtime::Builder;
use uuid::Uuid;

use crate::executable::verify_executable;
use crate::fingerprint::SessionFileDigestCache;
use crate::remote::{RemoteError, ServiceErrorClass};
#[cfg(test)]
use crate::runtime_attestation::RuntimeAttestationError;
use crate::runtime_attestation::TeamRuntimeAttestationV1;
use crate::store::{EventDisposition, Store};
use crate::team::MAX_MANIFEST_LIFETIME_SECONDS;
use crate::team_admission::{admit_team_command, preflight_team_command};
#[cfg(test)]
use crate::team_admission::{
    bare_command_name, exact_team_environment, runtime_checkpoint_refresh_allowed,
};
use crate::team_clock::{SystemTeamClock, TeamClock};
use crate::team_config::TeamLookupProtocolV1;
use crate::team_publish::{
    TeamPostCaptureFailureV1, TeamPublishCaptureV1, TeamPublishError, TeamPublishOptionsV1,
    publish_immutable_remote_v2,
};
use crate::team_pull::{TeamPullError, pull_verified_remote_bundle_v1, pull_verified_remote_v2};
use crate::team_request_key::build_team_request_key_v1_with_cache;
#[cfg(test)]
use crate::team_request_key::preflight_team_request_v1;

const SNAPSHOT_DIRECTORY_NAME: &str = "snapshots";
const TEAM_PRODUCER_VERSION: &str = concat!("again-", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TeamEventReason {
    TtyBypass,
    DigestCacheUnavailable,
    RequestPrivacyLocal,
    ExactRemoteReuse,
    CapturedAndPublished,
    CapturedLocalPrivacy,
    CapturedLocalManifest,
    CapturedLocalTransport,
    CapturedLocalClock,
    CapturedLocalRequestChanged,
    MissReadOnlyProfile,
    PullConfigurationDegraded,
    PullBindingDegraded,
    PullRuntimeDegraded,
    PullTransportDegraded,
    PullTrustDegraded,
    PullClockDegraded,
    PullCorruptionDegraded,
    SnapshotBoundaryDegraded,
    PublishConfigurationDegraded,
    PublishBindingDegraded,
    PublishTransportDegraded,
    PublishTrustDegraded,
    PublishCaptureDegraded,
    PublishManifestDegraded,
}

impl TeamEventReason {
    const fn code(self) -> &'static str {
        match self {
            Self::TtyBypass => "TEAM_TTY_BYPASS",
            Self::DigestCacheUnavailable => "TEAM_DIGEST_CACHE_UNAVAILABLE",
            Self::RequestPrivacyLocal => "TEAM_REQUEST_PRIVACY_LOCAL",
            Self::ExactRemoteReuse => "TEAM_EXACT_REMOTE_REUSE",
            Self::CapturedAndPublished => "TEAM_CAPTURED_AND_PUBLISHED",
            Self::CapturedLocalPrivacy => "TEAM_CAPTURED_LOCAL_PRIVACY",
            Self::CapturedLocalManifest => "TEAM_CAPTURED_LOCAL_MANIFEST",
            Self::CapturedLocalTransport => "TEAM_CAPTURED_LOCAL_TRANSPORT",
            Self::CapturedLocalClock => "TEAM_CAPTURED_LOCAL_CLOCK",
            Self::CapturedLocalRequestChanged => "TEAM_CAPTURED_LOCAL_REQUEST_CHANGED",
            Self::MissReadOnlyProfile => "TEAM_MISS_READ_ONLY_PROFILE",
            Self::PullConfigurationDegraded => "TEAM_PULL_CONFIGURATION_DEGRADED",
            Self::PullBindingDegraded => "TEAM_PULL_BINDING_DEGRADED",
            Self::PullRuntimeDegraded => "TEAM_PULL_RUNTIME_DEGRADED",
            Self::PullTransportDegraded => "TEAM_PULL_TRANSPORT_DEGRADED",
            Self::PullTrustDegraded => "TEAM_PULL_TRUST_DEGRADED",
            Self::PullClockDegraded => "TEAM_PULL_CLOCK_DEGRADED",
            Self::PullCorruptionDegraded => "TEAM_PULL_CORRUPTION_DEGRADED",
            Self::SnapshotBoundaryDegraded => "TEAM_SNAPSHOT_BOUNDARY_DEGRADED",
            Self::PublishConfigurationDegraded => "TEAM_PUBLISH_CONFIGURATION_DEGRADED",
            Self::PublishBindingDegraded => "TEAM_PUBLISH_BINDING_DEGRADED",
            Self::PublishTransportDegraded => "TEAM_PUBLISH_TRANSPORT_DEGRADED",
            Self::PublishTrustDegraded => "TEAM_PUBLISH_TRUST_DEGRADED",
            Self::PublishCaptureDegraded => "TEAM_PUBLISH_CAPTURE_DEGRADED",
            Self::PublishManifestDegraded => "TEAM_PUBLISH_MANIFEST_DEGRADED",
        }
    }

    const fn fallback_disposition(self) -> EventDisposition {
        match self {
            Self::TtyBypass
            | Self::DigestCacheUnavailable
            | Self::RequestPrivacyLocal
            | Self::CapturedLocalPrivacy
            | Self::CapturedLocalTransport
            | Self::CapturedLocalClock
            | Self::MissReadOnlyProfile
            | Self::PullTransportDegraded
            | Self::SnapshotBoundaryDegraded
            | Self::PublishTransportDegraded => EventDisposition::BypassedNoStore,
            Self::ExactRemoteReuse => EventDisposition::ReplayedFull,
            Self::CapturedAndPublished => EventDisposition::Executed,
            Self::CapturedLocalManifest
            | Self::CapturedLocalRequestChanged
            | Self::PullConfigurationDegraded
            | Self::PullBindingDegraded
            | Self::PullRuntimeDegraded
            | Self::PullTrustDegraded
            | Self::PullClockDegraded
            | Self::PullCorruptionDegraded
            | Self::PublishConfigurationDegraded
            | Self::PublishBindingDegraded
            | Self::PublishTrustDegraded
            | Self::PublishCaptureDegraded
            | Self::PublishManifestDegraded => EventDisposition::Quarantined,
        }
    }
}

enum PullRoute<T> {
    Hit(T),
    Miss,
    Degraded(TeamEventReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissRoute {
    Publish,
    LocalReadOnly,
}

enum DigestCacheRoute<T> {
    Ready(T),
    Local,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteFailureClass {
    Transient,
    ConfigurationOrAuth,
    Corruption,
}

/// Execute one opt-in team-cache request.
pub(crate) fn run(profile_path: PathBuf, command: Vec<OsString>) -> Result<i32> {
    let started = Instant::now();
    let preflight = preflight_team_command(profile_path, command)?;
    let stdin_is_tty = io::stdin().is_terminal();
    let stdout_is_tty = io::stdout().is_terminal();
    let stderr_is_tty = io::stderr().is_terminal();
    if stdin_is_tty || stdout_is_tty || stderr_is_tty {
        return tty_local_bypass(
            preflight.workspace(),
            preflight.cwd(),
            preflight.command_name(),
            preflight.command(),
            preflight.environment(),
            preflight.executable(),
        );
    }
    let mut persistent_digest_cache =
        match route_digest_cache(Store::open_for_workspace(preflight.workspace())) {
            DigestCacheRoute::Ready(store) => store,
            DigestCacheRoute::Local => {
                return pre_runtime_local_bypass(
                    preflight.workspace(),
                    preflight.cwd(),
                    preflight.command_name(),
                    preflight.command(),
                    preflight.environment(),
                    preflight.executable(),
                    TeamEventReason::DigestCacheUnavailable,
                    false,
                    started,
                );
            }
        };
    let mut digest_cache = SessionFileDigestCache::new(&mut persistent_digest_cache);
    let admission = admit_team_command(preflight, &mut digest_cache)?;
    let remote_admission = match admission.remote_request_admission() {
        Ok(remote_admission) => remote_admission,
        Err(_) => {
            return local_fallback(
                admission.workspace(),
                admission.cwd(),
                admission.command_name(),
                admission.command(),
                admission.environment(),
                admission.executable(),
                admission.runtime(),
                TeamEventReason::RequestPrivacyLocal,
                started,
            );
        }
    };
    let request_input = admission.request_input()?;

    let async_runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("start bounded team transport runtime")?;
    let mut clock = SystemTeamClock::new();
    // The admitted profile selects exactly one wire protocol. Neither errors
    // nor misses trigger a retry through the other protocol: silently probing
    // both would turn an authenticated capability pin into a downgrade path.
    let pulled = match admission.profile().lookup_protocol() {
        TeamLookupProtocolV1::LegacyV2 => async_runtime.block_on(pull_verified_remote_v2(
            admission.profile_path(),
            &request_input,
            admission.request(),
            remote_admission,
            admission.runtime(),
            &mut digest_cache,
            &mut clock,
        )),
        TeamLookupProtocolV1::BundleV1 => async_runtime.block_on(pull_verified_remote_bundle_v1(
            admission.profile_path(),
            &request_input,
            admission.request(),
            remote_admission,
            admission.runtime(),
            &mut digest_cache,
            &mut clock,
        )),
    };
    let route = route_pull(pulled);

    match route {
        PullRoute::Hit(result) => {
            let live_request =
                match build_team_request_key_v1_with_cache(&request_input, &mut digest_cache) {
                    Ok(live_request) if live_request == *admission.request() => live_request,
                    Ok(_) | Err(_) => {
                        return local_fallback(
                            admission.workspace(),
                            admission.cwd(),
                            admission.command_name(),
                            admission.command(),
                            admission.environment(),
                            admission.executable(),
                            admission.runtime(),
                            TeamEventReason::PullBindingDegraded,
                            started,
                        );
                    }
                };
            if admission
                .runtime()
                .verify_request_binding(&live_request)
                .is_err()
            {
                return local_fallback(
                    admission.workspace(),
                    admission.cwd(),
                    admission.command_name(),
                    admission.command(),
                    admission.environment(),
                    admission.executable(),
                    admission.runtime(),
                    TeamEventReason::PullRuntimeDegraded,
                    started,
                );
            }
            let release_now = match clock.sample_unix_seconds() {
                Ok(now) => now,
                Err(_) => {
                    return local_fallback(
                        admission.workspace(),
                        admission.cwd(),
                        admission.command_name(),
                        admission.command(),
                        admission.environment(),
                        admission.executable(),
                        admission.runtime(),
                        TeamEventReason::PullClockDegraded,
                        started,
                    );
                }
            };
            if result.verify_fresh_for_release(release_now).is_err() {
                return local_fallback(
                    admission.workspace(),
                    admission.cwd(),
                    admission.command_name(),
                    admission.command(),
                    admission.environment(),
                    admission.executable(),
                    admission.runtime(),
                    TeamEventReason::PullTrustDegraded,
                    started,
                );
            }
            let producer_duration_micros = result.duration_micros();
            let exit = present_exact(result.stdout(), result.stderr())?;
            let (saved_ms, bytes_omitted) =
                exact_remote_reuse_metrics(producer_duration_micros, started.elapsed());
            record_team_event(
                admission.workspace(),
                EventDisposition::ReplayedFull,
                TeamEventReason::ExactRemoteReuse,
                saved_ms,
                bytes_omitted,
            );
            Ok(exit)
        }
        PullRoute::Degraded(reason) => local_fallback(
            admission.workspace(),
            admission.cwd(),
            admission.command_name(),
            admission.command(),
            admission.environment(),
            admission.executable(),
            admission.runtime(),
            reason,
            started,
        ),
        PullRoute::Miss => match miss_route(admission.profile().publisher().is_some()) {
            MissRoute::LocalReadOnly => local_fallback(
                admission.workspace(),
                admission.cwd(),
                admission.command_name(),
                admission.command(),
                admission.environment(),
                admission.executable(),
                admission.runtime(),
                TeamEventReason::MissReadOnlyProfile,
                started,
            ),
            MissRoute::Publish => {
                let snapshot_parent = match ensure_snapshot_parent(
                    admission.workspace(),
                    admission.profile().runtime_attestation_checkpoint_file(),
                ) {
                    Ok(path) => path,
                    Err(_) => {
                        return local_fallback(
                            admission.workspace(),
                            admission.cwd(),
                            admission.command_name(),
                            admission.command(),
                            admission.environment(),
                            admission.executable(),
                            admission.runtime(),
                            TeamEventReason::SnapshotBoundaryDegraded,
                            started,
                        );
                    }
                };
                let record_id = format!("team-{}", Uuid::new_v4().simple());
                let published = async_runtime.block_on(publish_immutable_remote_v2(
                    admission.profile_path(),
                    &request_input,
                    admission.request(),
                    remote_admission,
                    TeamPublishCaptureV1 {
                        workspace: admission.workspace(),
                        snapshot_parent: &snapshot_parent,
                        environment: admission.environment(),
                        execution_profile: admission.execution_profile(),
                        runtime: admission.runtime(),
                        producer_version: TEAM_PRODUCER_VERSION,
                    },
                    TeamPublishOptionsV1 {
                        record_id: &record_id,
                        lifetime_seconds: MAX_MANIFEST_LIFETIME_SECONDS,
                    },
                    &mut digest_cache,
                    &mut clock,
                ));
                match published {
                    Ok(outcome) => {
                        let reason = match outcome.publication() {
                            Ok(_) => TeamEventReason::CapturedAndPublished,
                            Err(error) => post_capture_reason(error),
                        };
                        let disposition = reason.fallback_disposition();
                        let exit = present_exact_with_exit(
                            outcome.stdout(),
                            outcome.stderr(),
                            outcome.exit_code(),
                        )?;
                        record_team_event(
                            admission.workspace(),
                            disposition,
                            reason,
                            started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                            0,
                        );
                        Ok(exit)
                    }
                    Err(TeamPublishError::CaptureAfterStart(error)) => {
                        let exit = if matches!(
                            error,
                            crate::team_manifest_v2::ImmutableCaptureError::ExecutionTimeout { .. }
                        ) {
                            124
                        } else {
                            1
                        };
                        record_team_event(
                            admission.workspace(),
                            EventDisposition::Quarantined,
                            TeamEventReason::PublishCaptureDegraded,
                            started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                            0,
                        );
                        Ok(exit)
                    }
                    Err(error) => local_fallback(
                        admission.workspace(),
                        admission.cwd(),
                        admission.command_name(),
                        admission.command(),
                        admission.environment(),
                        admission.executable(),
                        admission.runtime(),
                        publish_error_reason(&error),
                        started,
                    ),
                }
            }
        },
    }
}

fn route_pull<T>(result: Result<T, TeamPullError>) -> PullRoute<T> {
    match result {
        Ok(result) => PullRoute::Hit(result),
        Err(TeamPullError::CacheMiss) => PullRoute::Miss,
        Err(error) => PullRoute::Degraded(pull_error_reason(&error)),
    }
}

fn miss_route(can_publish: bool) -> MissRoute {
    if can_publish {
        MissRoute::Publish
    } else {
        MissRoute::LocalReadOnly
    }
}

fn route_digest_cache<T, E>(result: std::result::Result<T, E>) -> DigestCacheRoute<T> {
    match result {
        Ok(cache) => DigestCacheRoute::Ready(cache),
        Err(_) => DigestCacheRoute::Local,
    }
}

fn estimated_saved_millis(producer_duration_micros: u64, lookup_elapsed: Duration) -> u64 {
    let lookup_micros = lookup_elapsed.as_micros().min(u64::MAX as u128) as u64;
    producer_duration_micros.saturating_sub(lookup_micros) / 1_000
}

fn exact_remote_reuse_metrics(
    producer_duration_micros: u64,
    lookup_elapsed: Duration,
) -> (u64, u64) {
    // Exact replay retains the complete output, so it omits no bytes. Only
    // avoided execution time contributes to the saved-time metric.
    (
        estimated_saved_millis(producer_duration_micros, lookup_elapsed),
        0,
    )
}

fn pull_error_reason(error: &TeamPullError) -> TeamEventReason {
    match error {
        TeamPullError::CacheMiss => TeamEventReason::PullTransportDegraded,
        TeamPullError::Config(_) => TeamEventReason::PullConfigurationDegraded,
        TeamPullError::TenantMismatch
        | TeamPullError::RepositoryMismatch
        | TeamPullError::GenerationMismatch
        | TeamPullError::PolicyMismatch
        | TeamPullError::RequestAdmissionMismatch
        | TeamPullError::Request(_)
        | TeamPullError::RequestChangedDuringLookup
        | TeamPullError::TransportBindingMismatch => TeamEventReason::PullBindingDegraded,
        TeamPullError::RuntimeAttestation(_) => TeamEventReason::PullRuntimeDegraded,
        TeamPullError::Remote(error) => match classify_remote_error(error) {
            RemoteFailureClass::Transient => TeamEventReason::PullTransportDegraded,
            RemoteFailureClass::ConfigurationOrAuth => TeamEventReason::PullConfigurationDegraded,
            RemoteFailureClass::Corruption => TeamEventReason::PullCorruptionDegraded,
        },
        TeamPullError::Trust(_) => TeamEventReason::PullTrustDegraded,
        TeamPullError::Manifest(_) | TeamPullError::LookupBundleWire(_) => {
            TeamEventReason::PullCorruptionDegraded
        }
        TeamPullError::Clock(_) => TeamEventReason::PullClockDegraded,
    }
}

fn publish_error_reason(error: &TeamPublishError) -> TeamEventReason {
    match error {
        TeamPublishError::Config(_) => TeamEventReason::PublishConfigurationDegraded,
        TeamPublishError::TenantMismatch
        | TeamPublishError::RepositoryMismatch
        | TeamPublishError::GenerationMismatch
        | TeamPublishError::PolicyMismatch
        | TeamPublishError::RequestAdmissionMismatch
        | TeamPublishError::InvalidRecordId
        | TeamPublishError::InvalidLifetime
        | TeamPublishError::InvalidSystemClock
        | TeamPublishError::Request(_)
        | TeamPublishError::RequestChangedBeforeNetwork
        | TeamPublishError::TransportBindingMismatch => TeamEventReason::PublishBindingDegraded,
        TeamPublishError::RuntimeAttestation(_) => TeamEventReason::PublishCaptureDegraded,
        TeamPublishError::Remote(error) => match classify_remote_error(error) {
            RemoteFailureClass::Transient => TeamEventReason::PublishTransportDegraded,
            RemoteFailureClass::ConfigurationOrAuth => {
                TeamEventReason::PublishConfigurationDegraded
            }
            RemoteFailureClass::Corruption => TeamEventReason::PublishManifestDegraded,
        },
        TeamPublishError::Trust(_) => TeamEventReason::PublishTrustDegraded,
        TeamPublishError::CaptureBeforeStart(_) | TeamPublishError::CaptureAfterStart(_) => {
            TeamEventReason::PublishCaptureDegraded
        }
        TeamPublishError::Clock(_) => TeamEventReason::PublishTrustDegraded,
        TeamPublishError::Manifest(_) => TeamEventReason::PublishManifestDegraded,
    }
}

fn classify_remote_error(error: &RemoteError) -> RemoteFailureClass {
    match error {
        RemoteError::Timeout { .. }
        | RemoteError::Transport { .. }
        | RemoteError::RateLimited
        | RemoteError::ServiceRejected {
            class: ServiceErrorClass::Transient,
            ..
        }
        | RemoteError::UnexpectedStatus(408 | 425 | 500..=599) => RemoteFailureClass::Transient,

        RemoteError::InvalidEndpoint
        | RemoteError::InsecureEndpoint
        | RemoteError::NonLoopbackTestEndpoint
        | RemoteError::InvalidToken
        | RemoteError::InvalidRepository
        | RemoteError::RequestBindingMismatch
        | RemoteError::RepositoryGenerationMismatch
        | RemoteError::TrustOriginMismatch
        | RemoteError::RequestBudgetExceeded
        | RemoteError::ResponseBudgetExceeded
        | RemoteError::TransferBudgetExceeded
        | RemoteError::PublishOriginMismatch
        | RemoteError::PublishCredentialRoleMismatch
        | RemoteError::RedirectRejected
        | RemoteError::Unauthorized
        | RemoteError::Forbidden
        | RemoteError::PayloadTooLarge
        | RemoteError::UnsupportedMediaType
        | RemoteError::ServiceRejected {
            class: ServiceErrorClass::ConfigurationOrAuth,
            ..
        } => RemoteFailureClass::ConfigurationOrAuth,

        RemoteError::TrustBundle(_)
        | RemoteError::BlobTooLarge
        | RemoteError::ManifestTooLarge
        | RemoteError::UploadDigestMismatch
        | RemoteError::ResponseTooLarge { .. }
        | RemoteError::MissingContentLength
        | RemoteError::DigestMismatch
        | RemoteError::SizeMismatch
        | RemoteError::DigestHeaderMismatch
        | RemoteError::InvalidManifest
        | RemoteError::InvalidTrustBundle
        | RemoteError::InvalidManifestV2
        | RemoteError::InvalidLookupBundle(_)
        | RemoteError::InvalidContentLength
        | RemoteError::InvalidResponseContentType
        | RemoteError::ManifestVerification(_)
        | RemoteError::NotFound
        | RemoteError::ManifestNotFound
        | RemoteError::Conflict
        | RemoteError::ValidationFailed
        | RemoteError::InvalidServiceErrorCode
        | RemoteError::ServiceRejected {
            class: ServiceErrorClass::Corruption,
            ..
        }
        | RemoteError::UnexpectedStatus(_) => RemoteFailureClass::Corruption,
    }
}

fn post_capture_reason(error: &TeamPostCaptureFailureV1) -> TeamEventReason {
    match error {
        TeamPostCaptureFailureV1::Config(_) => TeamEventReason::PublishConfigurationDegraded,
        TeamPostCaptureFailureV1::InvalidSystemClock
        | TeamPostCaptureFailureV1::InvalidLifetime => TeamEventReason::CapturedLocalClock,
        TeamPostCaptureFailureV1::Privacy(_) => TeamEventReason::CapturedLocalPrivacy,
        TeamPostCaptureFailureV1::RequestChanged => TeamEventReason::CapturedLocalRequestChanged,
        TeamPostCaptureFailureV1::RuntimeChanged(_)
        | TeamPostCaptureFailureV1::Capture(_)
        | TeamPostCaptureFailureV1::Interrupted { .. } => TeamEventReason::PublishCaptureDegraded,
        TeamPostCaptureFailureV1::Trust(_) => TeamEventReason::PublishTrustDegraded,
        TeamPostCaptureFailureV1::Manifest(_) => TeamEventReason::CapturedLocalManifest,
        TeamPostCaptureFailureV1::Remote(error) => match classify_remote_error(error) {
            RemoteFailureClass::Transient => TeamEventReason::CapturedLocalTransport,
            RemoteFailureClass::ConfigurationOrAuth => {
                TeamEventReason::PublishConfigurationDegraded
            }
            RemoteFailureClass::Corruption => TeamEventReason::PublishManifestDegraded,
        },
    }
}

fn ensure_snapshot_parent(workspace: &Path, runtime_checkpoint: &Path) -> Result<PathBuf> {
    #[cfg(not(unix))]
    {
        let _ = (workspace, runtime_checkpoint);
        bail!("team immutable snapshots are unsupported on this platform");
    }

    #[cfg(unix)]
    {
        let parent = runtime_checkpoint
            .parent()
            .ok_or_else(|| anyhow!("runtime checkpoint has no private parent"))?;
        let parent = fs::canonicalize(parent).context("resolve runtime checkpoint parent")?;
        let workspace = fs::canonicalize(workspace).context("resolve workspace")?;
        let snapshot_parent = parent.join(SNAPSHOT_DIRECTORY_NAME);
        if snapshot_parent.starts_with(&workspace) {
            bail!("team snapshot state must be outside the active workspace");
        }

        match fs::symlink_metadata(&snapshot_parent) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&snapshot_parent) {
                    Ok(()) => {
                        fs::set_permissions(&snapshot_parent, fs::Permissions::from_mode(0o700))
                            .context("seal team snapshot parent permissions")?
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error).context("create team snapshot parent"),
                }
            }
            Err(error) => return Err(error).context("inspect team snapshot parent"),
        }
        let metadata = fs::symlink_metadata(&snapshot_parent)
            .context("validate team snapshot parent metadata")?;
        // SAFETY: `geteuid` has no preconditions and accesses no Rust memory.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != current_uid
            || metadata.permissions().mode() & 0o7777 != 0o700
            || fs::canonicalize(&snapshot_parent).ok().as_deref() != Some(snapshot_parent.as_path())
        {
            bail!("team snapshot parent is not an owner-only canonical 0700 directory");
        }
        Ok(snapshot_parent)
    }
}

#[allow(clippy::too_many_arguments)]
fn local_fallback(
    workspace: &Path,
    cwd: &Path,
    command_name: &str,
    command: &[OsString],
    environment: &[(OsString, OsString)],
    executable: &Path,
    runtime: &TeamRuntimeAttestationV1,
    reason: TeamEventReason,
    started: Instant,
) -> Result<i32> {
    runtime
        .verify_executable_current()
        .context("revalidate runtime before local fallback")?;
    verify_executable(command_name, executable)
        .context("revalidate audited executable before local fallback")?;
    let status = Command::new(executable)
        .args(command.iter().skip(1))
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("execute audited local fallback {command_name}"))?;
    let exit = exit_code_for_status(status);
    record_team_event(
        workspace,
        reason.fallback_disposition(),
        reason,
        started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        0,
    );
    Ok(exit)
}

fn tty_local_bypass(
    workspace: &Path,
    cwd: &Path,
    command_name: &str,
    command: &[OsString],
    environment: &[(OsString, OsString)],
    executable: &Path,
) -> Result<i32> {
    pre_runtime_local_bypass(
        workspace,
        cwd,
        command_name,
        command,
        environment,
        executable,
        TeamEventReason::TtyBypass,
        true,
        Instant::now(),
    )
}

#[allow(clippy::too_many_arguments)]
fn pre_runtime_local_bypass(
    workspace: &Path,
    cwd: &Path,
    command_name: &str,
    command: &[OsString],
    environment: &[(OsString, OsString)],
    executable: &Path,
    reason: TeamEventReason,
    inherit_stdin: bool,
    started: Instant,
) -> Result<i32> {
    verify_executable(command_name, executable)
        .context("validate executable for local team bypass")?;
    let stdin = if inherit_stdin {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    let status = Command::new(executable)
        .args(command.iter().skip(1))
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(stdin)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("execute audited local team bypass {command_name}"))?;
    let exit = exit_code_for_status(status);
    record_team_event(
        workspace,
        reason.fallback_disposition(),
        reason,
        started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        0,
    );
    Ok(exit)
}

fn present_exact(stdout: &[u8], stderr: &[u8]) -> Result<i32> {
    present_exact_with_exit(stdout, stderr, 0)
}

fn present_exact_with_exit(stdout: &[u8], stderr: &[u8], exit_code: i32) -> Result<i32> {
    match write_exact_to(io::stdout().lock(), io::stderr().lock(), stdout, stderr) {
        Ok(()) => Ok(exit_code.clamp(0, 255)),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            Ok(signal_exit_code(libc::SIGPIPE))
        }
        Err(error) => Err(error).context("present verified team result"),
    }
}

fn write_exact_to(
    mut stdout_writer: impl Write,
    mut stderr_writer: impl Write,
    stdout: &[u8],
    stderr: &[u8],
) -> io::Result<()> {
    stdout_writer.write_all(stdout)?;
    stdout_writer.flush()?;
    stderr_writer.write_all(stderr)?;
    stderr_writer.flush()
}

fn record_team_event(
    workspace: &Path,
    disposition: EventDisposition,
    reason: TeamEventReason,
    elapsed_ms: u64,
    bytes_omitted: u64,
) {
    // Command semantics and exact output must not depend on observability. A
    // damaged local event store cannot turn a verified hit into failure or add
    // diagnostic bytes to the wrapped command's streams.
    if let Ok(store) = Store::open_for_workspace(workspace) {
        let _ = store.record_event(
            None,
            None,
            disposition,
            reason.code(),
            elapsed_ms,
            bytes_omitted,
        );
    }
}

fn signal_exit_code(signal: i32) -> i32 {
    128_i32.saturating_add(signal).min(255)
}

fn exit_code_for_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return signal_exit_code(signal);
        }
    }
    128
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::RemoteError;
    use crate::team_manifest_v2::ManifestV2Error;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn bare_argv_and_exact_environment_are_unambiguous() {
        assert_eq!(
            bare_command_name(&[OsString::from("wc"), OsString::from("-c")]).unwrap(),
            "wc"
        );
        assert!(bare_command_name(&[OsString::from("/usr/bin/wc")]).is_err());
        assert!(bare_command_name(&[OsString::from("bin/wc")]).is_err());
        assert_eq!(
            exact_team_environment(),
            vec![
                (OsString::from("LANG"), OsString::from("C")),
                (OsString::from("LC_ALL"), OsString::from("C")),
            ]
        );
    }

    #[test]
    fn only_typed_manifest_absence_is_a_miss() {
        assert!(matches!(
            route_pull::<&str>(Ok("verified")),
            PullRoute::Hit("verified")
        ));
        assert!(matches!(
            route_pull::<()>(Err(TeamPullError::CacheMiss)),
            PullRoute::Miss
        ));
        assert!(matches!(
            route_pull::<()>(Err(TeamPullError::Remote(RemoteError::NotFound))),
            PullRoute::Degraded(TeamEventReason::PullCorruptionDegraded)
        ));
        assert!(matches!(
            route_pull::<()>(Err(TeamPullError::Manifest(
                ManifestV2Error::AuthenticationFailed {
                    stream: crate::team_manifest_v2::EncryptedStreamLabelV2::Stdout,
                }
            ))),
            PullRoute::Degraded(TeamEventReason::PullCorruptionDegraded)
        ));
    }

    #[test]
    fn remote_errors_are_separated_into_transient_configuration_and_corruption() {
        assert_eq!(
            classify_remote_error(&RemoteError::Timeout { operation: "test" }),
            RemoteFailureClass::Transient
        );
        assert_eq!(
            classify_remote_error(&RemoteError::UnexpectedStatus(503)),
            RemoteFailureClass::Transient
        );
        assert_eq!(
            classify_remote_error(&RemoteError::Unauthorized),
            RemoteFailureClass::ConfigurationOrAuth
        );
        assert_eq!(
            classify_remote_error(&RemoteError::RedirectRejected),
            RemoteFailureClass::ConfigurationOrAuth
        );
        assert_eq!(
            classify_remote_error(&RemoteError::InvalidManifestV2),
            RemoteFailureClass::Corruption
        );
        assert_eq!(
            classify_remote_error(&RemoteError::InvalidLookupBundle(
                crate::team_lookup_bundle::TeamLookupBundleWireError::TrailingBytes,
            )),
            RemoteFailureClass::Corruption
        );
        assert_eq!(
            classify_remote_error(&RemoteError::DigestMismatch),
            RemoteFailureClass::Corruption
        );
        assert_eq!(
            classify_remote_error(&RemoteError::NotFound),
            RemoteFailureClass::Corruption
        );
        assert_eq!(
            classify_remote_error(&RemoteError::ServiceRejected {
                code: "internal_error".into(),
                status: 500,
                class: ServiceErrorClass::Transient,
            }),
            RemoteFailureClass::Transient
        );
        assert_eq!(
            classify_remote_error(&RemoteError::ServiceRejected {
                code: "invalid_json".into(),
                status: 422,
                class: ServiceErrorClass::ConfigurationOrAuth,
            }),
            RemoteFailureClass::ConfigurationOrAuth
        );
        assert_eq!(
            classify_remote_error(&RemoteError::InvalidServiceErrorCode),
            RemoteFailureClass::Corruption
        );
    }

    #[test]
    fn read_only_profile_miss_and_tty_use_explicit_bypass_routes() {
        assert_eq!(miss_route(false), MissRoute::LocalReadOnly);
        assert_eq!(miss_route(true), MissRoute::Publish);
        assert_eq!(
            TeamEventReason::MissReadOnlyProfile.fallback_disposition(),
            EventDisposition::BypassedNoStore
        );
        assert_eq!(
            TeamEventReason::TtyBypass.fallback_disposition(),
            EventDisposition::BypassedNoStore
        );
        assert_eq!(
            TeamEventReason::DigestCacheUnavailable.fallback_disposition(),
            EventDisposition::BypassedNoStore
        );
        assert_eq!(
            TeamEventReason::RequestPrivacyLocal.fallback_disposition(),
            EventDisposition::BypassedNoStore
        );
        assert_eq!(
            TeamEventReason::DigestCacheUnavailable.code(),
            "TEAM_DIGEST_CACHE_UNAVAILABLE"
        );
        assert_eq!(
            TeamEventReason::RequestPrivacyLocal.code(),
            "TEAM_REQUEST_PRIVACY_LOCAL"
        );
    }

    #[test]
    fn digest_cache_open_failure_routes_to_local_and_hits_count_only_saved_time() {
        assert!(matches!(
            route_digest_cache::<(), _>(Err("sqlite unavailable")),
            DigestCacheRoute::Local
        ));
        assert!(matches!(
            route_digest_cache::<_, &str>(Ok("persistent cache")),
            DigestCacheRoute::Ready("persistent cache")
        ));

        assert_eq!(
            exact_remote_reuse_metrics(5_000_000, Duration::from_millis(125)),
            (4_875, 0)
        );
        assert_eq!(
            exact_remote_reuse_metrics(1_000, Duration::from_millis(2)),
            (0, 0),
            "lookup overhead cannot underflow and exact replay omits no bytes"
        );
    }

    #[test]
    fn cheap_preflight_rejects_unsupported_flags_before_runtime_work() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("input.txt"), b"bytes\n").unwrap();
        let environment = exact_team_environment();
        assert!(
            preflight_team_request_v1(
                temp.path(),
                temp.path(),
                &[
                    OsString::from("wc"),
                    OsString::from("-c"),
                    OsString::from("input.txt"),
                ],
                &environment,
            )
            .is_ok()
        );
        assert!(
            preflight_team_request_v1(
                temp.path(),
                temp.path(),
                &[
                    OsString::from("wc"),
                    OsString::from("-m"),
                    OsString::from("input.txt"),
                ],
                &environment,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_stream_presenter_emits_each_retained_stream_once() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write_exact_to(&mut stdout, &mut stderr, b"one\ntwo\n", b"warning\n").unwrap();
        assert_eq!(stdout, b"one\ntwo\n");
        assert_eq!(stderr, b"warning\n");
    }

    #[test]
    fn degradation_reasons_are_fixed_and_non_secret() {
        assert_eq!(
            pull_error_reason(&TeamPullError::Manifest(ManifestV2Error::InvalidSignature)).code(),
            "TEAM_PULL_CORRUPTION_DEGRADED"
        );
        assert_eq!(
            TeamEventReason::MissReadOnlyProfile.code(),
            "TEAM_MISS_READ_ONLY_PROFILE"
        );
        assert_eq!(
            pull_error_reason(&TeamPullError::Remote(RemoteError::InvalidLookupBundle(
                crate::team_lookup_bundle::TeamLookupBundleWireError::PayloadTruncated,
            )))
            .code(),
            "TEAM_PULL_CORRUPTION_DEGRADED"
        );
    }

    #[test]
    fn runtime_checkpoint_refreshes_only_missing_or_stale_evidence() {
        assert!(runtime_checkpoint_refresh_allowed(
            &RuntimeAttestationError::CheckpointMissing
        ));
        assert!(runtime_checkpoint_refresh_allowed(
            &RuntimeAttestationError::CheckpointStale
        ));
        assert!(!runtime_checkpoint_refresh_allowed(
            &RuntimeAttestationError::CheckpointCorrupt
        ));
        assert!(!runtime_checkpoint_refresh_allowed(
            &RuntimeAttestationError::CheckpointUnsafe
        ));
    }

    #[test]
    fn snapshot_parent_is_external_owner_only_and_idempotent() {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = temp.path().join("workspace");
        let private = temp.path().join("private");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let checkpoint = private.join("runtime.json");
        let first = ensure_snapshot_parent(&workspace, &checkpoint).unwrap();
        let second = ensure_snapshot_parent(&workspace, &checkpoint).unwrap();
        assert_eq!(first, second);
        let metadata = fs::symlink_metadata(first).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    }
}
