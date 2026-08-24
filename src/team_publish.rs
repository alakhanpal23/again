//! Sealed producer-side encrypted team publication.
//!
//! This module remains crate-private behind the explicit team-alpha CLI. It
//! combines strict local credentials, durable root-signed trust, immutable
//! two-run capture, exact-byte privacy admission, authenticated encryption,
//! and manifest-last transport. It never imports a remote/team result into the
//! local V0 store and never sends plaintext execution output.

#![allow(
    dead_code,
    reason = "some receipt and adversarial transport helpers are intentionally crate-private"
)]

use std::ffi::OsString;
use std::path::Path;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::fingerprint::FileDigestCache;
use crate::privacy::{LocalOnlyReason, RemoteRequestAdmissionV1, RepositorySharingPolicy};
use crate::remote::{RemoteClient, RemoteError, RemotePublishSession, RemotePullSession};
use crate::runtime_attestation::{RuntimeAttestationError, TeamRuntimeAttestationV1};
use crate::team::{Digest, MAX_JSON_SAFE_INTEGER, MAX_MANIFEST_LIFETIME_SECONDS};
use crate::team_clock::{TeamClock, TeamClockError};
use crate::team_config::{
    ProducerSigningCredentialV1, TeamConfigError, TeamProfileV1, TeamPublishBudgetV1,
    load_producer_signer, load_read_token, load_repository_key, load_sharing_policy,
    load_team_profile, load_trust_tracker, load_write_token, persist_trust_checkpoint,
    validate_profile_state_external_to_workspace,
};
use crate::team_manifest_v2::{
    AdmittedLocalPublicationV2, CompleteImmutableExecutionV1, EncryptedPublicationV2,
    EncryptedRemoteCacheManifestV2, EncryptedStreamRefV2, ImmutableCaptureError,
    ImmutableCaptureFailureV1, ImmutableCaptureInputV1, ImmutableExecutionProfileV1,
    ManifestV2BuildInput, ManifestV2Error, ValidatedLocalResultV1,
    admit_validated_local_publication_v2, authorize_publication_v2, build_encrypted_publication_v2,
    capture_immutable_team_attempt_v1,
};
#[cfg(test)]
use crate::team_request_key::build_team_request_key_v1;
use crate::team_request_key::{
    TeamLocalOnlyReason, TeamRequestKeyInput, TeamRequestKeyV1,
    build_team_request_key_v1_with_cache,
};
use crate::trust_bundle::{
    TrustBundleError, TrustBundleV1, TrustEpochTracker, VerifiedTrustBundle, verify_trust_bundle,
};

/// Capture inputs that are not already sealed into the portable request.
pub(crate) struct TeamPublishCaptureV1<'a> {
    pub workspace: &'a Path,
    pub snapshot_parent: &'a Path,
    pub environment: &'a [(OsString, OsString)],
    pub execution_profile: &'a ImmutableExecutionProfileV1,
    pub runtime: &'a TeamRuntimeAttestationV1,
    pub producer_version: &'a str,
}

/// Non-secret publication options. Creation time comes from the local system
/// clock; callers can request only a bounded lifetime, not forge freshness.
pub(crate) struct TeamPublishOptionsV1<'a> {
    pub record_id: &'a str,
    pub lifetime_seconds: u64,
}

/// Small non-secret proof that the manifest-last transaction completed.
pub(crate) struct TeamPublishReceiptV1 {
    record_id: String,
    request_key: Digest,
    stdout_ciphertext_digest: Digest,
    stderr_ciphertext_digest: Digest,
    encrypted_bytes_uploaded: u64,
    trust_epoch: u64,
}

enum ExactLocalResultV1 {
    Complete(CompleteImmutableExecutionV1),
    /// An explicit parent interruption is not a command execution. When the
    /// first immutable run had already completed, retain its exact streams for
    /// one-shot presentation while overriding only the CLI exit to the
    /// shell-compatible `128 + signal` value.
    Interrupted {
        retained_execution: Option<CompleteImmutableExecutionV1>,
        signal: libc::c_int,
    },
    Validated(ValidatedLocalResultV1),
    Admitted(AdmittedLocalPublicationV2),
}

impl ExactLocalResultV1 {
    fn stdout(&self) -> &[u8] {
        match self {
            Self::Complete(result) => result.stdout(),
            Self::Interrupted {
                retained_execution, ..
            } => retained_execution
                .as_ref()
                .map_or(b"", CompleteImmutableExecutionV1::stdout),
            Self::Validated(result) => result.exact_stdout(),
            Self::Admitted(result) => result.exact_stdout(),
        }
    }

    fn stderr(&self) -> &[u8] {
        match self {
            Self::Complete(result) => result.stderr(),
            Self::Interrupted {
                retained_execution, ..
            } => retained_execution
                .as_ref()
                .map_or(b"", CompleteImmutableExecutionV1::stderr),
            Self::Validated(_) | Self::Admitted(_) => b"",
        }
    }

    fn exit_code(&self) -> i32 {
        match self {
            Self::Complete(result) => result.exit_code(),
            Self::Interrupted { signal, .. } => 128_i32.saturating_add(*signal).clamp(0, 255),
            Self::Validated(_) | Self::Admitted(_) => 0,
        }
    }

    fn duration_micros(&self) -> u64 {
        match self {
            Self::Complete(result) => result.duration_micros(),
            Self::Interrupted {
                retained_execution, ..
            } => retained_execution
                .as_ref()
                .map_or(0, CompleteImmutableExecutionV1::duration_micros),
            Self::Validated(result) => result.duration_micros(),
            Self::Admitted(result) => result.duration_micros(),
        }
    }
}

/// Completed immutable capture or explicit interruption, with an optional
/// manifest-last publication. Once capture starts this preserves any genuine
/// retained child output even when interruption, privacy, post-capture source
/// parity, encryption, or upload prevents publication. Debug never renders
/// captured bytes or failure details.
pub(crate) struct TeamPublishOutcomeV1 {
    local: ExactLocalResultV1,
    publication: Result<TeamPublishReceiptV1, TeamPostCaptureFailureV1>,
}

impl TeamPublishOutcomeV1 {
    pub(crate) fn stdout(&self) -> &[u8] {
        self.local.stdout()
    }

    pub(crate) fn stderr(&self) -> &[u8] {
        self.local.stderr()
    }

    pub(crate) fn exit_code(&self) -> i32 {
        self.local.exit_code()
    }

    pub(crate) fn duration_micros(&self) -> u64 {
        self.local.duration_micros()
    }

    pub(crate) fn publication(&self) -> Result<&TeamPublishReceiptV1, &TeamPostCaptureFailureV1> {
        self.publication.as_ref()
    }
}

impl std::fmt::Debug for TeamPublishOutcomeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamPublishOutcomeV1")
            .field("stdout_bytes", &self.stdout().len())
            .field("stderr_bytes", &self.stderr().len())
            .field("exit_code", &self.exit_code())
            .field(
                "publication_status",
                &if self.publication.is_ok() {
                    "published"
                } else {
                    "not_published"
                },
            )
            .finish()
    }
}

#[derive(Debug, Error)]
pub(crate) enum TeamPostCaptureFailureV1 {
    #[error("team configuration became unavailable after immutable capture: {0}")]
    Config(TeamConfigError),
    #[error("system clock became invalid after immutable capture")]
    InvalidSystemClock,
    #[error("publication lifetime became invalid after immutable capture")]
    InvalidLifetime,
    #[error("exact captured output is local-only: {0}")]
    Privacy(LocalOnlyReason),
    #[error("command inputs changed after immutable capture")]
    RequestChanged,
    #[error("audited runtime changed after immutable capture: {0}")]
    RuntimeChanged(RuntimeAttestationError),
    #[error("immutable capture could not mint a shared result: {0}")]
    Capture(ImmutableCaptureError),
    #[error("immutable capture was interrupted by signal {signal}")]
    Interrupted { signal: libc::c_int },
    #[error("fresh trust verification failed after immutable capture: {0}")]
    Trust(TrustBundleError),
    #[error("encrypted publication construction failed: {0}")]
    Manifest(ManifestV2Error),
    #[error("encrypted publication transport failed: {0}")]
    Remote(RemoteError),
}

impl TeamPublishReceiptV1 {
    pub(crate) fn record_id(&self) -> &str {
        &self.record_id
    }

    pub(crate) fn request_key(&self) -> Digest {
        self.request_key
    }

    pub(crate) fn encrypted_bytes_uploaded(&self) -> u64 {
        self.encrypted_bytes_uploaded
    }

    pub(crate) fn trust_epoch(&self) -> u64 {
        self.trust_epoch
    }
}

impl std::fmt::Debug for TeamPublishReceiptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TeamPublishReceiptV1")
            .field("record_id", &self.record_id)
            .field("request_key", &self.request_key)
            .field("stdout_ciphertext_digest", &self.stdout_ciphertext_digest)
            .field("stderr_ciphertext_digest", &self.stderr_ciphertext_digest)
            .field("encrypted_bytes_uploaded", &self.encrypted_bytes_uploaded)
            .field("trust_epoch", &self.trust_epoch)
            .finish()
    }
}

#[derive(Debug, Error)]
pub(crate) enum TeamPublishError {
    #[error("team configuration failed: {0}")]
    Config(#[from] TeamConfigError),
    #[error("sealed request tenant does not match the team profile")]
    TenantMismatch,
    #[error("sealed request repository does not match the team profile")]
    RepositoryMismatch,
    #[error("sealed request repository generation does not match the team profile")]
    GenerationMismatch,
    #[error("local sharing policy does not match the sealed request")]
    PolicyMismatch,
    #[error("output-independent remote admission does not match this request and policy")]
    RequestAdmissionMismatch,
    #[error("record id is not a strict portable identifier")]
    InvalidRecordId,
    #[error("publication lifetime is outside the encrypted-manifest limit")]
    InvalidLifetime,
    #[error("system clock is before the Unix epoch or outside the protocol range")]
    InvalidSystemClock,
    #[error("portable request admission failed: {0}")]
    Request(#[from] TeamLocalOnlyReason),
    #[error("command inputs changed before publication network I/O")]
    RequestChangedBeforeNetwork,
    #[error("audited runtime is invalid before immutable capture: {0}")]
    RuntimeAttestation(#[from] RuntimeAttestationError),
    #[error("publication transport is bound to a different endpoint or repository")]
    TransportBindingMismatch,
    #[error("remote publication transport failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("trust-bundle verification failed: {0}")]
    Trust(#[from] TrustBundleError),
    #[error("immutable capture failed before the command started: {0}")]
    CaptureBeforeStart(ImmutableCaptureError),
    #[error("immutable capture failed after the command started without a complete status: {0}")]
    CaptureAfterStart(ImmutableCaptureError),
    #[error("team freshness clock failed: {0}")]
    Clock(#[from] TeamClockError),
    #[error("encrypted publication construction failed: {0}")]
    Manifest(#[from] ManifestV2Error),
}

/// Complete producer flow. This API is intentionally not exported from the
/// library or CLI until the runtime-attestation seam can supply its execution,
/// platform, and image bindings without caller assertions.
#[allow(
    dead_code,
    clippy::too_many_arguments,
    reason = "the sealed request, admission, capture, cache, and clock capabilities stay explicit at this security boundary"
)]
pub(crate) async fn publish_immutable_remote_v2(
    profile_path: &Path,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    remote_admission: &RemoteRequestAdmissionV1,
    capture: TeamPublishCaptureV1<'_>,
    options: TeamPublishOptionsV1<'_>,
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<TeamPublishOutcomeV1, TeamPublishError> {
    validate_options(&options)?;
    capture.runtime.verify_request_binding(request)?;
    let profile = load_team_profile(profile_path)?;
    validate_profile_state_external_to_workspace(profile_path, &profile, request_input.workspace)?;
    let sharing_policy = load_sharing_policy(&profile)?;
    validate_local_bindings(&profile, request, &sharing_policy)?;
    if !remote_admission.matches(&sharing_policy, request) {
        return Err(TeamPublishError::RequestAdmissionMismatch);
    }
    let publisher = profile
        .publisher()
        .ok_or(TeamConfigError::MissingPublisherConfig)?;

    // Admit all local private material before the first network request. A
    // missing, aliased, replaced, or incorrectly permissioned credential must
    // never create a partial remote publication.
    let read_token = load_read_token(&profile)?;
    let write_token = load_write_token(&profile)?;
    let repository_key = load_repository_key(&profile)?;
    let signing_credential = load_producer_signer(&profile)?;
    let mut tracker = load_trust_tracker(&profile)?;

    let read_client = RemoteClient::new_team_read(profile.endpoint_origin(), &read_token)?;
    let write_client = RemoteClient::new_team_write(profile.endpoint_origin(), &write_token)?;

    // Authorize the exact producer before starting the user's command. This
    // lookup has its own bounded read session and cannot consume any of the
    // later upload deadline.
    let mut initial_trust = read_client.begin_pull(
        profile.repository_id(),
        profile.generation_id(),
        profile.lookup_budget(),
    )?;
    refresh_authorized_trust_v2(
        &profile,
        request,
        &signing_credential,
        &mut tracker,
        &mut initial_trust,
        options.record_id,
        clock,
    )
    .await
    .map_err(map_pre_capture_trust_error)?;
    drop(initial_trust);

    let validated = match capture_immutable_team_attempt_v1(
        ImmutableCaptureInputV1::new(
            request,
            capture.workspace,
            capture.snapshot_parent,
            capture.environment,
            capture.execution_profile,
            capture.runtime,
            capture.producer_version,
        ),
        digest_cache,
    ) {
        Ok(validated) => validated,
        Err(ImmutableCaptureFailureV1::BeforeStart { source }) => {
            return Err(TeamPublishError::CaptureBeforeStart(source));
        }
        Err(ImmutableCaptureFailureV1::AfterStart {
            first_complete: Some(first_complete),
            source,
        }) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Complete(first_complete),
                publication: Err(TeamPostCaptureFailureV1::Capture(source)),
            });
        }
        Err(ImmutableCaptureFailureV1::AfterStart {
            first_complete: None,
            source,
        }) => return Err(TeamPublishError::CaptureAfterStart(source)),
        Err(ImmutableCaptureFailureV1::Interrupted {
            signal,
            retained_execution,
        }) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Interrupted {
                    retained_execution,
                    signal,
                },
                publication: Err(TeamPostCaptureFailureV1::Interrupted { signal }),
            });
        }
    };

    finish_captured_publication_v2(
        &profile,
        request_input,
        request,
        remote_admission,
        capture.runtime,
        &sharing_policy,
        &repository_key,
        &signing_credential,
        &mut tracker,
        &read_client,
        &write_client,
        publisher.publish_budget(),
        options.record_id,
        options.lifetime_seconds,
        validated,
        digest_cache,
        clock,
    )
    .await
}

trait TeamTrustTransport {
    fn endpoint_origin(&self) -> String;
    fn repository_id(&self) -> &str;
    fn generation_id(&self) -> &str;
    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError>;
}

impl TeamTrustTransport for RemotePullSession<'_> {
    fn endpoint_origin(&self) -> String {
        RemotePullSession::endpoint_origin(self)
    }

    fn repository_id(&self) -> &str {
        RemotePullSession::repository_id(self)
    }

    fn generation_id(&self) -> &str {
        RemotePullSession::generation_id(self)
    }

    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
        RemotePullSession::fetch_latest_trust_bundle(self).await
    }
}

#[derive(Debug, Error)]
enum PublicationTrustError {
    #[error("trust transport binding mismatch")]
    Binding,
    #[error("trust transport failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("trust verification failed: {0}")]
    Trust(#[from] TrustBundleError),
    #[error("trust checkpoint persistence failed: {0}")]
    Config(#[from] TeamConfigError),
    #[error("producer authorization failed: {0}")]
    Manifest(#[from] ManifestV2Error),
    #[error("freshness clock failed: {0}")]
    Clock(#[from] TeamClockError),
}

#[allow(clippy::too_many_arguments)]
async fn refresh_authorized_trust_v2<T: TeamTrustTransport>(
    profile: &TeamProfileV1,
    request: &TeamRequestKeyV1,
    signing_credential: &ProducerSigningCredentialV1,
    tracker: &mut TrustEpochTracker,
    transport: &mut T,
    record_id: &str,
    clock: &mut dyn TeamClock,
) -> Result<(VerifiedTrustBundle, u64), PublicationTrustError> {
    if transport.endpoint_origin() != profile.endpoint_origin()
        || transport.repository_id() != profile.repository_id()
        || transport.generation_id() != profile.generation_id()
    {
        return Err(PublicationTrustError::Binding);
    }
    let bundle = transport.fetch_latest_trust_bundle().await?;
    let now_unix_seconds = clock.sample_unix_seconds()?;
    let verified = verify_trust_bundle(
        bundle,
        profile.expected_trust_bundle(),
        profile.pinned_root(),
        now_unix_seconds,
        tracker,
    )?;
    persist_trust_checkpoint(profile, tracker)?;
    authorize_publication_v2(
        record_id,
        request,
        signing_credential.signer(),
        &verified,
        now_unix_seconds,
    )?;
    Ok((verified, now_unix_seconds))
}

fn map_pre_capture_trust_error(error: PublicationTrustError) -> TeamPublishError {
    match error {
        PublicationTrustError::Binding => TeamPublishError::TransportBindingMismatch,
        PublicationTrustError::Remote(error) => TeamPublishError::Remote(error),
        PublicationTrustError::Trust(error) => TeamPublishError::Trust(error),
        PublicationTrustError::Config(error) => TeamPublishError::Config(error),
        PublicationTrustError::Manifest(error) => TeamPublishError::Manifest(error),
        PublicationTrustError::Clock(error) => TeamPublishError::Clock(error),
    }
}

fn map_post_capture_trust_error(error: PublicationTrustError) -> TeamPostCaptureFailureV1 {
    match error {
        PublicationTrustError::Binding => {
            TeamPostCaptureFailureV1::Remote(RemoteError::RequestBindingMismatch)
        }
        PublicationTrustError::Remote(error) => TeamPostCaptureFailureV1::Remote(error),
        PublicationTrustError::Trust(error) => TeamPostCaptureFailureV1::Trust(error),
        PublicationTrustError::Config(error) => TeamPostCaptureFailureV1::Config(error),
        PublicationTrustError::Manifest(error) => TeamPostCaptureFailureV1::Manifest(error),
        PublicationTrustError::Clock(_) => TeamPostCaptureFailureV1::InvalidSystemClock,
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_captured_publication_v2(
    profile: &TeamProfileV1,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    remote_admission: &RemoteRequestAdmissionV1,
    runtime: &TeamRuntimeAttestationV1,
    sharing_policy: &RepositorySharingPolicy,
    repository_key: &crate::team_manifest_v2::RepositoryEncryptionKeyV1,
    signing_credential: &ProducerSigningCredentialV1,
    tracker: &mut TrustEpochTracker,
    read_client: &RemoteClient,
    write_client: &RemoteClient,
    publish_budget: TeamPublishBudgetV1,
    record_id: &str,
    lifetime_seconds: u64,
    validated: ValidatedLocalResultV1,
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<TeamPublishOutcomeV1, TeamPublishError> {
    if !remote_admission.matches(sharing_policy, request) {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Validated(validated),
            publication: Err(TeamPostCaptureFailureV1::RequestChanged),
        });
    }
    let refreshed = build_team_request_key_v1_with_cache(request_input, digest_cache);
    if refreshed.as_ref().is_err() || refreshed.as_ref().is_ok_and(|value| value != request) {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Validated(validated),
            publication: Err(TeamPostCaptureFailureV1::RequestChanged),
        });
    }
    if let Err(error) = runtime.verify_request_binding(request) {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Validated(validated),
            publication: Err(TeamPostCaptureFailureV1::RuntimeChanged(error)),
        });
    }
    let admitted = match admit_validated_local_publication_v2(sharing_policy, request, validated) {
        Ok(admitted) => admitted,
        Err(rejected) => {
            let reason = rejected.reason();
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Validated((*rejected).into_result()),
                publication: Err(TeamPostCaptureFailureV1::Privacy(reason)),
            });
        }
    };

    // Refetch and durably reverify trust after capture. This uses an isolated
    // read budget. Only after it succeeds do we create the upload session, so
    // a long immutable capture consumes none of the mutation deadline.
    let mut refreshed_trust = match read_client.begin_pull(
        profile.repository_id(),
        profile.generation_id(),
        profile.lookup_budget(),
    ) {
        Ok(session) => session,
        Err(error) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Admitted(admitted),
                publication: Err(TeamPostCaptureFailureV1::Remote(error)),
            });
        }
    };
    let (verified_trust, publication_now_unix_seconds) = match refresh_authorized_trust_v2(
        profile,
        request,
        signing_credential,
        tracker,
        &mut refreshed_trust,
        record_id,
        clock,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Admitted(admitted),
                publication: Err(map_post_capture_trust_error(error)),
            });
        }
    };
    drop(refreshed_trust);

    let refreshed = build_team_request_key_v1_with_cache(request_input, digest_cache);
    if refreshed.as_ref().is_err() || refreshed.as_ref().is_ok_and(|value| value != request) {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::RequestChanged),
        });
    }
    if let Err(error) = runtime.verify_request_binding(request) {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::RuntimeChanged(error)),
        });
    }
    let Some(expires_at_unix_seconds) = publication_now_unix_seconds
        .checked_add(lifetime_seconds)
        .filter(|expires| *expires <= MAX_JSON_SAFE_INTEGER)
    else {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::InvalidLifetime),
        });
    };
    let encrypted = match build_publication(
        record_id,
        request,
        &admitted,
        signing_credential,
        &verified_trust,
        repository_key,
        publication_now_unix_seconds,
        expires_at_unix_seconds,
    ) {
        Ok(encrypted) => encrypted,
        Err(error) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Admitted(admitted),
                publication: Err(TeamPostCaptureFailureV1::Manifest(error)),
            });
        }
    };

    let mut publication = match read_client.begin_publish(
        write_client,
        profile.repository_id(),
        profile.generation_id(),
        publish_budget,
    ) {
        Ok(publication) => publication,
        Err(error) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Admitted(admitted),
                publication: Err(TeamPostCaptureFailureV1::Remote(error)),
            });
        }
    };
    finish_encrypted_upload_v2(
        admitted,
        encrypted,
        verified_trust.epoch(),
        profile.endpoint_origin(),
        &mut publication,
    )
    .await
}

trait TeamPublishTransport {
    fn endpoint_origin(&self) -> String;
    fn repository_id(&self) -> &str;
    fn generation_id(&self) -> &str;
    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError>;
    async fn put_ciphertext(
        &mut self,
        reference: &EncryptedStreamRefV2,
        ciphertext: &[u8],
    ) -> Result<(), RemoteError>;
    async fn put_manifest_v2(
        &mut self,
        manifest: &EncryptedRemoteCacheManifestV2,
    ) -> Result<(), RemoteError>;
}

impl TeamPublishTransport for RemotePublishSession<'_> {
    fn endpoint_origin(&self) -> String {
        RemotePublishSession::endpoint_origin(self)
    }

    fn repository_id(&self) -> &str {
        RemotePublishSession::repository_id(self)
    }

    fn generation_id(&self) -> &str {
        RemotePublishSession::generation_id(self)
    }

    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
        RemotePublishSession::fetch_latest_trust_bundle(self).await
    }

    async fn put_ciphertext(
        &mut self,
        reference: &EncryptedStreamRefV2,
        ciphertext: &[u8],
    ) -> Result<(), RemoteError> {
        RemotePublishSession::put_ciphertext(self, reference, ciphertext).await
    }

    async fn put_manifest_v2(
        &mut self,
        manifest: &EncryptedRemoteCacheManifestV2,
    ) -> Result<(), RemoteError> {
        RemotePublishSession::put_manifest_v2(self, manifest).await
    }
}

#[cfg(test)]
impl<T: TeamPublishTransport> TeamTrustTransport for T {
    fn endpoint_origin(&self) -> String {
        TeamPublishTransport::endpoint_origin(self)
    }

    fn repository_id(&self) -> &str {
        TeamPublishTransport::repository_id(self)
    }

    fn generation_id(&self) -> &str {
        TeamPublishTransport::generation_id(self)
    }

    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
        TeamPublishTransport::fetch_latest_trust_bundle(self).await
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
async fn finish_publish_v2<T, F, C>(
    profile: &TeamProfileV1,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    sharing_policy: &RepositorySharingPolicy,
    repository_key: &crate::team_manifest_v2::RepositoryEncryptionKeyV1,
    signing_credential: &ProducerSigningCredentialV1,
    tracker: &mut TrustEpochTracker,
    transport: &mut T,
    record_id: &str,
    trust_now_unix_seconds: u64,
    lifetime_seconds: u64,
    capture: F,
    post_capture_clock: C,
) -> Result<TeamPublishOutcomeV1, TeamPublishError>
where
    T: TeamPublishTransport,
    F: FnOnce() -> Result<ValidatedLocalResultV1, TeamPublishError>,
    C: FnOnce() -> Result<u64, TeamPublishError>,
{
    if transport.endpoint_origin() != profile.endpoint_origin()
        || transport.repository_id() != profile.repository_id()
        || transport.generation_id() != profile.generation_id()
    {
        return Err(TeamPublishError::TransportBindingMismatch);
    }

    let untrusted_bundle = transport.fetch_latest_trust_bundle().await?;
    let verified_trust = verify_trust_bundle(
        untrusted_bundle,
        profile.expected_trust_bundle(),
        profile.pinned_root(),
        trust_now_unix_seconds,
        tracker,
    )?;
    // No producer key, policy, or artifact may be trusted if this accepted
    // epoch cannot first be made durable across restart.
    persist_trust_checkpoint(profile, tracker)?;

    authorize_publication_v2(
        record_id,
        request,
        signing_credential.signer(),
        &verified_trust,
        trust_now_unix_seconds,
    )?;

    let validated = capture()?;
    let publication_now_unix_seconds = match post_capture_clock() {
        Ok(now) if now <= MAX_JSON_SAFE_INTEGER => now,
        Ok(_) | Err(_) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Validated(validated),
                publication: Err(TeamPostCaptureFailureV1::InvalidSystemClock),
            });
        }
    };
    let Some(expires_at_unix_seconds) = publication_now_unix_seconds
        .checked_add(lifetime_seconds)
        .filter(|expires| *expires <= MAX_JSON_SAFE_INTEGER)
    else {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Validated(validated),
            publication: Err(TeamPostCaptureFailureV1::InvalidLifetime),
        });
    };
    let admitted = match admit_validated_local_publication_v2(sharing_policy, request, validated) {
        Ok(admitted) => admitted,
        Err(rejected) => {
            let reason = rejected.reason();
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Validated((*rejected).into_result()),
                publication: Err(TeamPostCaptureFailureV1::Privacy(reason)),
            });
        }
    };

    // Immutable capture validates the private snapshot. Rebuild against the
    // original workspace too, preventing a source mutation after snapshot
    // materialization from being published under the stale portable key.
    let refreshed = build_team_request_key_v1(request_input);
    if refreshed.as_ref().is_err() || refreshed.as_ref().is_ok_and(|value| value != request) {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::RequestChanged),
        });
    }

    let encrypted = match build_publication(
        record_id,
        request,
        &admitted,
        signing_credential,
        &verified_trust,
        repository_key,
        publication_now_unix_seconds,
        expires_at_unix_seconds,
    ) {
        Ok(encrypted) => encrypted,
        Err(error) => {
            return Ok(TeamPublishOutcomeV1 {
                local: ExactLocalResultV1::Admitted(admitted),
                publication: Err(TeamPostCaptureFailureV1::Manifest(error)),
            });
        }
    };

    let manifest = encrypted.manifest();
    let Some(encrypted_bytes_uploaded) = manifest
        .stdout
        .ciphertext_size_bytes
        .checked_add(manifest.stderr.ciphertext_size_bytes)
    else {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::Manifest(
                ManifestV2Error::IntegerOutOfRange,
            )),
        });
    };
    if let Err(error) = upload_manifest_last(transport, &encrypted).await {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::Remote(error)),
        });
    }

    Ok(TeamPublishOutcomeV1 {
        local: ExactLocalResultV1::Admitted(admitted),
        publication: Ok(TeamPublishReceiptV1 {
            record_id: manifest.record_id.clone(),
            request_key: manifest.request_key,
            stdout_ciphertext_digest: manifest.stdout.ciphertext_digest,
            stderr_ciphertext_digest: manifest.stderr.ciphertext_digest,
            encrypted_bytes_uploaded,
            trust_epoch: verified_trust.epoch(),
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_publication(
    record_id: &str,
    request: &TeamRequestKeyV1,
    admitted: &AdmittedLocalPublicationV2,
    signing_credential: &ProducerSigningCredentialV1,
    verified_trust: &VerifiedTrustBundle,
    repository_key: &crate::team_manifest_v2::RepositoryEncryptionKeyV1,
    now_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<EncryptedPublicationV2, ManifestV2Error> {
    build_encrypted_publication_v2(ManifestV2BuildInput {
        record_id,
        request,
        admitted,
        signer: signing_credential.signer(),
        verified_trust,
        repository_key,
        now_unix_seconds,
        created_at_unix_seconds: now_unix_seconds,
        expires_at_unix_seconds,
    })
}

async fn upload_manifest_last<T: TeamPublishTransport>(
    transport: &mut T,
    encrypted: &EncryptedPublicationV2,
) -> Result<(), RemoteError> {
    let manifest = encrypted.manifest();
    transport
        .put_ciphertext(&manifest.stdout, encrypted.stdout_r2_bytes())
        .await?;
    transport
        .put_ciphertext(&manifest.stderr, encrypted.stderr_r2_bytes())
        .await?;
    transport.put_manifest_v2(manifest).await
}

async fn finish_encrypted_upload_v2<T: TeamPublishTransport>(
    admitted: AdmittedLocalPublicationV2,
    encrypted: EncryptedPublicationV2,
    trust_epoch: u64,
    endpoint_origin: &str,
    transport: &mut T,
) -> Result<TeamPublishOutcomeV1, TeamPublishError> {
    if transport.endpoint_origin() != endpoint_origin
        || transport.repository_id() != encrypted.manifest().repository_id
        || transport.generation_id() != encrypted.manifest().generation_id
    {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::Remote(
                RemoteError::RequestBindingMismatch,
            )),
        });
    }
    let manifest = encrypted.manifest();
    let Some(encrypted_bytes_uploaded) = manifest
        .stdout
        .ciphertext_size_bytes
        .checked_add(manifest.stderr.ciphertext_size_bytes)
    else {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::Manifest(
                ManifestV2Error::IntegerOutOfRange,
            )),
        });
    };
    if let Err(error) = upload_manifest_last(transport, &encrypted).await {
        return Ok(TeamPublishOutcomeV1 {
            local: ExactLocalResultV1::Admitted(admitted),
            publication: Err(TeamPostCaptureFailureV1::Remote(error)),
        });
    }
    Ok(TeamPublishOutcomeV1 {
        local: ExactLocalResultV1::Admitted(admitted),
        publication: Ok(TeamPublishReceiptV1 {
            record_id: manifest.record_id.clone(),
            request_key: manifest.request_key,
            stdout_ciphertext_digest: manifest.stdout.ciphertext_digest,
            stderr_ciphertext_digest: manifest.stderr.ciphertext_digest,
            encrypted_bytes_uploaded,
            trust_epoch,
        }),
    })
}

fn validate_options(options: &TeamPublishOptionsV1<'_>) -> Result<(), TeamPublishError> {
    if options.record_id.is_empty()
        || options.record_id.len() > 256
        || options
            .record_id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(TeamPublishError::InvalidRecordId);
    }
    if options.lifetime_seconds == 0 || options.lifetime_seconds > MAX_MANIFEST_LIFETIME_SECONDS {
        return Err(TeamPublishError::InvalidLifetime);
    }
    Ok(())
}

fn validate_local_bindings(
    profile: &TeamProfileV1,
    request: &TeamRequestKeyV1,
    sharing_policy: &RepositorySharingPolicy,
) -> Result<(), TeamPublishError> {
    let descriptor = request.descriptor();
    if descriptor.tenant_id() != profile.tenant_id() {
        return Err(TeamPublishError::TenantMismatch);
    }
    if descriptor.repository_id() != profile.repository_id() {
        return Err(TeamPublishError::RepositoryMismatch);
    }
    if descriptor.generation_id() != profile.generation_id() {
        return Err(TeamPublishError::GenerationMismatch);
    }
    if descriptor.policy_digest() != sharing_policy.digest() {
        return Err(TeamPublishError::PolicyMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn system_unix_seconds() -> Result<u64, TeamPublishError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TeamPublishError::InvalidSystemClock)?
        .as_secs();
    if seconds > MAX_JSON_SAFE_INTEGER {
        return Err(TeamPublishError::InvalidSystemClock);
    }
    Ok(seconds)
}

#[cfg(all(test, unix))]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::team::MAX_MANIFEST_LIFETIME_SECONDS;
    use crate::team_manifest_v2::{REPOSITORY_ENCRYPTION_KEY_BYTES, validate_test_local_result_v1};
    use crate::trust_bundle::{ProducerKeyBindingV1, TRUST_BUNDLE_SCHEMA_VERSION, TrustBundleV1};

    const ENDPOINT: &str = "https://cache.example.test";
    const TENANT: &str = "tenant-publish";
    const REPOSITORY: &str = "repo-publish";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";
    const RECORD: &str = "record-publish";

    struct Fixture {
        _temp: TempDir,
        workspace: PathBuf,
        profile_path: PathBuf,
        checkpoint_path: PathBuf,
        root: SigningKey,
        producer: SigningKey,
        policy: RepositorySharingPolicy,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TempDir::new().unwrap();
            let root_dir = temp.path().canonicalize().unwrap();
            fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let workspace = root_dir.join("workspace");
            let checkpoint_dir = root_dir.join("checkpoint");
            fs::create_dir(&workspace).unwrap();
            fs::create_dir(workspace.join("src")).unwrap();
            fs::write(workspace.join("src/input.txt"), b"stable source\n").unwrap();
            fs::create_dir(&checkpoint_dir).unwrap();
            fs::set_permissions(&checkpoint_dir, fs::Permissions::from_mode(0o700)).unwrap();

            let read_token = root_dir.join("read.token");
            let write_token = root_dir.join("write.token");
            let repository_key = root_dir.join("repository-key.json");
            let sharing_policy = root_dir.join("sharing-policy.json");
            let signing_key = root_dir.join("producer-key.json");
            let profile_path = root_dir.join("profile.json");
            let checkpoint_path = checkpoint_dir.join("trust.json");
            write_private(
                &read_token,
                b"ag1.reader.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            );
            write_private(
                &write_token,
                b"ag1.writer.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            );
            write_private(
                &repository_key,
                &serde_json::to_vec(&json!({
                    "schema_version": 1,
                    "namespace": "again.repository-encryption-key.v1",
                    "key_id": "repository-key-1",
                    "key_hex": "09".repeat(REPOSITORY_ENCRYPTION_KEY_BYTES),
                }))
                .unwrap(),
            );
            write_private(
                &sharing_policy,
                &serde_json::to_vec(&json!({
                    "schema_version": 1,
                    "namespace": "again.repository-sharing-policy.v1",
                    "version": "publish-v1",
                    "include_prefixes": ["src"],
                    "exclude_prefixes": ["target", ".env"],
                    "max_output_bytes": 1024 * 1024,
                }))
                .unwrap(),
            );
            let producer = SigningKey::from_bytes(&[7; 32]);
            write_private(
                &signing_key,
                &serde_json::to_vec(&json!({
                    "schema_version": 1,
                    "namespace": "again.producer-signing-key.v1",
                    "key_id": "producer-key-1",
                    "producer_id": "producer-a",
                    "secret_key_hex": "07".repeat(32),
                }))
                .unwrap(),
            );
            let root = SigningKey::from_bytes(&[8; 32]);
            let root_hex = root
                .verifying_key()
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            write_private(
                &profile_path,
                &serde_json::to_vec(&json!({
                    "schema_version": 1,
                    "namespace": "again.team-profile.v1",
                    "endpoint_origin": ENDPOINT,
                    "tenant_id": TENANT,
                    "repository_id": REPOSITORY,
                    "generation_id": GENERATION,
                    "pinned_root_key_id": "root-key-1",
                    "pinned_root_public_key_hex": root_hex,
                    "read_token_file": read_token,
                    "repository_key_file": repository_key,
                    "sharing_policy_file": sharing_policy,
                    "checkpoint_file": checkpoint_path,
                    "runtime_attestation_checkpoint_file": checkpoint_dir.join("runtime.json"),
                    "lookup_protocol": "legacy_v2",
                    "lookup_budget": {
                        "max_requests": 5,
                        "max_response_bytes": 1_000_000,
                        "total_timeout_ms": 5_000,
                    },
                    "publisher": {
                        "write_token_file": write_token,
                        "producer_signing_key_file": signing_key,
                        "publish_budget": {
                            "max_requests": 4,
                            "max_transfer_bytes": 1_000_000,
                            "total_timeout_ms": 5_000,
                        }
                    }
                }))
                .unwrap(),
            );
            let policy = RepositorySharingPolicy::new(
                "publish-v1",
                vec![PathBuf::from("src")],
                vec![PathBuf::from("target"), PathBuf::from(".env")],
                1024 * 1024,
            )
            .unwrap();
            Self {
                _temp: temp,
                workspace,
                profile_path,
                checkpoint_path,
                root,
                producer,
                policy,
            }
        }

        fn request<'a>(&'a self, argv: &'a [OsString]) -> TeamRequestKeyInput<'a> {
            TeamRequestKeyInput {
                tenant_id: TENANT,
                repository_id: REPOSITORY,
                generation_id: GENERATION,
                workspace: &self.workspace,
                cwd: &self.workspace,
                argv,
                environment: &[],
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
                policy_digest: self.policy.digest(),
                execution_profile_digest: fixed_digest(2),
                platform_digest: fixed_digest(3),
                image_digest: fixed_digest(4),
            }
        }

        fn bundle(
            &self,
            request: &TeamRequestKeyV1,
            producer_public_key: Option<[u8; 32]>,
            revoked: bool,
        ) -> TrustBundleV1 {
            let mut bundle = TrustBundleV1 {
                schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
                root_key_id: "root-key-1".into(),
                tenant_id: TENANT.into(),
                repository_id: REPOSITORY.into(),
                generation_id: GENERATION.into(),
                endpoint_origin: ENDPOINT.into(),
                epoch: 1,
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: 300,
                active_producer_keys: producer_public_key
                    .map(|public_key| {
                        vec![ProducerKeyBindingV1 {
                            key_id: "producer-key-1".into(),
                            producer_id: "producer-a".into(),
                            public_key,
                        }]
                    })
                    .unwrap_or_default(),
                revoked_key_ids: revoked
                    .then(|| "producer-key-1".into())
                    .into_iter()
                    .collect(),
                revoked_record_ids: Vec::new(),
                allowed_policy_digests: vec![request.descriptor().policy_digest()],
                allowed_execution_profile_digests: vec![
                    request.descriptor().execution_profile_digest(),
                ],
                allowed_platform_digests: vec![request.descriptor().platform_digest()],
                allowed_image_digests: vec![request.descriptor().image_digest()],
                signature: Vec::new(),
            };
            bundle.signature = self
                .root
                .sign(&bundle.canonical_signing_bytes())
                .to_bytes()
                .to_vec();
            bundle
        }
    }

    struct FakeTransport {
        bundle: TrustBundleV1,
        calls: Vec<&'static str>,
        uploaded: Vec<(EncryptedStreamRefV2, Vec<u8>)>,
        fail_at: Option<&'static str>,
    }

    impl TeamPublishTransport for FakeTransport {
        fn endpoint_origin(&self) -> String {
            ENDPOINT.into()
        }

        fn repository_id(&self) -> &str {
            REPOSITORY
        }

        fn generation_id(&self) -> &str {
            GENERATION
        }

        async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
            self.calls.push("trust");
            Ok(self.bundle.clone())
        }

        async fn put_ciphertext(
            &mut self,
            reference: &EncryptedStreamRefV2,
            ciphertext: &[u8],
        ) -> Result<(), RemoteError> {
            let digest = Digest::from_hex(blake3::hash(ciphertext).to_hex().as_ref()).unwrap();
            assert_eq!(reference.ciphertext_digest, digest);
            assert_eq!(reference.ciphertext_size_bytes, ciphertext.len() as u64);
            let operation = if self.uploaded.is_empty() {
                "stdout"
            } else {
                "stderr"
            };
            self.calls.push(operation);
            if self.fail_at == Some(operation) {
                return Err(RemoteError::Transport {
                    operation: "test encrypted upload",
                });
            }
            self.uploaded.push((reference.clone(), ciphertext.to_vec()));
            Ok(())
        }

        async fn put_manifest_v2(
            &mut self,
            manifest: &EncryptedRemoteCacheManifestV2,
        ) -> Result<(), RemoteError> {
            assert_eq!(self.uploaded.len(), 2);
            assert_eq!(manifest.stdout, self.uploaded[0].0);
            assert_eq!(manifest.stderr, self.uploaded[1].0);
            self.calls.push("manifest");
            if self.fail_at == Some("manifest") {
                return Err(RemoteError::Transport {
                    operation: "test manifest upload",
                });
            }
            Ok(())
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn fixed_digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn loaded(
        fixture: &Fixture,
    ) -> (
        TeamProfileV1,
        crate::team_manifest_v2::RepositoryEncryptionKeyV1,
        ProducerSigningCredentialV1,
        TrustEpochTracker,
    ) {
        let profile = load_team_profile(&fixture.profile_path).unwrap();
        let repository_key = load_repository_key(&profile).unwrap();
        let signer = load_producer_signer(&profile).unwrap();
        let tracker = load_trust_tracker(&profile).unwrap();
        (profile, repository_key, signer, tracker)
    }

    #[test]
    fn interrupted_local_outcome_uses_shell_compatible_exit_without_fallback_bytes() {
        for (signal, expected) in [
            (libc::SIGHUP, 129),
            (libc::SIGINT, 130),
            (libc::SIGTERM, 143),
        ] {
            let local = ExactLocalResultV1::Interrupted {
                retained_execution: None,
                signal,
            };
            assert_eq!(local.stdout(), b"");
            assert_eq!(local.stderr(), b"");
            assert_eq!(local.exit_code(), expected);
            assert_eq!(local.duration_micros(), 0);
        }
    }

    #[test]
    fn encrypted_publication_is_manifest_last_and_ciphertext_bound() {
        runtime().block_on(async {
            let fixture = Fixture::new();
            let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
            let request_input = fixture.request(&argv);
            let request = build_team_request_key_v1(&request_input).unwrap();
            let validated = validate_test_local_result_v1(&request, b"safe result\n");
            let (profile, repository_key, signer, mut tracker) = loaded(&fixture);
            let mut transport = FakeTransport {
                bundle: fixture.bundle(
                    &request,
                    Some(fixture.producer.verifying_key().to_bytes()),
                    false,
                ),
                calls: Vec::new(),
                uploaded: Vec::new(),
                fail_at: None,
            };
            let outcome = finish_publish_v2(
                &profile,
                &request_input,
                &request,
                &fixture.policy,
                &repository_key,
                &signer,
                &mut tracker,
                &mut transport,
                RECORD,
                150,
                50,
                || Ok(validated),
                || Ok(150),
            )
            .await
            .unwrap();
            assert_eq!(transport.calls, ["trust", "stdout", "stderr", "manifest"]);
            assert_eq!(outcome.stdout(), b"safe result\n");
            assert!(outcome.stderr().is_empty());
            let receipt = outcome.publication().unwrap();
            assert_eq!(receipt.record_id(), RECORD);
            assert_eq!(receipt.request_key(), request.digest());
            assert_eq!(receipt.trust_epoch(), 1);
            assert_eq!(
                receipt.encrypted_bytes_uploaded(),
                transport
                    .uploaded
                    .iter()
                    .map(|(_, bytes)| bytes.len() as u64)
                    .sum::<u64>()
            );
            let rendered = format!("{outcome:?}");
            assert!(!rendered.contains("safe result"));
            assert!(fixture.checkpoint_path.is_file());
        });
    }

    #[test]
    fn secret_output_and_input_mutation_refuse_before_remote_mutation() {
        runtime().block_on(async {
            let fixture = Fixture::new();
            let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
            let request_input = fixture.request(&argv);
            let request = build_team_request_key_v1(&request_input).unwrap();
            let secret = validate_test_local_result_v1(
                &request,
                b"-----BEGIN PRIVATE KEY-----\nnever-upload\n",
            );
            let (profile, repository_key, signer, mut tracker) = loaded(&fixture);
            let mut transport = FakeTransport {
                bundle: fixture.bundle(
                    &request,
                    Some(fixture.producer.verifying_key().to_bytes()),
                    false,
                ),
                calls: Vec::new(),
                uploaded: Vec::new(),
                fail_at: None,
            };
            let outcome = finish_publish_v2(
                &profile,
                &request_input,
                &request,
                &fixture.policy,
                &repository_key,
                &signer,
                &mut tracker,
                &mut transport,
                RECORD,
                150,
                50,
                || Ok(secret),
                || Ok(150),
            )
            .await
            .unwrap();
            assert_eq!(
                outcome.stdout(),
                b"-----BEGIN PRIVATE KEY-----\nnever-upload\n"
            );
            assert!(matches!(
                outcome.publication(),
                Err(TeamPostCaptureFailureV1::Privacy(_))
            ));
            assert_eq!(transport.calls, ["trust"]);

            let fixture = Fixture::new();
            let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
            let request_input = fixture.request(&argv);
            let request = build_team_request_key_v1(&request_input).unwrap();
            let validated = validate_test_local_result_v1(&request, b"safe result\n");
            let (profile, repository_key, signer, mut tracker) = loaded(&fixture);
            let mut transport = FakeTransport {
                bundle: fixture.bundle(
                    &request,
                    Some(fixture.producer.verifying_key().to_bytes()),
                    false,
                ),
                calls: Vec::new(),
                uploaded: Vec::new(),
                fail_at: None,
            };
            let source = fixture.workspace.join("src/input.txt");
            let outcome = finish_publish_v2(
                &profile,
                &request_input,
                &request,
                &fixture.policy,
                &repository_key,
                &signer,
                &mut tracker,
                &mut transport,
                RECORD,
                150,
                50,
                || {
                    fs::write(source, b"mutated source\n").unwrap();
                    Ok(validated)
                },
                || Ok(150),
            )
            .await
            .unwrap();
            assert_eq!(outcome.stdout(), b"safe result\n");
            assert!(matches!(
                outcome.publication(),
                Err(TeamPostCaptureFailureV1::RequestChanged)
            ));
            assert_eq!(transport.calls, ["trust"]);
        });
    }

    #[test]
    fn post_capture_upload_failures_preserve_exact_output_as_successful_local_outcome() {
        runtime().block_on(async {
            for fail_at in ["stdout", "manifest"] {
                let fixture = Fixture::new();
                let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
                let request_input = fixture.request(&argv);
                let request = build_team_request_key_v1(&request_input).unwrap();
                let validated = validate_test_local_result_v1(&request, b"present me once\n");
                let (profile, repository_key, signer, mut tracker) = loaded(&fixture);
                let mut transport = FakeTransport {
                    bundle: fixture.bundle(
                        &request,
                        Some(fixture.producer.verifying_key().to_bytes()),
                        false,
                    ),
                    calls: Vec::new(),
                    uploaded: Vec::new(),
                    fail_at: Some(fail_at),
                };
                let outcome = finish_publish_v2(
                    &profile,
                    &request_input,
                    &request,
                    &fixture.policy,
                    &repository_key,
                    &signer,
                    &mut tracker,
                    &mut transport,
                    RECORD,
                    150,
                    50,
                    || Ok(validated),
                    || Ok(150),
                )
                .await
                .unwrap();
                assert_eq!(outcome.stdout(), b"present me once\n");
                assert!(outcome.stderr().is_empty());
                assert!(matches!(
                    outcome.publication(),
                    Err(TeamPostCaptureFailureV1::Remote(_))
                ));
                let rendered = format!("{outcome:?}");
                assert!(rendered.contains("not_published"));
                assert!(!rendered.contains("present me once"));
                assert_eq!(transport.calls.last().copied(), Some(fail_at));
            }
        });
    }

    #[test]
    fn trust_freshness_is_rechecked_after_capture_without_losing_local_output() {
        runtime().block_on(async {
            let fixture = Fixture::new();
            let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
            let request_input = fixture.request(&argv);
            let request = build_team_request_key_v1(&request_input).unwrap();
            let validated = validate_test_local_result_v1(&request, b"fresh local output\n");
            let (profile, repository_key, signer, mut tracker) = loaded(&fixture);
            let mut transport = FakeTransport {
                bundle: fixture.bundle(
                    &request,
                    Some(fixture.producer.verifying_key().to_bytes()),
                    false,
                ),
                calls: Vec::new(),
                uploaded: Vec::new(),
                fail_at: None,
            };
            let outcome = finish_publish_v2(
                &profile,
                &request_input,
                &request,
                &fixture.policy,
                &repository_key,
                &signer,
                &mut tracker,
                &mut transport,
                RECORD,
                150,
                50,
                || Ok(validated),
                || Ok(300),
            )
            .await
            .unwrap();
            assert_eq!(outcome.stdout(), b"fresh local output\n");
            assert!(matches!(
                outcome.publication(),
                Err(TeamPostCaptureFailureV1::Manifest(ManifestV2Error::Trust(
                    TrustBundleError::Expired
                )))
            ));
            assert_eq!(transport.calls, ["trust"]);
        });
    }

    #[test]
    fn wrong_or_revoked_producer_refuses_before_capture_and_blobs() {
        runtime().block_on(async {
            for revoked in [false, true] {
                let fixture = Fixture::new();
                let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
                let request_input = fixture.request(&argv);
                let request = build_team_request_key_v1(&request_input).unwrap();
                let (profile, repository_key, signer, mut tracker) = loaded(&fixture);
                let other = SigningKey::from_bytes(&[99; 32]);
                let bundle = if revoked {
                    fixture.bundle(&request, None, true)
                } else {
                    fixture.bundle(&request, Some(other.verifying_key().to_bytes()), false)
                };
                let mut transport = FakeTransport {
                    bundle,
                    calls: Vec::new(),
                    uploaded: Vec::new(),
                    fail_at: None,
                };
                let capture_ran = Cell::new(false);
                let error = finish_publish_v2(
                    &profile,
                    &request_input,
                    &request,
                    &fixture.policy,
                    &repository_key,
                    &signer,
                    &mut tracker,
                    &mut transport,
                    RECORD,
                    150,
                    50,
                    || {
                        capture_ran.set(true);
                        Ok(validate_test_local_result_v1(&request, b"safe\n"))
                    },
                    || Ok(150),
                )
                .await
                .unwrap_err();
                assert!(!capture_ran.get());
                if revoked {
                    assert!(matches!(
                        error,
                        TeamPublishError::Manifest(ManifestV2Error::RevokedKey)
                    ));
                } else {
                    assert!(matches!(
                        error,
                        TeamPublishError::Manifest(ManifestV2Error::UntrustedProducerKeyMaterial)
                    ));
                }
                assert_eq!(transport.calls, ["trust"]);
            }
        });
    }

    #[test]
    fn options_reject_before_any_network_or_clock_use() {
        assert!(matches!(
            validate_options(&TeamPublishOptionsV1 {
                record_id: "bad id",
                lifetime_seconds: 1,
            }),
            Err(TeamPublishError::InvalidRecordId)
        ));
        assert!(matches!(
            validate_options(&TeamPublishOptionsV1 {
                record_id: RECORD,
                lifetime_seconds: MAX_MANIFEST_LIFETIME_SECONDS + 1,
            }),
            Err(TeamPublishError::InvalidLifetime)
        ));
    }

    #[test]
    fn trust_refresh_resamples_clock_and_rejects_expiry_or_rollback() {
        runtime().block_on(async {
            let fixture = Fixture::new();
            let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
            let request_input = fixture.request(&argv);
            let request = build_team_request_key_v1(&request_input).unwrap();
            let (profile, _repository_key, signer, mut tracker) = loaded(&fixture);
            let bundle = fixture.bundle(
                &request,
                Some(fixture.producer.verifying_key().to_bytes()),
                false,
            );
            let mut transport = FakeTransport {
                bundle: bundle.clone(),
                calls: Vec::new(),
                uploaded: Vec::new(),
                fail_at: None,
            };
            let mut clock = crate::team_clock::SequenceTeamClock::new([150]);
            let (_, sampled_at) = refresh_authorized_trust_v2(
                &profile,
                &request,
                &signer,
                &mut tracker,
                &mut transport,
                RECORD,
                &mut clock,
            )
            .await
            .unwrap();
            assert_eq!(sampled_at, 150);
            assert_eq!(transport.calls, ["trust"]);

            let mut rollback_transport = FakeTransport {
                bundle: bundle.clone(),
                calls: Vec::new(),
                uploaded: Vec::new(),
                fail_at: None,
            };
            let mut rollback_clock = crate::team_clock::SequenceTeamClock::new([160, 150]);
            assert_eq!(rollback_clock.sample_unix_seconds().unwrap(), 160);
            assert!(matches!(
                refresh_authorized_trust_v2(
                    &profile,
                    &request,
                    &signer,
                    &mut tracker,
                    &mut rollback_transport,
                    RECORD,
                    &mut rollback_clock,
                )
                .await,
                Err(PublicationTrustError::Clock(TeamClockError::Rollback {
                    previous: 160,
                    current: 150,
                }))
            ));

            let mut expired_transport = FakeTransport {
                bundle,
                calls: Vec::new(),
                uploaded: Vec::new(),
                fail_at: None,
            };
            let mut expired_clock = crate::team_clock::SequenceTeamClock::new([300]);
            assert!(matches!(
                refresh_authorized_trust_v2(
                    &profile,
                    &request,
                    &signer,
                    &mut tracker,
                    &mut expired_transport,
                    RECORD,
                    &mut expired_clock,
                )
                .await,
                Err(PublicationTrustError::Trust(TrustBundleError::Expired))
            ));
        });
    }
}
