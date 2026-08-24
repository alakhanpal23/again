//! Sealed pull-only team-cache lookup.
//!
//! This module is connected only to the explicit team-alpha CLI and remains
//! isolated from the local V0 result store. A lookup either returns a [`VerifiedRemoteResultV2`] after
//! strict configuration admission, durable trust acceptance, authenticated
//! decryption, and local privacy rescanning, or returns a typed error. Remote
//! bytes are never converted into a local two-execution proof.

use std::path::Path;

use thiserror::Error;

use crate::fingerprint::FileDigestCache;
use crate::privacy::{RemoteRequestAdmissionV1, RepositorySharingPolicy};
use crate::remote::{
    RemoteClient, RemoteError, RemotePullSession, decode_team_manifest_v2_response,
    decode_team_trust_response,
};
use crate::runtime_attestation::{RuntimeAttestationError, TeamRuntimeAttestationV1};
use crate::team_clock::{TeamClock, TeamClockError};
use crate::team_config::{
    TeamConfigError, TeamLookupProtocolV1, TeamProfileV1, load_read_token, load_repository_key,
    load_sharing_policy, load_team_profile, load_trust_tracker, persist_trust_checkpoint,
    validate_profile_state_external_to_workspace,
};
use crate::team_lookup_bundle::{TeamLookupBundleWireError, parse_team_lookup_bundle_v1};
use crate::team_manifest_v2::{
    EncryptedRemoteCacheManifestV2, EncryptedStreamRefV2, ManifestV2Error,
    RepositoryEncryptionKeyV1, VerifiedRemoteResultV2, verify_and_decrypt_v2,
    verify_manifest_for_pull_v2,
};
use crate::team_request_key::{
    TeamLocalOnlyReason, TeamRequestKeyInput, TeamRequestKeyV1,
    build_team_request_key_v1_with_cache,
};
use crate::trust_bundle::{
    TrustBoundRequest, TrustBundleError, TrustBundleV1, TrustEpochTracker, verify_trust_bundle,
};

#[derive(Debug, Error)]
pub(crate) enum TeamPullError {
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
    #[error("portable request admission failed: {0}")]
    Request(#[from] TeamLocalOnlyReason),
    #[error("command inputs changed while the remote lookup was in flight")]
    RequestChangedDuringLookup,
    #[error("the audited runtime changed or does not bind this request: {0}")]
    RuntimeAttestation(#[from] RuntimeAttestationError),
    #[error("pull transport is bound to a different endpoint or repository")]
    TransportBindingMismatch,
    #[error("no shared result exists for this exact request")]
    CacheMiss,
    #[error("remote transport failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("lookup-bundle framing failed: {0}")]
    LookupBundleWire(#[from] TeamLookupBundleWireError),
    #[error("trust-bundle verification failed: {0}")]
    Trust(#[from] TrustBundleError),
    #[error("encrypted result verification failed: {0}")]
    Manifest(#[from] ManifestV2Error),
    #[error("team freshness clock failed: {0}")]
    Clock(#[from] TeamClockError),
}

#[cfg(test)]
mod team_lookup_bundle_differential;

/// Perform one complete pull-only lookup from a strict profile file.
///
/// The trust checkpoint is durably advanced before any manifest or blob is
/// requested. Five GETs (trust, manifest, stdout ciphertext, stderr
/// ciphertext, final trust head) share the profile's one request-count, byte,
/// and wall-clock budget. The final trust fetch fences revocation immediately
/// before release. There are no retries or local-execution fallbacks here.
pub(crate) async fn pull_verified_remote_v2(
    profile_path: &Path,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    remote_admission: &RemoteRequestAdmissionV1,
    runtime: &TeamRuntimeAttestationV1,
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<VerifiedRemoteResultV2, TeamPullError> {
    runtime.verify_request_binding(request)?;
    let profile = load_team_profile(profile_path)?;
    require_lookup_protocol(&profile, TeamLookupProtocolV1::LegacyV2)?;
    validate_profile_state_external_to_workspace(profile_path, &profile, request_input.workspace)?;
    let sharing_policy = load_sharing_policy(&profile)?;
    validate_local_bindings(
        profile.tenant_id(),
        profile.repository_id(),
        profile.generation_id(),
        request,
        &sharing_policy,
    )?;
    if !remote_admission.matches(&sharing_policy, request) {
        return Err(TeamPullError::RequestAdmissionMismatch);
    }

    // Load every private local input before sending the bearer token or
    // advancing durable trust. Any filesystem uncertainty fails closed.
    let token = load_read_token(&profile)?;
    let repository_key = load_repository_key(&profile)?;
    let mut tracker = load_trust_tracker(&profile)?;
    let client = RemoteClient::new_team_read(profile.endpoint_origin(), &token)?;
    if client.endpoint_origin() != profile.endpoint_origin() {
        return Err(TeamPullError::Remote(RemoteError::TrustOriginMismatch));
    }
    let mut pull = client.begin_pull(
        profile.repository_id(),
        profile.generation_id(),
        profile.lookup_budget(),
    )?;

    finish_pull_v2(
        &profile,
        request_input,
        request,
        remote_admission,
        runtime,
        &sharing_policy,
        &repository_key,
        &mut tracker,
        &mut pull,
        digest_cache,
        clock,
    )
    .await
}

/// Perform the same sealed lookup through the two-request bundled protocol.
///
/// The CLI enters this path only when the strict profile explicitly pins
/// `bundle_v1`. Endpoint absence and every protocol failure are returned to
/// the caller; this function never retries through the legacy transport.
pub(crate) async fn pull_verified_remote_bundle_v1(
    profile_path: &Path,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    remote_admission: &RemoteRequestAdmissionV1,
    runtime: &TeamRuntimeAttestationV1,
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<VerifiedRemoteResultV2, TeamPullError> {
    runtime.verify_request_binding(request)?;
    let profile = load_team_profile(profile_path)?;
    require_lookup_protocol(&profile, TeamLookupProtocolV1::BundleV1)?;
    validate_profile_state_external_to_workspace(profile_path, &profile, request_input.workspace)?;
    let sharing_policy = load_sharing_policy(&profile)?;
    validate_local_bindings(
        profile.tenant_id(),
        profile.repository_id(),
        profile.generation_id(),
        request,
        &sharing_policy,
    )?;
    if !remote_admission.matches(&sharing_policy, request) {
        return Err(TeamPullError::RequestAdmissionMismatch);
    }

    let token = load_read_token(&profile)?;
    let repository_key = load_repository_key(&profile)?;
    let mut tracker = load_trust_tracker(&profile)?;
    let client = RemoteClient::new_team_read(profile.endpoint_origin(), &token)?;
    if client.endpoint_origin() != profile.endpoint_origin() {
        return Err(TeamPullError::Remote(RemoteError::TrustOriginMismatch));
    }
    let mut pull = client.begin_pull(
        profile.repository_id(),
        profile.generation_id(),
        profile.lookup_budget(),
    )?;

    finish_bundle_pull_v1(
        &profile,
        request_input,
        request,
        remote_admission,
        runtime,
        &sharing_policy,
        &repository_key,
        &mut tracker,
        &mut pull,
        digest_cache,
        clock,
    )
    .await
}

struct PendingBundledRemoteResultV1 {
    result: VerifiedRemoteResultV2,
    manifest: EncryptedRemoteCacheManifestV2,
}

trait TeamBundlePullTransport {
    async fn fetch_lookup_bundle_v1_body(
        &mut self,
        request_key: &crate::team::Digest,
    ) -> Result<Vec<u8>, RemoteError>;
    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError>;
    fn after_decrypt(&mut self) {}
}

impl TeamBundlePullTransport for RemotePullSession<'_> {
    async fn fetch_lookup_bundle_v1_body(
        &mut self,
        request_key: &crate::team::Digest,
    ) -> Result<Vec<u8>, RemoteError> {
        RemotePullSession::fetch_lookup_bundle_v1_body(self, request_key).await
    }

    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
        RemotePullSession::fetch_latest_trust_bundle(self).await
    }
}

fn require_lookup_protocol(
    profile: &TeamProfileV1,
    expected: TeamLookupProtocolV1,
) -> Result<(), TeamPullError> {
    if profile.lookup_protocol() != expected {
        return Err(TeamConfigError::InvalidProfileField("lookup_protocol").into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn finish_bundle_pull_v1<T: TeamBundlePullTransport>(
    profile: &TeamProfileV1,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    remote_admission: &RemoteRequestAdmissionV1,
    runtime: &TeamRuntimeAttestationV1,
    sharing_policy: &RepositorySharingPolicy,
    repository_key: &RepositoryEncryptionKeyV1,
    tracker: &mut TrustEpochTracker,
    pull: &mut T,
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<VerifiedRemoteResultV2, TeamPullError> {
    let body = match pull.fetch_lookup_bundle_v1_body(&request.digest()).await {
        Ok(body) => body,
        Err(error) => return Err(map_bundle_fetch_error(error)),
    };
    let pending = decrypt_bundle_body_v1(
        profile,
        request_input,
        request,
        remote_admission,
        runtime,
        sharing_policy,
        repository_key,
        tracker,
        &body,
        digest_cache,
        clock,
    )?;

    // There is intentionally no retry or reference-protocol fallback between
    // authenticated decryption and this mandatory revocation fence.
    pull.after_decrypt();
    let final_untrusted_bundle = pull.fetch_latest_trust_bundle().await?;
    finish_bundle_release_v1(
        profile,
        request_input,
        request,
        runtime,
        sharing_policy,
        repository_key,
        tracker,
        pending,
        final_untrusted_bundle,
        digest_cache,
        clock,
    )
}

#[allow(clippy::too_many_arguments)]
fn decrypt_bundle_body_v1(
    profile: &TeamProfileV1,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    remote_admission: &RemoteRequestAdmissionV1,
    runtime: &TeamRuntimeAttestationV1,
    sharing_policy: &RepositorySharingPolicy,
    repository_key: &RepositoryEncryptionKeyV1,
    tracker: &mut TrustEpochTracker,
    body: &[u8],
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<PendingBundledRemoteResultV1, TeamPullError> {
    runtime.verify_request_binding(request)?;
    if !remote_admission.matches(sharing_policy, request) {
        return Err(TeamPullError::RequestAdmissionMismatch);
    }
    let fields = parse_team_lookup_bundle_v1(body, profile.lookup_budget().max_response_bytes())?;
    let untrusted_bundle = decode_team_trust_response(fields.initial_trust_json())?;
    let manifest = decode_team_manifest_v2_response(fields.manifest_json())?;

    // The client treats the bundled authorization head as untrusted and
    // durably advances the monotonic epoch before decryption. Plaintext stays
    // quarantined until a separate post-decrypt latest-trust request passes.
    let trust_now_unix_seconds = clock.sample_unix_seconds()?;
    let verified_trust = verify_trust_bundle(
        untrusted_bundle,
        profile.expected_trust_bundle(),
        profile.pinned_root(),
        trust_now_unix_seconds,
        tracker,
    )?;
    persist_trust_checkpoint(profile, tracker)?;
    let trust_request = trust_request(request);
    verified_trust.verification_context(trust_request, trust_now_unix_seconds)?;
    preflight_manifest_bindings(&manifest, request)?;
    verify_manifest_for_pull_v2(
        &manifest,
        request,
        sharing_policy,
        &verified_trust,
        trust_request,
        repository_key,
        trust_now_unix_seconds,
    )?;

    let refreshed_request = build_team_request_key_v1_with_cache(request_input, digest_cache)
        .map_err(|_| TeamPullError::RequestChangedDuringLookup)?;
    if refreshed_request != *request {
        return Err(TeamPullError::RequestChangedDuringLookup);
    }
    runtime.verify_request_binding(&refreshed_request)?;
    let pre_decrypt_now_unix_seconds = clock.sample_unix_seconds()?;
    let result = verify_and_decrypt_v2(
        &manifest,
        fields.stdout_ciphertext(),
        fields.stderr_ciphertext(),
        request,
        sharing_policy,
        &verified_trust,
        trust_request,
        repository_key,
        pre_decrypt_now_unix_seconds,
    )
    .map_err(TeamPullError::Manifest)?;

    Ok(PendingBundledRemoteResultV1 { result, manifest })
}

#[allow(clippy::too_many_arguments)]
fn finish_bundle_release_v1(
    profile: &TeamProfileV1,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    runtime: &TeamRuntimeAttestationV1,
    sharing_policy: &RepositorySharingPolicy,
    repository_key: &RepositoryEncryptionKeyV1,
    tracker: &mut TrustEpochTracker,
    mut pending: PendingBundledRemoteResultV1,
    final_untrusted_bundle: TrustBundleV1,
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<VerifiedRemoteResultV2, TeamPullError> {
    // This request completes only after client receipt, authentication and
    // decryption of the payload. It preserves the reference flow's revocation
    // fence while reducing five serial requests to two.
    let release_now_unix_seconds = clock.sample_unix_seconds()?;
    let final_verified_trust = verify_trust_bundle(
        final_untrusted_bundle,
        profile.expected_trust_bundle(),
        profile.pinned_root(),
        release_now_unix_seconds,
        tracker,
    )?;
    persist_trust_checkpoint(profile, tracker)?;
    let trust_request = trust_request(request);
    verify_manifest_for_pull_v2(
        &pending.manifest,
        request,
        sharing_policy,
        &final_verified_trust,
        trust_request,
        repository_key,
        release_now_unix_seconds,
    )?;
    pending.result.rebind_release_freshness(
        release_now_unix_seconds,
        final_verified_trust.bundle().expires_at_unix_seconds,
    )?;
    let final_request = build_team_request_key_v1_with_cache(request_input, digest_cache)
        .map_err(|_| TeamPullError::RequestChangedDuringLookup)?;
    if final_request != *request {
        return Err(TeamPullError::RequestChangedDuringLookup);
    }
    runtime.verify_request_binding(&final_request)?;
    // Persistence, manifest revalidation, request reconstruction and runtime
    // verification can consume real time. Sample once more immediately after
    // those operations so the returned capability is fresh at this boundary,
    // rather than merely fresh before the final local work began.
    let final_now_unix_seconds = clock.sample_unix_seconds()?;
    pending
        .result
        .verify_fresh_for_release(final_now_unix_seconds)?;
    Ok(pending.result)
}

trait TeamPullTransport {
    fn endpoint_origin(&self) -> String;
    fn repository_id(&self) -> &str;
    fn generation_id(&self) -> &str;
    async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError>;
    async fn fetch_manifest_v2(
        &mut self,
        request_key: &crate::team::Digest,
    ) -> Result<EncryptedRemoteCacheManifestV2, RemoteError>;
    async fn fetch_ciphertext(
        &mut self,
        blob: &EncryptedStreamRefV2,
    ) -> Result<Vec<u8>, RemoteError>;
    fn after_decrypt(&mut self) {}
}

impl TeamPullTransport for RemotePullSession<'_> {
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

    async fn fetch_manifest_v2(
        &mut self,
        request_key: &crate::team::Digest,
    ) -> Result<EncryptedRemoteCacheManifestV2, RemoteError> {
        RemotePullSession::fetch_manifest_v2(self, request_key).await
    }

    async fn fetch_ciphertext(
        &mut self,
        blob: &EncryptedStreamRefV2,
    ) -> Result<Vec<u8>, RemoteError> {
        RemotePullSession::fetch_ciphertext(self, blob).await
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_pull_v2<T: TeamPullTransport>(
    profile: &TeamProfileV1,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    remote_admission: &RemoteRequestAdmissionV1,
    runtime: &TeamRuntimeAttestationV1,
    sharing_policy: &RepositorySharingPolicy,
    repository_key: &RepositoryEncryptionKeyV1,
    tracker: &mut TrustEpochTracker,
    pull: &mut T,
    digest_cache: &mut dyn FileDigestCache,
    clock: &mut dyn TeamClock,
) -> Result<VerifiedRemoteResultV2, TeamPullError> {
    // Reject a stale or caller-mismatched runtime before sending any token or
    // consuming remote bytes.
    runtime.verify_request_binding(request)?;
    if pull.endpoint_origin() != profile.endpoint_origin()
        || pull.repository_id() != profile.repository_id()
        || pull.generation_id() != profile.generation_id()
    {
        return Err(TeamPullError::TransportBindingMismatch);
    }
    if !remote_admission.matches(sharing_policy, request) {
        return Err(TeamPullError::RequestAdmissionMismatch);
    }

    let untrusted_bundle = pull.fetch_latest_trust_bundle().await?;
    let trust_now_unix_seconds = clock.sample_unix_seconds()?;
    let verified_trust = verify_trust_bundle(
        untrusted_bundle,
        profile.expected_trust_bundle(),
        profile.pinned_root(),
        trust_now_unix_seconds,
        tracker,
    )?;
    // A successfully verified but unpersisted epoch must never authorize a
    // candidate: doing so could permit rollback after process restart.
    persist_trust_checkpoint(profile, tracker)?;

    let trust_request = trust_request(request);
    // Check all allowlists and bundle freshness before accepting attacker-
    // controlled manifest/blob references or spending the remaining budget.
    verified_trust.verification_context(trust_request, trust_now_unix_seconds)?;
    let manifest = match pull.fetch_manifest_v2(&request.digest()).await {
        Ok(manifest) => manifest,
        Err(error) => return Err(map_manifest_fetch_error(error)),
    };
    preflight_manifest_bindings(&manifest, request)?;
    verify_manifest_for_pull_v2(
        &manifest,
        request,
        sharing_policy,
        &verified_trust,
        trust_request,
        repository_key,
        trust_now_unix_seconds,
    )?;
    let stdout_ciphertext = pull.fetch_ciphertext(&manifest.stdout).await?;
    let stderr_ciphertext = pull.fetch_ciphertext(&manifest.stderr).await?;
    let pre_decrypt_now_unix_seconds = clock.sample_unix_seconds()?;

    // Network time must not turn an old portable key into a fresh cache hit.
    // Rebuild from the caller's exact workspace/argv/environment facts after
    // all remote bytes arrive and before any plaintext is decrypted.
    let refreshed_request = build_team_request_key_v1_with_cache(request_input, digest_cache)
        .map_err(|_| TeamPullError::RequestChangedDuringLookup)?;
    if refreshed_request != *request {
        return Err(TeamPullError::RequestChangedDuringLookup);
    }

    // This is deliberately the final operation before authenticated
    // decryption. A loader/executable change during network I/O cannot turn a
    // formerly valid capability into a remote hit.
    runtime.verify_request_binding(&refreshed_request)?;

    let mut result = verify_and_decrypt_v2(
        &manifest,
        &stdout_ciphertext,
        &stderr_ciphertext,
        request,
        sharing_policy,
        &verified_trust,
        trust_request,
        repository_key,
        pre_decrypt_now_unix_seconds,
    )
    .map_err(TeamPullError::Manifest)?;

    // Plaintext is still quarantined here. Refetch the signed trust head so a
    // revocation published while manifest/blob bytes were in flight is an
    // immediate release fence, then reconstruct the live request and runtime
    // one final time before returning the release capability.
    pull.after_decrypt();
    let final_untrusted_bundle = pull.fetch_latest_trust_bundle().await?;
    let post_decrypt_now_unix_seconds = clock.sample_unix_seconds()?;
    let final_verified_trust = verify_trust_bundle(
        final_untrusted_bundle,
        profile.expected_trust_bundle(),
        profile.pinned_root(),
        post_decrypt_now_unix_seconds,
        tracker,
    )?;
    persist_trust_checkpoint(profile, tracker)?;
    verify_manifest_for_pull_v2(
        &manifest,
        request,
        sharing_policy,
        &final_verified_trust,
        trust_request,
        repository_key,
        post_decrypt_now_unix_seconds,
    )?;
    result.rebind_release_freshness(
        post_decrypt_now_unix_seconds,
        final_verified_trust.bundle().expires_at_unix_seconds,
    )?;
    let final_request = build_team_request_key_v1_with_cache(request_input, digest_cache)
        .map_err(|_| TeamPullError::RequestChangedDuringLookup)?;
    if final_request != *request {
        return Err(TeamPullError::RequestChangedDuringLookup);
    }
    runtime.verify_request_binding(&final_request)?;
    // This is the pull-layer release fence. The CLI presentation layer samples
    // again before writing bytes, but callers of this function must never
    // receive an already-expired capability or miss a clock rollback that
    // occurred during final checkpoint/hash/runtime work.
    let final_now_unix_seconds = clock.sample_unix_seconds()?;
    result.verify_fresh_for_release(final_now_unix_seconds)?;
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn finish_pull_at_v2<T: TeamPullTransport>(
    profile: &TeamProfileV1,
    request_input: &TeamRequestKeyInput<'_>,
    request: &TeamRequestKeyV1,
    runtime: &TeamRuntimeAttestationV1,
    sharing_policy: &RepositorySharingPolicy,
    repository_key: &RepositoryEncryptionKeyV1,
    tracker: &mut TrustEpochTracker,
    pull: &mut T,
    now_unix_seconds: u64,
) -> Result<VerifiedRemoteResultV2, TeamPullError> {
    let admission = crate::privacy::admit_remote_request_v1(sharing_policy, request)
        .expect("test request must pass static remote admission");
    let mut digest_cache = crate::fingerprint::NoFileDigestCache;
    let mut clock = crate::team_clock::SequenceTeamClock::new([now_unix_seconds; 4]);
    finish_pull_v2(
        profile,
        request_input,
        request,
        &admission,
        runtime,
        sharing_policy,
        repository_key,
        tracker,
        pull,
        &mut digest_cache,
        &mut clock,
    )
    .await
}

fn map_manifest_fetch_error(error: RemoteError) -> TeamPullError {
    match error {
        RemoteError::ManifestNotFound => TeamPullError::CacheMiss,
        error => TeamPullError::Remote(error),
    }
}

fn map_bundle_fetch_error(error: RemoteError) -> TeamPullError {
    match error {
        RemoteError::ManifestNotFound => TeamPullError::CacheMiss,
        RemoteError::InvalidLookupBundle(error) => TeamPullError::LookupBundleWire(error),
        error => TeamPullError::Remote(error),
    }
}

fn validate_local_bindings(
    tenant_id: &str,
    repository_id: &str,
    generation_id: &str,
    request: &TeamRequestKeyV1,
    sharing_policy: &RepositorySharingPolicy,
) -> Result<(), TeamPullError> {
    let descriptor = request.descriptor();
    if descriptor.tenant_id() != tenant_id {
        return Err(TeamPullError::TenantMismatch);
    }
    if descriptor.repository_id() != repository_id {
        return Err(TeamPullError::RepositoryMismatch);
    }
    if descriptor.generation_id() != generation_id {
        return Err(TeamPullError::GenerationMismatch);
    }
    if descriptor.policy_digest() != sharing_policy.digest() {
        return Err(TeamPullError::PolicyMismatch);
    }
    Ok(())
}

fn trust_request(request: &TeamRequestKeyV1) -> TrustBoundRequest {
    let descriptor = request.descriptor();
    TrustBoundRequest {
        request_key: request.digest(),
        policy_digest: descriptor.policy_digest(),
        execution_profile_digest: descriptor.execution_profile_digest(),
        platform_digest: descriptor.platform_digest(),
        image_digest: descriptor.image_digest(),
    }
}

/// Reject obvious cross-scope references before downloading ciphertext. This
/// is only a bandwidth guard; `verify_and_decrypt_v2` remains the authority
/// because these fields are untrusted until its producer-signature check.
fn preflight_manifest_bindings(
    manifest: &crate::team_manifest_v2::EncryptedRemoteCacheManifestV2,
    request: &TeamRequestKeyV1,
) -> Result<(), TeamPullError> {
    let descriptor = request.descriptor();
    if manifest.tenant_id != descriptor.tenant_id() {
        return Err(TeamPullError::Manifest(ManifestV2Error::TenantMismatch));
    }
    if manifest.repository_id != descriptor.repository_id() {
        return Err(TeamPullError::Manifest(ManifestV2Error::RepositoryMismatch));
    }
    if manifest.generation_id != descriptor.generation_id() {
        return Err(TeamPullError::Manifest(ManifestV2Error::GenerationMismatch));
    }
    if manifest.request_key != request.digest() {
        return Err(TeamPullError::Manifest(ManifestV2Error::RequestKeyMismatch));
    }
    if manifest.policy_digest != descriptor.policy_digest() {
        return Err(TeamPullError::Manifest(ManifestV2Error::PolicyMismatch));
    }
    if manifest.execution_profile_digest != descriptor.execution_profile_digest() {
        return Err(TeamPullError::Manifest(
            ManifestV2Error::ExecutionProfileMismatch,
        ));
    }
    if manifest.platform_digest != descriptor.platform_digest() {
        return Err(TeamPullError::Manifest(ManifestV2Error::PlatformMismatch));
    }
    if manifest.image_digest != descriptor.image_digest() {
        return Err(TeamPullError::Manifest(ManifestV2Error::ImageMismatch));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::team::{
        Digest, PrivacyClass, PrivacyMetadata, SIGNATURE_ENVELOPE_SCHEMA_VERSION, Shareability,
        SignatureAlgorithm,
    };
    use crate::team_crypto::Ed25519Signer;
    use crate::team_manifest_v2::{
        ENCRYPTED_MANIFEST_SCHEMA_VERSION, EncryptedRemoteCacheManifestV2, EncryptedStreamRefV2,
        LOCAL_RESULT_PROOF_SCHEMA_VERSION, ManifestSignatureV2, POLY1305_TAG_BYTES, ResultStatusV2,
        build_test_encrypted_publication_v2,
    };
    use crate::team_request_key::{TeamRequestKeyInput, build_team_request_key_v1};
    use crate::trust_bundle::{
        ExpectedTrustBundle, PinnedRootKey, ProducerKeyBindingV1, TRUST_BUNDLE_SCHEMA_VERSION,
    };

    const ENDPOINT: &str = "https://cache.example.test";
    const TOKEN: &str = "ag1.reader.abcdefghijklmnopqrstuvwxyzABCDEF";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";

    fn digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn bundle_body(
        trust: &TrustBundleV1,
        manifest: &EncryptedRemoteCacheManifestV2,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Vec<u8> {
        let trust = serde_json::to_vec(trust).unwrap();
        let manifest = serde_json::to_vec(manifest).unwrap();
        let mut body = vec![0_u8; crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_HEADER_BYTES];
        body[..8].copy_from_slice(&crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_MAGIC);
        body[8..10].copy_from_slice(
            &crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_SCHEMA_VERSION.to_be_bytes(),
        );
        body[12..16].copy_from_slice(&(trust.len() as u32).to_be_bytes());
        body[16..20].copy_from_slice(&(manifest.len() as u32).to_be_bytes());
        body[20..24].copy_from_slice(&(stdout.len() as u32).to_be_bytes());
        body[24..28].copy_from_slice(&(stderr.len() as u32).to_be_bytes());
        body.extend_from_slice(&trust);
        body.extend_from_slice(&manifest);
        body.extend_from_slice(stdout);
        body.extend_from_slice(stderr);
        body
    }

    fn fixture() -> (TempDir, RepositorySharingPolicy, TeamRequestKeyV1) {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/input.txt"), "safe input\n").unwrap();
        let policy = RepositorySharingPolicy::new(
            "policy-v1",
            vec![PathBuf::from("src")],
            vec![PathBuf::from(".git")],
            1024,
        )
        .unwrap();
        let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
        let request = build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: "tenant-a",
            repository_id: "repo-a",
            generation_id: GENERATION,
            workspace: temp.path(),
            cwd: temp.path(),
            argv: &argv,
            environment: &[],
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: policy.digest(),
            execution_profile_digest: digest(2),
            platform_digest: digest(3),
            image_digest: digest(4),
        })
        .unwrap();
        (temp, policy, request)
    }

    fn manifest(request: &TeamRequestKeyV1) -> EncryptedRemoteCacheManifestV2 {
        let descriptor = request.descriptor();
        EncryptedRemoteCacheManifestV2 {
            schema_version: ENCRYPTED_MANIFEST_SCHEMA_VERSION,
            record_id: "record-a".into(),
            tenant_id: descriptor.tenant_id().into(),
            repository_id: descriptor.repository_id().into(),
            generation_id: descriptor.generation_id().into(),
            request_key: request.digest(),
            policy_digest: descriptor.policy_digest(),
            classifier_digest: digest(5),
            execution_profile_digest: descriptor.execution_profile_digest(),
            platform_digest: descriptor.platform_digest(),
            image_digest: descriptor.image_digest(),
            result_status: ResultStatusV2::Success,
            duration_micros: 1,
            proof_schema_version: LOCAL_RESULT_PROOF_SCHEMA_VERSION,
            producer_version: "producer-v1".into(),
            local_proof_digest: digest(6),
            privacy: PrivacyMetadata {
                classification: PrivacyClass::Internal,
                shareability: Shareability::Repository,
                secret_tainted: false,
            },
            repository_encryption_key_id: "repository-key-1".into(),
            stdout: EncryptedStreamRefV2 {
                ciphertext_digest: digest(7),
                ciphertext_size_bytes: POLY1305_TAG_BYTES,
                nonce: [7; 24],
            },
            stderr: EncryptedStreamRefV2 {
                ciphertext_digest: digest(8),
                ciphertext_size_bytes: POLY1305_TAG_BYTES,
                nonce: [8; 24],
            },
            producer_id: "producer-a".into(),
            created_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            signature: ManifestSignatureV2 {
                schema_version: SIGNATURE_ENVELOPE_SCHEMA_VERSION,
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "producer-key-a".into(),
                signature: vec![0; 64],
            },
        }
    }

    struct StrictProfileFixture {
        _temp: TempDir,
        profile_path: PathBuf,
        checkpoint_path: PathBuf,
    }

    fn write_private(path: &std::path::Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn strict_profile(root_key: &SigningKey, repository_key: [u8; 32]) -> StrictProfileFixture {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let checkpoint_dir = root.join("checkpoint");
        fs::create_dir(&checkpoint_dir).unwrap();
        fs::set_permissions(&checkpoint_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let token_path = root.join("read.token");
        let repository_key_path = root.join("repository-key.json");
        let sharing_policy_path = root.join("sharing-policy.json");
        let profile_path = root.join("profile.json");
        let checkpoint_path = checkpoint_dir.join("trust.json");
        write_private(&token_path, TOKEN.as_bytes());
        write_private(
            &repository_key_path,
            &serde_json::to_vec(&json!({
                "schema_version": 1,
                "namespace": "again.repository-encryption-key.v1",
                "key_id": "repository-key-1",
                "key_hex": repository_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            }))
            .unwrap(),
        );
        write_private(
            &sharing_policy_path,
            &serde_json::to_vec(&json!({
                "schema_version": 1,
                "namespace": "again.repository-sharing-policy.v1",
                "version": "policy-v1",
                "include_prefixes": ["src"],
                "exclude_prefixes": [".git"],
                "max_output_bytes": 1024,
            }))
            .unwrap(),
        );
        let root_public_key_hex = root_key
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
                "tenant_id": "tenant-a",
                "repository_id": "repo-a",
                "generation_id": GENERATION,
                "pinned_root_key_id": "root-key-1",
                "pinned_root_public_key_hex": root_public_key_hex,
                "read_token_file": token_path,
                "repository_key_file": repository_key_path,
                "sharing_policy_file": sharing_policy_path,
                "checkpoint_file": checkpoint_path,
                "runtime_attestation_checkpoint_file": checkpoint_dir.join("runtime.json"),
                "lookup_protocol": "legacy_v2",
                "lookup_budget": {
                    "max_requests": 5,
                    "max_response_bytes": 1_000_000,
                    "total_timeout_ms": 5_000,
                },
            }))
            .unwrap(),
        );
        StrictProfileFixture {
            _temp: temp,
            profile_path,
            checkpoint_path,
        }
    }

    struct FakePull {
        endpoint_origin: String,
        repository_id: String,
        bundle: TrustBundleV1,
        final_bundle: Option<TrustBundleV1>,
        manifest: EncryptedRemoteCacheManifestV2,
        stdout_ciphertext: Vec<u8>,
        stderr_ciphertext: Vec<u8>,
        mutate_after_stderr: Option<PathBuf>,
        mutate_after_decrypt: Option<PathBuf>,
        invalidate_runtime_after_stderr: Option<crate::runtime_attestation::TestRuntimeInvalidator>,
        required_checkpoint_before_manifest: Option<PathBuf>,
        manifest_error: Option<RemoteError>,
        calls: Vec<&'static str>,
    }

    impl TeamPullTransport for FakePull {
        fn endpoint_origin(&self) -> String {
            self.endpoint_origin.clone()
        }

        fn repository_id(&self) -> &str {
            &self.repository_id
        }

        fn generation_id(&self) -> &str {
            &self.manifest.generation_id
        }

        async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
            self.calls.push("trust");
            if self.calls.iter().filter(|call| **call == "trust").count() > 1 {
                if let Some(bundle) = self.final_bundle.take() {
                    return Ok(bundle);
                }
            }
            Ok(self.bundle.clone())
        }

        async fn fetch_manifest_v2(
            &mut self,
            request_key: &Digest,
        ) -> Result<EncryptedRemoteCacheManifestV2, RemoteError> {
            self.calls.push("manifest");
            if let Some(path) = &self.required_checkpoint_before_manifest {
                assert!(
                    path.is_file(),
                    "trust must be durable before manifest fetch"
                );
            }
            if *request_key != self.manifest.request_key {
                return Err(RemoteError::RequestBindingMismatch);
            }
            if let Some(error) = self.manifest_error.take() {
                return Err(error);
            }
            Ok(self.manifest.clone())
        }

        async fn fetch_ciphertext(
            &mut self,
            blob: &EncryptedStreamRefV2,
        ) -> Result<Vec<u8>, RemoteError> {
            if blob == &self.manifest.stdout {
                self.calls.push("stdout");
                return Ok(self.stdout_ciphertext.clone());
            }
            if blob == &self.manifest.stderr {
                self.calls.push("stderr");
                if let Some(path) = self.mutate_after_stderr.take() {
                    fs::write(path, "changed while lookup was in flight\n").unwrap();
                }
                if let Some(invalidator) = self.invalidate_runtime_after_stderr.take() {
                    invalidator.invalidate();
                }
                return Ok(self.stderr_ciphertext.clone());
            }
            Err(RemoteError::NotFound)
        }

        fn after_decrypt(&mut self) {
            if let Some(path) = self.mutate_after_decrypt.take() {
                fs::write(path, "changed only after authenticated decryption\n").unwrap();
            }
        }
    }

    struct FakeBundlePull {
        body: Option<Result<Vec<u8>, RemoteError>>,
        final_trust: Option<Result<TrustBundleV1, RemoteError>>,
        mutate_after_decrypt: Option<PathBuf>,
        invalidate_runtime_after_decrypt:
            Option<crate::runtime_attestation::TestRuntimeInvalidator>,
        calls: Vec<&'static str>,
    }

    impl TeamBundlePullTransport for FakeBundlePull {
        async fn fetch_lookup_bundle_v1_body(
            &mut self,
            _request_key: &Digest,
        ) -> Result<Vec<u8>, RemoteError> {
            self.calls.push("lookup_bundle");
            self.body
                .take()
                .expect("bundle transport must never be called twice")
        }

        async fn fetch_latest_trust_bundle(&mut self) -> Result<TrustBundleV1, RemoteError> {
            self.calls.push("final_trust");
            self.final_trust
                .take()
                .expect("final trust transport must never be called twice")
        }

        fn after_decrypt(&mut self) {
            if let Some(path) = self.mutate_after_decrypt.take() {
                fs::write(path, "changed only after bundled decryption\n").unwrap();
            }
            if let Some(invalidator) = self.invalidate_runtime_after_decrypt.take() {
                invalidator.invalidate();
            }
        }
    }

    #[test]
    fn local_scope_and_policy_are_rejected_before_transport() {
        let (_temp, policy, request) = fixture();
        assert!(
            validate_local_bindings("tenant-a", "repo-a", GENERATION, &request, &policy).is_ok()
        );
        assert!(matches!(
            validate_local_bindings("tenant-b", "repo-a", GENERATION, &request, &policy),
            Err(TeamPullError::TenantMismatch)
        ));
        assert!(matches!(
            validate_local_bindings("tenant-a", "repo-b", GENERATION, &request, &policy),
            Err(TeamPullError::RepositoryMismatch)
        ));

        let other_policy = RepositorySharingPolicy::new(
            "policy-v2",
            vec![PathBuf::from("src")],
            vec![PathBuf::from(".git")],
            1024,
        )
        .unwrap();
        assert!(matches!(
            validate_local_bindings("tenant-a", "repo-a", GENERATION, &request, &other_policy),
            Err(TeamPullError::PolicyMismatch)
        ));
    }

    #[test]
    fn reloaded_profile_must_still_pin_the_selected_lookup_protocol() {
        let root = SigningKey::from_bytes(&[9; 32]);
        let strict = strict_profile(&root, [7; 32]);
        let legacy = load_team_profile(&strict.profile_path).unwrap();
        assert!(require_lookup_protocol(&legacy, TeamLookupProtocolV1::LegacyV2).is_ok());
        assert!(matches!(
            require_lookup_protocol(&legacy, TeamLookupProtocolV1::BundleV1),
            Err(TeamPullError::Config(TeamConfigError::InvalidProfileField(
                "lookup_protocol"
            )))
        ));

        let mut wire: serde_json::Value =
            serde_json::from_slice(&fs::read(&strict.profile_path).unwrap()).unwrap();
        wire["lookup_protocol"] = json!("bundle_v1");
        write_private(&strict.profile_path, &serde_json::to_vec(&wire).unwrap());
        let bundled = load_team_profile(&strict.profile_path).unwrap();
        assert!(require_lookup_protocol(&bundled, TeamLookupProtocolV1::BundleV1).is_ok());
        assert!(matches!(
            require_lookup_protocol(&bundled, TeamLookupProtocolV1::LegacyV2),
            Err(TeamPullError::Config(TeamConfigError::InvalidProfileField(
                "lookup_protocol"
            )))
        ));
    }

    #[test]
    fn manifest_cross_scope_references_are_rejected_before_blob_fetch() {
        let (_temp, _policy, request) = fixture();
        let valid = manifest(&request);
        assert!(preflight_manifest_bindings(&valid, &request).is_ok());

        let mut wrong_repository = valid.clone();
        wrong_repository.repository_id = "repo-b".into();
        assert!(matches!(
            preflight_manifest_bindings(&wrong_repository, &request),
            Err(TeamPullError::Manifest(ManifestV2Error::RepositoryMismatch))
        ));

        let mut wrong_request = valid;
        wrong_request.request_key = digest(9);
        assert!(matches!(
            preflight_manifest_bindings(&wrong_request, &request),
            Err(TeamPullError::Manifest(ManifestV2Error::RequestKeyMismatch))
        ));
    }

    #[test]
    fn only_a_missing_manifest_is_a_cache_miss() {
        assert!(matches!(
            map_manifest_fetch_error(RemoteError::ManifestNotFound),
            TeamPullError::CacheMiss
        ));
        // A bare or untyped 404 is never authenticated evidence of a cache
        // miss. It may be a route, proxy, tenant, or repository failure.
        assert!(matches!(
            map_manifest_fetch_error(RemoteError::NotFound),
            TeamPullError::Remote(RemoteError::NotFound)
        ));
        // Trust and ciphertext fetches use the ordinary `From<RemoteError>`
        // path, so the same HTTP 404 remains a hard transport error there.
        assert!(matches!(
            TeamPullError::from(RemoteError::NotFound),
            TeamPullError::Remote(RemoteError::NotFound)
        ));
        assert!(matches!(
            map_bundle_fetch_error(RemoteError::ManifestNotFound),
            TeamPullError::CacheMiss
        ));
        assert!(matches!(
            map_bundle_fetch_error(RemoteError::NotFound),
            TeamPullError::Remote(RemoteError::NotFound)
        ));
    }

    #[test]
    fn sealed_pull_persists_trust_then_authenticates_decrypts_and_rescans() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let workspace = TempDir::new().unwrap();
                fs::create_dir(workspace.path().join("src")).unwrap();
                fs::write(workspace.path().join("src/input.txt"), "portable input\n").unwrap();
                let policy = RepositorySharingPolicy::new(
                    "policy-v1",
                    vec![PathBuf::from("src")],
                    vec![PathBuf::from(".git")],
                    1024,
                )
                .unwrap();
                let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
                let request_input = TeamRequestKeyInput {
                    tenant_id: "tenant-a",
                    repository_id: "repo-a",
                    generation_id: GENERATION,
                    workspace: workspace.path(),
                    cwd: workspace.path(),
                    argv: &argv,
                    environment: &[],
                    stdin_is_tty: false,
                    stdout_is_tty: false,
                    stderr_is_tty: false,
                    policy_digest: policy.digest(),
                    execution_profile_digest: digest(2),
                    platform_digest: digest(3),
                    image_digest: digest(4),
                };
                let request = build_team_request_key_v1(&request_input).unwrap();
                let (runtime, _runtime_invalidator) =
                    TeamRuntimeAttestationV1::new_for_test("cat", digest(3), digest(4));
                let output = b"ordinary result: 42 checks passed\n";
                let root = SigningKey::from_bytes(&[11; 32]);
                let signer =
                    Ed25519Signer::from_secret_key("producer-key-1", "producer-a", &[7; 32])
                        .unwrap();
                let mut bundle = TrustBundleV1 {
                    schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
                    root_key_id: "root-key-1".into(),
                    tenant_id: "tenant-a".into(),
                    repository_id: "repo-a".into(),
                    generation_id: GENERATION.into(),
                    endpoint_origin: ENDPOINT.into(),
                    epoch: 1,
                    issued_at_unix_seconds: 100,
                    expires_at_unix_seconds: 300,
                    active_producer_keys: vec![ProducerKeyBindingV1 {
                        key_id: signer.key_id().into(),
                        producer_id: signer.producer_id().into(),
                        public_key: signer.public_key_bytes(),
                    }],
                    revoked_key_ids: Vec::new(),
                    revoked_record_ids: Vec::new(),
                    allowed_policy_digests: vec![request.descriptor().policy_digest()],
                    allowed_execution_profile_digests: vec![
                        request.descriptor().execution_profile_digest(),
                    ],
                    allowed_platform_digests: vec![request.descriptor().platform_digest()],
                    allowed_image_digests: vec![request.descriptor().image_digest()],
                    signature: Vec::new(),
                };
                bundle.signature = root
                    .sign(&bundle.canonical_signing_bytes())
                    .to_bytes()
                    .to_vec();
                let pinned_root =
                    PinnedRootKey::from_public_key("root-key-1", &root.verifying_key().to_bytes())
                        .unwrap();
                let verified_trust = verify_trust_bundle(
                    bundle.clone(),
                    ExpectedTrustBundle {
                        tenant_id: "tenant-a",
                        repository_id: "repo-a",
                        generation_id: GENERATION,
                        endpoint_origin: ENDPOINT,
                    },
                    &pinned_root,
                    150,
                    &mut TrustEpochTracker::new(),
                )
                .unwrap();

                let key_bytes = [9; 32];
                let build_key =
                    RepositoryEncryptionKeyV1::from_bytes("repository-key-1", key_bytes).unwrap();
                let publication = build_test_encrypted_publication_v2(
                    "record-a",
                    &request,
                    &policy,
                    output,
                    &signer,
                    &verified_trust,
                    &build_key,
                    150,
                    120,
                    200,
                );
                let wire_manifest = publication.manifest().clone();
                let stdout_ciphertext = publication.stdout_r2_bytes().to_vec();
                let stderr_ciphertext = publication.stderr_r2_bytes().to_vec();

                let strict = strict_profile(&root, key_bytes);
                let profile = load_team_profile(&strict.profile_path).unwrap();
                let repository_key = load_repository_key(&profile).unwrap();
                let mut tracker = load_trust_tracker(&profile).unwrap();
                let mut fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: bundle.clone(),
                    final_bundle: None,
                    manifest: wire_manifest.clone(),
                    stdout_ciphertext: stdout_ciphertext.clone(),
                    stderr_ciphertext: stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let result = finish_pull_at_v2(
                    &profile,
                    &request_input,
                    &request,
                    &runtime,
                    &policy,
                    &repository_key,
                    &mut tracker,
                    &mut fake,
                    150,
                )
                .await
                .unwrap();
                assert_eq!(result.stdout(), output);
                assert_eq!(result.stderr(), b"");
                assert_eq!(
                    fake.calls,
                    ["trust", "manifest", "stdout", "stderr", "trust"]
                );
                assert!(strict.checkpoint_path.is_file());
                assert_eq!(
                    tracker.highest_accepted_epoch("tenant-a", "repo-a", GENERATION, ENDPOINT),
                    Some(1)
                );

                // Exercise the complete reference pull seam, not only the
                // mapper: only the authenticated service disposition is a
                // miss, while a bare/proxy 404 remains a hard remote error.
                let mut typed_miss = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: bundle.clone(),
                    final_bundle: None,
                    manifest: wire_manifest.clone(),
                    stdout_ciphertext: stdout_ciphertext.clone(),
                    stderr_ciphertext: stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: Some(RemoteError::ManifestNotFound),
                    calls: Vec::new(),
                };
                assert!(matches!(
                    finish_pull_at_v2(
                        &profile,
                        &request_input,
                        &request,
                        &runtime,
                        &policy,
                        &repository_key,
                        &mut tracker,
                        &mut typed_miss,
                        150,
                    )
                    .await,
                    Err(TeamPullError::CacheMiss)
                ));
                assert_eq!(typed_miss.calls, ["trust", "manifest"]);

                let mut untyped_404 = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: bundle.clone(),
                    final_bundle: None,
                    manifest: wire_manifest.clone(),
                    stdout_ciphertext: stdout_ciphertext.clone(),
                    stderr_ciphertext: stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: Some(RemoteError::NotFound),
                    calls: Vec::new(),
                };
                assert!(matches!(
                    finish_pull_at_v2(
                        &profile,
                        &request_input,
                        &request,
                        &runtime,
                        &policy,
                        &repository_key,
                        &mut tracker,
                        &mut untyped_404,
                        150,
                    )
                    .await,
                    Err(TeamPullError::Remote(RemoteError::NotFound))
                ));
                assert_eq!(untyped_404.calls, ["trust", "manifest"]);

                // The two-request protocol must yield the exact same
                // authenticated plaintext/provenance capability as the
                // five-request reference path.
                let bundle_strict = strict_profile(&root, key_bytes);
                let bundle_profile = load_team_profile(&bundle_strict.profile_path).unwrap();
                let bundle_repository_key = load_repository_key(&bundle_profile).unwrap();
                let mut bundle_tracker = load_trust_tracker(&bundle_profile).unwrap();
                let bundle_bytes = bundle_body(
                    &bundle,
                    &wire_manifest,
                    &stdout_ciphertext,
                    &stderr_ciphertext,
                );
                let admission = crate::privacy::admit_remote_request_v1(&policy, &request).unwrap();
                let mut no_cache = crate::fingerprint::NoFileDigestCache;
                let mut bundle_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                let mut bundled_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes.clone())),
                    final_trust: Some(Ok(bundle.clone())),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let bundled = finish_bundle_pull_v1(
                    &bundle_profile,
                    &request_input,
                    &request,
                    &admission,
                    &runtime,
                    &policy,
                    &bundle_repository_key,
                    &mut bundle_tracker,
                    &mut bundled_pull,
                    &mut no_cache,
                    &mut bundle_clock,
                )
                .await
                .unwrap();
                assert_eq!(bundled_pull.calls, ["lookup_bundle", "final_trust"]);
                assert_eq!(bundled.stdout(), result.stdout());
                assert_eq!(bundled.stderr(), result.stderr());
                assert_eq!(bundled.duration_micros(), result.duration_micros());
                assert_eq!(bundled.local_proof_digest(), result.local_proof_digest());
                assert_eq!(bundled.producer_id(), result.producer_id());
                assert!(bundle_strict.checkpoint_path.is_file());

                // Mutations injected after authenticated decryption remain
                // quarantined. The client still performs exactly the one
                // mandatory final-trust fence, then the final live request
                // reconstruction detects the changed input. There is no
                // legacy retry or third request.
                let bundle_mutation_strict = strict_profile(&root, key_bytes);
                let bundle_mutation_profile =
                    load_team_profile(&bundle_mutation_strict.profile_path).unwrap();
                let bundle_mutation_key = load_repository_key(&bundle_mutation_profile).unwrap();
                let mut bundle_mutation_tracker =
                    load_trust_tracker(&bundle_mutation_profile).unwrap();
                let mut bundle_mutation_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes.clone())),
                    final_trust: Some(Ok(bundle.clone())),
                    mutate_after_decrypt: Some(workspace.path().join("src/input.txt")),
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let mut bundle_mutation_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                assert!(matches!(
                    finish_bundle_pull_v1(
                        &bundle_mutation_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &bundle_mutation_key,
                        &mut bundle_mutation_tracker,
                        &mut bundle_mutation_pull,
                        &mut no_cache,
                        &mut bundle_mutation_clock,
                    )
                    .await,
                    Err(TeamPullError::RequestChangedDuringLookup)
                ));
                assert_eq!(bundle_mutation_pull.calls, ["lookup_bundle", "final_trust"]);
                fs::write(workspace.path().join("src/input.txt"), "portable input\n").unwrap();

                // Runtime authority can change at the same post-decrypt seam.
                // The final live runtime check rejects it after the bounded
                // second request, without returning the decrypted capability.
                let (bundle_runtime, bundle_runtime_invalidator) =
                    TeamRuntimeAttestationV1::new_for_test("cat", digest(3), digest(4));
                let bundle_runtime_strict = strict_profile(&root, key_bytes);
                let bundle_runtime_profile =
                    load_team_profile(&bundle_runtime_strict.profile_path).unwrap();
                let bundle_runtime_key = load_repository_key(&bundle_runtime_profile).unwrap();
                let mut bundle_runtime_tracker =
                    load_trust_tracker(&bundle_runtime_profile).unwrap();
                let mut bundle_runtime_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes.clone())),
                    final_trust: Some(Ok(bundle.clone())),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: Some(bundle_runtime_invalidator),
                    calls: Vec::new(),
                };
                let mut bundle_runtime_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                assert!(matches!(
                    finish_bundle_pull_v1(
                        &bundle_runtime_profile,
                        &request_input,
                        &request,
                        &admission,
                        &bundle_runtime,
                        &policy,
                        &bundle_runtime_key,
                        &mut bundle_runtime_tracker,
                        &mut bundle_runtime_pull,
                        &mut no_cache,
                        &mut bundle_runtime_clock,
                    )
                    .await,
                    Err(TeamPullError::RuntimeAttestation(
                        RuntimeAttestationError::ExecutableChanged
                    ))
                ));
                assert_eq!(bundle_runtime_pull.calls, ["lookup_bundle", "final_trust"]);

                // The fourth sample is deliberately after checkpoint
                // persistence, final manifest verification, request rebuild,
                // and runtime verification. Expiry at exactly that boundary
                // must quarantine the capability even though all three
                // earlier samples were fresh.
                let bundle_expiry_strict = strict_profile(&root, key_bytes);
                let bundle_expiry_profile =
                    load_team_profile(&bundle_expiry_strict.profile_path).unwrap();
                let bundle_expiry_key = load_repository_key(&bundle_expiry_profile).unwrap();
                let mut bundle_expiry_tracker = load_trust_tracker(&bundle_expiry_profile).unwrap();
                let mut bundle_expiry_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes.clone())),
                    final_trust: Some(Ok(bundle.clone())),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let mut bundle_expiry_clock =
                    crate::team_clock::SequenceTeamClock::new([150, 150, 150, 200]);
                assert!(matches!(
                    finish_bundle_pull_v1(
                        &bundle_expiry_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &bundle_expiry_key,
                        &mut bundle_expiry_tracker,
                        &mut bundle_expiry_pull,
                        &mut no_cache,
                        &mut bundle_expiry_clock,
                    )
                    .await,
                    Err(TeamPullError::Manifest(ManifestV2Error::Expired))
                ));
                assert_eq!(bundle_expiry_pull.calls, ["lookup_bundle", "final_trust"]);

                let bundle_rollback_strict = strict_profile(&root, key_bytes);
                let bundle_rollback_profile =
                    load_team_profile(&bundle_rollback_strict.profile_path).unwrap();
                let bundle_rollback_key = load_repository_key(&bundle_rollback_profile).unwrap();
                let mut bundle_rollback_tracker =
                    load_trust_tracker(&bundle_rollback_profile).unwrap();
                let mut bundle_rollback_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes.clone())),
                    final_trust: Some(Ok(bundle.clone())),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let mut bundle_rollback_clock =
                    crate::team_clock::SequenceTeamClock::new([150, 150, 150, 149]);
                assert!(matches!(
                    finish_bundle_pull_v1(
                        &bundle_rollback_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &bundle_rollback_key,
                        &mut bundle_rollback_tracker,
                        &mut bundle_rollback_pull,
                        &mut no_cache,
                        &mut bundle_rollback_clock,
                    )
                    .await,
                    Err(TeamPullError::Clock(TeamClockError::Rollback {
                        previous: 150,
                        current: 149,
                    }))
                ));
                assert_eq!(bundle_rollback_pull.calls, ["lookup_bundle", "final_trust"]);

                // A benign trust-head rotation is accepted by the mandatory
                // second request and durably advances the checkpoint before
                // the already-decrypted plaintext can be released.
                let mut rotated_bundle = bundle.clone();
                rotated_bundle.epoch = 2;
                rotated_bundle.issued_at_unix_seconds = 125;
                rotated_bundle.signature = root
                    .sign(&rotated_bundle.canonical_signing_bytes())
                    .to_bytes()
                    .to_vec();
                let mut rotation_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes.clone())),
                    final_trust: Some(Ok(rotated_bundle)),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let mut rotation_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                let rotated = finish_bundle_pull_v1(
                    &bundle_profile,
                    &request_input,
                    &request,
                    &admission,
                    &runtime,
                    &policy,
                    &bundle_repository_key,
                    &mut bundle_tracker,
                    &mut rotation_pull,
                    &mut no_cache,
                    &mut rotation_clock,
                )
                .await
                .unwrap();
                assert_eq!(rotated.stdout(), result.stdout());
                assert_eq!(rotation_pull.calls, ["lookup_bundle", "final_trust"]);
                let restored_rotation = load_trust_tracker(&bundle_profile).unwrap();
                assert_eq!(
                    restored_rotation.highest_accepted_epoch(
                        bundle_profile.tenant_id(),
                        bundle_profile.repository_id(),
                        bundle_profile.generation_id(),
                        bundle_profile.endpoint_origin(),
                    ),
                    Some(2)
                );

                // Malformed payloads stop before the final-trust request. A
                // protocol failure cannot trigger a retry or legacy fallback.
                let mut truncated_body = bundle_bytes.clone();
                truncated_body.pop();
                let mut truncated_pull = FakeBundlePull {
                    body: Some(Ok(truncated_body)),
                    final_trust: Some(Ok(bundle.clone())),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let mut truncated_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                assert!(matches!(
                    finish_bundle_pull_v1(
                        &bundle_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &bundle_repository_key,
                        &mut bundle_tracker,
                        &mut truncated_pull,
                        &mut no_cache,
                        &mut truncated_clock,
                    )
                    .await,
                    Err(TeamPullError::LookupBundleWire(
                        TeamLookupBundleWireError::PayloadTruncated
                    ))
                ));
                assert_eq!(truncated_pull.calls, ["lookup_bundle"]);

                // Exhaustion or failure on the mandatory second request is a
                // terminal remote error: the plaintext remains quarantined and
                // the outer flow does not issue a third request.
                let budget_strict = strict_profile(&root, key_bytes);
                let budget_profile = load_team_profile(&budget_strict.profile_path).unwrap();
                let budget_repository_key = load_repository_key(&budget_profile).unwrap();
                let mut budget_tracker = load_trust_tracker(&budget_profile).unwrap();
                let mut budget_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes.clone())),
                    final_trust: Some(Err(RemoteError::RequestBudgetExceeded)),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let mut budget_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                assert!(matches!(
                    finish_bundle_pull_v1(
                        &budget_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &budget_repository_key,
                        &mut budget_tracker,
                        &mut budget_pull,
                        &mut no_cache,
                        &mut budget_clock,
                    )
                    .await,
                    Err(TeamPullError::Remote(RemoteError::RequestBudgetExceeded))
                ));
                assert_eq!(budget_pull.calls, ["lookup_bundle", "final_trust"]);

                // A newly published revocation epoch after authenticated
                // decryption is observed by the second-request fence.
                let mut revoked_bundle = fake.bundle.clone();
                revoked_bundle.epoch = 2;
                revoked_bundle.issued_at_unix_seconds = 125;
                revoked_bundle.revoked_record_ids = vec!["record-a".into()];
                revoked_bundle.signature = root
                    .sign(&revoked_bundle.canonical_signing_bytes())
                    .to_bytes()
                    .to_vec();
                let bundled_revocation_strict = strict_profile(&root, key_bytes);
                let bundled_revocation_profile =
                    load_team_profile(&bundled_revocation_strict.profile_path).unwrap();
                let bundled_revocation_key =
                    load_repository_key(&bundled_revocation_profile).unwrap();
                let mut bundled_revocation_tracker =
                    load_trust_tracker(&bundled_revocation_profile).unwrap();
                let mut bundled_revocation_pull = FakeBundlePull {
                    body: Some(Ok(bundle_bytes)),
                    final_trust: Some(Ok(revoked_bundle.clone())),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_decrypt: None,
                    calls: Vec::new(),
                };
                let mut bundled_revocation_clock =
                    crate::team_clock::SequenceTeamClock::new([150; 4]);
                assert!(matches!(
                    finish_bundle_pull_v1(
                        &bundled_revocation_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &bundled_revocation_key,
                        &mut bundled_revocation_tracker,
                        &mut bundled_revocation_pull,
                        &mut no_cache,
                        &mut bundled_revocation_clock,
                    )
                    .await,
                    Err(TeamPullError::Manifest(ManifestV2Error::RevokedRecord))
                ));
                assert_eq!(
                    bundled_revocation_pull.calls,
                    ["lookup_bundle", "final_trust"]
                );

                let revoked_strict = strict_profile(&root, key_bytes);
                let revoked_profile = load_team_profile(&revoked_strict.profile_path).unwrap();
                let revoked_repository_key = load_repository_key(&revoked_profile).unwrap();
                let mut revoked_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: fake.bundle.clone(),
                    final_bundle: Some(revoked_bundle),
                    manifest: fake.manifest.clone(),
                    stdout_ciphertext: fake.stdout_ciphertext.clone(),
                    stderr_ciphertext: fake.stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(
                        revoked_strict.checkpoint_path.clone(),
                    ),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let admission = crate::privacy::admit_remote_request_v1(&policy, &request).unwrap();
                let mut no_cache = crate::fingerprint::NoFileDigestCache;
                let mut revoked_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                let mut restored = load_trust_tracker(&revoked_profile).unwrap();
                assert!(matches!(
                    finish_pull_v2(
                        &revoked_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &revoked_repository_key,
                        &mut restored,
                        &mut revoked_fake,
                        &mut no_cache,
                        &mut revoked_clock,
                    )
                    .await,
                    Err(TeamPullError::Manifest(ManifestV2Error::RevokedRecord))
                ));
                assert_eq!(
                    revoked_fake.calls,
                    ["trust", "manifest", "stdout", "stderr", "trust"]
                );

                // The final bundle can have a shorter lifetime than the
                // bundle used to decrypt. Rebind the result so a CLI clock
                // sample crossing that newer expiry cannot release bytes.
                let mut short_bundle = fake.bundle.clone();
                short_bundle.epoch = 2;
                short_bundle.issued_at_unix_seconds = 125;
                short_bundle.expires_at_unix_seconds = 151;
                short_bundle.signature = root
                    .sign(&short_bundle.canonical_signing_bytes())
                    .to_bytes()
                    .to_vec();
                let short_strict = strict_profile(&root, key_bytes);
                let short_profile = load_team_profile(&short_strict.profile_path).unwrap();
                let short_repository_key = load_repository_key(&short_profile).unwrap();
                let mut short_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: fake.bundle.clone(),
                    final_bundle: Some(short_bundle),
                    manifest: fake.manifest.clone(),
                    stdout_ciphertext: fake.stdout_ciphertext.clone(),
                    stderr_ciphertext: fake.stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(short_strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let mut no_cache = crate::fingerprint::NoFileDigestCache;
                let mut short_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                let mut restored = load_trust_tracker(&short_profile).unwrap();
                let short_result = finish_pull_v2(
                    &short_profile,
                    &request_input,
                    &request,
                    &admission,
                    &runtime,
                    &policy,
                    &short_repository_key,
                    &mut restored,
                    &mut short_fake,
                    &mut no_cache,
                    &mut short_clock,
                )
                .await
                .unwrap();
                assert!(short_result.verify_fresh_for_release(150).is_ok());
                assert!(matches!(
                    short_result.verify_fresh_for_release(151),
                    Err(ManifestV2Error::Expired)
                ));

                // The legacy five-request path has the same fourth clock
                // boundary as bundle_v1. A capability that expires or sees a
                // rollback during final checkpoint/hash/runtime work must not
                // escape merely because the post-decrypt trust sample passed.
                let final_expiry_strict = strict_profile(&root, key_bytes);
                let final_expiry_profile =
                    load_team_profile(&final_expiry_strict.profile_path).unwrap();
                let final_expiry_key = load_repository_key(&final_expiry_profile).unwrap();
                let mut final_expiry_tracker = load_trust_tracker(&final_expiry_profile).unwrap();
                let mut final_expiry_pull = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: bundle.clone(),
                    final_bundle: None,
                    manifest: wire_manifest.clone(),
                    stdout_ciphertext: stdout_ciphertext.clone(),
                    stderr_ciphertext: stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(
                        final_expiry_strict.checkpoint_path.clone(),
                    ),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let mut final_expiry_clock =
                    crate::team_clock::SequenceTeamClock::new([150, 150, 150, 200]);
                assert!(matches!(
                    finish_pull_v2(
                        &final_expiry_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &final_expiry_key,
                        &mut final_expiry_tracker,
                        &mut final_expiry_pull,
                        &mut no_cache,
                        &mut final_expiry_clock,
                    )
                    .await,
                    Err(TeamPullError::Manifest(ManifestV2Error::Expired))
                ));
                assert_eq!(
                    final_expiry_pull.calls,
                    ["trust", "manifest", "stdout", "stderr", "trust"]
                );

                let final_rollback_strict = strict_profile(&root, key_bytes);
                let final_rollback_profile =
                    load_team_profile(&final_rollback_strict.profile_path).unwrap();
                let final_rollback_key = load_repository_key(&final_rollback_profile).unwrap();
                let mut final_rollback_tracker =
                    load_trust_tracker(&final_rollback_profile).unwrap();
                let mut final_rollback_pull = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: bundle.clone(),
                    final_bundle: None,
                    manifest: wire_manifest.clone(),
                    stdout_ciphertext: stdout_ciphertext.clone(),
                    stderr_ciphertext: stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(
                        final_rollback_strict.checkpoint_path.clone(),
                    ),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let mut final_rollback_clock =
                    crate::team_clock::SequenceTeamClock::new([150, 150, 150, 149]);
                assert!(matches!(
                    finish_pull_v2(
                        &final_rollback_profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &final_rollback_key,
                        &mut final_rollback_tracker,
                        &mut final_rollback_pull,
                        &mut no_cache,
                        &mut final_rollback_clock,
                    )
                    .await,
                    Err(TeamPullError::Clock(TeamClockError::Rollback {
                        previous: 150,
                        current: 149,
                    }))
                ));
                assert_eq!(
                    final_rollback_pull.calls,
                    ["trust", "manifest", "stdout", "stderr", "trust"]
                );

                // A mutation injected only after authenticated decryption is
                // caught by the final request reconstruction, not released.
                let mut post_decrypt_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: fake.bundle.clone(),
                    final_bundle: None,
                    manifest: fake.manifest.clone(),
                    stdout_ciphertext: fake.stdout_ciphertext.clone(),
                    stderr_ciphertext: fake.stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: Some(workspace.path().join("src/input.txt")),
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let admission = crate::privacy::admit_remote_request_v1(&policy, &request).unwrap();
                let mut no_cache = crate::fingerprint::NoFileDigestCache;
                let mut post_decrypt_clock = crate::team_clock::SequenceTeamClock::new([150; 4]);
                let mut restored = load_trust_tracker(&profile).unwrap();
                assert!(matches!(
                    finish_pull_v2(
                        &profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &repository_key,
                        &mut restored,
                        &mut post_decrypt_fake,
                        &mut no_cache,
                        &mut post_decrypt_clock,
                    )
                    .await,
                    Err(TeamPullError::RequestChangedDuringLookup)
                ));
                fs::write(workspace.path().join("src/input.txt"), "portable input\n").unwrap();

                // Freshness is sampled independently at trust acceptance,
                // before decryption, after decryption, and at the final local
                // release boundary. These cases retain coverage for failures
                // at the earlier post-network samples.
                let mut expiring_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: fake.bundle.clone(),
                    final_bundle: None,
                    manifest: fake.manifest.clone(),
                    stdout_ciphertext: fake.stdout_ciphertext.clone(),
                    stderr_ciphertext: fake.stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let mut no_cache = crate::fingerprint::NoFileDigestCache;
                let mut expiry_clock = crate::team_clock::SequenceTeamClock::new([150, 150, 200]);
                let mut restored = load_trust_tracker(&profile).unwrap();
                assert!(matches!(
                    finish_pull_v2(
                        &profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &repository_key,
                        &mut restored,
                        &mut expiring_fake,
                        &mut no_cache,
                        &mut expiry_clock,
                    )
                    .await,
                    Err(TeamPullError::Manifest(ManifestV2Error::Expired))
                ));

                let mut rollback_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: fake.bundle.clone(),
                    final_bundle: None,
                    manifest: fake.manifest.clone(),
                    stdout_ciphertext: fake.stdout_ciphertext.clone(),
                    stderr_ciphertext: fake.stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let mut no_cache = crate::fingerprint::NoFileDigestCache;
                let mut rollback_clock = crate::team_clock::SequenceTeamClock::new([150, 149]);
                let mut restored = load_trust_tracker(&profile).unwrap();
                assert!(matches!(
                    finish_pull_v2(
                        &profile,
                        &request_input,
                        &request,
                        &admission,
                        &runtime,
                        &policy,
                        &repository_key,
                        &mut restored,
                        &mut rollback_fake,
                        &mut no_cache,
                        &mut rollback_clock,
                    )
                    .await,
                    Err(TeamPullError::Clock(TeamClockError::Rollback {
                        previous: 150,
                        current: 149,
                    }))
                ));

                // A caller-supplied platform/image pair cannot start a pull:
                // the sealed runtime must bind the exact request first.
                let (wrong_runtime, _wrong_runtime_invalidator) =
                    TeamRuntimeAttestationV1::new_for_test("cat", digest(99), digest(4));
                let mut mismatch_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: bundle.clone(),
                    final_bundle: None,
                    manifest: wire_manifest.clone(),
                    stdout_ciphertext: stdout_ciphertext.clone(),
                    stderr_ciphertext: stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let mut mismatch_tracker = load_trust_tracker(&profile).unwrap();
                assert!(matches!(
                    finish_pull_at_v2(
                        &profile,
                        &request_input,
                        &request,
                        &wrong_runtime,
                        &policy,
                        &repository_key,
                        &mut mismatch_tracker,
                        &mut mismatch_fake,
                        150,
                    )
                    .await,
                    Err(TeamPullError::RuntimeAttestation(
                        RuntimeAttestationError::RequestBindingMismatch
                    ))
                ));
                assert!(mismatch_fake.calls.is_empty());

                // Even an otherwise valid manifest with one bad signature is
                // rejected before either attacker-selected blob is fetched.
                let mut bad_manifest = wire_manifest.clone();
                bad_manifest.signature.signature[0] ^= 1;
                let mut bad_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle,
                    final_bundle: None,
                    manifest: bad_manifest,
                    stdout_ciphertext,
                    stderr_ciphertext,
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let repository_key = load_repository_key(&profile).unwrap();
                let mut restored = load_trust_tracker(&profile).unwrap();
                assert!(matches!(
                    finish_pull_at_v2(
                        &profile,
                        &request_input,
                        &request,
                        &runtime,
                        &policy,
                        &repository_key,
                        &mut restored,
                        &mut bad_fake,
                        150,
                    )
                    .await,
                    Err(TeamPullError::Manifest(ManifestV2Error::InvalidSignature))
                ));
                assert_eq!(bad_fake.calls, ["trust", "manifest"]);

                let mut changing_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: bad_fake.bundle.clone(),
                    final_bundle: None,
                    manifest: wire_manifest,
                    stdout_ciphertext: bad_fake.stdout_ciphertext.clone(),
                    stderr_ciphertext: bad_fake.stderr_ciphertext.clone(),
                    mutate_after_stderr: Some(workspace.path().join("src/input.txt")),
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: None,
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let repository_key = load_repository_key(&profile).unwrap();
                let mut restored = load_trust_tracker(&profile).unwrap();
                assert!(matches!(
                    finish_pull_at_v2(
                        &profile,
                        &request_input,
                        &request,
                        &runtime,
                        &policy,
                        &repository_key,
                        &mut restored,
                        &mut changing_fake,
                        150,
                    )
                    .await,
                    Err(TeamPullError::RequestChangedDuringLookup)
                ));
                assert_eq!(
                    changing_fake.calls,
                    ["trust", "manifest", "stdout", "stderr"]
                );

                // The final runtime check occurs after all ciphertext bytes
                // arrive and rejects an invalidated executable authority
                // before any plaintext is produced.
                fs::write(workspace.path().join("src/input.txt"), "portable input\n").unwrap();
                let (changing_runtime, runtime_invalidator) =
                    TeamRuntimeAttestationV1::new_for_test("cat", digest(3), digest(4));
                let mut runtime_changing_fake = FakePull {
                    endpoint_origin: ENDPOINT.into(),
                    repository_id: "repo-a".into(),
                    bundle: changing_fake.bundle.clone(),
                    final_bundle: None,
                    manifest: changing_fake.manifest.clone(),
                    stdout_ciphertext: changing_fake.stdout_ciphertext.clone(),
                    stderr_ciphertext: changing_fake.stderr_ciphertext.clone(),
                    mutate_after_stderr: None,
                    mutate_after_decrypt: None,
                    invalidate_runtime_after_stderr: Some(runtime_invalidator),
                    required_checkpoint_before_manifest: Some(strict.checkpoint_path.clone()),
                    manifest_error: None,
                    calls: Vec::new(),
                };
                let repository_key = load_repository_key(&profile).unwrap();
                let mut restored = load_trust_tracker(&profile).unwrap();
                assert!(matches!(
                    finish_pull_at_v2(
                        &profile,
                        &request_input,
                        &request,
                        &changing_runtime,
                        &policy,
                        &repository_key,
                        &mut restored,
                        &mut runtime_changing_fake,
                        150,
                    )
                    .await,
                    Err(TeamPullError::RuntimeAttestation(
                        RuntimeAttestationError::ExecutableChanged
                    ))
                ));
                assert_eq!(
                    runtime_changing_fake.calls,
                    ["trust", "manifest", "stdout", "stderr"]
                );
            });
    }
}
