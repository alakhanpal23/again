//! Authenticated, freshness-bound trust distribution for shared-cache reads.
//!
//! A [`TrustBundleV1`] is an untrusted wire object until
//! [`verify_trust_bundle`] returns a [`VerifiedTrustBundle`]. Verification
//! binds the bundle to one tenant, repository, canonical HTTPS endpoint
//! origin, and caller-pinned Ed25519 root key. The returned capability can
//! then derive the existing manifest [`VerificationContext`] and producer
//! verifier without accepting caller-supplied authorization maps.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::team::{Digest, ED25519_SIGNATURE_SIZE, MAX_JSON_SAFE_INTEGER, VerificationContext};
use crate::team_crypto::Ed25519Verifier;

pub const TRUST_BUNDLE_SCHEMA_VERSION: u16 = 1;
pub const TRUST_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const TRUST_CHECKPOINT_NAMESPACE: &str = "again.trust-checkpoint.v1";
pub const MAX_TRUST_BUNDLE_LIFETIME_SECONDS: u64 = 5 * 60;
pub const MAX_TRUST_BUNDLE_FUTURE_SKEW_SECONDS: u64 = 30;
pub const MAX_TRUST_BUNDLE_ENTRIES_PER_SET: usize = 4_096;

const TRUST_BUNDLE_SIGNING_DOMAIN: &[u8] = b"again.trust-bundle.v1";
const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// One immutable producer-key authorization in a trust bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProducerKeyBindingV1 {
    pub key_id: String,
    pub producer_id: String,
    pub public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
}

/// Strict v1 trust-distribution wire format.
///
/// All list fields must be strictly sorted and duplicate-free. Producer keys
/// are sorted by `key_id`; identifier lists use bytewise string order; digest
/// lists use their decoded 32-byte order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TrustBundleV1 {
    pub schema_version: u16,
    pub root_key_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub generation_id: String,
    pub endpoint_origin: String,
    pub epoch: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub active_producer_keys: Vec<ProducerKeyBindingV1>,
    pub revoked_key_ids: Vec<String>,
    pub revoked_record_ids: Vec<String>,
    pub allowed_policy_digests: Vec<Digest>,
    pub allowed_execution_profile_digests: Vec<Digest>,
    pub allowed_platform_digests: Vec<Digest>,
    pub allowed_image_digests: Vec<Digest>,
    pub signature: Vec<u8>,
}

/// Durable anti-rollback state for one exact shared-cache trust scope.
///
/// This is not a remotely authenticated object. It may only be restored from
/// the strict, current-user-owned checkpoint file admitted by
/// `crate::team_config`. The authenticated bundle digest detects divergent
/// contents at the highest accepted epoch, while the complete historical key
/// map and cumulative revocation sets preserve monotonic trust decisions
/// across process restarts.
///
/// A same-user or root attacker that can roll back or replace both the profile
/// and checkpoint remains outside this file-based threat boundary. Deployments
/// requiring resistance to that attacker need a platform monotonic counter or
/// externally witnessed checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TrustCheckpointV1 {
    pub schema_version: u16,
    pub namespace: String,
    pub root_key_id: String,
    pub root_public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    pub tenant_id: String,
    pub repository_id: String,
    pub generation_id: String,
    pub endpoint_origin: String,
    pub highest_epoch: u64,
    pub same_epoch_digest: Digest,
    pub historical_key_bindings: Vec<ProducerKeyBindingV1>,
    pub revoked_key_ids: Vec<String>,
    pub revoked_record_ids: Vec<String>,
}

impl TrustBundleV1 {
    /// Exact deterministic bytes authenticated by the root signature.
    ///
    /// JSON serialization and field order are deliberately irrelevant. Every
    /// variable-width value and sequence is length-prefixed, integers use
    /// fixed-width little-endian encoding, and the signature is excluded.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_024);
        put_bytes(&mut output, TRUST_BUNDLE_SIGNING_DOMAIN);
        put_u16(&mut output, self.schema_version);
        put_string(&mut output, &self.root_key_id);
        put_string(&mut output, &self.tenant_id);
        put_string(&mut output, &self.repository_id);
        put_string(&mut output, &self.generation_id);
        put_string(&mut output, &self.endpoint_origin);
        put_u64(&mut output, self.epoch);
        put_u64(&mut output, self.issued_at_unix_seconds);
        put_u64(&mut output, self.expires_at_unix_seconds);

        put_count(&mut output, self.active_producer_keys.len());
        for binding in &self.active_producer_keys {
            put_string(&mut output, &binding.key_id);
            put_string(&mut output, &binding.producer_id);
            put_bytes(&mut output, &binding.public_key);
        }
        put_strings(&mut output, &self.revoked_key_ids);
        put_strings(&mut output, &self.revoked_record_ids);
        put_digests(&mut output, &self.allowed_policy_digests);
        put_digests(&mut output, &self.allowed_execution_profile_digests);
        put_digests(&mut output, &self.allowed_platform_digests);
        put_digests(&mut output, &self.allowed_image_digests);
        output
    }
}

/// Caller-pinned root identity and Ed25519 public key.
///
/// There is intentionally no production root-signing API in this module.
#[derive(Debug, Clone)]
pub struct PinnedRootKey {
    key_id: String,
    verifying_key: VerifyingKey,
}

impl PinnedRootKey {
    pub fn from_public_key(key_id: &str, public_key: &[u8]) -> Result<Self, TrustBundleError> {
        validate_identifier(key_id, "pinned_root_key_id")?;
        let bytes: [u8; ED25519_PUBLIC_KEY_SIZE] = public_key
            .try_into()
            .map_err(|_| TrustBundleError::InvalidRootPublicKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| TrustBundleError::InvalidRootPublicKey)?;
        Ok(Self {
            key_id: key_id.to_owned(),
            verifying_key,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
        self.verifying_key.to_bytes()
    }
}

/// Exact trust scope expected by the caller that fetched a bundle.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedTrustBundle<'a> {
    pub tenant_id: &'a str,
    pub repository_id: &'a str,
    pub generation_id: &'a str,
    /// Canonical textual origin, such as `https://cache.example.com`.
    pub endpoint_origin: &'a str,
}

/// Locally recomputed bindings for one requested cache candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustBoundRequest {
    pub request_key: Digest,
    pub policy_digest: Digest,
    pub execution_profile_digest: Digest,
    pub platform_digest: Digest,
    pub image_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TrustScope {
    tenant_id: String,
    repository_id: String,
    generation_id: String,
    endpoint_origin: String,
}

#[derive(Debug, Clone)]
struct AcceptedEpoch {
    epoch: u64,
    canonical_signing_digest: Digest,
    historical_key_bindings: BTreeMap<String, (String, [u8; ED25519_PUBLIC_KEY_SIZE])>,
    revoked_key_ids: BTreeSet<String>,
    revoked_record_ids: BTreeSet<String>,
}

/// Monotonicity and key-identity guard for authenticated trust bundles.
///
/// Keep one tracker across refreshes and restore its strict checkpoint before
/// accepting a bundle after restart. A fresh tracker intentionally represents
/// first use and has no memory of earlier epochs.
#[derive(Debug, Default)]
pub struct TrustEpochTracker {
    accepted: BTreeMap<TrustScope, AcceptedEpoch>,
}

impl TrustEpochTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn highest_accepted_epoch(
        &self,
        tenant_id: &str,
        repository_id: &str,
        generation_id: &str,
        endpoint_origin: &str,
    ) -> Option<u64> {
        self.accepted
            .get(&TrustScope {
                tenant_id: tenant_id.to_owned(),
                repository_id: repository_id.to_owned(),
                generation_id: generation_id.to_owned(),
                endpoint_origin: endpoint_origin.to_owned(),
            })
            .map(|state| state.epoch)
    }

    /// Export the complete durable state for one exact trust scope.
    ///
    /// `None` means this tracker has not accepted a bundle for the requested
    /// scope and therefore has no anti-rollback history to persist.
    pub fn export_checkpoint(
        &self,
        expected: ExpectedTrustBundle<'_>,
        pinned_root: &PinnedRootKey,
    ) -> Result<Option<TrustCheckpointV1>, TrustBundleError> {
        validate_identifier(expected.tenant_id, "expected.tenant_id")?;
        validate_identifier(expected.repository_id, "expected.repository_id")?;
        validate_generation_id(expected.generation_id)?;
        validate_endpoint_origin(expected.endpoint_origin)?;
        let scope = TrustScope {
            tenant_id: expected.tenant_id.to_owned(),
            repository_id: expected.repository_id.to_owned(),
            generation_id: expected.generation_id.to_owned(),
            endpoint_origin: expected.endpoint_origin.to_owned(),
        };
        let Some(state) = self.accepted.get(&scope) else {
            return Ok(None);
        };
        let historical_key_bindings = state
            .historical_key_bindings
            .iter()
            .map(|(key_id, (producer_id, public_key))| ProducerKeyBindingV1 {
                key_id: key_id.clone(),
                producer_id: producer_id.clone(),
                public_key: *public_key,
            })
            .collect();
        Ok(Some(TrustCheckpointV1 {
            schema_version: TRUST_CHECKPOINT_SCHEMA_VERSION,
            namespace: TRUST_CHECKPOINT_NAMESPACE.to_owned(),
            root_key_id: pinned_root.key_id.clone(),
            root_public_key: pinned_root.public_key_bytes(),
            tenant_id: scope.tenant_id,
            repository_id: scope.repository_id,
            generation_id: scope.generation_id,
            endpoint_origin: scope.endpoint_origin,
            highest_epoch: state.epoch,
            same_epoch_digest: state.canonical_signing_digest,
            historical_key_bindings,
            revoked_key_ids: state.revoked_key_ids.iter().cloned().collect(),
            revoked_record_ids: state.revoked_record_ids.iter().cloned().collect(),
        }))
    }

    /// Restore one strict durable checkpoint into this tracker.
    ///
    /// Existing in-memory state is never weakened: restoring an older epoch,
    /// divergent same-epoch digest, historical key omission/rebinding, or
    /// revocation omission fails without updating the tracker.
    pub fn restore_checkpoint(
        &mut self,
        checkpoint: TrustCheckpointV1,
        expected: ExpectedTrustBundle<'_>,
        pinned_root: &PinnedRootKey,
    ) -> Result<(), TrustBundleError> {
        let (scope, restored) = validate_checkpoint(checkpoint, expected, pinned_root)?;
        if let Some(previous) = self.accepted.get(&scope) {
            validate_monotonic_state(previous, &restored)?;
        }
        self.accepted.insert(scope, restored);
        Ok(())
    }
}

/// Capability proving that one bundle passed signature, scope, freshness,
/// rollback, revocation, and key-identity validation.
#[derive(Debug)]
pub struct VerifiedTrustBundle {
    bundle: TrustBundleV1,
    trusted_producer_keys: BTreeMap<String, String>,
    revoked_key_ids: BTreeSet<String>,
    revoked_record_ids: BTreeSet<String>,
    producer_verifier: Ed25519Verifier,
}

impl VerifiedTrustBundle {
    pub fn bundle(&self) -> &TrustBundleV1 {
        &self.bundle
    }

    pub fn epoch(&self) -> u64 {
        self.bundle.epoch
    }

    pub fn endpoint_origin(&self) -> &str {
        &self.bundle.endpoint_origin
    }

    pub fn generation_id(&self) -> &str {
        &self.bundle.generation_id
    }

    /// The only producer verifier associated with this verified capability.
    pub fn producer_verifier(&self) -> &Ed25519Verifier {
        &self.producer_verifier
    }

    /// Construct the existing manifest verification input without accepting
    /// caller-supplied producer authorization or revocation maps.
    ///
    /// The request's policy, execution profile, platform, and image digests
    /// must all be explicitly active in this bundle. Freshness is rechecked so
    /// retaining a capability cannot extend the bundle lifetime.
    pub fn verification_context(
        &self,
        request: TrustBoundRequest,
        now_unix_seconds: u64,
    ) -> Result<VerificationContext, TrustBundleError> {
        validate_freshness(&self.bundle, now_unix_seconds)?;
        if !contains_digest(&self.bundle.allowed_policy_digests, request.policy_digest) {
            return Err(TrustBundleError::PolicyDigestNotAllowed);
        }
        if !contains_digest(
            &self.bundle.allowed_execution_profile_digests,
            request.execution_profile_digest,
        ) {
            return Err(TrustBundleError::ExecutionProfileDigestNotAllowed);
        }
        if !contains_digest(
            &self.bundle.allowed_platform_digests,
            request.platform_digest,
        ) {
            return Err(TrustBundleError::PlatformDigestNotAllowed);
        }
        if !contains_digest(&self.bundle.allowed_image_digests, request.image_digest) {
            return Err(TrustBundleError::ImageDigestNotAllowed);
        }
        Ok(VerificationContext {
            tenant_id: self.bundle.tenant_id.clone(),
            repository_id: self.bundle.repository_id.clone(),
            request_key: request.request_key,
            policy_digest: request.policy_digest,
            execution_profile_digest: request.execution_profile_digest,
            platform_digest: request.platform_digest,
            image_digest: request.image_digest,
            now_unix_seconds,
            trusted_producer_keys: self.trusted_producer_keys.clone(),
            revoked_key_ids: self.revoked_key_ids.clone(),
            revoked_record_ids: self.revoked_record_ids.clone(),
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrustBundleError {
    #[error("unknown trust-bundle schema version")]
    UnknownSchemaVersion,
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(&'static str),
    #[error(
        "endpoint origin must be an exact canonical HTTPS origin without credentials, path, query, or fragment"
    )]
    InvalidEndpointOrigin,
    #[error("trust-bundle epoch must be non-zero")]
    InvalidEpoch,
    #[error("trust-bundle epoch exceeds the shared JSON safe-integer range")]
    EpochOutOfRange,
    #[error("trust-bundle timestamp exceeds the shared JSON safe-integer range")]
    TimestampOutOfRange,
    #[error("invalid trust-bundle issue/expiry interval")]
    InvalidLifetime,
    #[error("trust bundle is not yet valid")]
    IssuedInFuture,
    #[error("trust bundle has expired")]
    Expired,
    #[error("root key id does not match the caller-pinned root")]
    RootKeyMismatch,
    #[error("Ed25519 root public key is malformed")]
    InvalidRootPublicKey,
    #[error("root signature must contain exactly 64 bytes")]
    InvalidSignatureSize,
    #[error("root signature verification failed")]
    InvalidSignature,
    #[error("tenant binding mismatch")]
    TenantMismatch,
    #[error("repository binding mismatch")]
    RepositoryMismatch,
    #[error("repository generation must be exactly 32 lower-case hexadecimal characters")]
    InvalidGenerationId,
    #[error("repository-generation binding mismatch")]
    GenerationMismatch,
    #[error("endpoint-origin binding mismatch")]
    EndpointOriginMismatch,
    #[error("too many entries in {0}")]
    TooManyEntries(&'static str),
    #[error("{0} must be strictly sorted and duplicate-free")]
    UnsortedOrDuplicate(&'static str),
    #[error("producer Ed25519 public key is malformed")]
    InvalidProducerPublicKey,
    #[error("an active producer key is also revoked")]
    ActiveKeyRevoked,
    #[error("trust-bundle epoch rolled back")]
    EpochRollback,
    #[error("same trust-bundle epoch has divergent authenticated contents")]
    DivergentEpoch,
    #[error("a producer key id was rebound to different key material or producer")]
    KeyRebinding,
    #[error("a previously revoked key was reactivated or omitted from revocations")]
    KeyRevocationRollback,
    #[error("a previously revoked record was omitted from revocations")]
    RecordRevocationRollback,
    #[error("policy digest is not active in the verified trust bundle")]
    PolicyDigestNotAllowed,
    #[error("execution-profile digest is not active in the verified trust bundle")]
    ExecutionProfileDigestNotAllowed,
    #[error("platform digest is not active in the verified trust bundle")]
    PlatformDigestNotAllowed,
    #[error("image digest is not active in the verified trust bundle")]
    ImageDigestNotAllowed,
    #[error("unknown trust-checkpoint schema version")]
    UnknownCheckpointSchemaVersion,
    #[error("trust-checkpoint namespace mismatch")]
    CheckpointNamespaceMismatch,
    #[error("trust-checkpoint scope does not match the configured profile")]
    CheckpointScopeMismatch,
    #[error("trust-checkpoint root identity does not match the pinned root")]
    CheckpointRootMismatch,
    #[error("a historical producer key binding was omitted from the checkpoint")]
    HistoricalKeyBindingRollback,
}

/// Authenticate and accept one trust bundle.
///
/// The tracker is updated only after every check succeeds. The root key is
/// caller-pinned rather than discovered from the untrusted bundle.
pub fn verify_trust_bundle(
    bundle: TrustBundleV1,
    expected: ExpectedTrustBundle<'_>,
    pinned_root: &PinnedRootKey,
    now_unix_seconds: u64,
    tracker: &mut TrustEpochTracker,
) -> Result<VerifiedTrustBundle, TrustBundleError> {
    validate_wire_shape(&bundle)?;
    validate_identifier(expected.tenant_id, "expected.tenant_id")?;
    validate_identifier(expected.repository_id, "expected.repository_id")?;
    validate_generation_id(expected.generation_id)?;
    validate_endpoint_origin(expected.endpoint_origin)?;

    if bundle.root_key_id != pinned_root.key_id {
        return Err(TrustBundleError::RootKeyMismatch);
    }
    let canonical = bundle.canonical_signing_bytes();
    let canonical_digest = digest_bytes(&canonical);
    let signature_bytes: [u8; ED25519_SIGNATURE_SIZE] = bundle
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| TrustBundleError::InvalidSignatureSize)?;
    if pinned_root
        .verifying_key
        .verify_strict(&canonical, &Signature::from_bytes(&signature_bytes))
        .is_err()
    {
        return Err(TrustBundleError::InvalidSignature);
    }

    if bundle.tenant_id != expected.tenant_id {
        return Err(TrustBundleError::TenantMismatch);
    }
    if bundle.repository_id != expected.repository_id {
        return Err(TrustBundleError::RepositoryMismatch);
    }
    if bundle.generation_id != expected.generation_id {
        return Err(TrustBundleError::GenerationMismatch);
    }
    if bundle.endpoint_origin != expected.endpoint_origin {
        return Err(TrustBundleError::EndpointOriginMismatch);
    }
    validate_freshness(&bundle, now_unix_seconds)?;

    let scope = TrustScope {
        tenant_id: bundle.tenant_id.clone(),
        repository_id: bundle.repository_id.clone(),
        generation_id: bundle.generation_id.clone(),
        endpoint_origin: bundle.endpoint_origin.clone(),
    };
    let active_bindings = bundle
        .active_producer_keys
        .iter()
        .map(|binding| {
            (
                binding.key_id.clone(),
                (binding.producer_id.clone(), binding.public_key),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let revoked_key_ids = bundle
        .revoked_key_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let revoked_record_ids = bundle
        .revoked_record_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    if let Some(previous) = tracker.accepted.get(&scope) {
        if bundle.epoch < previous.epoch {
            return Err(TrustBundleError::EpochRollback);
        }
        if bundle.epoch == previous.epoch {
            if canonical_digest != previous.canonical_signing_digest {
                return Err(TrustBundleError::DivergentEpoch);
            }
        } else {
            for (key_id, binding) in &active_bindings {
                if previous
                    .historical_key_bindings
                    .get(key_id)
                    .is_some_and(|historical| historical != binding)
                {
                    return Err(TrustBundleError::KeyRebinding);
                }
                if previous.revoked_key_ids.contains(key_id) {
                    return Err(TrustBundleError::KeyRevocationRollback);
                }
            }
            if !previous.revoked_key_ids.is_subset(&revoked_key_ids) {
                return Err(TrustBundleError::KeyRevocationRollback);
            }
            if !previous.revoked_record_ids.is_subset(&revoked_record_ids) {
                return Err(TrustBundleError::RecordRevocationRollback);
            }
        }
    }

    let mut producer_verifier = Ed25519Verifier::new();
    let mut trusted_producer_keys = BTreeMap::new();
    for binding in &bundle.active_producer_keys {
        producer_verifier
            .insert_public_key(&binding.key_id, &binding.producer_id, &binding.public_key)
            .map_err(|_| TrustBundleError::InvalidProducerPublicKey)?;
        trusted_producer_keys.insert(binding.key_id.clone(), binding.producer_id.clone());
    }

    let mut historical_key_bindings = tracker
        .accepted
        .get(&scope)
        .map_or_else(BTreeMap::new, |previous| {
            previous.historical_key_bindings.clone()
        });
    historical_key_bindings.extend(active_bindings);
    tracker.accepted.insert(
        scope,
        AcceptedEpoch {
            epoch: bundle.epoch,
            canonical_signing_digest: canonical_digest,
            historical_key_bindings,
            revoked_key_ids: revoked_key_ids.clone(),
            revoked_record_ids: revoked_record_ids.clone(),
        },
    );

    Ok(VerifiedTrustBundle {
        bundle,
        trusted_producer_keys,
        revoked_key_ids,
        revoked_record_ids,
        producer_verifier,
    })
}

fn validate_checkpoint(
    checkpoint: TrustCheckpointV1,
    expected: ExpectedTrustBundle<'_>,
    pinned_root: &PinnedRootKey,
) -> Result<(TrustScope, AcceptedEpoch), TrustBundleError> {
    if checkpoint.schema_version != TRUST_CHECKPOINT_SCHEMA_VERSION {
        return Err(TrustBundleError::UnknownCheckpointSchemaVersion);
    }
    if checkpoint.namespace != TRUST_CHECKPOINT_NAMESPACE {
        return Err(TrustBundleError::CheckpointNamespaceMismatch);
    }
    validate_identifier(expected.tenant_id, "expected.tenant_id")?;
    validate_identifier(expected.repository_id, "expected.repository_id")?;
    validate_generation_id(expected.generation_id)?;
    validate_endpoint_origin(expected.endpoint_origin)?;
    validate_identifier(&checkpoint.root_key_id, "checkpoint.root_key_id")?;
    validate_identifier(&checkpoint.tenant_id, "checkpoint.tenant_id")?;
    validate_identifier(&checkpoint.repository_id, "checkpoint.repository_id")?;
    validate_generation_id(&checkpoint.generation_id)?;
    validate_endpoint_origin(&checkpoint.endpoint_origin)?;
    VerifyingKey::from_bytes(&checkpoint.root_public_key)
        .map_err(|_| TrustBundleError::InvalidRootPublicKey)?;
    if checkpoint.root_key_id != pinned_root.key_id
        || checkpoint.root_public_key != pinned_root.public_key_bytes()
    {
        return Err(TrustBundleError::CheckpointRootMismatch);
    }
    if checkpoint.tenant_id != expected.tenant_id
        || checkpoint.repository_id != expected.repository_id
        || checkpoint.generation_id != expected.generation_id
        || checkpoint.endpoint_origin != expected.endpoint_origin
    {
        return Err(TrustBundleError::CheckpointScopeMismatch);
    }
    if checkpoint.highest_epoch == 0 {
        return Err(TrustBundleError::InvalidEpoch);
    }
    if checkpoint.highest_epoch > MAX_JSON_SAFE_INTEGER {
        return Err(TrustBundleError::EpochOutOfRange);
    }
    check_count(
        "checkpoint.historical_key_bindings",
        checkpoint.historical_key_bindings.len(),
    )?;
    for binding in &checkpoint.historical_key_bindings {
        validate_identifier(&binding.key_id, "checkpoint.historical_key_bindings.key_id")?;
        validate_identifier(
            &binding.producer_id,
            "checkpoint.historical_key_bindings.producer_id",
        )?;
        VerifyingKey::from_bytes(&binding.public_key)
            .map_err(|_| TrustBundleError::InvalidProducerPublicKey)?;
    }
    if !strictly_sorted_by(&checkpoint.historical_key_bindings, |left, right| {
        left.key_id.as_bytes() < right.key_id.as_bytes()
    }) {
        return Err(TrustBundleError::UnsortedOrDuplicate(
            "checkpoint.historical_key_bindings",
        ));
    }
    validate_identifier_list("checkpoint.revoked_key_ids", &checkpoint.revoked_key_ids)?;
    validate_identifier_list(
        "checkpoint.revoked_record_ids",
        &checkpoint.revoked_record_ids,
    )?;

    let scope = TrustScope {
        tenant_id: checkpoint.tenant_id,
        repository_id: checkpoint.repository_id,
        generation_id: checkpoint.generation_id,
        endpoint_origin: checkpoint.endpoint_origin,
    };
    let historical_key_bindings = checkpoint
        .historical_key_bindings
        .into_iter()
        .map(|binding| (binding.key_id, (binding.producer_id, binding.public_key)))
        .collect();
    let accepted = AcceptedEpoch {
        epoch: checkpoint.highest_epoch,
        canonical_signing_digest: checkpoint.same_epoch_digest,
        historical_key_bindings,
        revoked_key_ids: checkpoint.revoked_key_ids.into_iter().collect(),
        revoked_record_ids: checkpoint.revoked_record_ids.into_iter().collect(),
    };
    Ok((scope, accepted))
}

fn validate_monotonic_state(
    previous: &AcceptedEpoch,
    candidate: &AcceptedEpoch,
) -> Result<(), TrustBundleError> {
    if candidate.epoch < previous.epoch {
        return Err(TrustBundleError::EpochRollback);
    }
    if candidate.epoch == previous.epoch
        && candidate.canonical_signing_digest != previous.canonical_signing_digest
    {
        return Err(TrustBundleError::DivergentEpoch);
    }
    for (key_id, historical) in &previous.historical_key_bindings {
        match candidate.historical_key_bindings.get(key_id) {
            Some(candidate_binding) if candidate_binding == historical => {}
            Some(_) => return Err(TrustBundleError::KeyRebinding),
            None => return Err(TrustBundleError::HistoricalKeyBindingRollback),
        }
    }
    if !previous
        .revoked_key_ids
        .is_subset(&candidate.revoked_key_ids)
    {
        return Err(TrustBundleError::KeyRevocationRollback);
    }
    if !previous
        .revoked_record_ids
        .is_subset(&candidate.revoked_record_ids)
    {
        return Err(TrustBundleError::RecordRevocationRollback);
    }
    Ok(())
}

fn validate_wire_shape(bundle: &TrustBundleV1) -> Result<(), TrustBundleError> {
    if bundle.schema_version != TRUST_BUNDLE_SCHEMA_VERSION {
        return Err(TrustBundleError::UnknownSchemaVersion);
    }
    validate_identifier(&bundle.root_key_id, "root_key_id")?;
    validate_identifier(&bundle.tenant_id, "tenant_id")?;
    validate_identifier(&bundle.repository_id, "repository_id")?;
    validate_generation_id(&bundle.generation_id)?;
    validate_endpoint_origin(&bundle.endpoint_origin)?;
    if bundle.epoch == 0 {
        return Err(TrustBundleError::InvalidEpoch);
    }
    if bundle.epoch > MAX_JSON_SAFE_INTEGER {
        return Err(TrustBundleError::EpochOutOfRange);
    }
    if bundle.issued_at_unix_seconds > MAX_JSON_SAFE_INTEGER
        || bundle.expires_at_unix_seconds > MAX_JSON_SAFE_INTEGER
    {
        return Err(TrustBundleError::TimestampOutOfRange);
    }
    if bundle.expires_at_unix_seconds <= bundle.issued_at_unix_seconds
        || bundle.expires_at_unix_seconds - bundle.issued_at_unix_seconds
            > MAX_TRUST_BUNDLE_LIFETIME_SECONDS
    {
        return Err(TrustBundleError::InvalidLifetime);
    }
    if bundle.signature.len() != ED25519_SIGNATURE_SIZE {
        return Err(TrustBundleError::InvalidSignatureSize);
    }

    check_count("active_producer_keys", bundle.active_producer_keys.len())?;
    for binding in &bundle.active_producer_keys {
        validate_identifier(&binding.key_id, "active_producer_keys.key_id")?;
        validate_identifier(&binding.producer_id, "active_producer_keys.producer_id")?;
        VerifyingKey::from_bytes(&binding.public_key)
            .map_err(|_| TrustBundleError::InvalidProducerPublicKey)?;
    }
    if !strictly_sorted_by(&bundle.active_producer_keys, |left, right| {
        left.key_id.as_bytes() < right.key_id.as_bytes()
    }) {
        return Err(TrustBundleError::UnsortedOrDuplicate(
            "active_producer_keys",
        ));
    }

    validate_identifier_list("revoked_key_ids", &bundle.revoked_key_ids)?;
    validate_identifier_list("revoked_record_ids", &bundle.revoked_record_ids)?;
    validate_digest_list("allowed_policy_digests", &bundle.allowed_policy_digests)?;
    validate_digest_list(
        "allowed_execution_profile_digests",
        &bundle.allowed_execution_profile_digests,
    )?;
    validate_digest_list("allowed_platform_digests", &bundle.allowed_platform_digests)?;
    validate_digest_list("allowed_image_digests", &bundle.allowed_image_digests)?;

    let revoked = bundle
        .revoked_key_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if bundle
        .active_producer_keys
        .iter()
        .any(|binding| revoked.contains(binding.key_id.as_str()))
    {
        return Err(TrustBundleError::ActiveKeyRevoked);
    }
    Ok(())
}

fn validate_freshness(
    bundle: &TrustBundleV1,
    now_unix_seconds: u64,
) -> Result<(), TrustBundleError> {
    if bundle.issued_at_unix_seconds
        > now_unix_seconds.saturating_add(MAX_TRUST_BUNDLE_FUTURE_SKEW_SECONDS)
    {
        return Err(TrustBundleError::IssuedInFuture);
    }
    if now_unix_seconds >= bundle.expires_at_unix_seconds {
        return Err(TrustBundleError::Expired);
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), TrustBundleError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        Err(TrustBundleError::InvalidIdentifier(field))
    } else {
        Ok(())
    }
}

fn validate_generation_id(value: &str) -> Result<(), TrustBundleError> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(TrustBundleError::InvalidGenerationId);
    }
    Ok(())
}

fn validate_endpoint_origin(value: &str) -> Result<(), TrustBundleError> {
    if value.len() > 2_048 || !value.is_ascii() {
        return Err(TrustBundleError::InvalidEndpointOrigin);
    }
    let parsed = reqwest::Url::parse(value).map_err(|_| TrustBundleError::InvalidEndpointOrigin)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != value
    {
        return Err(TrustBundleError::InvalidEndpointOrigin);
    }
    Ok(())
}

fn validate_identifier_list(
    field: &'static str,
    values: &[String],
) -> Result<(), TrustBundleError> {
    check_count(field, values.len())?;
    for value in values {
        validate_identifier(value, field)?;
    }
    if !strictly_sorted_by(values, |left, right| left.as_bytes() < right.as_bytes()) {
        return Err(TrustBundleError::UnsortedOrDuplicate(field));
    }
    Ok(())
}

fn validate_digest_list(field: &'static str, values: &[Digest]) -> Result<(), TrustBundleError> {
    check_count(field, values.len())?;
    if !strictly_sorted_by(values, |left, right| left.as_bytes() < right.as_bytes()) {
        return Err(TrustBundleError::UnsortedOrDuplicate(field));
    }
    Ok(())
}

fn check_count(field: &'static str, count: usize) -> Result<(), TrustBundleError> {
    if count > MAX_TRUST_BUNDLE_ENTRIES_PER_SET {
        Err(TrustBundleError::TooManyEntries(field))
    } else {
        Ok(())
    }
}

fn strictly_sorted_by<T>(values: &[T], less: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less(&pair[0], &pair[1]))
}

fn contains_digest(values: &[Digest], expected: Digest) -> bool {
    values
        .binary_search_by(|candidate| candidate.as_bytes().cmp(expected.as_bytes()))
        .is_ok()
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex(blake3::hash(bytes).to_hex().as_str())
        .expect("BLAKE3 always emits one lower-case 32-byte digest")
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn put_string(output: &mut Vec<u8>, value: &str) {
    put_bytes(output, value.as_bytes());
}

fn put_strings(output: &mut Vec<u8>, values: &[String]) {
    put_count(output, values.len());
    for value in values {
        put_string(output, value);
    }
}

fn put_digests(output: &mut Vec<u8>, values: &[Digest]) {
    put_count(output, values.len());
    for value in values {
        put_bytes(output, value.as_bytes());
    }
}

fn put_count(output: &mut Vec<u8>, count: usize) {
    put_u64(output, count as u64);
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;
    use crate::team::{
        BlobRef, PrivacyClass, PrivacyMetadata, REMOTE_CACHE_SCHEMA_VERSION, RemoteCacheManifest,
        Shareability, verify_candidate,
    };
    use crate::team_crypto::Ed25519Signer;

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TWO: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const THREE: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const FOUR: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const FIVE: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";
    const GENERATION_B: &str = "fedcba9876543210fedcba9876543210";

    fn digest(value: &str) -> Digest {
        Digest::from_hex(value).unwrap()
    }

    fn root_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    fn producer_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn pinned_root() -> PinnedRootKey {
        PinnedRootKey::from_public_key("root-key-1", &root_signing_key().verifying_key().to_bytes())
            .unwrap()
    }

    fn unsigned_fixture() -> TrustBundleV1 {
        TrustBundleV1 {
            schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
            root_key_id: "root-key-1".into(),
            tenant_id: "tenant-a".into(),
            repository_id: "repo-a".into(),
            generation_id: GENERATION.into(),
            endpoint_origin: "https://cache.example.test".into(),
            epoch: 1,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            active_producer_keys: vec![ProducerKeyBindingV1 {
                key_id: "producer-key-1".into(),
                producer_id: "producer-a".into(),
                public_key: producer_signing_key().verifying_key().to_bytes(),
            }],
            revoked_key_ids: vec!["revoked-key-1".into()],
            revoked_record_ids: vec!["revoked-record-1".into()],
            allowed_policy_digests: vec![digest(ONE)],
            allowed_execution_profile_digests: vec![digest(TWO)],
            allowed_platform_digests: vec![digest(THREE)],
            allowed_image_digests: vec![digest(FOUR)],
            signature: Vec::new(),
        }
    }

    fn sign(mut bundle: TrustBundleV1) -> TrustBundleV1 {
        bundle.signature = root_signing_key()
            .sign(&bundle.canonical_signing_bytes())
            .to_bytes()
            .to_vec();
        bundle
    }

    fn resign(bundle: &mut TrustBundleV1) {
        bundle.signature = root_signing_key()
            .sign(&bundle.canonical_signing_bytes())
            .to_bytes()
            .to_vec();
    }

    fn expected() -> ExpectedTrustBundle<'static> {
        ExpectedTrustBundle {
            tenant_id: "tenant-a",
            repository_id: "repo-a",
            generation_id: GENERATION,
            endpoint_origin: "https://cache.example.test",
        }
    }

    fn request() -> TrustBoundRequest {
        TrustBoundRequest {
            request_key: digest(ZERO),
            policy_digest: digest(ONE),
            execution_profile_digest: digest(TWO),
            platform_digest: digest(THREE),
            image_digest: digest(FOUR),
        }
    }

    #[test]
    fn verified_bundle_builds_context_and_real_producer_verifier() {
        let wire = sign(unsigned_fixture());
        let encoded = serde_json::to_vec(&wire).unwrap();
        let decoded: TrustBundleV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, wire);
        assert_eq!(
            decoded.canonical_signing_bytes(),
            wire.canonical_signing_bytes()
        );

        let mut tracker = TrustEpochTracker::new();
        let verified =
            verify_trust_bundle(decoded, expected(), &pinned_root(), 120, &mut tracker).unwrap();
        assert_eq!(verified.epoch(), 1);
        assert_eq!(verified.endpoint_origin(), expected().endpoint_origin);
        assert_eq!(
            tracker.highest_accepted_epoch(
                expected().tenant_id,
                expected().repository_id,
                expected().generation_id,
                expected().endpoint_origin
            ),
            Some(1)
        );
        assert_eq!(
            verified
                .producer_verifier()
                .producer_for_key("producer-key-1"),
            Some("producer-a")
        );

        let context = verified.verification_context(request(), 120).unwrap();
        assert_eq!(context.tenant_id, "tenant-a");
        assert_eq!(context.repository_id, "repo-a");
        assert_eq!(
            context.trusted_producer_keys,
            BTreeMap::from([("producer-key-1".into(), "producer-a".into())])
        );
        assert_eq!(
            context.revoked_key_ids,
            BTreeSet::from(["revoked-key-1".into()])
        );
        assert_eq!(
            context.revoked_record_ids,
            BTreeSet::from(["revoked-record-1".into()])
        );

        let producer =
            Ed25519Signer::from_secret_key("producer-key-1", "producer-a", &[7; 32]).unwrap();
        let mut manifest = RemoteCacheManifest {
            schema_version: REMOTE_CACHE_SCHEMA_VERSION,
            record_id: "record-a".into(),
            tenant_id: "tenant-a".into(),
            repository_id: "repo-a".into(),
            request_key: request().request_key,
            policy_digest: request().policy_digest,
            execution_profile_digest: request().execution_profile_digest,
            platform_digest: request().platform_digest,
            image_digest: request().image_digest,
            stdout: BlobRef {
                digest: digest(FIVE),
                size_bytes: 3,
            },
            stderr: BlobRef {
                digest: digest(ZERO),
                size_bytes: 0,
            },
            producer_id: "producer-a".into(),
            created_at_unix_seconds: 110,
            expires_at_unix_seconds: 180,
            privacy: PrivacyMetadata {
                classification: PrivacyClass::Internal,
                shareability: Shareability::Repository,
                secret_tainted: false,
            },
            signature: None,
        };
        producer.sign_manifest(&mut manifest).unwrap();
        assert!(
            verify_candidate(&manifest, &context, verified.producer_verifier()).is_ok(),
            "the capability-derived context and keyring must verify a real manifest"
        );
    }

    #[test]
    fn generation_a_trust_and_checkpoint_cannot_authorize_recreated_generation_b() {
        let bundle_a = sign(unsigned_fixture());
        let expected_b = ExpectedTrustBundle {
            generation_id: GENERATION_B,
            ..expected()
        };
        assert_eq!(
            verify_trust_bundle(
                bundle_a.clone(),
                expected_b,
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new(),
            )
            .unwrap_err(),
            TrustBundleError::GenerationMismatch,
        );

        let root = pinned_root();
        let mut tracker = TrustEpochTracker::new();
        verify_trust_bundle(bundle_a, expected(), &root, 120, &mut tracker).unwrap();
        let checkpoint_a = tracker
            .export_checkpoint(expected(), &root)
            .unwrap()
            .unwrap();
        assert_eq!(
            TrustEpochTracker::new()
                .restore_checkpoint(checkpoint_a, expected_b, &root)
                .unwrap_err(),
            TrustBundleError::CheckpointScopeMismatch,
        );
    }

    #[test]
    fn retained_cross_language_trust_canonical_vector_matches_rust() {
        let producer_public_key =
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let mut public_key = [0u8; 32];
        for (index, byte) in public_key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&producer_public_key[index * 2..index * 2 + 2], 16).unwrap();
        }
        let vector = TrustBundleV1 {
            schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
            root_key_id: "root-vector-1".into(),
            tenant_id: "tenant-vector".into(),
            repository_id: "repo-vector".into(),
            generation_id: GENERATION.into(),
            endpoint_origin: "https://cache.vector.invalid".into(),
            epoch: 42,
            issued_at_unix_seconds: 1_700_000_000,
            expires_at_unix_seconds: 1_700_000_300,
            active_producer_keys: vec![ProducerKeyBindingV1 {
                key_id: "key-vector-1".into(),
                producer_id: "producer-vector".into(),
                public_key,
            }],
            revoked_key_ids: vec!["key-old".into()],
            revoked_record_ids: vec!["record-old".into()],
            allowed_policy_digests: vec![digest(&"11".repeat(32))],
            allowed_execution_profile_digests: vec![digest(&"22".repeat(32))],
            allowed_platform_digests: vec![digest(&"33".repeat(32))],
            allowed_image_digests: vec![digest(&"44".repeat(32))],
            signature: vec![0; ED25519_SIGNATURE_SIZE],
        };
        let actual = vector
            .canonical_signing_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let retained: serde_json::Value = serde_json::from_str(include_str!(
            "../service/test/fixtures/trust-v1-canonical-rust.json"
        ))
        .unwrap();
        assert_eq!(actual, retained["canonical_hex"].as_str().unwrap());
    }

    #[test]
    fn signed_field_tampering_fails_root_verification() {
        for mutation in 0..5 {
            let mut bundle = sign(unsigned_fixture());
            match mutation {
                0 => bundle.epoch += 1,
                1 => bundle.endpoint_origin = "https://other.example.test".into(),
                2 => bundle.allowed_policy_digests[0] = digest(FIVE),
                3 => {
                    bundle.active_producer_keys[0].public_key =
                        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
                }
                4 => bundle.revoked_record_ids.push("revoked-record-2".into()),
                _ => unreachable!(),
            }
            assert_eq!(
                verify_trust_bundle(
                    bundle,
                    expected(),
                    &pinned_root(),
                    120,
                    &mut TrustEpochTracker::new()
                )
                .unwrap_err(),
                TrustBundleError::InvalidSignature,
                "mutation {mutation} must invalidate the signature"
            );
        }
    }

    #[test]
    fn valid_cross_namespace_and_origin_bundles_are_rejected() {
        for mutation in 0..3 {
            let mut bundle = unsigned_fixture();
            match mutation {
                0 => bundle.tenant_id = "tenant-b".into(),
                1 => bundle.repository_id = "repo-b".into(),
                2 => bundle.endpoint_origin = "https://other.example.test".into(),
                _ => unreachable!(),
            }
            let expected_error = match mutation {
                0 => TrustBundleError::TenantMismatch,
                1 => TrustBundleError::RepositoryMismatch,
                2 => TrustBundleError::EndpointOriginMismatch,
                _ => unreachable!(),
            };
            assert_eq!(
                verify_trust_bundle(
                    sign(bundle),
                    expected(),
                    &pinned_root(),
                    120,
                    &mut TrustEpochTracker::new()
                )
                .unwrap_err(),
                expected_error
            );
        }
    }

    #[test]
    fn lifecycle_and_short_lifetime_are_enforced_and_rechecked() {
        let mut expired = unsigned_fixture();
        expired.expires_at_unix_seconds = 120;
        assert_eq!(
            verify_trust_bundle(
                sign(expired),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::Expired
        );

        let mut future = unsigned_fixture();
        future.issued_at_unix_seconds = 151;
        future.expires_at_unix_seconds = 200;
        assert_eq!(
            verify_trust_bundle(
                sign(future),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::IssuedInFuture
        );

        let mut edge_of_skew = unsigned_fixture();
        edge_of_skew.issued_at_unix_seconds = 150;
        assert!(
            verify_trust_bundle(
                sign(edge_of_skew),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .is_ok()
        );

        let mut long_lived = unsigned_fixture();
        long_lived.expires_at_unix_seconds =
            long_lived.issued_at_unix_seconds + MAX_TRUST_BUNDLE_LIFETIME_SECONDS + 1;
        assert_eq!(
            verify_trust_bundle(
                sign(long_lived),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::InvalidLifetime
        );

        let mut tracker = TrustEpochTracker::new();
        let verified = verify_trust_bundle(
            sign(unsigned_fixture()),
            expected(),
            &pinned_root(),
            120,
            &mut tracker,
        )
        .unwrap();
        assert_eq!(
            verified.verification_context(request(), 200).unwrap_err(),
            TrustBundleError::Expired
        );
    }

    #[test]
    fn rollback_equivocation_and_key_rebinding_are_rejected() {
        let mut first = unsigned_fixture();
        first.epoch = 10;
        let first = sign(first);
        let idempotent = first.clone();
        let mut tracker = TrustEpochTracker::new();
        verify_trust_bundle(first, expected(), &pinned_root(), 120, &mut tracker).unwrap();
        assert!(
            verify_trust_bundle(idempotent, expected(), &pinned_root(), 120, &mut tracker).is_ok()
        );

        let mut lower = unsigned_fixture();
        lower.epoch = 9;
        assert_eq!(
            verify_trust_bundle(sign(lower), expected(), &pinned_root(), 120, &mut tracker)
                .unwrap_err(),
            TrustBundleError::EpochRollback
        );

        let mut divergent = unsigned_fixture();
        divergent.epoch = 10;
        divergent.allowed_policy_digests = vec![digest(FIVE)];
        assert_eq!(
            verify_trust_bundle(
                sign(divergent),
                expected(),
                &pinned_root(),
                120,
                &mut tracker
            )
            .unwrap_err(),
            TrustBundleError::DivergentEpoch
        );

        let mut rebound = unsigned_fixture();
        rebound.epoch = 11;
        rebound.active_producer_keys[0].producer_id = "producer-b".into();
        rebound.active_producer_keys[0].public_key =
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_trust_bundle(sign(rebound), expected(), &pinned_root(), 120, &mut tracker)
                .unwrap_err(),
            TrustBundleError::KeyRebinding
        );
        assert_eq!(
            tracker.highest_accepted_epoch(
                expected().tenant_id,
                expected().repository_id,
                expected().generation_id,
                expected().endpoint_origin
            ),
            Some(10),
            "failed acceptance must not advance the tracker"
        );
    }

    #[test]
    fn checkpoint_roundtrip_preserves_epoch_key_history_and_revocations() {
        let root = pinned_root();
        let mut tracker = TrustEpochTracker::new();
        verify_trust_bundle(
            sign(unsigned_fixture()),
            expected(),
            &root,
            120,
            &mut tracker,
        )
        .unwrap();

        let mut second = unsigned_fixture();
        second.epoch = 2;
        second.active_producer_keys.clear();
        second.revoked_key_ids = vec!["producer-key-1".into(), "revoked-key-1".into()];
        verify_trust_bundle(sign(second), expected(), &root, 120, &mut tracker).unwrap();

        let checkpoint = tracker
            .export_checkpoint(expected(), &root)
            .unwrap()
            .unwrap();
        let encoded = serde_json::to_vec(&checkpoint).unwrap();
        let decoded: TrustCheckpointV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, checkpoint);
        assert_eq!(checkpoint.highest_epoch, 2);
        assert_eq!(checkpoint.historical_key_bindings.len(), 1);
        assert_eq!(
            checkpoint.revoked_key_ids,
            vec!["producer-key-1", "revoked-key-1"]
        );

        let mut restored = TrustEpochTracker::new();
        restored
            .restore_checkpoint(checkpoint.clone(), expected(), &root)
            .unwrap();
        assert_eq!(
            restored.highest_accepted_epoch(
                expected().tenant_id,
                expected().repository_id,
                expected().generation_id,
                expected().endpoint_origin
            ),
            Some(2)
        );

        let mut rebind = unsigned_fixture();
        rebind.epoch = 3;
        rebind.active_producer_keys[0].producer_id = "producer-b".into();
        rebind.active_producer_keys[0].public_key =
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_trust_bundle(sign(rebind), expected(), &root, 120, &mut restored).unwrap_err(),
            TrustBundleError::KeyRebinding
        );

        let mut revocation_rollback = unsigned_fixture();
        revocation_rollback.epoch = 3;
        revocation_rollback.active_producer_keys.clear();
        assert_eq!(
            verify_trust_bundle(
                sign(revocation_rollback),
                expected(),
                &root,
                120,
                &mut restored
            )
            .unwrap_err(),
            TrustBundleError::KeyRevocationRollback
        );

        let mut omitted_history = checkpoint.clone();
        omitted_history.highest_epoch = 3;
        omitted_history.historical_key_bindings.clear();
        assert_eq!(
            restored
                .restore_checkpoint(omitted_history, expected(), &root)
                .unwrap_err(),
            TrustBundleError::HistoricalKeyBindingRollback
        );

        let mut divergent = checkpoint;
        divergent.same_epoch_digest = digest(FIVE);
        assert_eq!(
            restored
                .restore_checkpoint(divergent, expected(), &root)
                .unwrap_err(),
            TrustBundleError::DivergentEpoch
        );
    }

    #[test]
    fn revocations_cannot_be_removed_or_reactivated() {
        let mut tracker = TrustEpochTracker::new();
        let mut first = unsigned_fixture();
        first.epoch = 20;
        first.revoked_key_ids = vec!["old-key".into(), "revoked-key-1".into()];
        first.revoked_record_ids = vec!["old-record".into(), "revoked-record-1".into()];
        verify_trust_bundle(sign(first), expected(), &pinned_root(), 120, &mut tracker).unwrap();

        let mut key_omitted = unsigned_fixture();
        key_omitted.epoch = 21;
        assert_eq!(
            verify_trust_bundle(
                sign(key_omitted),
                expected(),
                &pinned_root(),
                120,
                &mut tracker
            )
            .unwrap_err(),
            TrustBundleError::KeyRevocationRollback
        );

        let mut record_omitted = unsigned_fixture();
        record_omitted.epoch = 21;
        record_omitted.revoked_key_ids = vec!["old-key".into(), "revoked-key-1".into()];
        assert_eq!(
            verify_trust_bundle(
                sign(record_omitted),
                expected(),
                &pinned_root(),
                120,
                &mut tracker
            )
            .unwrap_err(),
            TrustBundleError::RecordRevocationRollback
        );

        let mut reactivated = unsigned_fixture();
        reactivated.epoch = 21;
        reactivated.active_producer_keys.insert(
            0,
            ProducerKeyBindingV1 {
                key_id: "old-key".into(),
                producer_id: "old-producer".into(),
                public_key: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
            },
        );
        reactivated.revoked_key_ids = vec!["revoked-key-1".into()];
        reactivated.revoked_record_ids = vec!["old-record".into(), "revoked-record-1".into()];
        assert_eq!(
            verify_trust_bundle(
                sign(reactivated),
                expected(),
                &pinned_root(),
                120,
                &mut tracker
            )
            .unwrap_err(),
            TrustBundleError::KeyRevocationRollback
        );
    }

    #[test]
    fn ordering_duplicates_active_revocation_and_origin_fail_closed() {
        let mut duplicate_key = unsigned_fixture();
        duplicate_key
            .active_producer_keys
            .push(duplicate_key.active_producer_keys[0].clone());
        assert_eq!(
            verify_trust_bundle(
                sign(duplicate_key),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::UnsortedOrDuplicate("active_producer_keys")
        );

        let mut unsorted_revocations = unsigned_fixture();
        unsorted_revocations.revoked_record_ids = vec!["z-record".into(), "a-record".into()];
        assert_eq!(
            verify_trust_bundle(
                sign(unsorted_revocations),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::UnsortedOrDuplicate("revoked_record_ids")
        );

        let mut duplicate_digest = unsigned_fixture();
        duplicate_digest.allowed_policy_digests.push(digest(ONE));
        assert_eq!(
            verify_trust_bundle(
                sign(duplicate_digest),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::UnsortedOrDuplicate("allowed_policy_digests")
        );

        let mut active_and_revoked = unsigned_fixture();
        active_and_revoked.revoked_key_ids = vec!["producer-key-1".into(), "revoked-key-1".into()];
        assert_eq!(
            verify_trust_bundle(
                sign(active_and_revoked),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::ActiveKeyRevoked
        );

        for invalid in [
            "http://cache.example.test",
            "https://cache.example.test/",
            "https://cache.example.test/path",
            "https://user@cache.example.test",
            "https://CACHE.example.test",
            "https://cache.example.test:443",
        ] {
            let mut bundle = unsigned_fixture();
            bundle.endpoint_origin = invalid.into();
            assert_eq!(
                verify_trust_bundle(
                    sign(bundle),
                    ExpectedTrustBundle {
                        endpoint_origin: invalid,
                        ..expected()
                    },
                    &pinned_root(),
                    120,
                    &mut TrustEpochTracker::new()
                )
                .unwrap_err(),
                TrustBundleError::InvalidEndpointOrigin,
                "invalid origin {invalid}"
            );
        }
    }

    #[test]
    fn root_identity_signature_and_wire_schema_are_strict() {
        let bundle = sign(unsigned_fixture());
        let wrong_id = PinnedRootKey::from_public_key(
            "root-key-2",
            &root_signing_key().verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_trust_bundle(
                bundle.clone(),
                expected(),
                &wrong_id,
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::RootKeyMismatch
        );

        let wrong_key = PinnedRootKey::from_public_key(
            "root-key-1",
            &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_trust_bundle(
                bundle.clone(),
                expected(),
                &wrong_key,
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::InvalidSignature
        );

        let mut short_signature = bundle.clone();
        short_signature.signature.pop();
        assert_eq!(
            verify_trust_bundle(
                short_signature,
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::InvalidSignatureSize
        );
        assert_eq!(
            PinnedRootKey::from_public_key("root-key-1", &[0; 31]).unwrap_err(),
            TrustBundleError::InvalidRootPublicKey
        );

        let mut unknown_top_level = serde_json::to_value(&bundle).unwrap();
        unknown_top_level["unexpected"] = json!(true);
        assert!(serde_json::from_value::<TrustBundleV1>(unknown_top_level).is_err());

        let mut unknown_binding = serde_json::to_value(&bundle).unwrap();
        unknown_binding["active_producer_keys"][0]["unexpected"] = json!(true);
        assert!(serde_json::from_value::<TrustBundleV1>(unknown_binding).is_err());
    }

    #[test]
    fn request_allowlists_and_capability_freshness_are_mandatory() {
        let mut tracker = TrustEpochTracker::new();
        let verified = verify_trust_bundle(
            sign(unsigned_fixture()),
            expected(),
            &pinned_root(),
            120,
            &mut tracker,
        )
        .unwrap();

        for mutation in 0..4 {
            let mut denied = request();
            match mutation {
                0 => denied.policy_digest = digest(FIVE),
                1 => denied.execution_profile_digest = digest(FIVE),
                2 => denied.platform_digest = digest(FIVE),
                3 => denied.image_digest = digest(FIVE),
                _ => unreachable!(),
            }
            let expected_error = match mutation {
                0 => TrustBundleError::PolicyDigestNotAllowed,
                1 => TrustBundleError::ExecutionProfileDigestNotAllowed,
                2 => TrustBundleError::PlatformDigestNotAllowed,
                3 => TrustBundleError::ImageDigestNotAllowed,
                _ => unreachable!(),
            };
            assert_eq!(
                verified.verification_context(denied, 120).unwrap_err(),
                expected_error
            );
        }
    }

    #[test]
    fn malformed_json_corpus_never_panics() {
        let static_cases: &[&[u8]] = &[
            b"",
            b"null",
            b"[]",
            b"{}",
            b"{",
            b"{\"schema_version\":1}",
            b"{\"signature\":[0,1,2]}",
            b"[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]",
            &[0xff, 0xfe, 0xfd],
        ];
        for input in static_cases {
            assert!(
                catch_unwind(AssertUnwindSafe(|| exercise_json(input))).is_ok(),
                "static malformed input panicked"
            );
        }

        for length in 0..512 {
            let input = (0..length)
                .map(|index| ((index * 73 + length * 29) & 0xff) as u8)
                .collect::<Vec<_>>();
            assert!(
                catch_unwind(AssertUnwindSafe(|| exercise_json(&input))).is_ok(),
                "generated malformed input of length {length} panicked"
            );
        }
    }

    fn exercise_json(input: &[u8]) {
        if let Ok(bundle) = serde_json::from_slice::<TrustBundleV1>(input) {
            let _ = verify_trust_bundle(
                bundle,
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new(),
            );
        }
    }

    #[test]
    fn excessive_collections_and_invalid_epoch_are_rejected() {
        let mut excessive = unsigned_fixture();
        excessive.revoked_record_ids = (0..=MAX_TRUST_BUNDLE_ENTRIES_PER_SET)
            .map(|index| format!("record-{index:05}"))
            .collect();
        assert_eq!(
            verify_trust_bundle(
                sign(excessive),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::TooManyEntries("revoked_record_ids")
        );

        let mut zero_epoch = unsigned_fixture();
        zero_epoch.epoch = 0;
        assert_eq!(
            verify_trust_bundle(
                sign(zero_epoch),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::InvalidEpoch
        );

        let mut huge_epoch = unsigned_fixture();
        huge_epoch.epoch = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            verify_trust_bundle(
                sign(huge_epoch),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::EpochOutOfRange
        );

        let mut huge_timestamp = unsigned_fixture();
        huge_timestamp.expires_at_unix_seconds = MAX_JSON_SAFE_INTEGER + 1;
        assert_eq!(
            verify_trust_bundle(
                sign(huge_timestamp),
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::TimestampOutOfRange
        );
    }

    #[test]
    fn same_key_id_duplicate_is_rejected_even_when_material_differs() {
        let mut duplicate = unsigned_fixture();
        duplicate.active_producer_keys.push(ProducerKeyBindingV1 {
            key_id: "producer-key-1".into(),
            producer_id: "producer-b".into(),
            public_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        });
        resign(&mut duplicate);
        assert_eq!(
            verify_trust_bundle(
                duplicate,
                expected(),
                &pinned_root(),
                120,
                &mut TrustEpochTracker::new()
            )
            .unwrap_err(),
            TrustBundleError::UnsortedOrDuplicate("active_producer_keys")
        );
    }
}
