//! Encrypted, proof-carrying manifest v2 for the repository-scoped team cache.
//!
//! The explicit team-alpha CLI wires this module to the sealed pull and
//! publication orchestrators. Publication requires three unforgeable local
//! capabilities: a portable [`TeamRequestKeyV1`] and one sealed
//! [`AdmittedLocalPublicationV2`] that owns both a two-execution result and the
//! privacy decision evaluated over those exact captured bytes. Remote bytes
//! are XChaCha20-Poly1305 ciphertext plus tag; neither plaintext nor
//! repository-key material appears in the wire manifest.

#![allow(
    dead_code,
    reason = "some sealed protocol helpers are exercised only by the orchestrators and adversarial tests"
)]

use std::fmt;

use chacha20poly1305::aead::array::Array;
use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::privacy::{
    CapturedExecution, CapturedExit, CapturedStdin, CapturedStream, LocalOnlyReason,
    PublishableResult, RepositorySharingPolicy,
};
use crate::team::{
    Digest, ED25519_SIGNATURE_SIZE, MAX_BLOB_SIZE, MAX_JSON_SAFE_INTEGER,
    MAX_MANIFEST_LIFETIME_SECONDS, PrivacyClass, PrivacyMetadata,
    SIGNATURE_ENVELOPE_SCHEMA_VERSION, Shareability, SignatureAlgorithm, SignatureVerifier,
};
use crate::team_crypto::Ed25519Signer;
use crate::team_request_key::TeamRequestKeyV1;
use crate::trust_bundle::{TrustBoundRequest, TrustBundleError, VerifiedTrustBundle};

mod immutable_capture;

#[allow(
    unused_imports,
    reason = "the private re-export keeps the capture capability inside the sealed protocol boundary"
)]
pub(crate) use immutable_capture::{
    CompleteImmutableExecutionV1, ImmutableCaptureError, ImmutableCaptureFailureV1,
    ImmutableCaptureInputV1, ImmutableExecutionProfileV1, capture_immutable_team_attempt_v1,
    capture_immutable_team_result_v1,
};

pub const ENCRYPTED_MANIFEST_SCHEMA_VERSION: u16 = 2;
pub const LOCAL_RESULT_PROOF_SCHEMA_VERSION: u16 = 1;
pub const REPOSITORY_ENCRYPTION_KEY_BYTES: usize = 32;
pub const XCHACHA20_NONCE_BYTES: usize = 24;
pub const POLY1305_TAG_BYTES: u64 = 16;
pub const MAX_V2_CIPHERTEXT_STREAM_BYTES: u64 = MAX_BLOB_SIZE;
pub const MAX_V2_PLAINTEXT_STREAM_BYTES: u64 = MAX_V2_CIPHERTEXT_STREAM_BYTES - POLY1305_TAG_BYTES;

const SIGNING_DOMAIN: &[u8] = b"again.remote-cache.encrypted-manifest.v2";
const STREAM_AAD_DOMAIN: &[u8] = b"again.remote-cache.encrypted-stream-aad.v2";
const LOCAL_PROOF_DOMAIN: &[u8] = b"again.local-two-execution-proof.v1";
const PRODUCER_AUTHORIZATION_DOMAIN: &[u8] = b"again.team-producer-authorization.v1";

/// A repository encryption key retained in zeroizing storage.
///
/// This value is intentionally non-`Clone`, non-serializable, and redacted in
/// `Debug`. Callers should move the only key copy they need into this wrapper
/// and provision it independently of manifests and ciphertext objects.
pub struct RepositoryEncryptionKeyV1 {
    key_id: String,
    key_bytes: Zeroizing<[u8; REPOSITORY_ENCRYPTION_KEY_BYTES]>,
}

impl RepositoryEncryptionKeyV1 {
    pub fn from_bytes(
        key_id: impl Into<String>,
        key_bytes: [u8; REPOSITORY_ENCRYPTION_KEY_BYTES],
    ) -> Result<Self, ManifestV2Error> {
        let key_id = key_id.into();
        validate_identifier(&key_id)
            .map_err(|_| ManifestV2Error::InvalidIdentifier("repository_encryption_key_id"))?;
        Ok(Self {
            key_id,
            key_bytes: Zeroizing::new(key_bytes),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl fmt::Debug for RepositoryEncryptionKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositoryEncryptionKeyV1")
            .field("key_id", &self.key_id)
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatusV2 {
    Success,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedStreamLabelV2 {
    Stdout,
    Stderr,
}

/// Content address, exact R2 object length, and XChaCha20 nonce for one stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EncryptedStreamRefV2 {
    pub ciphertext_digest: Digest,
    pub ciphertext_size_bytes: u64,
    pub nonce: [u8; XCHACHA20_NONCE_BYTES],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ManifestSignatureV2 {
    pub schema_version: u16,
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub signature: Vec<u8>,
}

/// Strict encrypted manifest v2 wire format.
///
/// The two R2 objects named by `stdout` and `stderr` contain ciphertext plus
/// the 16-byte Poly1305 tag only. Plaintext is never embedded here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EncryptedRemoteCacheManifestV2 {
    pub schema_version: u16,
    pub record_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub generation_id: String,
    pub request_key: Digest,
    pub policy_digest: Digest,
    pub classifier_digest: Digest,
    pub execution_profile_digest: Digest,
    pub platform_digest: Digest,
    pub image_digest: Digest,
    pub result_status: ResultStatusV2,
    pub duration_micros: u64,
    pub proof_schema_version: u16,
    pub producer_version: String,
    pub local_proof_digest: Digest,
    pub privacy: PrivacyMetadata,
    pub repository_encryption_key_id: String,
    pub stdout: EncryptedStreamRefV2,
    pub stderr: EncryptedStreamRefV2,
    pub producer_id: String,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub signature: ManifestSignatureV2,
}

impl EncryptedRemoteCacheManifestV2 {
    /// Exact deterministic bytes authenticated by the producer signature.
    /// JSON order and formatting are never protocol inputs.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_024);
        put_bytes(&mut output, SIGNING_DOMAIN);
        put_manifest_semantics(&mut output, self, true);
        output
    }

    /// AAD authenticated independently for each encrypted stream.
    ///
    /// Both stream sizes/nonces and every non-ciphertext-derived manifest
    /// field are included. Ciphertext digests are necessarily produced after
    /// encryption and are instead covered by the Ed25519 signature.
    fn stream_aad(&self, stream: EncryptedStreamLabelV2) -> Vec<u8> {
        let mut output = Vec::with_capacity(1_024);
        put_bytes(&mut output, STREAM_AAD_DOMAIN);
        put_manifest_semantics(&mut output, self, false);
        put_u8(&mut output, stream_label_tag(stream));
        output
    }

    fn validate_wire(&self) -> Result<(), ManifestV2Error> {
        if self.schema_version != ENCRYPTED_MANIFEST_SCHEMA_VERSION {
            return Err(ManifestV2Error::UnknownSchemaVersion);
        }
        for (value, field) in [
            (&self.record_id, "record_id"),
            (&self.tenant_id, "tenant_id"),
            (&self.repository_id, "repository_id"),
            (&self.producer_version, "producer_version"),
            (
                &self.repository_encryption_key_id,
                "repository_encryption_key_id",
            ),
            (&self.producer_id, "producer_id"),
            (&self.signature.key_id, "signature.key_id"),
        ] {
            validate_identifier(value).map_err(|_| ManifestV2Error::InvalidIdentifier(field))?;
        }
        validate_generation_id(&self.generation_id)?;
        if self.proof_schema_version != LOCAL_RESULT_PROOF_SCHEMA_VERSION {
            return Err(ManifestV2Error::UnknownProofSchemaVersion);
        }
        if self.signature.schema_version != SIGNATURE_ENVELOPE_SCHEMA_VERSION {
            return Err(ManifestV2Error::UnknownSignatureSchemaVersion);
        }
        if self.signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(ManifestV2Error::UnsupportedSignatureAlgorithm);
        }
        if self.signature.signature.len() != ED25519_SIGNATURE_SIZE {
            return Err(ManifestV2Error::InvalidSignatureSize);
        }
        if self.duration_micros > MAX_JSON_SAFE_INTEGER
            || self.created_at_unix_seconds > MAX_JSON_SAFE_INTEGER
            || self.expires_at_unix_seconds > MAX_JSON_SAFE_INTEGER
        {
            return Err(ManifestV2Error::IntegerOutOfRange);
        }
        if self.expires_at_unix_seconds <= self.created_at_unix_seconds
            || self.expires_at_unix_seconds - self.created_at_unix_seconds
                > MAX_MANIFEST_LIFETIME_SECONDS
        {
            return Err(ManifestV2Error::InvalidLifetime);
        }
        validate_privacy(&self.privacy)?;
        validate_stream_ref(&self.stdout, EncryptedStreamLabelV2::Stdout)?;
        validate_stream_ref(&self.stderr, EncryptedStreamLabelV2::Stderr)?;
        if self.stderr.ciphertext_size_bytes != POLY1305_TAG_BYTES {
            return Err(ManifestV2Error::NonEmptyEncryptedStderr);
        }
        if self.stdout.nonce == self.stderr.nonce {
            return Err(ManifestV2Error::NonceReuse);
        }
        Ok(())
    }
}

fn validate_privacy(privacy: &PrivacyMetadata) -> Result<(), ManifestV2Error> {
    if privacy.shareability == Shareability::LocalOnly {
        return Err(ManifestV2Error::Unshareable);
    }
    if privacy.secret_tainted || privacy.classification == PrivacyClass::Secret {
        return Err(ManifestV2Error::SecretTainted);
    }
    Ok(())
}

fn validate_stream_ref(
    stream: &EncryptedStreamRefV2,
    label: EncryptedStreamLabelV2,
) -> Result<(), ManifestV2Error> {
    if stream.ciphertext_size_bytes < POLY1305_TAG_BYTES
        || stream.ciphertext_size_bytes > MAX_V2_CIPHERTEXT_STREAM_BYTES
    {
        return Err(ManifestV2Error::InvalidCiphertextSize { stream: label });
    }
    Ok(())
}

/// Raw facts asserted by the future reviewed capture boundary for one complete
/// execution. The fields are private; only this module can turn two such facts
/// into a reusable result capability.
pub(crate) struct CompleteLocalExecutionV1<'a> {
    exit_code: Option<i32>,
    stdout: &'a [u8],
    stderr: &'a [u8],
    duration_micros: u64,
}

impl<'a> CompleteLocalExecutionV1<'a> {
    /// The future capture adapter must call this only after both pipes reached
    /// EOF and the child was reaped. This constructor is crate-private and is
    /// not exposed by the public library API.
    pub(crate) fn from_complete_capture(
        exit_code: Option<i32>,
        stdout: &'a [u8],
        stderr: &'a [u8],
        duration_micros: u64,
    ) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
            duration_micros,
        }
    }
}

/// Unforgeable evidence that exactly two complete executions had identical
/// successful, bounded results. It is crate-private, non-serializable, and
/// redacts captured bytes from `Debug`.
pub(crate) struct ValidatedLocalResultV1 {
    request_key: Digest,
    stdout: Vec<u8>,
    duration_micros: u64,
    proof_schema_version: u16,
    producer_version: String,
    local_proof_digest: Digest,
}

/// One unforgeable producer-side publication admission.
///
/// This object deliberately owns the validated capture. Its only constructor
/// evaluates the privacy classifier against the stdout/stderr retained in
/// that exact capture. The manifest builder never accepts a separate privacy
/// decision or a separate result, so a caller cannot scan benign bytes and
/// encrypt different bytes.
pub(crate) struct AdmittedLocalPublicationV2 {
    result: ValidatedLocalResultV1,
    privacy: PrivacyMetadata,
    classifier_digest: Digest,
    policy_digest: Digest,
}

/// Failed privacy admission that preserves the exact validated local result
/// for one-shot presentation. It cannot be passed to the manifest builder.
pub(crate) struct RejectedLocalPublicationV2 {
    reason: LocalOnlyReason,
    result: ValidatedLocalResultV1,
}

impl RejectedLocalPublicationV2 {
    pub(crate) fn reason(&self) -> LocalOnlyReason {
        self.reason
    }

    pub(crate) fn into_result(self) -> ValidatedLocalResultV1 {
        self.result
    }
}

impl fmt::Debug for RejectedLocalPublicationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedLocalPublicationV2")
            .field("reason", &self.reason)
            .field("result", &self.result)
            .finish()
    }
}

impl fmt::Debug for AdmittedLocalPublicationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedLocalPublicationV2")
            .field("result", &self.result)
            .field("privacy", &self.privacy)
            .field("classifier_digest", &self.classifier_digest)
            .field("policy_digest", &self.policy_digest)
            .finish()
    }
}

impl AdmittedLocalPublicationV2 {
    /// Exact stdout from the same validated capture that passed privacy
    /// admission. This is crate-private so the future command presenter can
    /// avoid a third execution without exposing a raw construction API.
    pub(crate) fn exact_stdout(&self) -> &[u8] {
        &self.result.stdout
    }

    pub(crate) fn duration_micros(&self) -> u64 {
        self.result.duration_micros
    }
}

/// Bind privacy admission to the exact bytes retained by a genuine
/// two-execution capture capability.
pub(crate) fn admit_validated_local_publication_v2(
    policy: &RepositorySharingPolicy,
    request: &TeamRequestKeyV1,
    result: ValidatedLocalResultV1,
) -> Result<AdmittedLocalPublicationV2, Box<RejectedLocalPublicationV2>> {
    // A request mismatch is rejected before classification. The only
    // successful path evaluates the retained stdout and the validator-proven
    // empty stderr directly; no caller-provided byte slice participates.
    if result.request_key != request.digest() {
        return Err(Box::new(RejectedLocalPublicationV2 {
            reason: LocalOnlyReason::RequestDigestMismatch,
            result,
        }));
    }
    let publishable = match PublishableResult::evaluate(
        policy,
        request,
        CapturedExecution::new(
            CapturedStdin::Closed,
            CapturedStream::CompletePipe(&result.stdout),
            CapturedStream::CompletePipe(b""),
            CapturedExit::Code(0),
        ),
    ) {
        Ok(publishable) => publishable,
        Err(reason) => return Err(Box::new(RejectedLocalPublicationV2 { reason, result })),
    };
    Ok(AdmittedLocalPublicationV2 {
        privacy: publishable.privacy().clone(),
        classifier_digest: publishable.classifier_digest(),
        policy_digest: publishable.policy_digest(),
        result,
    })
}

impl fmt::Debug for ValidatedLocalResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedLocalResultV1")
            .field("request_key", &self.request_key)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &0usize)
            .field("duration_micros", &self.duration_micros)
            .field("proof_schema_version", &self.proof_schema_version)
            .field("producer_version", &self.producer_version)
            .field("local_proof_digest", &self.local_proof_digest)
            .finish()
    }
}

impl ValidatedLocalResultV1 {
    pub(crate) fn exact_stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub(crate) fn duration_micros(&self) -> u64 {
        self.duration_micros
    }
}

/// Validate exactly two complete local executions and mint the only result
/// capability accepted by the encrypted-manifest builder.
fn validate_two_complete_executions_v1(
    request: &TeamRequestKeyV1,
    first: CompleteLocalExecutionV1<'_>,
    second: CompleteLocalExecutionV1<'_>,
    producer_version: impl Into<String>,
) -> Result<ValidatedLocalResultV1, LocalResultValidationError> {
    let producer_version = producer_version.into();
    validate_identifier(&producer_version)
        .map_err(|_| LocalResultValidationError::InvalidProducerVersion)?;
    for (execution, run) in [(&first, 1u8), (&second, 2u8)] {
        match execution.exit_code {
            Some(0) => {}
            Some(code) => return Err(LocalResultValidationError::NonZeroExit { run, code }),
            None => return Err(LocalResultValidationError::AbnormalExit { run }),
        }
        if !execution.stderr.is_empty() {
            return Err(LocalResultValidationError::NonEmptyStderr {
                run,
                bytes: execution.stderr.len() as u64,
            });
        }
        if execution.stdout.len() as u64 > MAX_V2_PLAINTEXT_STREAM_BYTES {
            return Err(LocalResultValidationError::OversizeStdout {
                run,
                bytes: execution.stdout.len() as u64,
            });
        }
        if execution.duration_micros > MAX_JSON_SAFE_INTEGER {
            return Err(LocalResultValidationError::DurationOutOfRange { run });
        }
    }
    if first.stdout != second.stdout
        || first.stderr != second.stderr
        || first.exit_code != second.exit_code
    {
        return Err(LocalResultValidationError::ExecutionMismatch);
    }

    let local_proof_digest = local_proof_digest(
        request.digest(),
        first.stdout,
        first.stderr,
        first.duration_micros,
        second.duration_micros,
        &producer_version,
    );
    Ok(ValidatedLocalResultV1 {
        request_key: request.digest(),
        stdout: first.stdout.to_vec(),
        duration_micros: first.duration_micros,
        proof_schema_version: LOCAL_RESULT_PROOF_SCHEMA_VERSION,
        producer_version,
        local_proof_digest,
    })
}

#[cfg(test)]
pub(crate) fn validate_test_local_result_v1(
    request: &TeamRequestKeyV1,
    stdout: &[u8],
) -> ValidatedLocalResultV1 {
    validate_two_complete_executions_v1(
        request,
        CompleteLocalExecutionV1::from_complete_capture(Some(0), stdout, b"", 11),
        CompleteLocalExecutionV1::from_complete_capture(Some(0), stdout, b"", 12),
        "again-test-v1",
    )
    .expect("test fixture must pass the production two-execution validator")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum LocalResultValidationError {
    #[error("producer version is not a strict identifier")]
    InvalidProducerVersion,
    #[error("execution {run} exited unsuccessfully with code {code}")]
    NonZeroExit { run: u8, code: i32 },
    #[error("execution {run} did not have a normal exit code")]
    AbnormalExit { run: u8 },
    #[error("execution {run} captured non-empty stderr ({bytes} bytes)")]
    NonEmptyStderr { run: u8, bytes: u64 },
    #[error("execution {run} stdout exceeds the encrypted publication limit ({bytes} bytes)")]
    OversizeStdout { run: u8, bytes: u64 },
    #[error("execution {run} duration exceeds the shared integer range")]
    DurationOutOfRange { run: u8 },
    #[error("the two complete executions did not produce an exact matching result")]
    ExecutionMismatch,
}

fn local_proof_digest(
    request_key: Digest,
    stdout: &[u8],
    stderr: &[u8],
    first_duration_micros: u64,
    second_duration_micros: u64,
    producer_version: &str,
) -> Digest {
    let mut proof = blake3::Hasher::new();
    hash_put_bytes(&mut proof, LOCAL_PROOF_DOMAIN);
    proof.update(&LOCAL_RESULT_PROOF_SCHEMA_VERSION.to_le_bytes());
    hash_put_bytes(&mut proof, request_key.as_bytes());
    proof.update(&[0]); // exact successful exit status
    hash_put_bytes(&mut proof, stdout);
    hash_put_bytes(&mut proof, stderr);
    proof.update(&first_duration_micros.to_le_bytes());
    proof.update(&second_duration_micros.to_le_bytes());
    hash_put_bytes(&mut proof, producer_version.as_bytes());
    Digest::from_hex(&proof.finalize().to_hex()).expect("BLAKE3 always emits a lower-case digest")
}

fn hash_put_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

/// Builder inputs stay crate-private until a reviewed capture boundary can
/// supply `ValidatedLocalResultV1` without weakening its provenance.
pub(crate) struct ManifestV2BuildInput<'a> {
    pub record_id: &'a str,
    pub request: &'a TeamRequestKeyV1,
    pub admitted: &'a AdmittedLocalPublicationV2,
    pub signer: &'a Ed25519Signer,
    pub verified_trust: &'a VerifiedTrustBundle,
    pub repository_key: &'a RepositoryEncryptionKeyV1,
    pub now_unix_seconds: u64,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

/// Encrypted output of the manifest-v2 builder. Blob getters expose only the
/// exact ciphertext-plus-tag bytes intended for R2.
pub(crate) struct EncryptedPublicationV2 {
    manifest: EncryptedRemoteCacheManifestV2,
    stdout_ciphertext: Vec<u8>,
    stderr_ciphertext: Vec<u8>,
}

impl EncryptedPublicationV2 {
    pub(crate) fn manifest(&self) -> &EncryptedRemoteCacheManifestV2 {
        &self.manifest
    }

    pub(crate) fn stdout_r2_bytes(&self) -> &[u8] {
        &self.stdout_ciphertext
    }

    pub(crate) fn stderr_r2_bytes(&self) -> &[u8] {
        &self.stderr_ciphertext
    }
}

impl fmt::Debug for EncryptedPublicationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedPublicationV2")
            .field("manifest", &self.manifest)
            .field("stdout_ciphertext_bytes", &self.stdout_ciphertext.len())
            .field("stderr_ciphertext_bytes", &self.stderr_ciphertext.len())
            .finish()
    }
}

pub(crate) fn build_encrypted_publication_v2(
    input: ManifestV2BuildInput<'_>,
) -> Result<EncryptedPublicationV2, ManifestV2Error> {
    let stdout_nonce = XNonce::generate().0;
    let mut stderr_nonce = XNonce::generate().0;
    while stdout_nonce == stderr_nonce {
        stderr_nonce = XNonce::generate().0;
    }
    build_encrypted_publication_with_nonces_v2(input, stdout_nonce, stderr_nonce)
}

/// Fail-closed producer authorization that performs no encryption and no
/// network mutation. The signature challenge proves that the loaded private
/// key is the exact public key currently authorized by the fresh trust
/// capability, rather than merely sharing its key-id and producer-id.
pub(crate) fn authorize_publication_v2(
    record_id: &str,
    request: &TeamRequestKeyV1,
    signer: &Ed25519Signer,
    verified_trust: &VerifiedTrustBundle,
    now_unix_seconds: u64,
) -> Result<(), ManifestV2Error> {
    validate_identifier(record_id).map_err(|_| ManifestV2Error::InvalidIdentifier("record_id"))?;
    let descriptor = request.descriptor();
    let trust_request = TrustBoundRequest {
        request_key: request.digest(),
        policy_digest: descriptor.policy_digest(),
        execution_profile_digest: descriptor.execution_profile_digest(),
        platform_digest: descriptor.platform_digest(),
        image_digest: descriptor.image_digest(),
    };
    let context = verified_trust.verification_context(trust_request, now_unix_seconds)?;
    if context.tenant_id != descriptor.tenant_id() {
        return Err(ManifestV2Error::TenantMismatch);
    }
    if context.repository_id != descriptor.repository_id() {
        return Err(ManifestV2Error::RepositoryMismatch);
    }
    if verified_trust.generation_id() != descriptor.generation_id() {
        return Err(ManifestV2Error::GenerationMismatch);
    }
    if context.revoked_key_ids.contains(signer.key_id()) {
        return Err(ManifestV2Error::RevokedKey);
    }
    if context.revoked_record_ids.contains(record_id) {
        return Err(ManifestV2Error::RevokedRecord);
    }
    if context
        .trusted_producer_keys
        .get(signer.key_id())
        .is_none_or(|producer| producer != signer.producer_id())
    {
        return Err(ManifestV2Error::UntrustedProducer);
    }

    let mut challenge = Vec::new();
    put_bytes(&mut challenge, PRODUCER_AUTHORIZATION_DOMAIN);
    put_string(&mut challenge, descriptor.tenant_id());
    put_string(&mut challenge, descriptor.repository_id());
    put_string(&mut challenge, descriptor.generation_id());
    put_bytes(&mut challenge, request.digest().as_bytes());
    put_string(&mut challenge, record_id);
    put_string(&mut challenge, signer.key_id());
    put_string(&mut challenge, signer.producer_id());
    let signature = signer.sign_protocol_message(&challenge);
    if !verified_trust.producer_verifier().verify(
        SignatureAlgorithm::Ed25519,
        signer.key_id(),
        signer.producer_id(),
        &challenge,
        &signature,
    ) {
        return Err(ManifestV2Error::UntrustedProducerKeyMaterial);
    }
    Ok(())
}

/// Test-only fixture builder. Production siblings cannot mint the private
/// two-execution capability; tests that exercise downstream pull transport can
/// obtain a genuine encrypted publication without widening that seam.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_test_encrypted_publication_v2(
    record_id: &str,
    request: &TeamRequestKeyV1,
    sharing_policy: &RepositorySharingPolicy,
    output: &[u8],
    signer: &Ed25519Signer,
    verified_trust: &VerifiedTrustBundle,
    repository_key: &RepositoryEncryptionKeyV1,
    now_unix_seconds: u64,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> EncryptedPublicationV2 {
    let validated = validate_two_complete_executions_v1(
        request,
        CompleteLocalExecutionV1::from_complete_capture(Some(0), output, b"", 11),
        CompleteLocalExecutionV1::from_complete_capture(Some(0), output, b"", 12),
        "again-test-v1",
    )
    .expect("test fixture must satisfy the real two-execution validator");
    let admitted = admit_validated_local_publication_v2(sharing_policy, request, validated)
        .expect("test fixture output must pass the real publication classifier");
    build_encrypted_publication_v2(ManifestV2BuildInput {
        record_id,
        request,
        admitted: &admitted,
        signer,
        verified_trust,
        repository_key,
        now_unix_seconds,
        created_at_unix_seconds,
        expires_at_unix_seconds,
    })
    .expect("test fixture must satisfy the real encrypted publication builder")
}

fn build_encrypted_publication_with_nonces_v2(
    input: ManifestV2BuildInput<'_>,
    stdout_nonce: [u8; XCHACHA20_NONCE_BYTES],
    stderr_nonce: [u8; XCHACHA20_NONCE_BYTES],
) -> Result<EncryptedPublicationV2, ManifestV2Error> {
    if input.admitted.result.request_key != input.request.digest() {
        return Err(ManifestV2Error::ValidatedResultRequestMismatch);
    }
    if input.admitted.policy_digest != input.request.descriptor().policy_digest() {
        return Err(ManifestV2Error::PublicationPolicyMismatch);
    }
    validate_privacy(&input.admitted.privacy)?;
    authorize_publication_v2(
        input.record_id,
        input.request,
        input.signer,
        input.verified_trust,
        input.now_unix_seconds,
    )?;
    if input.now_unix_seconds > MAX_JSON_SAFE_INTEGER
        || input.created_at_unix_seconds > MAX_JSON_SAFE_INTEGER
        || input.expires_at_unix_seconds > MAX_JSON_SAFE_INTEGER
    {
        return Err(ManifestV2Error::IntegerOutOfRange);
    }
    if input.created_at_unix_seconds > input.now_unix_seconds {
        return Err(ManifestV2Error::CreatedInFuture);
    }
    let descriptor = input.request.descriptor();
    let stdout_ciphertext_size = (input.admitted.result.stdout.len() as u64)
        .checked_add(POLY1305_TAG_BYTES)
        .ok_or(ManifestV2Error::IntegerOutOfRange)?;
    let stderr_ciphertext_size = POLY1305_TAG_BYTES;
    let placeholder_digest = digest_bytes(&[]);
    let mut manifest = EncryptedRemoteCacheManifestV2 {
        schema_version: ENCRYPTED_MANIFEST_SCHEMA_VERSION,
        record_id: input.record_id.to_owned(),
        tenant_id: descriptor.tenant_id().to_owned(),
        repository_id: descriptor.repository_id().to_owned(),
        generation_id: descriptor.generation_id().to_owned(),
        request_key: input.request.digest(),
        policy_digest: descriptor.policy_digest(),
        classifier_digest: input.admitted.classifier_digest,
        execution_profile_digest: descriptor.execution_profile_digest(),
        platform_digest: descriptor.platform_digest(),
        image_digest: descriptor.image_digest(),
        result_status: ResultStatusV2::Success,
        duration_micros: input.admitted.result.duration_micros,
        proof_schema_version: input.admitted.result.proof_schema_version,
        producer_version: input.admitted.result.producer_version.clone(),
        local_proof_digest: input.admitted.result.local_proof_digest,
        privacy: input.admitted.privacy.clone(),
        repository_encryption_key_id: input.repository_key.key_id.clone(),
        stdout: EncryptedStreamRefV2 {
            ciphertext_digest: placeholder_digest,
            ciphertext_size_bytes: stdout_ciphertext_size,
            nonce: stdout_nonce,
        },
        stderr: EncryptedStreamRefV2 {
            ciphertext_digest: placeholder_digest,
            ciphertext_size_bytes: stderr_ciphertext_size,
            nonce: stderr_nonce,
        },
        producer_id: input.signer.producer_id().to_owned(),
        created_at_unix_seconds: input.created_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        signature: ManifestSignatureV2 {
            schema_version: SIGNATURE_ENVELOPE_SCHEMA_VERSION,
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: input.signer.key_id().to_owned(),
            signature: vec![0; ED25519_SIGNATURE_SIZE],
        },
    };
    manifest.validate_wire()?;

    let cipher = XChaCha20Poly1305::new_from_slice(input.repository_key.key_bytes.as_ref())
        .expect("repository encryption keys always contain exactly 32 bytes");
    let stdout_ciphertext = cipher
        .encrypt(
            &Array(manifest.stdout.nonce),
            Payload {
                msg: &input.admitted.result.stdout,
                aad: &manifest.stream_aad(EncryptedStreamLabelV2::Stdout),
            },
        )
        .map_err(|_| ManifestV2Error::EncryptionFailed {
            stream: EncryptedStreamLabelV2::Stdout,
        })?;
    let stderr_ciphertext = cipher
        .encrypt(
            &Array(manifest.stderr.nonce),
            Payload {
                msg: &[],
                aad: &manifest.stream_aad(EncryptedStreamLabelV2::Stderr),
            },
        )
        .map_err(|_| ManifestV2Error::EncryptionFailed {
            stream: EncryptedStreamLabelV2::Stderr,
        })?;
    if stdout_ciphertext.len() as u64 != manifest.stdout.ciphertext_size_bytes
        || stderr_ciphertext.len() as u64 != manifest.stderr.ciphertext_size_bytes
    {
        return Err(ManifestV2Error::CiphertextLengthInvariant);
    }
    manifest.stdout.ciphertext_digest = digest_bytes(&stdout_ciphertext);
    manifest.stderr.ciphertext_digest = digest_bytes(&stderr_ciphertext);
    manifest.signature.signature = input
        .signer
        .sign_protocol_message(&manifest.canonical_signing_bytes())
        .to_vec();
    manifest.validate_wire()?;
    if !input.verified_trust.producer_verifier().verify(
        manifest.signature.algorithm,
        &manifest.signature.key_id,
        &manifest.producer_id,
        &manifest.canonical_signing_bytes(),
        &manifest.signature.signature,
    ) {
        return Err(ManifestV2Error::UntrustedProducerKeyMaterial);
    }

    Ok(EncryptedPublicationV2 {
        manifest,
        stdout_ciphertext,
        stderr_ciphertext,
    })
}

/// Verified, fully authenticated plaintext. Private fields prevent callers
/// from constructing a remote hit without running `verify_and_decrypt_v2`.
pub struct VerifiedRemoteResultV2 {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_micros: u64,
    local_proof_digest: Digest,
    producer_id: String,
    verified_at_unix_seconds: u64,
    release_expires_at_unix_seconds: u64,
}

impl VerifiedRemoteResultV2 {
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn duration_micros(&self) -> u64 {
        self.duration_micros
    }

    pub fn local_proof_digest(&self) -> Digest {
        self.local_proof_digest
    }

    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    /// Recheck the retained plaintext capability at the final presentation
    /// boundary. The shorter of manifest and trust lifetime controls release;
    /// a rollback can never make a previously checked result fresh again.
    pub(crate) fn verify_fresh_for_release(
        &self,
        now_unix_seconds: u64,
    ) -> Result<(), ManifestV2Error> {
        if now_unix_seconds < self.verified_at_unix_seconds {
            return Err(ManifestV2Error::ReleaseClockRollback);
        }
        if now_unix_seconds >= self.release_expires_at_unix_seconds {
            return Err(ManifestV2Error::Expired);
        }
        Ok(())
    }

    /// Advance this plaintext capability to a later trust fence. A newer
    /// bundle may expire sooner than the bundle used during decryption, so the
    /// retained release lifetime can only shrink.
    pub(crate) fn rebind_release_freshness(
        &mut self,
        now_unix_seconds: u64,
        trust_expires_at_unix_seconds: u64,
    ) -> Result<(), ManifestV2Error> {
        self.verify_fresh_for_release(now_unix_seconds)?;
        if now_unix_seconds >= trust_expires_at_unix_seconds {
            return Err(ManifestV2Error::Expired);
        }
        self.verified_at_unix_seconds = now_unix_seconds;
        self.release_expires_at_unix_seconds = self
            .release_expires_at_unix_seconds
            .min(trust_expires_at_unix_seconds);
        Ok(())
    }
}

impl fmt::Debug for VerifiedRemoteResultV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRemoteResultV2")
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("duration_micros", &self.duration_micros)
            .field("local_proof_digest", &self.local_proof_digest)
            .field("producer_id", &self.producer_id)
            .finish()
    }
}

/// Authenticate all manifest semantics and both ciphertexts before returning
/// any plaintext capability.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_and_decrypt_v2(
    manifest: &EncryptedRemoteCacheManifestV2,
    stdout_ciphertext: &[u8],
    stderr_ciphertext: &[u8],
    request: &TeamRequestKeyV1,
    sharing_policy: &RepositorySharingPolicy,
    verified_trust: &VerifiedTrustBundle,
    trust_request: TrustBoundRequest,
    repository_key: &RepositoryEncryptionKeyV1,
    now_unix_seconds: u64,
) -> Result<VerifiedRemoteResultV2, ManifestV2Error> {
    verify_manifest_for_pull_v2(
        manifest,
        request,
        sharing_policy,
        verified_trust,
        trust_request,
        repository_key,
        now_unix_seconds,
    )?;

    validate_ciphertext(
        &manifest.stdout,
        stdout_ciphertext,
        EncryptedStreamLabelV2::Stdout,
    )?;
    validate_ciphertext(
        &manifest.stderr,
        stderr_ciphertext,
        EncryptedStreamLabelV2::Stderr,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(repository_key.key_bytes.as_ref())
        .expect("repository encryption keys always contain exactly 32 bytes");
    let stdout = cipher
        .decrypt(
            &Array(manifest.stdout.nonce),
            Payload {
                msg: stdout_ciphertext,
                aad: &manifest.stream_aad(EncryptedStreamLabelV2::Stdout),
            },
        )
        .map_err(|_| ManifestV2Error::AuthenticationFailed {
            stream: EncryptedStreamLabelV2::Stdout,
        })?;
    let stderr = cipher
        .decrypt(
            &Array(manifest.stderr.nonce),
            Payload {
                msg: stderr_ciphertext,
                aad: &manifest.stream_aad(EncryptedStreamLabelV2::Stderr),
            },
        )
        .map_err(|_| ManifestV2Error::AuthenticationFailed {
            stream: EncryptedStreamLabelV2::Stderr,
        })?;
    if !stderr.is_empty() {
        return Err(ManifestV2Error::NonEmptyEncryptedStderr);
    }
    if stdout.len() as u64 + POLY1305_TAG_BYTES != manifest.stdout.ciphertext_size_bytes {
        return Err(ManifestV2Error::CiphertextLengthInvariant);
    }
    let locally_classified = PublishableResult::evaluate(
        sharing_policy,
        request,
        CapturedExecution::new(
            CapturedStdin::Closed,
            CapturedStream::CompletePipe(&stdout),
            CapturedStream::CompletePipe(&stderr),
            CapturedExit::Code(0),
        ),
    )
    .map_err(|_| ManifestV2Error::ConsumerPrivacyGateRejected)?;
    if manifest.classifier_digest != locally_classified.classifier_digest() {
        return Err(ManifestV2Error::ClassifierMismatch);
    }
    if &manifest.privacy != locally_classified.privacy() {
        return Err(ManifestV2Error::PrivacyMismatch);
    }

    Ok(VerifiedRemoteResultV2 {
        stdout,
        stderr,
        duration_micros: manifest.duration_micros,
        local_proof_digest: manifest.local_proof_digest,
        producer_id: manifest.producer_id.clone(),
        verified_at_unix_seconds: now_unix_seconds,
        release_expires_at_unix_seconds: manifest
            .expires_at_unix_seconds
            .min(verified_trust.bundle().expires_at_unix_seconds),
    })
}

/// Authenticate the complete manifest envelope before a pull-only client
/// follows its ciphertext references. This is crate-private because it mints
/// no reusable result capability; `verify_and_decrypt_v2` repeats the checks
/// after transport and remains the only plaintext-producing authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_manifest_for_pull_v2(
    manifest: &EncryptedRemoteCacheManifestV2,
    request: &TeamRequestKeyV1,
    sharing_policy: &RepositorySharingPolicy,
    verified_trust: &VerifiedTrustBundle,
    trust_request: TrustBoundRequest,
    repository_key: &RepositoryEncryptionKeyV1,
    now_unix_seconds: u64,
) -> Result<(), ManifestV2Error> {
    manifest.validate_wire()?;
    let descriptor = request.descriptor();
    let expected_trust_request = TrustBoundRequest {
        request_key: request.digest(),
        policy_digest: descriptor.policy_digest(),
        execution_profile_digest: descriptor.execution_profile_digest(),
        platform_digest: descriptor.platform_digest(),
        image_digest: descriptor.image_digest(),
    };
    if trust_request != expected_trust_request {
        return Err(ManifestV2Error::TrustRequestMismatch);
    }
    let trust_context = verified_trust.verification_context(trust_request, now_unix_seconds)?;
    if trust_context.tenant_id != descriptor.tenant_id() {
        return Err(ManifestV2Error::TenantMismatch);
    }
    if trust_context.repository_id != descriptor.repository_id() {
        return Err(ManifestV2Error::RepositoryMismatch);
    }
    if verified_trust.generation_id() != descriptor.generation_id() {
        return Err(ManifestV2Error::GenerationMismatch);
    }
    if manifest.tenant_id != descriptor.tenant_id() {
        return Err(ManifestV2Error::TenantMismatch);
    }
    if manifest.repository_id != descriptor.repository_id() {
        return Err(ManifestV2Error::RepositoryMismatch);
    }
    if manifest.generation_id != descriptor.generation_id() {
        return Err(ManifestV2Error::GenerationMismatch);
    }
    if manifest.request_key != request.digest() {
        return Err(ManifestV2Error::RequestKeyMismatch);
    }
    if manifest.policy_digest != descriptor.policy_digest()
        || manifest.policy_digest != sharing_policy.digest()
    {
        return Err(ManifestV2Error::PolicyMismatch);
    }
    if manifest.execution_profile_digest != descriptor.execution_profile_digest() {
        return Err(ManifestV2Error::ExecutionProfileMismatch);
    }
    if manifest.platform_digest != descriptor.platform_digest() {
        return Err(ManifestV2Error::PlatformMismatch);
    }
    if manifest.image_digest != descriptor.image_digest() {
        return Err(ManifestV2Error::ImageMismatch);
    }
    if now_unix_seconds < manifest.created_at_unix_seconds {
        return Err(ManifestV2Error::CreatedInFuture);
    }
    if now_unix_seconds >= manifest.expires_at_unix_seconds {
        return Err(ManifestV2Error::Expired);
    }
    if manifest.repository_encryption_key_id != repository_key.key_id {
        return Err(ManifestV2Error::RepositoryKeyIdMismatch);
    }
    if trust_context
        .revoked_record_ids
        .contains(&manifest.record_id)
    {
        return Err(ManifestV2Error::RevokedRecord);
    }
    if trust_context
        .revoked_key_ids
        .contains(&manifest.signature.key_id)
    {
        return Err(ManifestV2Error::RevokedKey);
    }
    if trust_context
        .trusted_producer_keys
        .get(&manifest.signature.key_id)
        .is_none_or(|producer| producer != &manifest.producer_id)
    {
        return Err(ManifestV2Error::UntrustedProducer);
    }
    if !verified_trust.producer_verifier().verify(
        manifest.signature.algorithm,
        &manifest.signature.key_id,
        &manifest.producer_id,
        &manifest.canonical_signing_bytes(),
        &manifest.signature.signature,
    ) {
        return Err(ManifestV2Error::InvalidSignature);
    }
    Ok(())
}

fn validate_ciphertext(
    reference: &EncryptedStreamRefV2,
    ciphertext: &[u8],
    stream: EncryptedStreamLabelV2,
) -> Result<(), ManifestV2Error> {
    if ciphertext.len() as u64 != reference.ciphertext_size_bytes {
        return Err(ManifestV2Error::CiphertextSizeMismatch { stream });
    }
    if digest_bytes(ciphertext) != reference.ciphertext_digest {
        return Err(ManifestV2Error::CiphertextDigestMismatch { stream });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ManifestV2Error {
    #[error("unknown encrypted-manifest schema version")]
    UnknownSchemaVersion,
    #[error("unknown local-result proof schema version")]
    UnknownProofSchemaVersion,
    #[error("unknown signature-envelope schema version")]
    UnknownSignatureSchemaVersion,
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(&'static str),
    #[error("manifest integer exceeds the shared JSON safe-integer range")]
    IntegerOutOfRange,
    #[error("invalid manifest creation/expiry interval")]
    InvalidLifetime,
    #[error("manifest was created in the future")]
    CreatedInFuture,
    #[error("manifest has expired")]
    Expired,
    #[error("clock moved backwards after remote result verification")]
    ReleaseClockRollback,
    #[error("invalid producer signature size")]
    InvalidSignatureSize,
    #[error("producer signature verification failed")]
    InvalidSignature,
    #[error("candidate is not shareable")]
    Unshareable,
    #[error("candidate is secret-tainted")]
    SecretTainted,
    #[error("ciphertext size is invalid for {stream:?}")]
    InvalidCiphertextSize { stream: EncryptedStreamLabelV2 },
    #[error("validated stderr must encrypt to one authentication tag")]
    NonEmptyEncryptedStderr,
    #[error("a nonce was reused across the two encrypted streams")]
    NonceReuse,
    #[error("validated local result belongs to a different request")]
    ValidatedResultRequestMismatch,
    #[error("publication policy does not match the sealed portable request")]
    PublicationPolicyMismatch,
    #[error("verified trust bundle rejected the requested binding: {0}")]
    Trust(#[from] TrustBundleError),
    #[error("producer is not authorized by the verified trust bundle")]
    UntrustedProducer,
    #[error("producer private key does not match the public key in verified trust")]
    UntrustedProducerKeyMaterial,
    #[error("producer signing key is revoked")]
    RevokedKey,
    #[error("record is revoked")]
    RevokedRecord,
    #[error("encryption failed for {stream:?}")]
    EncryptionFailed { stream: EncryptedStreamLabelV2 },
    #[error("ciphertext length violated the AEAD framing invariant")]
    CiphertextLengthInvariant,
    #[error("caller trust request does not match the sealed portable request")]
    TrustRequestMismatch,
    #[error("tenant binding mismatch")]
    TenantMismatch,
    #[error("repository binding mismatch")]
    RepositoryMismatch,
    #[error("repository generation must be exactly 32 lower-case hexadecimal characters")]
    InvalidGenerationId,
    #[error("repository-generation binding mismatch")]
    GenerationMismatch,
    #[error("request-key binding mismatch")]
    RequestKeyMismatch,
    #[error("policy binding mismatch")]
    PolicyMismatch,
    #[error("classifier binding mismatch")]
    ClassifierMismatch,
    #[error("privacy binding mismatch")]
    PrivacyMismatch,
    #[error("decrypted result was rejected by the local publication classifier")]
    ConsumerPrivacyGateRejected,
    #[error("execution-profile binding mismatch")]
    ExecutionProfileMismatch,
    #[error("platform binding mismatch")]
    PlatformMismatch,
    #[error("image binding mismatch")]
    ImageMismatch,
    #[error("repository encryption-key id mismatch")]
    RepositoryKeyIdMismatch,
    #[error("ciphertext size does not match manifest for {stream:?}")]
    CiphertextSizeMismatch { stream: EncryptedStreamLabelV2 },
    #[error("ciphertext digest does not match manifest for {stream:?}")]
    CiphertextDigestMismatch { stream: EncryptedStreamLabelV2 },
    #[error("ciphertext authentication failed for {stream:?}")]
    AuthenticationFailed { stream: EncryptedStreamLabelV2 },
}

fn put_manifest_semantics(
    output: &mut Vec<u8>,
    manifest: &EncryptedRemoteCacheManifestV2,
    include_ciphertext_digests: bool,
) {
    put_u16(output, manifest.schema_version);
    put_string(output, &manifest.record_id);
    put_string(output, &manifest.tenant_id);
    put_string(output, &manifest.repository_id);
    put_string(output, &manifest.generation_id);
    put_digest(output, &manifest.request_key);
    put_digest(output, &manifest.policy_digest);
    put_digest(output, &manifest.classifier_digest);
    put_digest(output, &manifest.execution_profile_digest);
    put_digest(output, &manifest.platform_digest);
    put_digest(output, &manifest.image_digest);
    put_u8(output, result_status_tag(manifest.result_status));
    put_u64(output, manifest.duration_micros);
    put_u16(output, manifest.proof_schema_version);
    put_string(output, &manifest.producer_version);
    put_digest(output, &manifest.local_proof_digest);
    put_u8(output, privacy_class_tag(manifest.privacy.classification));
    put_u8(output, shareability_tag(manifest.privacy.shareability));
    put_u8(output, u8::from(manifest.privacy.secret_tainted));
    put_string(output, &manifest.repository_encryption_key_id);
    put_stream_ref(output, &manifest.stdout, include_ciphertext_digests);
    put_stream_ref(output, &manifest.stderr, include_ciphertext_digests);
    put_string(output, &manifest.producer_id);
    put_u64(output, manifest.created_at_unix_seconds);
    put_u64(output, manifest.expires_at_unix_seconds);
    put_u16(output, manifest.signature.schema_version);
    put_u8(
        output,
        signature_algorithm_tag(manifest.signature.algorithm),
    );
    put_string(output, &manifest.signature.key_id);
}

fn put_stream_ref(
    output: &mut Vec<u8>,
    stream: &EncryptedStreamRefV2,
    include_ciphertext_digest: bool,
) {
    if include_ciphertext_digest {
        put_digest(output, &stream.ciphertext_digest);
    }
    put_u64(output, stream.ciphertext_size_bytes);
    put_bytes(output, &stream.nonce);
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex(&blake3::hash(bytes).to_hex())
        .expect("BLAKE3 always emits a lower-case digest")
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_generation_id(value: &str) -> Result<(), ManifestV2Error> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ManifestV2Error::InvalidGenerationId);
    }
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn put_string(output: &mut Vec<u8>, value: &str) {
    put_bytes(output, value.as_bytes());
}

fn put_digest(output: &mut Vec<u8>, value: &Digest) {
    put_bytes(output, value.as_bytes());
}

fn put_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn result_status_tag(value: ResultStatusV2) -> u8 {
    match value {
        ResultStatusV2::Success => 1,
    }
}

fn stream_label_tag(value: EncryptedStreamLabelV2) -> u8 {
    match value {
        EncryptedStreamLabelV2::Stdout => 1,
        EncryptedStreamLabelV2::Stderr => 2,
    }
}

fn privacy_class_tag(value: PrivacyClass) -> u8 {
    match value {
        PrivacyClass::Public => 1,
        PrivacyClass::Internal => 2,
        PrivacyClass::Confidential => 3,
        PrivacyClass::Secret => 4,
    }
}

fn shareability_tag(value: Shareability) -> u8 {
    match value {
        Shareability::LocalOnly => 1,
        Shareability::Tenant => 2,
        Shareability::Repository => 3,
    }
}

fn signature_algorithm_tag(value: SignatureAlgorithm) -> u8 {
    match value {
        SignatureAlgorithm::Ed25519 => 1,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;

    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;
    use tempfile::TempDir;

    use super::*;
    use crate::privacy::RepositorySharingPolicy;
    use crate::team_request_key::{TeamRequestKeyInput, build_team_request_key_v1};
    use crate::trust_bundle::{
        ExpectedTrustBundle, PinnedRootKey, ProducerKeyBindingV1, TrustBundleV1, TrustEpochTracker,
        verify_trust_bundle,
    };

    const TENANT: &str = "tenant-v2";
    const REPOSITORY: &str = "repository-v2";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";
    const GENERATION_B: &str = "fedcba9876543210fedcba9876543210";
    const ENDPOINT: &str = "https://cache.example.test";
    const ROOT_KEY_ID: &str = "root-v2";
    const PRODUCER_KEY_ID: &str = "producer-key-v2";
    const PRODUCER_ID: &str = "producer-v2";
    const RECORD_ID: &str = "record-v2";
    const CREATED_AT: u64 = 100;
    const EXPIRES_AT: u64 = 200;
    const TRUST_EXPIRES_AT: u64 = 300;
    const DEFAULT_OUTPUT: &[u8] = b"ordinary compile summary: 42 checks passed\n";

    struct Fixture {
        _workspace: TempDir,
        policy: RepositorySharingPolicy,
        request: TeamRequestKeyV1,
        admitted: AdmittedLocalPublicationV2,
        signer: Ed25519Signer,
        trust: VerifiedTrustBundle,
        repository_key: RepositoryEncryptionKeyV1,
    }

    impl Fixture {
        fn new(output: &[u8]) -> Self {
            let workspace = TempDir::new().unwrap();
            fs::create_dir(workspace.path().join("src")).unwrap();
            fs::write(
                workspace.path().join("src/input.txt"),
                b"portable source input\n",
            )
            .unwrap();
            let policy = RepositorySharingPolicy::new(
                "sharing-v2",
                vec![PathBuf::from("src")],
                vec![PathBuf::from("target"), PathBuf::from(".env")],
                1024 * 1024,
            )
            .unwrap();
            let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
            let request = build_team_request_key_v1(&TeamRequestKeyInput {
                tenant_id: TENANT,
                repository_id: REPOSITORY,
                generation_id: GENERATION,
                workspace: workspace.path(),
                cwd: workspace.path(),
                argv: &argv,
                environment: &[],
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
                policy_digest: policy.digest(),
                execution_profile_digest: fixed_digest(2),
                platform_digest: fixed_digest(3),
                image_digest: fixed_digest(4),
            })
            .unwrap();
            let first =
                CompleteLocalExecutionV1::from_complete_capture(Some(0), output, b"", 12_345);
            let second =
                CompleteLocalExecutionV1::from_complete_capture(Some(0), output, b"", 11_111);
            let result = validate_two_complete_executions_v1(
                &request,
                first,
                second,
                "again-producer-0.1.0",
            )
            .unwrap();
            let admitted = admit_validated_local_publication_v2(&policy, &request, result).unwrap();
            let signer =
                Ed25519Signer::from_secret_key(PRODUCER_KEY_ID, PRODUCER_ID, &[7; 32]).unwrap();
            let trust = verified_trust(
                &request,
                vec![producer_binding(&signer)],
                vec![],
                vec![],
                true,
                TRUST_EXPIRES_AT,
                CREATED_AT,
            );
            let repository_key =
                RepositoryEncryptionKeyV1::from_bytes("repository-key-v2", [9; 32]).unwrap();
            Self {
                _workspace: workspace,
                policy,
                request,
                admitted,
                signer,
                trust,
                repository_key,
            }
        }

        fn publication(&self) -> EncryptedPublicationV2 {
            self.publication_with_times(CREATED_AT, EXPIRES_AT)
        }

        fn publication_with_times(
            &self,
            created_at: u64,
            expires_at: u64,
        ) -> EncryptedPublicationV2 {
            build_encrypted_publication_with_nonces_v2(
                ManifestV2BuildInput {
                    record_id: RECORD_ID,
                    request: &self.request,
                    admitted: &self.admitted,
                    signer: &self.signer,
                    verified_trust: &self.trust,
                    repository_key: &self.repository_key,
                    now_unix_seconds: CREATED_AT,
                    created_at_unix_seconds: created_at,
                    expires_at_unix_seconds: expires_at,
                },
                [1; XCHACHA20_NONCE_BYTES],
                [2; XCHACHA20_NONCE_BYTES],
            )
            .unwrap()
        }

        fn trust_request(&self) -> TrustBoundRequest {
            request_binding(&self.request)
        }

        fn verify(
            &self,
            manifest: &EncryptedRemoteCacheManifestV2,
            stdout: &[u8],
            stderr: &[u8],
        ) -> Result<VerifiedRemoteResultV2, ManifestV2Error> {
            verify_and_decrypt_v2(
                manifest,
                stdout,
                stderr,
                &self.request,
                &self.policy,
                &self.trust,
                self.trust_request(),
                &self.repository_key,
                150,
            )
        }
    }

    fn fixed_digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    #[test]
    fn retained_cross_language_manifest_v2_canonical_vector_matches_rust() {
        let vector = EncryptedRemoteCacheManifestV2 {
            schema_version: ENCRYPTED_MANIFEST_SCHEMA_VERSION,
            record_id: "record-vector-2".into(),
            tenant_id: "tenant-vector".into(),
            repository_id: "repo-vector".into(),
            generation_id: GENERATION.into(),
            request_key: fixed_digest(0x01),
            policy_digest: fixed_digest(0x11),
            classifier_digest: fixed_digest(0x12),
            execution_profile_digest: fixed_digest(0x22),
            platform_digest: fixed_digest(0x33),
            image_digest: fixed_digest(0x44),
            result_status: ResultStatusV2::Success,
            duration_micros: 987_654,
            proof_schema_version: LOCAL_RESULT_PROOF_SCHEMA_VERSION,
            producer_version: "again-vector-0.1.0".into(),
            local_proof_digest: fixed_digest(0x55),
            privacy: PrivacyMetadata {
                classification: PrivacyClass::Confidential,
                shareability: Shareability::Repository,
                secret_tainted: false,
            },
            repository_encryption_key_id: "repository-key-vector".into(),
            stdout: EncryptedStreamRefV2 {
                ciphertext_digest: fixed_digest(0x66),
                ciphertext_size_bytes: 48,
                nonce: [0x77; XCHACHA20_NONCE_BYTES],
            },
            stderr: EncryptedStreamRefV2 {
                ciphertext_digest: fixed_digest(0x88),
                ciphertext_size_bytes: 16,
                nonce: [0x99; XCHACHA20_NONCE_BYTES],
            },
            producer_id: "producer-vector".into(),
            created_at_unix_seconds: 1_700_000_000,
            expires_at_unix_seconds: 1_700_003_600,
            signature: ManifestSignatureV2 {
                schema_version: SIGNATURE_ENVELOPE_SCHEMA_VERSION,
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "key-vector-1".into(),
                signature: vec![0; ED25519_SIGNATURE_SIZE],
            },
        };
        let actual = vector
            .canonical_signing_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let retained: Value = serde_json::from_str(include_str!(
            "../service/test/fixtures/manifest-v2-canonical-rust.json"
        ))
        .unwrap();
        assert_eq!(actual, retained["canonical_hex"].as_str().unwrap());
    }

    #[test]
    fn generation_a_request_manifest_and_ciphertext_refs_fail_under_generation_b() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication_a = fixture.publication();
        let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
        let request_b = build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: TENANT,
            repository_id: REPOSITORY,
            generation_id: GENERATION_B,
            workspace: fixture._workspace.path(),
            cwd: fixture._workspace.path(),
            argv: &argv,
            environment: &[],
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: fixture.policy.digest(),
            execution_profile_digest: fixed_digest(2),
            platform_digest: fixed_digest(3),
            image_digest: fixed_digest(4),
        })
        .unwrap();
        assert_ne!(fixture.request.digest(), request_b.digest());

        let trust_b = verified_trust(
            &request_b,
            vec![producer_binding(&fixture.signer)],
            vec![],
            vec![],
            true,
            TRUST_EXPIRES_AT,
            CREATED_AT,
        );
        assert!(matches!(
            verify_and_decrypt_v2(
                publication_a.manifest(),
                publication_a.stdout_r2_bytes(),
                publication_a.stderr_r2_bytes(),
                &request_b,
                &fixture.policy,
                &trust_b,
                request_binding(&request_b),
                &fixture.repository_key,
                150,
            ),
            Err(ManifestV2Error::GenerationMismatch)
        ));
    }

    fn request_binding(request: &TeamRequestKeyV1) -> TrustBoundRequest {
        TrustBoundRequest {
            request_key: request.digest(),
            policy_digest: request.descriptor().policy_digest(),
            execution_profile_digest: request.descriptor().execution_profile_digest(),
            platform_digest: request.descriptor().platform_digest(),
            image_digest: request.descriptor().image_digest(),
        }
    }

    fn producer_binding(signer: &Ed25519Signer) -> ProducerKeyBindingV1 {
        ProducerKeyBindingV1 {
            key_id: signer.key_id().to_owned(),
            producer_id: signer.producer_id().to_owned(),
            public_key: signer.public_key_bytes(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_trust(
        request: &TeamRequestKeyV1,
        active_keys: Vec<ProducerKeyBindingV1>,
        revoked_key_ids: Vec<String>,
        revoked_record_ids: Vec<String>,
        allow_profile: bool,
        expires_at: u64,
        verify_now: u64,
    ) -> VerifiedTrustBundle {
        verified_trust_for_scope(
            request,
            TENANT,
            REPOSITORY,
            active_keys,
            revoked_key_ids,
            revoked_record_ids,
            allow_profile,
            expires_at,
            verify_now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_trust_for_scope(
        request: &TeamRequestKeyV1,
        tenant_id: &str,
        repository_id: &str,
        active_keys: Vec<ProducerKeyBindingV1>,
        revoked_key_ids: Vec<String>,
        revoked_record_ids: Vec<String>,
        allow_profile: bool,
        expires_at: u64,
        verify_now: u64,
    ) -> VerifiedTrustBundle {
        let root = SigningKey::from_bytes(&[11; 32]);
        let mut bundle = TrustBundleV1 {
            schema_version: 1,
            root_key_id: ROOT_KEY_ID.to_owned(),
            tenant_id: tenant_id.to_owned(),
            repository_id: repository_id.to_owned(),
            generation_id: request.descriptor().generation_id().to_owned(),
            endpoint_origin: ENDPOINT.to_owned(),
            epoch: 1,
            issued_at_unix_seconds: 90,
            expires_at_unix_seconds: expires_at,
            active_producer_keys: active_keys,
            revoked_key_ids,
            revoked_record_ids,
            allowed_policy_digests: vec![request.descriptor().policy_digest()],
            allowed_execution_profile_digests: if allow_profile {
                vec![request.descriptor().execution_profile_digest()]
            } else {
                vec![]
            },
            allowed_platform_digests: vec![request.descriptor().platform_digest()],
            allowed_image_digests: vec![request.descriptor().image_digest()],
            signature: vec![0; ED25519_SIGNATURE_SIZE],
        };
        bundle.signature = root
            .sign(&bundle.canonical_signing_bytes())
            .to_bytes()
            .to_vec();
        let pinned =
            PinnedRootKey::from_public_key(ROOT_KEY_ID, &root.verifying_key().to_bytes()).unwrap();
        verify_trust_bundle(
            bundle,
            ExpectedTrustBundle {
                tenant_id,
                repository_id,
                generation_id: request.descriptor().generation_id(),
                endpoint_origin: ENDPOINT,
            },
            &pinned,
            verify_now,
            &mut TrustEpochTracker::new(),
        )
        .unwrap()
    }

    fn resign(manifest: &mut EncryptedRemoteCacheManifestV2, signer: &Ed25519Signer) {
        manifest.signature.key_id = signer.key_id().to_owned();
        manifest.producer_id = signer.producer_id().to_owned();
        manifest.signature.signature = signer
            .sign_protocol_message(&manifest.canonical_signing_bytes())
            .to_vec();
    }

    fn reencrypt_and_resign(
        manifest: &mut EncryptedRemoteCacheManifestV2,
        plaintext: &[u8],
        repository_key: &RepositoryEncryptionKeyV1,
        signer: &Ed25519Signer,
    ) -> (Vec<u8>, Vec<u8>) {
        manifest.stdout.ciphertext_size_bytes = plaintext.len() as u64 + POLY1305_TAG_BYTES;
        manifest.stderr.ciphertext_size_bytes = POLY1305_TAG_BYTES;
        let cipher = XChaCha20Poly1305::new_from_slice(repository_key.key_bytes.as_ref()).unwrap();
        let stdout = cipher
            .encrypt(
                &Array(manifest.stdout.nonce),
                Payload {
                    msg: plaintext,
                    aad: &manifest.stream_aad(EncryptedStreamLabelV2::Stdout),
                },
            )
            .unwrap();
        let stderr = cipher
            .encrypt(
                &Array(manifest.stderr.nonce),
                Payload {
                    msg: b"",
                    aad: &manifest.stream_aad(EncryptedStreamLabelV2::Stderr),
                },
            )
            .unwrap();
        manifest.stdout.ciphertext_digest = digest_bytes(&stdout);
        manifest.stderr.ciphertext_digest = digest_bytes(&stderr);
        resign(manifest, signer);
        (stdout, stderr)
    }

    #[test]
    fn upstream_xchacha20poly1305_vector_matches() {
        // draft-irtf-cfrg-xchacha Appendix A.1, also used by RustCrypto's
        // chacha20poly1305 0.11 upstream test suite.
        const KEY: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        const NONCE: [u8; 24] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        const AAD: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const EXPECTED: &[u8] = &[
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0,
            0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c,
            0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3,
            0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
            0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5,
            0xd9, 0x45, 0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
            0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9,
            0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
            0xb5, 0x2e, 0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8,
            0x78, 0x0a, 0xcf, 0x49,
        ];

        let cipher = XChaCha20Poly1305::new(&Array(KEY));
        let encrypted = cipher
            .encrypt(
                &Array(NONCE),
                Payload {
                    msg: PLAINTEXT,
                    aad: &AAD,
                },
            )
            .unwrap();
        assert_eq!(encrypted, EXPECTED);
        assert_eq!(
            cipher
                .decrypt(
                    &Array(NONCE),
                    Payload {
                        msg: &encrypted,
                        aad: &AAD,
                    },
                )
                .unwrap(),
            PLAINTEXT
        );
    }

    #[test]
    fn builds_random_nonce_ciphertexts_and_roundtrips_only_after_full_verification() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = build_encrypted_publication_v2(ManifestV2BuildInput {
            record_id: RECORD_ID,
            request: &fixture.request,
            admitted: &fixture.admitted,
            signer: &fixture.signer,
            verified_trust: &fixture.trust,
            repository_key: &fixture.repository_key,
            now_unix_seconds: CREATED_AT,
            created_at_unix_seconds: CREATED_AT,
            expires_at_unix_seconds: EXPIRES_AT,
        })
        .unwrap();
        assert_ne!(
            publication.manifest().stdout.nonce,
            publication.manifest().stderr.nonce
        );
        assert_eq!(
            publication.stdout_r2_bytes().len() as u64,
            DEFAULT_OUTPUT.len() as u64 + POLY1305_TAG_BYTES
        );
        assert_eq!(
            publication.stderr_r2_bytes().len() as u64,
            POLY1305_TAG_BYTES
        );
        let verified = fixture
            .verify(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
            )
            .unwrap();
        assert_eq!(verified.stdout(), DEFAULT_OUTPUT);
        assert!(verified.stderr().is_empty());
        assert_eq!(verified.duration_micros(), 12_345);
        assert_eq!(verified.producer_id(), PRODUCER_ID);
        assert_eq!(
            verified.local_proof_digest(),
            publication.manifest().local_proof_digest
        );
        assert!(verified.verify_fresh_for_release(150).is_ok());
        assert!(verified.verify_fresh_for_release(199).is_ok());
        assert!(matches!(
            verified.verify_fresh_for_release(200),
            Err(ManifestV2Error::Expired)
        ));
        assert!(matches!(
            verified.verify_fresh_for_release(149),
            Err(ManifestV2Error::ReleaseClockRollback)
        ));
    }

    #[test]
    fn privacy_admission_owns_and_scans_the_exact_validated_bytes() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let secret = b"-----BEGIN PRIVATE KEY-----\nproducer-secret\n";
        let secret_result = validate_test_local_result_v1(&fixture.request, secret);
        let rejected =
            admit_validated_local_publication_v2(&fixture.policy, &fixture.request, secret_result)
                .unwrap_err();
        assert!(matches!(
            rejected.reason(),
            LocalOnlyReason::CredentialShape { .. }
        ));
        assert_eq!((*rejected).into_result().exact_stdout(), secret);

        // A result for another sealed request cannot be paired with an
        // otherwise valid privacy decision. More importantly, the builder's
        // input has no PublishableResult or ValidatedLocalResultV1 field at
        // all: only the aggregate returned above is accepted.
        let argv = [OsString::from("cat"), OsString::from("src/input.txt")];
        let other_request = build_team_request_key_v1(&TeamRequestKeyInput {
            tenant_id: TENANT,
            repository_id: REPOSITORY,
            generation_id: GENERATION,
            workspace: fixture._workspace.path(),
            cwd: fixture._workspace.path(),
            argv: &argv,
            environment: &[],
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: fixture.policy.digest(),
            execution_profile_digest: fixed_digest(22),
            platform_digest: fixed_digest(3),
            image_digest: fixed_digest(4),
        })
        .unwrap();
        let result = validate_test_local_result_v1(&fixture.request, DEFAULT_OUTPUT);
        let rejected =
            admit_validated_local_publication_v2(&fixture.policy, &other_request, result)
                .unwrap_err();
        assert_eq!(rejected.reason(), LocalOnlyReason::RequestDigestMismatch);
        assert_eq!((*rejected).into_result().exact_stdout(), DEFAULT_OUTPUT);
    }

    #[test]
    fn producer_private_key_must_match_current_signed_trust() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let impostor =
            Ed25519Signer::from_secret_key(PRODUCER_KEY_ID, PRODUCER_ID, &[99; 32]).unwrap();
        assert!(matches!(
            authorize_publication_v2(
                RECORD_ID,
                &fixture.request,
                &impostor,
                &fixture.trust,
                CREATED_AT,
            ),
            Err(ManifestV2Error::UntrustedProducerKeyMaterial)
        ));
    }

    #[test]
    fn wrong_key_nonce_tag_and_authenticated_semantics_fail_closed() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();

        let wrong_key =
            RepositoryEncryptionKeyV1::from_bytes("repository-key-v2", [8; 32]).unwrap();
        assert!(matches!(
            verify_and_decrypt_v2(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &fixture.trust,
                fixture.trust_request(),
                &wrong_key,
                150,
            ),
            Err(ManifestV2Error::AuthenticationFailed {
                stream: EncryptedStreamLabelV2::Stdout
            })
        ));

        let mut wrong_nonce = publication.manifest().clone();
        wrong_nonce.stdout.nonce[0] ^= 1;
        resign(&mut wrong_nonce, &fixture.signer);
        assert!(matches!(
            fixture.verify(
                &wrong_nonce,
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes()
            ),
            Err(ManifestV2Error::AuthenticationFailed {
                stream: EncryptedStreamLabelV2::Stdout
            })
        ));

        let mut wrong_tag_bytes = publication.stdout_r2_bytes().to_vec();
        *wrong_tag_bytes.last_mut().unwrap() ^= 1;
        let mut wrong_tag = publication.manifest().clone();
        wrong_tag.stdout.ciphertext_digest = digest_bytes(&wrong_tag_bytes);
        resign(&mut wrong_tag, &fixture.signer);
        assert!(matches!(
            fixture.verify(&wrong_tag, &wrong_tag_bytes, publication.stderr_r2_bytes()),
            Err(ManifestV2Error::AuthenticationFailed {
                stream: EncryptedStreamLabelV2::Stdout
            })
        ));

        let mut wrong_aad = publication.manifest().clone();
        wrong_aad.duration_micros += 1;
        resign(&mut wrong_aad, &fixture.signer);
        assert!(matches!(
            fixture.verify(
                &wrong_aad,
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes()
            ),
            Err(ManifestV2Error::AuthenticationFailed {
                stream: EncryptedStreamLabelV2::Stdout
            })
        ));
    }

    #[test]
    fn unsigned_field_tamper_fails_signature_before_decryption() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();
        let mut manifest = publication.manifest().clone();
        manifest.duration_micros += 1;
        assert!(matches!(
            fixture.verify(
                &manifest,
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes()
            ),
            Err(ManifestV2Error::InvalidSignature)
        ));
    }

    #[test]
    fn stream_swaps_are_rejected_by_stream_specific_aad() {
        let fixture = Fixture::new(b"");
        let publication = fixture.publication();
        let mut swapped = publication.manifest().clone();
        std::mem::swap(&mut swapped.stdout, &mut swapped.stderr);
        resign(&mut swapped, &fixture.signer);
        assert!(matches!(
            fixture.verify(
                &swapped,
                publication.stderr_r2_bytes(),
                publication.stdout_r2_bytes()
            ),
            Err(ManifestV2Error::AuthenticationFailed {
                stream: EncryptedStreamLabelV2::Stdout
            })
        ));
    }

    #[test]
    fn ciphertext_digest_and_size_are_verified_before_decryption() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();
        let mut corrupt = publication.stdout_r2_bytes().to_vec();
        corrupt[0] ^= 1;
        assert!(matches!(
            fixture.verify(
                publication.manifest(),
                &corrupt,
                publication.stderr_r2_bytes()
            ),
            Err(ManifestV2Error::CiphertextDigestMismatch {
                stream: EncryptedStreamLabelV2::Stdout
            })
        ));
        assert!(matches!(
            fixture.verify(
                publication.manifest(),
                &publication.stdout_r2_bytes()[1..],
                publication.stderr_r2_bytes()
            ),
            Err(ManifestV2Error::CiphertextSizeMismatch {
                stream: EncryptedStreamLabelV2::Stdout
            })
        ));
    }

    #[test]
    fn all_request_scope_bindings_are_checked() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();
        for (index, expected) in [
            ManifestV2Error::TenantMismatch,
            ManifestV2Error::RepositoryMismatch,
            ManifestV2Error::RequestKeyMismatch,
            ManifestV2Error::ExecutionProfileMismatch,
            ManifestV2Error::PlatformMismatch,
            ManifestV2Error::ImageMismatch,
        ]
        .into_iter()
        .enumerate()
        {
            let mut manifest = publication.manifest().clone();
            match index {
                0 => manifest.tenant_id = "tenant-other".into(),
                1 => manifest.repository_id = "repository-other".into(),
                2 => manifest.request_key = fixed_digest(90),
                3 => manifest.execution_profile_digest = fixed_digest(91),
                4 => manifest.platform_digest = fixed_digest(92),
                5 => manifest.image_digest = fixed_digest(93),
                _ => unreachable!(),
            }
            resign(&mut manifest, &fixture.signer);
            let error = fixture
                .verify(
                    &manifest,
                    publication.stdout_r2_bytes(),
                    publication.stderr_r2_bytes(),
                )
                .unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
        }
    }

    #[test]
    fn policy_classifier_and_privacy_mismatches_are_rejected() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();

        let mut policy = publication.manifest().clone();
        policy.policy_digest = fixed_digest(80);
        resign(&mut policy, &fixture.signer);
        assert!(matches!(
            fixture.verify(
                &policy,
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes()
            ),
            Err(ManifestV2Error::PolicyMismatch)
        ));

        let mut classifier = publication.manifest().clone();
        classifier.classifier_digest = fixed_digest(81);
        let (classifier_stdout, classifier_stderr) = reencrypt_and_resign(
            &mut classifier,
            DEFAULT_OUTPUT,
            &fixture.repository_key,
            &fixture.signer,
        );
        assert!(matches!(
            fixture.verify(&classifier, &classifier_stdout, &classifier_stderr),
            Err(ManifestV2Error::ClassifierMismatch)
        ));

        let mut privacy = publication.manifest().clone();
        privacy.privacy.classification = PrivacyClass::Confidential;
        let (privacy_stdout, privacy_stderr) = reencrypt_and_resign(
            &mut privacy,
            DEFAULT_OUTPUT,
            &fixture.repository_key,
            &fixture.signer,
        );
        assert!(matches!(
            fixture.verify(&privacy, &privacy_stdout, &privacy_stderr),
            Err(ManifestV2Error::PrivacyMismatch)
        ));
    }

    #[test]
    fn trust_expiry_allowlist_untrusted_revoked_and_record_revocation_fail() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();
        let other_signer =
            Ed25519Signer::from_secret_key("other-key", "other-producer", &[12; 32]).unwrap();

        let expired_result = verify_and_decrypt_v2(
            publication.manifest(),
            publication.stdout_r2_bytes(),
            publication.stderr_r2_bytes(),
            &fixture.request,
            &fixture.policy,
            &fixture.trust,
            fixture.trust_request(),
            &fixture.repository_key,
            TRUST_EXPIRES_AT,
        );
        assert!(matches!(
            expired_result,
            Err(ManifestV2Error::Trust(TrustBundleError::Expired))
        ));

        let profile_denied = verified_trust(
            &fixture.request,
            vec![producer_binding(&fixture.signer)],
            vec![],
            vec![],
            false,
            TRUST_EXPIRES_AT,
            CREATED_AT,
        );
        assert!(matches!(
            verify_and_decrypt_v2(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &profile_denied,
                fixture.trust_request(),
                &fixture.repository_key,
                150,
            ),
            Err(ManifestV2Error::Trust(
                TrustBundleError::ExecutionProfileDigestNotAllowed
            ))
        ));

        let untrusted = verified_trust(
            &fixture.request,
            vec![producer_binding(&other_signer)],
            vec![],
            vec![],
            true,
            TRUST_EXPIRES_AT,
            CREATED_AT,
        );
        assert!(matches!(
            verify_and_decrypt_v2(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &untrusted,
                fixture.trust_request(),
                &fixture.repository_key,
                150,
            ),
            Err(ManifestV2Error::UntrustedProducer)
        ));

        let revoked = verified_trust(
            &fixture.request,
            vec![producer_binding(&other_signer)],
            vec![PRODUCER_KEY_ID.to_owned()],
            vec![],
            true,
            TRUST_EXPIRES_AT,
            CREATED_AT,
        );
        assert!(matches!(
            verify_and_decrypt_v2(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &revoked,
                fixture.trust_request(),
                &fixture.repository_key,
                150,
            ),
            Err(ManifestV2Error::RevokedKey)
        ));

        let record_revoked = verified_trust(
            &fixture.request,
            vec![producer_binding(&fixture.signer)],
            vec![],
            vec![RECORD_ID.to_owned()],
            true,
            TRUST_EXPIRES_AT,
            CREATED_AT,
        );
        assert!(matches!(
            verify_and_decrypt_v2(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &record_revoked,
                fixture.trust_request(),
                &fixture.repository_key,
                150,
            ),
            Err(ManifestV2Error::RevokedRecord)
        ));
    }

    #[test]
    fn verified_trust_scope_must_match_the_sealed_request_scope() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();
        let wrong_tenant_trust = verified_trust_for_scope(
            &fixture.request,
            "tenant-other",
            REPOSITORY,
            vec![producer_binding(&fixture.signer)],
            vec![],
            vec![],
            true,
            TRUST_EXPIRES_AT,
            CREATED_AT,
        );
        assert!(matches!(
            verify_and_decrypt_v2(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &wrong_tenant_trust,
                fixture.trust_request(),
                &fixture.repository_key,
                150,
            ),
            Err(ManifestV2Error::TenantMismatch)
        ));
        assert!(matches!(
            build_encrypted_publication_with_nonces_v2(
                ManifestV2BuildInput {
                    record_id: RECORD_ID,
                    request: &fixture.request,
                    admitted: &fixture.admitted,
                    signer: &fixture.signer,
                    verified_trust: &wrong_tenant_trust,
                    repository_key: &fixture.repository_key,
                    now_unix_seconds: CREATED_AT,
                    created_at_unix_seconds: CREATED_AT,
                    expires_at_unix_seconds: EXPIRES_AT,
                },
                [1; 24],
                [2; 24],
            ),
            Err(ManifestV2Error::TenantMismatch)
        ));
    }

    #[test]
    fn consumer_rescans_decrypted_output_even_from_an_authorized_signer() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();
        let mut malicious = publication.manifest().clone();
        let secret_output = b"-----BEGIN PRIVATE KEY-----\nnot-for-remote-reuse\n";
        let (stdout, stderr) = reencrypt_and_resign(
            &mut malicious,
            secret_output,
            &fixture.repository_key,
            &fixture.signer,
        );
        assert!(matches!(
            fixture.verify(&malicious, &stdout, &stderr),
            Err(ManifestV2Error::ConsumerPrivacyGateRejected)
        ));
    }

    #[test]
    fn artifact_lifetime_is_independent_but_every_use_requires_fresh_trust() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let longer_lived = build_encrypted_publication_with_nonces_v2(
            ManifestV2BuildInput {
                record_id: RECORD_ID,
                request: &fixture.request,
                admitted: &fixture.admitted,
                signer: &fixture.signer,
                verified_trust: &fixture.trust,
                repository_key: &fixture.repository_key,
                now_unix_seconds: CREATED_AT,
                created_at_unix_seconds: CREATED_AT,
                expires_at_unix_seconds: TRUST_EXPIRES_AT + 1,
            },
            [1; 24],
            [2; 24],
        )
        .unwrap();
        assert_eq!(
            longer_lived.manifest().expires_at_unix_seconds,
            TRUST_EXPIRES_AT + 1
        );
        assert!(matches!(
            verify_and_decrypt_v2(
                longer_lived.manifest(),
                longer_lived.stdout_r2_bytes(),
                longer_lived.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &fixture.trust,
                fixture.trust_request(),
                &fixture.repository_key,
                TRUST_EXPIRES_AT,
            ),
            Err(ManifestV2Error::Trust(TrustBundleError::Expired))
        ));
        let renewed_trust = verified_trust(
            &fixture.request,
            vec![producer_binding(&fixture.signer)],
            vec![],
            vec![],
            true,
            350,
            CREATED_AT,
        );
        assert!(
            verify_and_decrypt_v2(
                longer_lived.manifest(),
                longer_lived.stdout_r2_bytes(),
                longer_lived.stderr_r2_bytes(),
                &fixture.request,
                &fixture.policy,
                &renewed_trust,
                fixture.trust_request(),
                &fixture.repository_key,
                TRUST_EXPIRES_AT,
            )
            .is_ok()
        );

        let publication = fixture.publication();
        let mut expired = publication.manifest().clone();
        expired.expires_at_unix_seconds = 140;
        resign(&mut expired, &fixture.signer);
        assert!(matches!(
            fixture.verify(
                &expired,
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes()
            ),
            Err(ManifestV2Error::Expired)
        ));
    }

    #[test]
    fn plaintext_and_key_material_are_absent_from_wire_and_debug_views() {
        let plaintext = b"UNIQUE PLAINTEXT THAT MUST NEVER APPEAR IN MANIFEST OR R2 BYTES 7f19";
        let fixture = Fixture::new(plaintext);
        let publication = fixture.publication();
        let manifest_json = serde_json::to_vec(publication.manifest()).unwrap();
        assert!(!contains_subslice(&manifest_json, plaintext));
        assert!(!contains_subslice(publication.stdout_r2_bytes(), plaintext));
        assert!(!contains_subslice(publication.stderr_r2_bytes(), plaintext));
        assert!(!format!("{publication:?}").contains("UNIQUE PLAINTEXT"));
        assert!(!format!("{:?}", fixture.repository_key).contains("09090909"));
        let verified = fixture
            .verify(
                publication.manifest(),
                publication.stdout_r2_bytes(),
                publication.stderr_r2_bytes(),
            )
            .unwrap();
        assert!(!format!("{verified:?}").contains("UNIQUE PLAINTEXT"));
    }

    #[test]
    fn strict_manifest_serde_rejects_unknown_fields() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let publication = fixture.publication();
        let mut value = serde_json::to_value(publication.manifest()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("future_field".into(), Value::Bool(true));
        assert!(serde_json::from_value::<EncryptedRemoteCacheManifestV2>(value).is_err());
    }

    #[test]
    fn local_capability_requires_two_zero_exit_empty_stderr_matching_runs() {
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let nonzero = validate_two_complete_executions_v1(
            &fixture.request,
            CompleteLocalExecutionV1::from_complete_capture(Some(1), b"x", b"", 1),
            CompleteLocalExecutionV1::from_complete_capture(Some(0), b"x", b"", 1),
            "producer-v1",
        );
        assert!(matches!(
            nonzero,
            Err(LocalResultValidationError::NonZeroExit { run: 1, code: 1 })
        ));

        let stderr = validate_two_complete_executions_v1(
            &fixture.request,
            CompleteLocalExecutionV1::from_complete_capture(Some(0), b"x", b"warning", 1),
            CompleteLocalExecutionV1::from_complete_capture(Some(0), b"x", b"warning", 1),
            "producer-v1",
        );
        assert!(matches!(
            stderr,
            Err(LocalResultValidationError::NonEmptyStderr { run: 1, .. })
        ));

        let mismatch = validate_two_complete_executions_v1(
            &fixture.request,
            CompleteLocalExecutionV1::from_complete_capture(Some(0), b"first", b"", 1),
            CompleteLocalExecutionV1::from_complete_capture(Some(0), b"second", b"", 1),
            "producer-v1",
        );
        assert!(matches!(
            mismatch,
            Err(LocalResultValidationError::ExecutionMismatch)
        ));

        // There is intentionally no one-run constructor for
        // `ValidatedLocalResultV1`; its fields are module-private and the only
        // minting function has two required execution arguments.
    }

    #[test]
    fn plaintext_limit_leaves_exact_room_for_the_r2_authentication_tag() {
        assert_eq!(MAX_V2_CIPHERTEXT_STREAM_BYTES, MAX_BLOB_SIZE);
        assert_eq!(
            MAX_V2_PLAINTEXT_STREAM_BYTES + POLY1305_TAG_BYTES,
            MAX_BLOB_SIZE
        );
        let fixture = Fixture::new(DEFAULT_OUTPUT);
        let at_limit = vec![b'x'; MAX_V2_PLAINTEXT_STREAM_BYTES as usize];
        let admitted = validate_two_complete_executions_v1(
            &fixture.request,
            CompleteLocalExecutionV1::from_complete_capture(Some(0), &at_limit, b"", 1),
            CompleteLocalExecutionV1::from_complete_capture(Some(0), &at_limit, b"", 2),
            "producer-v1",
        )
        .unwrap();
        assert_eq!(admitted.stdout.len() as u64, MAX_V2_PLAINTEXT_STREAM_BYTES);
        drop(admitted);
        drop(at_limit);

        let over_limit = vec![b'x'; MAX_V2_PLAINTEXT_STREAM_BYTES as usize + 1];
        assert!(matches!(
            validate_two_complete_executions_v1(
                &fixture.request,
                CompleteLocalExecutionV1::from_complete_capture(Some(0), &over_limit, b"", 1,),
                CompleteLocalExecutionV1::from_complete_capture(Some(0), &over_limit, b"", 2,),
                "producer-v1",
            ),
            Err(LocalResultValidationError::OversizeStdout { run: 1, .. })
        ));
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }
}
