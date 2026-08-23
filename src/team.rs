//! Versioned wire types and fail-closed verification for the day-30 shared cache.
//!
//! The [`crate::team_crypto`] adapter supplies the reviewed Ed25519
//! implementation. The bytes authenticated by that verifier are a manual,
//! length-prefixed encoding; JSON field order is never part of the protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub const REMOTE_CACHE_SCHEMA_VERSION: u16 = 1;
pub const SIGNATURE_ENVELOPE_SCHEMA_VERSION: u16 = 1;
pub const MAX_BLOB_SIZE: u64 = 16 * 1024 * 1024;
pub const MAX_MANIFEST_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const MAX_JSON_SAFE_INTEGER: u64 = (1 << 53) - 1;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

const SIGNING_DOMAIN: &[u8] = b"again.remote-cache.manifest.v1";

/// A lower-case BLAKE3 digest encoded as 64 hexadecimal characters on the
/// wire. Keeping the decoded bytes here makes canonical signing independent
/// of textual formatting.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn from_hex(value: &str) -> Result<Self, DigestError> {
        if value.len() != 64 {
            return Err(DigestError::Length);
        }
        if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DigestError::Hex);
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(DigestError::Uppercase);
        }
        let mut bytes = [0u8; 32];
        let encoded = value.as_bytes();
        for (index, output) in bytes.iter_mut().enumerate() {
            *output = (hex_nibble(encoded[index * 2]) << 4) | hex_nibble(encoded[index * 2 + 1]);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DigestError {
    #[error("digest must contain exactly 64 hexadecimal characters")]
    Length,
    #[error("digest contains a non-hexadecimal character")]
    Hex,
    #[error("digest must use lower-case hexadecimal")]
    Uppercase,
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest syntax was validated before decoding"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BlobRef {
    pub digest: Digest,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    Public,
    Internal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Shareability {
    /// The result must not leave the local cache.
    LocalOnly,
    /// The result may be shared within the tenant, subject to this protocol's
    /// repository binding.
    Tenant,
    /// The result may be shared with members of this repository.
    Repository,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PrivacyMetadata {
    pub classification: PrivacyClass,
    pub shareability: Shareability,
    pub secret_tainted: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub schema_version: u16,
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub signature: Vec<u8>,
}

/// A signed, content-addressed result description. Blob bytes are transferred
/// separately; this record binds their digests and exact sizes to the request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RemoteCacheManifest {
    pub schema_version: u16,
    pub record_id: String,
    pub tenant_id: String,
    pub repository_id: String,
    pub request_key: Digest,
    pub policy_digest: Digest,
    pub execution_profile_digest: Digest,
    pub platform_digest: Digest,
    pub image_digest: Digest,
    pub stdout: BlobRef,
    pub stderr: BlobRef,
    pub producer_id: String,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub privacy: PrivacyMetadata,
    pub signature: Option<SignatureEnvelope>,
}

impl RemoteCacheManifest {
    /// Return the exact bytes a signature implementation must authenticate.
    /// Every variable-width field has a byte length prefix, and enums/numbers
    /// have explicit fixed-width encodings.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);
        put_bytes(&mut bytes, SIGNING_DOMAIN);
        put_u16(&mut bytes, self.schema_version);
        put_string(&mut bytes, &self.record_id);
        put_string(&mut bytes, &self.tenant_id);
        put_string(&mut bytes, &self.repository_id);
        put_digest(&mut bytes, &self.request_key);
        put_digest(&mut bytes, &self.policy_digest);
        put_digest(&mut bytes, &self.execution_profile_digest);
        put_digest(&mut bytes, &self.platform_digest);
        put_digest(&mut bytes, &self.image_digest);
        put_blob(&mut bytes, &self.stdout);
        put_blob(&mut bytes, &self.stderr);
        put_string(&mut bytes, &self.producer_id);
        put_u64(&mut bytes, self.created_at_unix_seconds);
        put_u64(&mut bytes, self.expires_at_unix_seconds);
        put_u8(&mut bytes, privacy_class_tag(self.privacy.classification));
        put_u8(&mut bytes, shareability_tag(self.privacy.shareability));
        put_u8(&mut bytes, u8::from(self.privacy.secret_tainted));
        match &self.signature {
            Some(signature) => {
                put_u8(&mut bytes, 1);
                put_u16(&mut bytes, signature.schema_version);
                put_u8(&mut bytes, signature_algorithm_tag(signature.algorithm));
                put_string(&mut bytes, &signature.key_id);
            }
            None => put_u8(&mut bytes, 0),
        }
        bytes
    }

    pub(crate) fn validate_for_signing(&self) -> Result<(), VerificationError> {
        if self.schema_version != REMOTE_CACHE_SCHEMA_VERSION {
            return Err(VerificationError::UnknownSchemaVersion);
        }
        for value in [
            (&self.record_id, "record_id"),
            (&self.tenant_id, "tenant_id"),
            (&self.repository_id, "repository_id"),
            (&self.producer_id, "producer_id"),
        ] {
            validate_identifier(value.0)
                .map_err(|_| VerificationError::InvalidIdentifier(value.1))?;
        }
        validate_blob(&self.stdout)?;
        validate_blob(&self.stderr)?;
        if self.created_at_unix_seconds > MAX_JSON_SAFE_INTEGER
            || self.expires_at_unix_seconds > MAX_JSON_SAFE_INTEGER
        {
            return Err(VerificationError::TimestampOutOfRange);
        }
        if self.expires_at_unix_seconds <= self.created_at_unix_seconds
            || self.expires_at_unix_seconds - self.created_at_unix_seconds
                > MAX_MANIFEST_LIFETIME_SECONDS
        {
            return Err(VerificationError::InvalidLifetime);
        }
        if self.privacy.secret_tainted || self.privacy.classification == PrivacyClass::Secret {
            return Err(VerificationError::SecretTainted);
        }
        if self.privacy.shareability == Shareability::LocalOnly {
            return Err(VerificationError::Unshareable);
        }
        let signature = self.signature.as_ref().ok_or(VerificationError::Unsigned)?;
        if signature.schema_version != SIGNATURE_ENVELOPE_SCHEMA_VERSION {
            return Err(VerificationError::UnknownSignatureSchemaVersion);
        }
        validate_identifier(&signature.key_id)
            .map_err(|_| VerificationError::InvalidIdentifier("signature.key_id"))?;
        Ok(())
    }

    fn validate_wire(&self) -> Result<(), VerificationError> {
        self.validate_for_signing()?;
        let signature = self.signature.as_ref().ok_or(VerificationError::Unsigned)?;
        if signature.signature.len() != ED25519_SIGNATURE_SIZE {
            return Err(VerificationError::InvalidSignatureSize);
        }
        Ok(())
    }
}

fn validate_blob(blob: &BlobRef) -> Result<(), VerificationError> {
    if blob.size_bytes > MAX_BLOB_SIZE {
        return Err(VerificationError::InvalidBlobSize);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        Err(())
    } else {
        Ok(())
    }
}

/// The client's complete binding for which a remote result was requested.
///
/// This is a verification input, not an authenticated trust object: callers
/// must recompute the expected digests locally and populate key authorization,
/// revocation, and time from fresh trusted sources. The v1 type carries no
/// source, freshness epoch, tenant-policy version, or authenticated envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationContext {
    pub tenant_id: String,
    pub repository_id: String,
    pub request_key: Digest,
    pub policy_digest: Digest,
    pub execution_profile_digest: Digest,
    pub platform_digest: Digest,
    pub image_digest: Digest,
    pub now_unix_seconds: u64,
    /// Explicit key-to-producer authorization for this tenant/repository.
    pub trusted_producer_keys: BTreeMap<String, String>,
    pub revoked_key_ids: BTreeSet<String>,
    pub revoked_record_ids: BTreeSet<String>,
}

/// The result of verification retains the original manifest only after all
/// bindings, lifecycle, privacy, and signature checks have succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedCandidate<'a> {
    pub manifest: &'a RemoteCacheManifest,
}

/// Cryptographic verification is deliberately injected. Again does not claim
/// that a homemade hash or MAC is a signature implementation.
pub trait SignatureVerifier {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        key_id: &str,
        producer_id: &str,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> bool;
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    #[error("unknown remote-cache schema version")]
    UnknownSchemaVersion,
    #[error("unknown signature-envelope schema version")]
    UnknownSignatureSchemaVersion,
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("manifest is unsigned")]
    Unsigned,
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(&'static str),
    #[error("invalid blob size")]
    InvalidBlobSize,
    #[error("invalid signature size")]
    InvalidSignatureSize,
    #[error("manifest timestamp exceeds the shared JSON safe-integer range")]
    TimestampOutOfRange,
    #[error("invalid creation/expiry interval")]
    InvalidLifetime,
    #[error("candidate has expired")]
    Expired,
    #[error("candidate was created in the future")]
    CreatedInFuture,
    #[error("signing key is revoked")]
    RevokedKey,
    #[error("signing key is not authorized for the claimed producer")]
    UntrustedProducer,
    #[error("record is revoked")]
    RevokedRecord,
    #[error("tenant binding mismatch")]
    TenantMismatch,
    #[error("repository binding mismatch")]
    RepositoryMismatch,
    #[error("request-key binding mismatch")]
    RequestKeyMismatch,
    #[error("policy binding mismatch")]
    PolicyMismatch,
    #[error("execution-profile binding mismatch")]
    ExecutionProfileMismatch,
    #[error("platform binding mismatch")]
    PlatformMismatch,
    #[error("image binding mismatch")]
    ImageMismatch,
    #[error("candidate is not shareable")]
    Unshareable,
    #[error("candidate is secret-tainted")]
    SecretTainted,
    #[error("signature verification failed")]
    InvalidSignature,
}

pub fn verify_candidate<'a, V: SignatureVerifier>(
    manifest: &'a RemoteCacheManifest,
    expected: &VerificationContext,
    verifier: &V,
) -> Result<VerifiedCandidate<'a>, VerificationError> {
    manifest.validate_wire()?;
    validate_identifier(&expected.tenant_id)
        .map_err(|_| VerificationError::InvalidIdentifier("expected.tenant_id"))?;
    validate_identifier(&expected.repository_id)
        .map_err(|_| VerificationError::InvalidIdentifier("expected.repository_id"))?;
    if manifest.tenant_id != expected.tenant_id {
        return Err(VerificationError::TenantMismatch);
    }
    if manifest.repository_id != expected.repository_id {
        return Err(VerificationError::RepositoryMismatch);
    }
    if manifest.request_key != expected.request_key {
        return Err(VerificationError::RequestKeyMismatch);
    }
    if manifest.policy_digest != expected.policy_digest {
        return Err(VerificationError::PolicyMismatch);
    }
    if manifest.execution_profile_digest != expected.execution_profile_digest {
        return Err(VerificationError::ExecutionProfileMismatch);
    }
    if manifest.platform_digest != expected.platform_digest {
        return Err(VerificationError::PlatformMismatch);
    }
    if manifest.image_digest != expected.image_digest {
        return Err(VerificationError::ImageMismatch);
    }
    if expected.now_unix_seconds < manifest.created_at_unix_seconds {
        return Err(VerificationError::CreatedInFuture);
    }
    if expected.now_unix_seconds >= manifest.expires_at_unix_seconds {
        return Err(VerificationError::Expired);
    }
    if expected.revoked_record_ids.contains(&manifest.record_id) {
        return Err(VerificationError::RevokedRecord);
    }
    let signature = manifest
        .signature
        .as_ref()
        .ok_or(VerificationError::Unsigned)?;
    if expected.revoked_key_ids.contains(&signature.key_id) {
        return Err(VerificationError::RevokedKey);
    }
    if expected
        .trusted_producer_keys
        .get(&signature.key_id)
        .is_none_or(|producer| producer != &manifest.producer_id)
    {
        return Err(VerificationError::UntrustedProducer);
    }
    if !verifier.verify(
        signature.algorithm,
        &signature.key_id,
        &manifest.producer_id,
        &manifest.canonical_signing_bytes(),
        &signature.signature,
    ) {
        return Err(VerificationError::InvalidSignature);
    }
    Ok(VerifiedCandidate { manifest })
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

fn put_blob(output: &mut Vec<u8>, value: &BlobRef) {
    put_digest(output, &value.digest);
    put_u64(output, value.size_bytes);
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
    use super::*;
    use serde_json::json;

    const A: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const B: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const C: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const D: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const E: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const F: &str = "5555555555555555555555555555555555555555555555555555555555555555";

    struct FakeVerifier {
        expected_bytes: Vec<u8>,
        expected_key: String,
        valid_signature: Vec<u8>,
    }

    impl SignatureVerifier for FakeVerifier {
        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            key_id: &str,
            _producer_id: &str,
            signing_bytes: &[u8],
            signature: &[u8],
        ) -> bool {
            algorithm == SignatureAlgorithm::Ed25519
                && key_id == self.expected_key
                && signing_bytes == self.expected_bytes
                && signature == self.valid_signature
        }
    }

    fn digest(value: &str) -> Digest {
        Digest::from_hex(value).unwrap()
    }

    fn fixture() -> RemoteCacheManifest {
        RemoteCacheManifest {
            schema_version: REMOTE_CACHE_SCHEMA_VERSION,
            record_id: "record-1".into(),
            tenant_id: "tenant-a".into(),
            repository_id: "repo-a".into(),
            request_key: digest(A),
            policy_digest: digest(B),
            execution_profile_digest: digest(C),
            platform_digest: digest(D),
            image_digest: digest(E),
            stdout: BlobRef {
                digest: digest(F),
                size_bytes: 12,
            },
            stderr: BlobRef {
                digest: digest(A),
                size_bytes: 0,
            },
            producer_id: "producer-1".into(),
            created_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            privacy: PrivacyMetadata {
                classification: PrivacyClass::Internal,
                shareability: Shareability::Repository,
                secret_tainted: false,
            },
            signature: Some(SignatureEnvelope {
                schema_version: SIGNATURE_ENVELOPE_SCHEMA_VERSION,
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "key-1".into(),
                signature: vec![0; ED25519_SIGNATURE_SIZE],
            }),
        }
    }

    fn expected(manifest: &RemoteCacheManifest) -> VerificationContext {
        VerificationContext {
            tenant_id: manifest.tenant_id.clone(),
            repository_id: manifest.repository_id.clone(),
            request_key: manifest.request_key,
            policy_digest: manifest.policy_digest,
            execution_profile_digest: manifest.execution_profile_digest,
            platform_digest: manifest.platform_digest,
            image_digest: manifest.image_digest,
            now_unix_seconds: 150,
            trusted_producer_keys: BTreeMap::from([("key-1".into(), "producer-1".into())]),
            revoked_key_ids: BTreeSet::new(),
            revoked_record_ids: BTreeSet::new(),
        }
    }

    fn verifier(manifest: &RemoteCacheManifest) -> FakeVerifier {
        FakeVerifier {
            expected_bytes: manifest.canonical_signing_bytes(),
            expected_key: "key-1".into(),
            valid_signature: vec![0; ED25519_SIGNATURE_SIZE],
        }
    }

    #[test]
    fn valid_fixture_verifies_and_canonical_bytes_are_stable() {
        let manifest = fixture();
        let context = expected(&manifest);
        let verifier = verifier(&manifest);
        assert_eq!(
            verify_candidate(&manifest, &context, &verifier)
                .unwrap()
                .manifest,
            &manifest
        );
        assert_eq!(
            manifest.canonical_signing_bytes(),
            manifest.canonical_signing_bytes()
        );
        let encoded = serde_json::to_string(&manifest).unwrap();
        let decoded: RemoteCacheManifest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn every_binding_mismatch_is_rejected() {
        let manifest = fixture();
        let verifier = verifier(&manifest);
        for (name, mutate, expected_error) in [
            ("tenant", 0, VerificationError::TenantMismatch),
            ("repository", 1, VerificationError::RepositoryMismatch),
            ("request", 2, VerificationError::RequestKeyMismatch),
            ("policy", 3, VerificationError::PolicyMismatch),
            ("profile", 4, VerificationError::ExecutionProfileMismatch),
            ("platform", 5, VerificationError::PlatformMismatch),
            ("image", 6, VerificationError::ImageMismatch),
        ] {
            let mut context = expected(&manifest);
            match mutate {
                0 => context.tenant_id = "tenant-other".into(),
                1 => context.repository_id = "repo-other".into(),
                2 => context.request_key = digest(B),
                3 => context.policy_digest = digest(C),
                4 => context.execution_profile_digest = digest(D),
                5 => context.platform_digest = digest(E),
                6 => context.image_digest = digest(F),
                _ => unreachable!(),
            }
            assert_eq!(
                verify_candidate(&manifest, &context, &verifier).unwrap_err(),
                expected_error,
                "{name} mismatch"
            );
        }
    }

    #[test]
    fn lifecycle_revocation_privacy_and_signature_fail_closed() {
        let base = fixture();
        let verifier = verifier(&base);

        let mut expired = base.clone();
        expired.expires_at_unix_seconds = 150;
        assert_eq!(
            verify_candidate(&expired, &expected(&expired), &verifier),
            Err(VerificationError::Expired)
        );

        let mut future_context = expected(&base);
        future_context.now_unix_seconds = 99;
        assert_eq!(
            verify_candidate(&base, &future_context, &verifier),
            Err(VerificationError::CreatedInFuture)
        );

        let mut revoked_key = expected(&base);
        revoked_key.revoked_key_ids.insert("key-1".into());
        assert_eq!(
            verify_candidate(&base, &revoked_key, &verifier),
            Err(VerificationError::RevokedKey)
        );

        let mut revoked_record = expected(&base);
        revoked_record.revoked_record_ids.insert("record-1".into());
        assert_eq!(
            verify_candidate(&base, &revoked_record, &verifier),
            Err(VerificationError::RevokedRecord)
        );

        let mut untrusted_producer = expected(&base);
        untrusted_producer.trusted_producer_keys.clear();
        assert_eq!(
            verify_candidate(&base, &untrusted_producer, &verifier),
            Err(VerificationError::UntrustedProducer)
        );

        let mut wrong_producer = expected(&base);
        wrong_producer
            .trusted_producer_keys
            .insert("key-1".into(), "producer-other".into());
        assert_eq!(
            verify_candidate(&base, &wrong_producer, &verifier),
            Err(VerificationError::UntrustedProducer)
        );

        let mut local = base.clone();
        local.privacy.shareability = Shareability::LocalOnly;
        assert_eq!(
            verify_candidate(&local, &expected(&local), &verifier),
            Err(VerificationError::Unshareable)
        );

        let mut tainted = base.clone();
        tainted.privacy.secret_tainted = true;
        assert_eq!(
            verify_candidate(&tainted, &expected(&tainted), &verifier),
            Err(VerificationError::SecretTainted)
        );

        let mut secret = base.clone();
        secret.privacy.classification = PrivacyClass::Secret;
        assert_eq!(
            verify_candidate(&secret, &expected(&secret), &verifier),
            Err(VerificationError::SecretTainted)
        );

        let mut unsigned = base.clone();
        unsigned.signature = None;
        assert_eq!(
            verify_candidate(&unsigned, &expected(&unsigned), &verifier),
            Err(VerificationError::Unsigned)
        );

        let mut bad_signature = base.clone();
        bad_signature.signature.as_mut().unwrap().signature[0] = 1;
        assert_eq!(
            verify_candidate(&bad_signature, &expected(&bad_signature), &verifier),
            Err(VerificationError::InvalidSignature)
        );
    }

    #[test]
    fn unknown_versions_invalid_sizes_and_digests_are_rejected() {
        let base = fixture();
        let verifier = verifier(&base);

        let mut schema = base.clone();
        schema.schema_version = 99;
        assert_eq!(
            verify_candidate(&schema, &expected(&schema), &verifier),
            Err(VerificationError::UnknownSchemaVersion)
        );

        let mut signature_schema = base.clone();
        signature_schema.signature.as_mut().unwrap().schema_version = 99;
        assert_eq!(
            verify_candidate(&signature_schema, &expected(&signature_schema), &verifier),
            Err(VerificationError::UnknownSignatureSchemaVersion)
        );

        let mut size = base.clone();
        size.stdout.size_bytes = MAX_BLOB_SIZE + 1;
        assert_eq!(
            verify_candidate(&size, &expected(&size), &verifier),
            Err(VerificationError::InvalidBlobSize)
        );

        let mut oversized_signature = base.clone();
        oversized_signature.signature.as_mut().unwrap().signature =
            vec![0; ED25519_SIGNATURE_SIZE + 1];
        assert_eq!(
            verify_candidate(
                &oversized_signature,
                &expected(&oversized_signature),
                &verifier
            ),
            Err(VerificationError::InvalidSignatureSize)
        );

        let mut undersized_signature = base.clone();
        undersized_signature.signature.as_mut().unwrap().signature =
            vec![0; ED25519_SIGNATURE_SIZE - 1];
        assert_eq!(
            verify_candidate(
                &undersized_signature,
                &expected(&undersized_signature),
                &verifier
            ),
            Err(VerificationError::InvalidSignatureSize)
        );

        let mut unknown_digest = serde_json::to_value(&base).unwrap();
        unknown_digest["request_key"] = json!("not-a-digest");
        assert!(serde_json::from_value::<RemoteCacheManifest>(unknown_digest).is_err());

        let mut uppercase_digest = serde_json::to_value(&base).unwrap();
        uppercase_digest["request_key"] = json!(format!("{}ABCD", "ABCDEF".repeat(10)));
        assert!(serde_json::from_value::<RemoteCacheManifest>(uppercase_digest).is_err());

        let mut unknown_algorithm = serde_json::to_value(&base).unwrap();
        unknown_algorithm["signature"]["algorithm"] = json!("rsa_pss");
        assert!(serde_json::from_value::<RemoteCacheManifest>(unknown_algorithm).is_err());
    }

    #[test]
    fn wire_parser_rejects_unknown_fields_without_panicking_on_unicode_digests() {
        let base = fixture();

        let mut unknown_top_level = serde_json::to_value(&base).unwrap();
        unknown_top_level["requires_attestation"] = json!(true);
        assert!(serde_json::from_value::<RemoteCacheManifest>(unknown_top_level).is_err());

        let mut unknown_nested = serde_json::to_value(&base).unwrap();
        unknown_nested["stdout"]["compression"] = json!("zstd");
        assert!(serde_json::from_value::<RemoteCacheManifest>(unknown_nested).is_err());

        let mut unicode_digest = serde_json::to_value(&base).unwrap();
        unicode_digest["request_key"] = json!(format!("€{}", "0".repeat(61)));
        let parsed = std::panic::catch_unwind(|| {
            serde_json::from_value::<RemoteCacheManifest>(unicode_digest)
        });
        assert!(parsed.is_ok(), "malformed remote JSON must not panic");
        assert!(parsed.unwrap().is_err());
    }

    #[test]
    fn lifetime_timestamp_and_identifier_rules_match_the_service_wire_contract() {
        let mut long_lived = fixture();
        long_lived.expires_at_unix_seconds =
            long_lived.created_at_unix_seconds + MAX_MANIFEST_LIFETIME_SECONDS + 1;
        let long_lived_verifier = verifier(&long_lived);
        assert_eq!(
            verify_candidate(&long_lived, &expected(&long_lived), &long_lived_verifier),
            Err(VerificationError::InvalidLifetime)
        );

        let mut unsafe_timestamp = fixture();
        unsafe_timestamp.created_at_unix_seconds = MAX_JSON_SAFE_INTEGER + 1;
        unsafe_timestamp.expires_at_unix_seconds = MAX_JSON_SAFE_INTEGER + 2;
        let unsafe_timestamp_verifier = verifier(&unsafe_timestamp);
        assert_eq!(
            verify_candidate(
                &unsafe_timestamp,
                &expected(&unsafe_timestamp),
                &unsafe_timestamp_verifier
            ),
            Err(VerificationError::TimestampOutOfRange)
        );

        let mut c1_control = fixture();
        c1_control.record_id = "record\u{80}".into();
        let c1_verifier = verifier(&c1_control);
        assert_eq!(
            verify_candidate(&c1_control, &expected(&c1_control), &c1_verifier),
            Err(VerificationError::InvalidIdentifier("record_id"))
        );

        let mut byte_order_mark = fixture();
        byte_order_mark.record_id = "record\u{feff}".into();
        let bom_verifier = verifier(&byte_order_mark);
        assert!(
            verify_candidate(&byte_order_mark, &expected(&byte_order_mark), &bom_verifier).is_ok()
        );
    }

    #[test]
    fn canonical_encoding_is_length_delimited_and_binds_all_fields() {
        let base = fixture();
        let base_bytes = base.canonical_signing_bytes();
        let mut changed = base.clone();
        changed.record_id = "record-1:changed".into();
        assert_ne!(base_bytes, changed.canonical_signing_bytes());

        let mut changed_size = base.clone();
        changed_size.stdout.size_bytes += 1;
        assert_ne!(base_bytes, changed_size.canonical_signing_bytes());

        let mut changed_signature_metadata = base.clone();
        changed_signature_metadata
            .signature
            .as_mut()
            .unwrap()
            .key_id = "key-2".into();
        assert_ne!(
            base_bytes,
            changed_signature_metadata.canonical_signing_bytes()
        );
    }
}
