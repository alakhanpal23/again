//! Ed25519 implementation for the shared-cache trust boundary.
//!
//! Key material is accepted only in the fixed-size raw formats defined by
//! ed25519-dalek. This module never falls back to hashes, MACs, or a permissive
//! parser when a key or signature is malformed.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::team::{
    ED25519_SIGNATURE_SIZE, RemoteCacheManifest, SIGNATURE_ENVELOPE_SCHEMA_VERSION,
    SignatureAlgorithm, SignatureEnvelope, SignatureVerifier, VerificationError,
};

const ED25519_SECRET_KEY_BYTES: usize = 32;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("{0} is empty or contains whitespace/control characters")]
    InvalidIdentifier(&'static str),
    #[error("Ed25519 secret key must be exactly 32 bytes")]
    InvalidSecretKeyLength,
    #[error("Ed25519 public key must be exactly 32 bytes")]
    InvalidPublicKeyLength,
    #[error("Ed25519 public key is not a valid compressed point")]
    InvalidPublicKey,
    #[error("manifest producer does not match signing key owner")]
    ProducerMismatch,
    #[error("manifest already carries a different signing key")]
    KeyMismatch,
    #[error("key id is already bound to different key material or producer")]
    KeyIdCollision,
    #[error("manifest is not signable: {0}")]
    InvalidManifest(#[source] VerificationError),
}

/// A signing key with an explicit key-id and producer binding.
#[derive(Debug)]
pub struct Ed25519Signer {
    key_id: String,
    producer_id: String,
    signing_key: SigningKey,
}

impl Ed25519Signer {
    pub fn from_secret_key(
        key_id: &str,
        producer_id: &str,
        secret_key: &[u8],
    ) -> Result<Self, CryptoError> {
        validate_identifier(key_id, "key_id")?;
        validate_identifier(producer_id, "producer_id")?;
        let key_bytes: [u8; ED25519_SECRET_KEY_BYTES] = secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidSecretKeyLength)?;
        Ok(Self {
            key_id: key_id.to_owned(),
            producer_id: producer_id.to_owned(),
            signing_key: SigningKey::from_bytes(&key_bytes),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    pub fn public_key_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Signs the manifest's canonical bytes. The signature bytes themselves
    /// are excluded from canonical encoding, while key-id and algorithm are
    /// included, preventing envelope substitution.
    pub fn sign_manifest(&self, manifest: &mut RemoteCacheManifest) -> Result<(), CryptoError> {
        if manifest.producer_id != self.producer_id {
            return Err(CryptoError::ProducerMismatch);
        }
        if manifest
            .signature
            .as_ref()
            .is_some_and(|signature| signature.key_id != self.key_id)
        {
            return Err(CryptoError::KeyMismatch);
        }
        let mut candidate = manifest.clone();
        candidate.signature = Some(SignatureEnvelope {
            schema_version: SIGNATURE_ENVELOPE_SCHEMA_VERSION,
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: self.key_id.clone(),
            // A fixed-size placeholder keeps signing independent of whether a
            // caller previously supplied a signature. It is not authenticated.
            signature: vec![0; ED25519_SIGNATURE_SIZE],
        });
        candidate
            .validate_for_signing()
            .map_err(CryptoError::InvalidManifest)?;
        let signature = self.signing_key.sign(&candidate.canonical_signing_bytes());
        candidate
            .signature
            .as_mut()
            .expect("signature just installed")
            .signature = signature.to_bytes().to_vec();
        manifest.signature = candidate.signature;
        Ok(())
    }
}

/// A verifier keyring. The producer value is retained for callers that need
/// to build `VerificationContext::trusted_producer_keys`; candidate
/// verification performs that binding before invoking the cryptographic check.
#[derive(Debug, Default)]
pub struct Ed25519Verifier {
    keys: BTreeMap<String, (String, VerifyingKey)>,
}

impl Ed25519Verifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_public_key(
        key_id: &str,
        producer_id: &str,
        public_key: &[u8],
    ) -> Result<Self, CryptoError> {
        let mut verifier = Self::new();
        verifier.insert_public_key(key_id, producer_id, public_key)?;
        Ok(verifier)
    }

    pub fn insert_public_key(
        &mut self,
        key_id: &str,
        producer_id: &str,
        public_key: &[u8],
    ) -> Result<(), CryptoError> {
        validate_identifier(key_id, "key_id")?;
        validate_identifier(producer_id, "producer_id")?;
        let key_bytes: [u8; ED25519_PUBLIC_KEY_BYTES] = public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKeyLength)?;
        let verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        if let Some((existing_producer, existing_key)) = self.keys.get(key_id) {
            if existing_producer == producer_id && existing_key == &verifying_key {
                return Ok(());
            }
            return Err(CryptoError::KeyIdCollision);
        }
        self.keys
            .insert(key_id.to_owned(), (producer_id.to_owned(), verifying_key));
        Ok(())
    }

    pub fn producer_for_key(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).map(|(producer, _)| producer.as_str())
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        key_id: &str,
        producer_id: &str,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> bool {
        if algorithm != SignatureAlgorithm::Ed25519 || signature.len() != ED25519_SIGNATURE_SIZE {
            return false;
        }
        let Some((owner, key)) = self.keys.get(key_id) else {
            return false;
        };
        if owner != producer_id {
            return false;
        }
        let signature_bytes: [u8; ED25519_SIGNATURE_SIZE] = match signature.try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        key.verify_strict(signing_bytes, &Signature::from_bytes(&signature_bytes))
            .is_ok()
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), CryptoError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        Err(CryptoError::InvalidIdentifier(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::team::{
        BlobRef, Digest, PrivacyClass, PrivacyMetadata, RemoteCacheManifest, Shareability,
        VerificationContext, verify_candidate,
    };

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn digest(value: &str) -> Digest {
        Digest::from_hex(value).unwrap()
    }

    fn manifest() -> RemoteCacheManifest {
        RemoteCacheManifest {
            schema_version: 1,
            record_id: "record-crypto".into(),
            tenant_id: "tenant-crypto".into(),
            repository_id: "repo-crypto".into(),
            request_key: digest(ZERO),
            policy_digest: digest(ONE),
            execution_profile_digest: digest(ZERO),
            platform_digest: digest(ONE),
            image_digest: digest(ZERO),
            stdout: BlobRef {
                digest: digest(ONE),
                size_bytes: 5,
            },
            stderr: BlobRef {
                digest: digest(ZERO),
                size_bytes: 0,
            },
            producer_id: "producer-crypto".into(),
            created_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            privacy: PrivacyMetadata {
                classification: PrivacyClass::Internal,
                shareability: Shareability::Repository,
                secret_tainted: false,
            },
            signature: None,
        }
    }

    fn context(
        value: &RemoteCacheManifest,
        key_id: &str,
        producer_id: &str,
    ) -> VerificationContext {
        VerificationContext {
            tenant_id: value.tenant_id.clone(),
            repository_id: value.repository_id.clone(),
            request_key: value.request_key,
            policy_digest: value.policy_digest,
            execution_profile_digest: value.execution_profile_digest,
            platform_digest: value.platform_digest,
            image_digest: value.image_digest,
            now_unix_seconds: 150,
            trusted_producer_keys: BTreeMap::from([(key_id.into(), producer_id.into())]),
            revoked_key_ids: BTreeSet::new(),
            revoked_record_ids: BTreeSet::new(),
        }
    }

    #[test]
    fn signs_and_verifies_real_ed25519_bytes() {
        let signer =
            Ed25519Signer::from_secret_key("key-crypto", "producer-crypto", &[7; 32]).unwrap();
        let mut value = manifest();
        signer.sign_manifest(&mut value).unwrap();
        let verifier = Ed25519Verifier::from_public_key(
            signer.key_id(),
            signer.producer_id(),
            &signer.public_key_bytes(),
        )
        .unwrap();
        assert!(
            verify_candidate(
                &value,
                &context(&value, signer.key_id(), signer.producer_id()),
                &verifier
            )
            .is_ok()
        );
        assert_eq!(
            value.signature.as_ref().unwrap().signature.len(),
            ED25519_SIGNATURE_SIZE
        );
    }

    #[test]
    fn malformed_keys_and_signatures_are_rejected() {
        assert_eq!(
            Ed25519Signer::from_secret_key("key", "producer", &[0; 31]).unwrap_err(),
            CryptoError::InvalidSecretKeyLength
        );
        assert_eq!(
            Ed25519Verifier::from_public_key("key", "producer", &[0; 31]).unwrap_err(),
            CryptoError::InvalidPublicKeyLength
        );
        assert_eq!(
            Ed25519Signer::from_secret_key("key bad", "producer", &[0; 32]).unwrap_err(),
            CryptoError::InvalidIdentifier("key_id")
        );

        let signer =
            Ed25519Signer::from_secret_key("key-crypto", "producer-crypto", &[8; 32]).unwrap();
        let mut value = manifest();
        signer.sign_manifest(&mut value).unwrap();
        let verifier = Ed25519Verifier::from_public_key(
            signer.key_id(),
            signer.producer_id(),
            &signer.public_key_bytes(),
        )
        .unwrap();
        value.signature.as_mut().unwrap().signature = vec![0; ED25519_SIGNATURE_SIZE - 1];
        assert_eq!(
            verify_candidate(
                &value,
                &context(&value, signer.key_id(), signer.producer_id()),
                &verifier
            )
            .unwrap_err(),
            VerificationError::InvalidSignatureSize
        );
        signer.sign_manifest(&mut value).unwrap();
        value.signature.as_mut().unwrap().signature[0] ^= 1;
        assert_eq!(
            verify_candidate(
                &value,
                &context(&value, signer.key_id(), signer.producer_id()),
                &verifier
            )
            .unwrap_err(),
            VerificationError::InvalidSignature
        );
    }

    #[test]
    fn failed_signing_does_not_mutate_an_existing_manifest() {
        let signer =
            Ed25519Signer::from_secret_key("key-crypto", "producer-crypto", &[8; 32]).unwrap();
        let mut value = manifest();
        signer.sign_manifest(&mut value).unwrap();
        value.expires_at_unix_seconds = value.created_at_unix_seconds;
        let before = value.clone();

        assert_eq!(
            signer.sign_manifest(&mut value),
            Err(CryptoError::InvalidManifest(
                VerificationError::InvalidLifetime
            ))
        );
        assert_eq!(value, before);
    }

    #[test]
    fn key_id_and_producer_binding_is_enforced() {
        let signer = Ed25519Signer::from_secret_key("key-a", "producer-a", &[9; 32]).unwrap();
        let mut value = manifest();
        assert_eq!(
            signer.sign_manifest(&mut value),
            Err(CryptoError::ProducerMismatch)
        );
        value.producer_id = "producer-a".into();
        signer.sign_manifest(&mut value).unwrap();
        let verifier =
            Ed25519Verifier::from_public_key("key-a", "producer-a", &signer.public_key_bytes())
                .unwrap();
        let mut wrong_owner = context(&value, "key-a", "producer-other");
        assert_eq!(
            verify_candidate(&value, &wrong_owner, &verifier).unwrap_err(),
            VerificationError::UntrustedProducer
        );
        wrong_owner.trusted_producer_keys.clear();
        assert_eq!(
            verify_candidate(&value, &wrong_owner, &verifier).unwrap_err(),
            VerificationError::UntrustedProducer
        );

        let mut keyring = Ed25519Verifier::new();
        keyring
            .insert_public_key("key-a", "producer-a", &signer.public_key_bytes())
            .unwrap();
        assert_eq!(
            keyring.insert_public_key("key-a", "producer-other", &signer.public_key_bytes()),
            Err(CryptoError::KeyIdCollision)
        );
        assert!(!keyring.verify(
            SignatureAlgorithm::Ed25519,
            "key-a",
            "producer-other",
            &value.canonical_signing_bytes(),
            &value.signature.as_ref().unwrap().signature,
        ));
    }
}
