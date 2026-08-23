use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use again::team::{
    MAX_JSON_SAFE_INTEGER, MAX_MANIFEST_LIFETIME_SECONDS, RemoteCacheManifest, SignatureAlgorithm,
    SignatureVerifier, VerificationContext, VerificationError, verify_candidate,
};

#[test]
fn rust_and_service_share_manifest_v1_canonical_bytes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_bytes = fs::read(root.join("service/test/fixtures/manifest-v1.json")).unwrap();
    let expected_bytes =
        fs::read(root.join("service/test/fixtures/manifest-v1-canonical.json")).unwrap();
    let manifest: RemoteCacheManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    let expected: serde_json::Value = serde_json::from_slice(&expected_bytes).unwrap();
    let expected_hex = expected
        .get("hex_chunks")
        .and_then(|value| value.as_array())
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<String>();
    let actual_hex = to_hex(&manifest.canonical_signing_bytes());
    if actual_hex != expected_hex {
        let first_difference = actual_hex
            .bytes()
            .zip(expected_hex.bytes())
            .position(|(actual, expected)| actual != expected)
            .unwrap_or(actual_hex.len().min(expected_hex.len()));
        let start = first_difference.saturating_sub(24);
        let actual_end = (first_difference + 48).min(actual_hex.len());
        let expected_end = (first_difference + 48).min(expected_hex.len());
        panic!(
            "canonical vector differs at {first_difference}; lengths actual={} expected={}; actual={} expected={}",
            actual_hex.len(),
            expected_hex.len(),
            &actual_hex[start..actual_end],
            &expected_hex[start..expected_end]
        );
    }
}

struct AcceptFixtureSignature;

impl SignatureVerifier for AcceptFixtureSignature {
    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        _key_id: &str,
        _producer_id: &str,
        _signing_bytes: &[u8],
        _signature: &[u8],
    ) -> bool {
        true
    }
}

#[test]
fn rust_manifest_v1_rejection_boundary_matches_service() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let base_bytes = fs::read(root.join("service/test/fixtures/manifest-v1.json")).unwrap();
    let base: serde_json::Value = serde_json::from_slice(&base_bytes).unwrap();

    let mut unknown_top_level = base.clone();
    unknown_top_level["requires_attestation"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RemoteCacheManifest>(unknown_top_level).is_err());

    let mut unknown_nested = base.clone();
    unknown_nested["stdout"]["compression"] = serde_json::json!("zstd");
    assert!(serde_json::from_value::<RemoteCacheManifest>(unknown_nested).is_err());

    let mut unicode_digest = base.clone();
    unicode_digest["request_key"] = serde_json::json!(format!("€{}", "0".repeat(61)));
    let parsed =
        std::panic::catch_unwind(|| serde_json::from_value::<RemoteCacheManifest>(unicode_digest));
    assert!(parsed.is_ok(), "malformed digest JSON must not panic");
    assert!(parsed.unwrap().is_err());

    let mut long_lived: RemoteCacheManifest = serde_json::from_value(base.clone()).unwrap();
    long_lived.expires_at_unix_seconds =
        long_lived.created_at_unix_seconds + MAX_MANIFEST_LIFETIME_SECONDS + 1;
    assert_eq!(
        verify_candidate(&long_lived, &context(&long_lived), &AcceptFixtureSignature),
        Err(VerificationError::InvalidLifetime)
    );

    let mut unsafe_timestamp: RemoteCacheManifest = serde_json::from_value(base.clone()).unwrap();
    unsafe_timestamp.created_at_unix_seconds = MAX_JSON_SAFE_INTEGER + 1;
    unsafe_timestamp.expires_at_unix_seconds = MAX_JSON_SAFE_INTEGER + 2;
    assert_eq!(
        verify_candidate(
            &unsafe_timestamp,
            &context(&unsafe_timestamp),
            &AcceptFixtureSignature
        ),
        Err(VerificationError::TimestampOutOfRange)
    );

    let mut short_signature: RemoteCacheManifest = serde_json::from_value(base.clone()).unwrap();
    short_signature.signature.as_mut().unwrap().signature.pop();
    assert_eq!(
        verify_candidate(
            &short_signature,
            &context(&short_signature),
            &AcceptFixtureSignature
        ),
        Err(VerificationError::InvalidSignatureSize)
    );

    let mut c1_control: RemoteCacheManifest = serde_json::from_value(base.clone()).unwrap();
    c1_control.record_id = "record\u{80}".into();
    assert_eq!(
        verify_candidate(&c1_control, &context(&c1_control), &AcceptFixtureSignature),
        Err(VerificationError::InvalidIdentifier("record_id"))
    );

    let mut byte_order_mark: RemoteCacheManifest = serde_json::from_value(base).unwrap();
    byte_order_mark.record_id = "record\u{feff}".into();
    assert!(
        verify_candidate(
            &byte_order_mark,
            &context(&byte_order_mark),
            &AcceptFixtureSignature
        )
        .is_ok()
    );
}

fn context(manifest: &RemoteCacheManifest) -> VerificationContext {
    VerificationContext {
        tenant_id: manifest.tenant_id.clone(),
        repository_id: manifest.repository_id.clone(),
        request_key: manifest.request_key,
        policy_digest: manifest.policy_digest,
        execution_profile_digest: manifest.execution_profile_digest,
        platform_digest: manifest.platform_digest,
        image_digest: manifest.image_digest,
        now_unix_seconds: manifest.created_at_unix_seconds,
        trusted_producer_keys: BTreeMap::from([("key-1".into(), "producer-1".into())]),
        revoked_key_ids: BTreeSet::new(),
        revoked_record_ids: BTreeSet::new(),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
