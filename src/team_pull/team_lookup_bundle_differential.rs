//! Deterministic bundle-v1 versus five-request reference rollout gates.
//!
//! The parity corpus has exactly 100,000 cases. Every case independently
//! traverses both production protocol observations: bundle framing plus the
//! bundle error mapper, and the legacy trust/manifest/blob response decoders
//! plus the legacy error mapper. A separate 100,000-case malformed-wire corpus
//! compares the production bundle parser with a small literal-contract oracle;
//! malformed cases are deliberately not counted as protocol-parity cases.
//! This generated gate complements rather than replaces the stateful Worker
//! route tests and the full trust/signature/AEAD/revocation pull-path tests.

use std::collections::BTreeMap;

use super::{TeamPullError, map_bundle_fetch_error, map_manifest_fetch_error};
use crate::remote::{
    RemoteError, ServiceErrorClass, decode_team_manifest_v2_response, decode_team_trust_response,
    validate_team_ciphertext_response,
};
use crate::team::{
    Digest, PrivacyClass, PrivacyMetadata, SIGNATURE_ENVELOPE_SCHEMA_VERSION, Shareability,
    SignatureAlgorithm,
};
use crate::team_lookup_bundle::{
    TeamLookupBundleStreamValidator, TeamLookupBundleWireError, parse_team_lookup_bundle_v1,
};
use crate::team_manifest_v2::{
    ENCRYPTED_MANIFEST_SCHEMA_VERSION, EncryptedRemoteCacheManifestV2, EncryptedStreamRefV2,
    LOCAL_RESULT_PROOF_SCHEMA_VERSION, ManifestSignatureV2, ResultStatusV2,
};
use crate::trust_bundle::{TRUST_BUNDLE_SCHEMA_VERSION, TrustBundleV1};

const PARITY_SEED: u64 = 0xb17d_1e5e_2026_0002;
const MALFORMED_SEED: u64 = 0xb17d_bad0_2026_0001;
const PARITY_CASES: usize = 100_000;
const MALFORMED_CASES: usize = 100_000;

// Literal values from docs/TEAM_LOOKUP_BUNDLE_V1.md. The independent oracle
// intentionally does not import the production framing constants.
const SPEC_HEADER_BYTES: usize = 32;
const SPEC_MAX_TRUST_BYTES: usize = 1_500_000;
const SPEC_MAX_MANIFEST_BYTES: usize = 64 * 1024;
const SPEC_MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const SPEC_MAX_RESPONSE_BYTES: u64 = 40 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"AGNBNDL1";
const VERSION_OFFSET: usize = 8;
const FLAGS_OFFSET: usize = 10;
const TRUST_LENGTH_OFFSET: usize = 12;
const MANIFEST_LENGTH_OFFSET: usize = 16;
const STDOUT_LENGTH_OFFSET: usize = 20;
const STDERR_LENGTH_OFFSET: usize = 24;
const RESERVED_OFFSET: usize = 28;

#[derive(Clone, Copy)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn bounded(&mut self, upper_exclusive: usize) -> usize {
        assert!(upper_exclusive > 0);
        (self.next() as usize) % upper_exclusive
    }
}

fn random_bytes(rng: &mut SplitMix64, length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let block = rng.next().to_le_bytes();
        let remaining = length - bytes.len();
        bytes.extend_from_slice(&block[..remaining.min(block.len())]);
    }
    bytes
}

fn random_bounded_bytes(rng: &mut SplitMix64, minimum: usize, spread: usize) -> Vec<u8> {
    let length = minimum + rng.bounded(spread);
    random_bytes(rng, length)
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex(blake3::hash(bytes).to_hex().as_str()).expect("BLAKE3 is lower hexadecimal")
}

fn repeated_digest(byte: u8) -> Digest {
    Digest::from_hex(&format!("{byte:02x}").repeat(32)).expect("literal digest")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactFields {
    trust_json: Vec<u8>,
    manifest_json: Vec<u8>,
    stdout_ciphertext: Vec<u8>,
    stderr_ciphertext: Vec<u8>,
}

struct HitWire {
    fields: ExactFields,
    stdout_ref: EncryptedStreamRefV2,
    stderr_ref: EncryptedStreamRefV2,
}

fn make_hit_wire(rng: &mut SplitMix64, variant: usize) -> HitWire {
    let (stdout, stderr) = match variant {
        0 => (
            random_bounded_bytes(rng, 1, 513),
            random_bounded_bytes(rng, 1, 513),
        ),
        1 => (Vec::new(), Vec::new()),
        2 => (random_bounded_bytes(rng, 1, 513), Vec::new()),
        3 => (Vec::new(), random_bounded_bytes(rng, 1, 513)),
        _ => unreachable!(),
    };
    let stdout_ref = EncryptedStreamRefV2 {
        ciphertext_digest: digest_bytes(&stdout),
        ciphertext_size_bytes: stdout.len() as u64,
        nonce: [0x51; 24],
    };
    let stderr_ref = EncryptedStreamRefV2 {
        ciphertext_digest: digest_bytes(&stderr),
        ciphertext_size_bytes: stderr.len() as u64,
        nonce: [0xa2; 24],
    };
    let nonce = rng.next();
    let trust = TrustBundleV1 {
        schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
        root_key_id: "root-key-generated".into(),
        tenant_id: "tenant-generated".into(),
        repository_id: "repo-generated".into(),
        generation_id: "0123456789abcdef0123456789abcdef".into(),
        endpoint_origin: "https://cache.generated.invalid".into(),
        epoch: 1 + nonce % 1_000_000,
        issued_at_unix_seconds: 1_700_000_000,
        expires_at_unix_seconds: 1_700_003_600,
        active_producer_keys: Vec::new(),
        revoked_key_ids: Vec::new(),
        revoked_record_ids: Vec::new(),
        allowed_policy_digests: Vec::new(),
        allowed_execution_profile_digests: Vec::new(),
        allowed_platform_digests: Vec::new(),
        allowed_image_digests: Vec::new(),
        signature: random_bytes(rng, 64),
    };
    let manifest = EncryptedRemoteCacheManifestV2 {
        schema_version: ENCRYPTED_MANIFEST_SCHEMA_VERSION,
        record_id: format!("record-{nonce:016x}"),
        tenant_id: "tenant-generated".into(),
        repository_id: "repo-generated".into(),
        generation_id: "0123456789abcdef0123456789abcdef".into(),
        request_key: repeated_digest(0x10),
        policy_digest: repeated_digest(0x11),
        classifier_digest: repeated_digest(0x12),
        execution_profile_digest: repeated_digest(0x13),
        platform_digest: repeated_digest(0x14),
        image_digest: repeated_digest(0x15),
        result_status: ResultStatusV2::Success,
        duration_micros: 1 + nonce % 10_000_000,
        proof_schema_version: LOCAL_RESULT_PROOF_SCHEMA_VERSION,
        producer_version: "again-generated-differential".into(),
        local_proof_digest: repeated_digest(0x16),
        privacy: PrivacyMetadata {
            classification: PrivacyClass::Internal,
            shareability: Shareability::Repository,
            secret_tainted: false,
        },
        repository_encryption_key_id: "repository-key-generated".into(),
        stdout: stdout_ref.clone(),
        stderr: stderr_ref.clone(),
        producer_id: "producer-generated".into(),
        created_at_unix_seconds: 1_700_000_000,
        expires_at_unix_seconds: 1_700_003_600,
        signature: ManifestSignatureV2 {
            schema_version: SIGNATURE_ENVELOPE_SCHEMA_VERSION,
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "producer-key-generated".into(),
            signature: random_bytes(rng, 64),
        },
    };
    HitWire {
        fields: ExactFields {
            trust_json: serde_json::to_vec(&trust).expect("generated trust JSON"),
            manifest_json: serde_json::to_vec(&manifest).expect("generated manifest JSON"),
            stdout_ciphertext: stdout,
            stderr_ciphertext: stderr,
        },
        stdout_ref,
        stderr_ref,
    }
}

fn encode_bundle_wire(fields: &ExactFields) -> Vec<u8> {
    let mut bytes = header_with_lengths(
        fields.trust_json.len() as u32,
        fields.manifest_json.len() as u32,
        fields.stdout_ciphertext.len() as u32,
        fields.stderr_ciphertext.len() as u32,
    );
    bytes.extend_from_slice(&fields.trust_json);
    bytes.extend_from_slice(&fields.manifest_json);
    bytes.extend_from_slice(&fields.stdout_ciphertext);
    bytes.extend_from_slice(&fields.stderr_ciphertext);
    bytes
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MatrixState {
    NoManifest,
    DeletedManifest,
    ExpiredManifest,
    FutureManifest,
    ProducerRevoked,
    RecordRevoked,
    PolicyDisallowed,
    ExecutionProfileDisallowed,
    PlatformDisallowed,
    ImageDisallowed,
    ReadyHit,
    ReadyHitEmptyOutputs,
    ReadyHitStdoutOnly,
    ReadyHitStderrOnly,
    QuarantinedManifest,
    NonReadyManifest,
    InconsistentManifestMetadata,
    NonReadyStdoutBlob,
    NonReadyStderrBlob,
    MissingStdoutObject,
    MissingStderrObject,
    WrongStdoutDigest,
    WrongStderrDigest,
    WrongStdoutSize,
    WrongStderrSize,
    MissingTrust,
    ExpiredTrust,
    MalformedTrustHead,
    DisabledRoot,
    StaleGeneration,
    WrongGenerationHeader,
    MalformedRequest,
    Unauthorized,
    RequestBudgetExceeded,
    Timeout,
    TransportFailure,
    TrustChangedDuringFence,
    BlobStateChangedDuringRead,
    ManifestChangedBeforeRelease,
    FinalTrustMissing,
}

const MATRIX_STATES: [MatrixState; 40] = [
    MatrixState::NoManifest,
    MatrixState::DeletedManifest,
    MatrixState::ExpiredManifest,
    MatrixState::FutureManifest,
    MatrixState::ProducerRevoked,
    MatrixState::RecordRevoked,
    MatrixState::PolicyDisallowed,
    MatrixState::ExecutionProfileDisallowed,
    MatrixState::PlatformDisallowed,
    MatrixState::ImageDisallowed,
    MatrixState::ReadyHit,
    MatrixState::ReadyHitEmptyOutputs,
    MatrixState::ReadyHitStdoutOnly,
    MatrixState::ReadyHitStderrOnly,
    MatrixState::QuarantinedManifest,
    MatrixState::NonReadyManifest,
    MatrixState::InconsistentManifestMetadata,
    MatrixState::NonReadyStdoutBlob,
    MatrixState::NonReadyStderrBlob,
    MatrixState::MissingStdoutObject,
    MatrixState::MissingStderrObject,
    MatrixState::WrongStdoutDigest,
    MatrixState::WrongStderrDigest,
    MatrixState::WrongStdoutSize,
    MatrixState::WrongStderrSize,
    MatrixState::MissingTrust,
    MatrixState::ExpiredTrust,
    MatrixState::MalformedTrustHead,
    MatrixState::DisabledRoot,
    MatrixState::StaleGeneration,
    MatrixState::WrongGenerationHeader,
    MatrixState::MalformedRequest,
    MatrixState::Unauthorized,
    MatrixState::RequestBudgetExceeded,
    MatrixState::Timeout,
    MatrixState::TransportFailure,
    MatrixState::TrustChangedDuringFence,
    MatrixState::BlobStateChangedDuringRead,
    MatrixState::ManifestChangedBeforeRelease,
    MatrixState::FinalTrustMissing,
];

impl MatrixState {
    fn hit_variant(self) -> Option<usize> {
        match self {
            Self::ReadyHit => Some(0),
            Self::ReadyHitEmptyOutputs => Some(1),
            Self::ReadyHitStdoutOnly => Some(2),
            Self::ReadyHitStderrOnly => Some(3),
            _ => None,
        }
    }

    fn is_miss(self) -> bool {
        matches!(
            self,
            Self::NoManifest
                | Self::DeletedManifest
                | Self::ExpiredManifest
                | Self::FutureManifest
                | Self::ProducerRevoked
                | Self::RecordRevoked
                | Self::PolicyDisallowed
                | Self::ExecutionProfileDisallowed
                | Self::PlatformDisallowed
                | Self::ImageDisallowed
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizedServiceClass {
    Transient,
    ConfigurationOrAuth,
    Corruption,
}

impl From<ServiceErrorClass> for NormalizedServiceClass {
    fn from(value: ServiceErrorClass) -> Self {
        match value {
            ServiceErrorClass::Transient => Self::Transient,
            ServiceErrorClass::ConfigurationOrAuth => Self::ConfigurationOrAuth,
            ServiceErrorClass::Corruption => Self::Corruption,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExactFailure {
    Service {
        code: String,
        status: u16,
        class: NormalizedServiceClass,
    },
    NotFound,
    RepositoryGenerationMismatch,
    Unauthorized,
    RequestBudgetExceeded,
    Timeout(&'static str),
    Transport(&'static str),
    InvalidTrustBundle,
    InvalidManifestV2,
    SizeMismatch,
    DigestMismatch,
    Wire(OracleWireError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Observation {
    Miss,
    Hit(ExactFields),
    FailClosed(ExactFailure),
}

fn service_failure(code: &'static str, status: u16, class: NormalizedServiceClass) -> ExactFailure {
    ExactFailure::Service {
        code: code.into(),
        status,
        class,
    }
}

/// Independent expected disposition and exact failure classification.
fn expected_observation(state: MatrixState, hit: Option<&HitWire>) -> Observation {
    if state.is_miss() {
        return Observation::Miss;
    }
    if state.hit_variant().is_some() {
        return Observation::Hit(hit.expect("hit wire").fields.clone());
    }
    let failure = match state {
        MatrixState::QuarantinedManifest
        | MatrixState::NonReadyManifest
        | MatrixState::InconsistentManifestMetadata
        | MatrixState::NonReadyStdoutBlob
        | MatrixState::NonReadyStderrBlob
        | MatrixState::ManifestChangedBeforeRelease => service_failure(
            "manifest_state_corrupt",
            409,
            NormalizedServiceClass::Corruption,
        ),
        MatrixState::MissingStdoutObject
        | MatrixState::MissingStderrObject
        | MatrixState::WrongStdoutDigest
        | MatrixState::WrongStderrDigest
        | MatrixState::WrongStdoutSize
        | MatrixState::WrongStderrSize => service_failure(
            "blob_integrity_failure",
            409,
            NormalizedServiceClass::Corruption,
        ),
        MatrixState::MissingTrust
        | MatrixState::ExpiredTrust
        | MatrixState::DisabledRoot
        | MatrixState::FinalTrustMissing => ExactFailure::NotFound,
        MatrixState::MalformedTrustHead => service_failure(
            "trust_state_corrupt",
            409,
            NormalizedServiceClass::Corruption,
        ),
        MatrixState::StaleGeneration => service_failure(
            "repository_generation_mismatch",
            412,
            NormalizedServiceClass::Corruption,
        ),
        MatrixState::WrongGenerationHeader => ExactFailure::RepositoryGenerationMismatch,
        MatrixState::MalformedRequest => service_failure(
            "invalid_field",
            400,
            NormalizedServiceClass::ConfigurationOrAuth,
        ),
        MatrixState::Unauthorized => ExactFailure::Unauthorized,
        MatrixState::RequestBudgetExceeded => ExactFailure::RequestBudgetExceeded,
        MatrixState::Timeout => ExactFailure::Timeout("remote pull"),
        MatrixState::TransportFailure => ExactFailure::Transport("get candidate"),
        MatrixState::TrustChangedDuringFence => {
            service_failure("trust_changed", 409, NormalizedServiceClass::Transient)
        }
        MatrixState::BlobStateChangedDuringRead => {
            service_failure("blob_state_changed", 409, NormalizedServiceClass::Transient)
        }
        state if state.is_miss() || state.hit_variant().is_some() => unreachable!(),
        _ => unreachable!(),
    };
    Observation::FailClosed(failure)
}

/// Construct the exact production transport result independently of the
/// expected-observation match above.
fn production_error_for_state(state: MatrixState) -> RemoteError {
    if state.is_miss() {
        return RemoteError::ManifestNotFound;
    }
    let service = |code: &str, status, class| RemoteError::ServiceRejected {
        code: code.into(),
        status,
        class,
    };
    match state {
        MatrixState::QuarantinedManifest
        | MatrixState::NonReadyManifest
        | MatrixState::InconsistentManifestMetadata
        | MatrixState::NonReadyStdoutBlob
        | MatrixState::NonReadyStderrBlob
        | MatrixState::ManifestChangedBeforeRelease => {
            service("manifest_state_corrupt", 409, ServiceErrorClass::Corruption)
        }
        MatrixState::MissingStdoutObject
        | MatrixState::MissingStderrObject
        | MatrixState::WrongStdoutDigest
        | MatrixState::WrongStderrDigest
        | MatrixState::WrongStdoutSize
        | MatrixState::WrongStderrSize => {
            service("blob_integrity_failure", 409, ServiceErrorClass::Corruption)
        }
        MatrixState::MissingTrust
        | MatrixState::ExpiredTrust
        | MatrixState::DisabledRoot
        | MatrixState::FinalTrustMissing => RemoteError::NotFound,
        MatrixState::MalformedTrustHead => {
            service("trust_state_corrupt", 409, ServiceErrorClass::Corruption)
        }
        MatrixState::StaleGeneration => service(
            "repository_generation_mismatch",
            412,
            ServiceErrorClass::Corruption,
        ),
        MatrixState::WrongGenerationHeader => RemoteError::RepositoryGenerationMismatch,
        MatrixState::MalformedRequest => {
            service("invalid_field", 400, ServiceErrorClass::ConfigurationOrAuth)
        }
        MatrixState::Unauthorized => RemoteError::Unauthorized,
        MatrixState::RequestBudgetExceeded => RemoteError::RequestBudgetExceeded,
        MatrixState::Timeout => RemoteError::Timeout {
            operation: "remote pull",
        },
        MatrixState::TransportFailure => RemoteError::Transport {
            operation: "get candidate",
        },
        MatrixState::TrustChangedDuringFence => {
            service("trust_changed", 409, ServiceErrorClass::Transient)
        }
        MatrixState::BlobStateChangedDuringRead => {
            service("blob_state_changed", 409, ServiceErrorClass::Transient)
        }
        state if state.hit_variant().is_some() => panic!("hit has no production error"),
        _ => unreachable!(),
    }
}

fn normalize_remote_error(error: RemoteError) -> ExactFailure {
    match error {
        RemoteError::ServiceRejected {
            code,
            status,
            class,
        } => ExactFailure::Service {
            code,
            status,
            class: class.into(),
        },
        RemoteError::NotFound => ExactFailure::NotFound,
        RemoteError::RepositoryGenerationMismatch => ExactFailure::RepositoryGenerationMismatch,
        RemoteError::Unauthorized => ExactFailure::Unauthorized,
        RemoteError::RequestBudgetExceeded => ExactFailure::RequestBudgetExceeded,
        RemoteError::Timeout { operation } => ExactFailure::Timeout(operation),
        RemoteError::Transport { operation } => ExactFailure::Transport(operation),
        RemoteError::InvalidTrustBundle => ExactFailure::InvalidTrustBundle,
        RemoteError::InvalidManifestV2 => ExactFailure::InvalidManifestV2,
        RemoteError::SizeMismatch => ExactFailure::SizeMismatch,
        RemoteError::DigestMismatch => ExactFailure::DigestMismatch,
        RemoteError::InvalidLookupBundle(error) => ExactFailure::Wire(normalize_wire_error(error)),
        unexpected => panic!("unexpected generated remote error: {unexpected:?}"),
    }
}

fn normalize_team_error(error: TeamPullError) -> Observation {
    match error {
        TeamPullError::CacheMiss => Observation::Miss,
        TeamPullError::LookupBundleWire(error) => {
            Observation::FailClosed(ExactFailure::Wire(normalize_wire_error(error)))
        }
        TeamPullError::Remote(error) => Observation::FailClosed(normalize_remote_error(error)),
        unexpected => panic!("unexpected generated team pull error: {unexpected:?}"),
    }
}

fn production_bundle_hit(hit: &HitWire) -> Result<ExactFields, RemoteError> {
    let body = encode_bundle_wire(&hit.fields);
    let parsed = parse_team_lookup_bundle_v1(&body, SPEC_MAX_RESPONSE_BYTES)
        .map_err(RemoteError::InvalidLookupBundle)?;
    decode_team_trust_response(parsed.initial_trust_json())?;
    let manifest = decode_team_manifest_v2_response(parsed.manifest_json())?;
    validate_team_ciphertext_response(&manifest.stdout, parsed.stdout_ciphertext())?;
    validate_team_ciphertext_response(&manifest.stderr, parsed.stderr_ciphertext())?;
    Ok(ExactFields {
        trust_json: parsed.initial_trust_json().to_vec(),
        manifest_json: parsed.manifest_json().to_vec(),
        stdout_ciphertext: parsed.stdout_ciphertext().to_vec(),
        stderr_ciphertext: parsed.stderr_ciphertext().to_vec(),
    })
}

fn production_legacy_hit(hit: &HitWire) -> Result<ExactFields, RemoteError> {
    // These are four distinct legacy response bodies. They are parsed and
    // validated through the exact pure functions delegated to by the
    // production legacy route; no assembled candidate is cloned into success.
    decode_team_trust_response(&hit.fields.trust_json)?;
    let manifest = decode_team_manifest_v2_response(&hit.fields.manifest_json)?;
    assert_eq!(manifest.stdout, hit.stdout_ref);
    assert_eq!(manifest.stderr, hit.stderr_ref);
    validate_team_ciphertext_response(&manifest.stdout, &hit.fields.stdout_ciphertext)?;
    validate_team_ciphertext_response(&manifest.stderr, &hit.fields.stderr_ciphertext)?;
    Ok(ExactFields {
        trust_json: hit.fields.trust_json.as_slice().to_vec(),
        manifest_json: hit.fields.manifest_json.as_slice().to_vec(),
        stdout_ciphertext: hit.fields.stdout_ciphertext.as_slice().to_vec(),
        stderr_ciphertext: hit.fields.stderr_ciphertext.as_slice().to_vec(),
    })
}

fn production_bundle_observation(state: MatrixState, hit: Option<&HitWire>) -> Observation {
    if let Some(hit) = hit {
        return production_bundle_hit(hit)
            .map(Observation::Hit)
            .unwrap_or_else(|error| Observation::FailClosed(normalize_remote_error(error)));
    }
    normalize_team_error(map_bundle_fetch_error(production_error_for_state(state)))
}

fn production_legacy_observation(state: MatrixState, hit: Option<&HitWire>) -> Observation {
    if let Some(hit) = hit {
        return production_legacy_hit(hit)
            .map(Observation::Hit)
            .unwrap_or_else(|error| Observation::FailClosed(normalize_remote_error(error)));
    }
    normalize_team_error(map_manifest_fetch_error(production_error_for_state(state)))
}

#[test]
fn production_response_decoder_delegation_regression() {
    let mut rng = SplitMix64(PARITY_SEED);
    let hit = make_hit_wire(&mut rng, 0);
    let trust: TrustBundleV1 = decode_team_trust_response(&hit.fields.trust_json).unwrap();
    assert_eq!(serde_json::to_vec(&trust).unwrap(), hit.fields.trust_json);
    let manifest = decode_team_manifest_v2_response(&hit.fields.manifest_json).unwrap();
    assert_eq!(manifest.stdout, hit.stdout_ref);
    assert_eq!(manifest.stderr, hit.stderr_ref);
    validate_team_ciphertext_response(&manifest.stdout, &hit.fields.stdout_ciphertext).unwrap();
    validate_team_ciphertext_response(&manifest.stderr, &hit.fields.stderr_ciphertext).unwrap();
    assert_eq!(
        decode_team_trust_response(b"not-json"),
        Err(RemoteError::InvalidTrustBundle)
    );
    assert_eq!(
        decode_team_manifest_v2_response(b"{}"),
        Err(RemoteError::InvalidManifestV2)
    );
    let mut wrong_size = manifest.stdout.clone();
    wrong_size.ciphertext_size_bytes += 1;
    assert_eq!(
        validate_team_ciphertext_response(&wrong_size, &hit.fields.stdout_ciphertext),
        Err(RemoteError::SizeMismatch),
        "size remains the first post-body failure"
    );
    let mut wrong_digest = manifest.stdout;
    wrong_digest.ciphertext_digest = repeated_digest(0xfe);
    assert_eq!(
        validate_team_ciphertext_response(&wrong_digest, &hit.fields.stdout_ciphertext),
        Err(RemoteError::DigestMismatch)
    );
}

#[test]
fn lookup_bundle_state_matrix_protocol_parity_100k() {
    assert_eq!(PARITY_CASES % MATRIX_STATES.len(), 0);
    let mut rng = SplitMix64(PARITY_SEED);
    let mut state_counts = BTreeMap::<MatrixState, usize>::new();
    let mut hits = 0;
    let mut misses = 0;
    let mut fail_closed = 0;
    for index in 0..PARITY_CASES {
        let state = MATRIX_STATES[index % MATRIX_STATES.len()];
        let hit = state
            .hit_variant()
            .map(|variant| make_hit_wire(&mut rng, variant));
        let expected = expected_observation(state, hit.as_ref());
        let bundle = production_bundle_observation(state, hit.as_ref());
        let legacy = production_legacy_observation(state, hit.as_ref());
        assert_eq!(
            bundle, expected,
            "bundle/state-oracle mismatch at parity case {index}: {state:?}"
        );
        assert_eq!(
            legacy, expected,
            "legacy/state-oracle mismatch at parity case {index}: {state:?}"
        );
        assert_eq!(
            bundle, legacy,
            "bundle/legacy mismatch at parity case {index}: {state:?}"
        );
        match expected {
            Observation::Hit(_) => hits += 1,
            Observation::Miss => misses += 1,
            Observation::FailClosed(_) => fail_closed += 1,
        }
        *state_counts.entry(state).or_default() += 1;
    }
    let per_state = PARITY_CASES / MATRIX_STATES.len();
    for state in MATRIX_STATES {
        assert_eq!(state_counts.get(&state), Some(&per_state), "{state:?}");
    }
    assert_eq!(hits, 4 * per_state);
    assert_eq!(misses, 10 * per_state);
    assert_eq!(fail_closed, 26 * per_state);
    assert_eq!(hits + misses + fail_closed, PARITY_CASES);
    eprintln!(
        "lookup-bundle-v1 protocol parity: seed=0x{PARITY_SEED:016x} \
         cases={PARITY_CASES} states={} per_state={per_state} hits={hits} \
         misses={misses} fail_closed={fail_closed}",
        MATRIX_STATES.len()
    );
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OracleWireError {
    ResponseBudgetExceeded,
    HeaderTruncated,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedFlags,
    NonZeroReserved,
    EmptyTrustBundle,
    EmptyManifest,
    TrustBundleTooLarge,
    ManifestTooLarge,
    StdoutCiphertextTooLarge,
    StderrCiphertextTooLarge,
    LengthOverflow,
    PayloadTruncated,
    TrailingBytes,
}

fn normalize_wire_error(error: TeamLookupBundleWireError) -> OracleWireError {
    match error {
        TeamLookupBundleWireError::ResponseBudgetExceeded => {
            OracleWireError::ResponseBudgetExceeded
        }
        TeamLookupBundleWireError::HeaderTruncated => OracleWireError::HeaderTruncated,
        TeamLookupBundleWireError::InvalidMagic => OracleWireError::InvalidMagic,
        TeamLookupBundleWireError::UnsupportedVersion => OracleWireError::UnsupportedVersion,
        TeamLookupBundleWireError::UnsupportedFlags => OracleWireError::UnsupportedFlags,
        TeamLookupBundleWireError::NonZeroReserved => OracleWireError::NonZeroReserved,
        TeamLookupBundleWireError::EmptyTrustBundle => OracleWireError::EmptyTrustBundle,
        TeamLookupBundleWireError::EmptyManifest => OracleWireError::EmptyManifest,
        TeamLookupBundleWireError::TrustBundleTooLarge => OracleWireError::TrustBundleTooLarge,
        TeamLookupBundleWireError::ManifestTooLarge => OracleWireError::ManifestTooLarge,
        TeamLookupBundleWireError::StdoutCiphertextTooLarge => {
            OracleWireError::StdoutCiphertextTooLarge
        }
        TeamLookupBundleWireError::StderrCiphertextTooLarge => {
            OracleWireError::StderrCiphertextTooLarge
        }
        TeamLookupBundleWireError::LengthOverflow => OracleWireError::LengthOverflow,
        TeamLookupBundleWireError::PayloadTruncated => OracleWireError::PayloadTruncated,
        TeamLookupBundleWireError::TrailingBytes => OracleWireError::TrailingBytes,
    }
}

fn header_with_lengths(trust: u32, manifest: u32, stdout: u32, stderr: u32) -> Vec<u8> {
    let mut bytes = vec![0_u8; SPEC_HEADER_BYTES];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    put_u16(&mut bytes, VERSION_OFFSET, 1);
    put_u32(&mut bytes, TRUST_LENGTH_OFFSET, trust);
    put_u32(&mut bytes, MANIFEST_LENGTH_OFFSET, manifest);
    put_u32(&mut bytes, STDOUT_LENGTH_OFFSET, stdout);
    put_u32(&mut bytes, STDERR_LENGTH_OFFSET, stderr);
    bytes
}

fn exact_sized_body(trust: usize, manifest: usize, stdout: usize, stderr: usize) -> Vec<u8> {
    let mut bytes =
        header_with_lengths(trust as u32, manifest as u32, stdout as u32, stderr as u32);
    bytes.resize(SPEC_HEADER_BYTES + trust + manifest + stdout + stderr, 0x5a);
    bytes
}

fn small_valid_wire(rng: &mut SplitMix64) -> Vec<u8> {
    let trust = random_bounded_bytes(rng, 2, 63);
    let manifest = random_bounded_bytes(rng, 1, 95);
    let stdout = random_bounded_bytes(rng, 1, 129);
    let stderr = random_bounded_bytes(rng, 1, 129);
    let mut bytes = header_with_lengths(
        trust.len() as u32,
        manifest.len() as u32,
        stdout.len() as u32,
        stderr.len() as u32,
    );
    bytes.extend_from_slice(&trust);
    bytes.extend_from_slice(&manifest);
    bytes.extend_from_slice(&stdout);
    bytes.extend_from_slice(&stderr);
    bytes
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Independent framing oracle implemented from the written v1 contract.
fn oracle_parse(bytes: &[u8], budget: u64) -> Result<(), OracleWireError> {
    if bytes.len() as u64 > budget {
        return Err(OracleWireError::ResponseBudgetExceeded);
    }
    if bytes.len() < SPEC_HEADER_BYTES {
        return Err(OracleWireError::HeaderTruncated);
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(OracleWireError::InvalidMagic);
    }
    if get_u16(bytes, VERSION_OFFSET) != 1 {
        return Err(OracleWireError::UnsupportedVersion);
    }
    if get_u16(bytes, FLAGS_OFFSET) != 0 {
        return Err(OracleWireError::UnsupportedFlags);
    }
    if get_u32(bytes, RESERVED_OFFSET) != 0 {
        return Err(OracleWireError::NonZeroReserved);
    }
    let trust = get_u32(bytes, TRUST_LENGTH_OFFSET) as u64;
    let manifest = get_u32(bytes, MANIFEST_LENGTH_OFFSET) as u64;
    let stdout = get_u32(bytes, STDOUT_LENGTH_OFFSET) as u64;
    let stderr = get_u32(bytes, STDERR_LENGTH_OFFSET) as u64;
    if trust == 0 {
        return Err(OracleWireError::EmptyTrustBundle);
    }
    if manifest == 0 {
        return Err(OracleWireError::EmptyManifest);
    }
    if trust > SPEC_MAX_TRUST_BYTES as u64 {
        return Err(OracleWireError::TrustBundleTooLarge);
    }
    if manifest > SPEC_MAX_MANIFEST_BYTES as u64 {
        return Err(OracleWireError::ManifestTooLarge);
    }
    if stdout > SPEC_MAX_CIPHERTEXT_BYTES as u64 {
        return Err(OracleWireError::StdoutCiphertextTooLarge);
    }
    if stderr > SPEC_MAX_CIPHERTEXT_BYTES as u64 {
        return Err(OracleWireError::StderrCiphertextTooLarge);
    }
    let expected_u64 = (SPEC_HEADER_BYTES as u64)
        .checked_add(trust)
        .and_then(|total| total.checked_add(manifest))
        .and_then(|total| total.checked_add(stdout))
        .and_then(|total| total.checked_add(stderr))
        .ok_or(OracleWireError::LengthOverflow)?;
    usize::try_from(expected_u64).map_err(|_| OracleWireError::LengthOverflow)?;
    if expected_u64 > budget {
        return Err(OracleWireError::ResponseBudgetExceeded);
    }
    match (bytes.len() as u64).cmp(&expected_u64) {
        std::cmp::Ordering::Less => Err(OracleWireError::PayloadTruncated),
        std::cmp::Ordering::Greater => Err(OracleWireError::TrailingBytes),
        std::cmp::Ordering::Equal => Ok(()),
    }
}

fn malformed_wire_case(rng: &mut SplitMix64, scenario: usize) -> (Vec<u8>, u64, OracleWireError) {
    let mut bytes = small_valid_wire(rng);
    let mut budget = SPEC_MAX_RESPONSE_BYTES;
    let expected = match scenario {
        0 => {
            bytes.truncate(rng.bounded(SPEC_HEADER_BYTES));
            OracleWireError::HeaderTruncated
        }
        1 => {
            bytes[rng.bounded(MAGIC.len())] ^= 0xff;
            OracleWireError::InvalidMagic
        }
        2 => {
            put_u16(&mut bytes, VERSION_OFFSET, 2);
            OracleWireError::UnsupportedVersion
        }
        3 => {
            put_u16(&mut bytes, FLAGS_OFFSET, 1);
            OracleWireError::UnsupportedFlags
        }
        4 => {
            put_u32(&mut bytes, RESERVED_OFFSET, 1);
            OracleWireError::NonZeroReserved
        }
        5 => {
            bytes = exact_sized_body(0, 1, 0, 0);
            OracleWireError::EmptyTrustBundle
        }
        6 => {
            bytes = exact_sized_body(1, 0, 0, 0);
            OracleWireError::EmptyManifest
        }
        7 => {
            bytes = header_with_lengths(SPEC_MAX_TRUST_BYTES as u32 + 1, 1, 0, 0);
            OracleWireError::TrustBundleTooLarge
        }
        8 => {
            bytes = header_with_lengths(1, SPEC_MAX_MANIFEST_BYTES as u32 + 1, 0, 0);
            OracleWireError::ManifestTooLarge
        }
        9 => {
            bytes = header_with_lengths(1, 1, SPEC_MAX_CIPHERTEXT_BYTES as u32 + 1, 0);
            OracleWireError::StdoutCiphertextTooLarge
        }
        10 => {
            bytes = header_with_lengths(1, 1, 0, SPEC_MAX_CIPHERTEXT_BYTES as u32 + 1);
            OracleWireError::StderrCiphertextTooLarge
        }
        11 => {
            budget = bytes.len() as u64 - 1;
            OracleWireError::ResponseBudgetExceeded
        }
        12 => {
            bytes = exact_sized_body(1, 1, 0, 0);
            put_u32(&mut bytes, STDOUT_LENGTH_OFFSET, 1024);
            budget = 128;
            OracleWireError::ResponseBudgetExceeded
        }
        13 => {
            bytes.pop();
            OracleWireError::PayloadTruncated
        }
        14 => {
            let retained = SPEC_HEADER_BYTES + rng.bounded(bytes.len() - SPEC_HEADER_BYTES);
            bytes.truncate(retained);
            OracleWireError::PayloadTruncated
        }
        15 => {
            bytes.push(rng.next() as u8);
            OracleWireError::TrailingBytes
        }
        16 => {
            let extra = 1 + rng.bounded(32);
            bytes.extend_from_slice(&random_bytes(rng, extra));
            OracleWireError::TrailingBytes
        }
        17 => {
            let trust = get_u32(&bytes, TRUST_LENGTH_OFFSET);
            put_u32(&mut bytes, TRUST_LENGTH_OFFSET, trust + 1);
            OracleWireError::PayloadTruncated
        }
        18 => {
            let trust = get_u32(&bytes, TRUST_LENGTH_OFFSET);
            put_u32(&mut bytes, TRUST_LENGTH_OFFSET, trust - 1);
            OracleWireError::TrailingBytes
        }
        19 => {
            bytes[0] ^= 0xff;
            put_u32(
                &mut bytes,
                TRUST_LENGTH_OFFSET,
                SPEC_MAX_TRUST_BYTES as u32 + 1,
            );
            OracleWireError::InvalidMagic
        }
        _ => unreachable!(),
    };
    (bytes, budget, expected)
}

fn incremental_accepts(bytes: &[u8], budget: u64, rng: &mut SplitMix64) -> bool {
    let mut validator = TeamLookupBundleStreamValidator::new(budget);
    let mut offset = 0;
    while offset < bytes.len() {
        let chunk_length = (1 + rng.bounded(97)).min(bytes.len() - offset);
        if validator
            .push(&bytes[offset..offset + chunk_length])
            .is_err()
        {
            return false;
        }
        offset += chunk_length;
    }
    validator.finish().is_ok()
}

fn verify_literal_contract_boundaries() {
    assert_eq!(
        crate::team_lookup_bundle::TEAM_LOOKUP_BUNDLE_HEADER_BYTES,
        SPEC_HEADER_BYTES
    );
    assert_eq!(crate::remote::MAX_TRUST_BUNDLE_BYTES, SPEC_MAX_TRUST_BYTES);
    assert_eq!(crate::remote::MAX_MANIFEST_BYTES, SPEC_MAX_MANIFEST_BYTES);
    assert_eq!(crate::remote::MAX_BLOB_BYTES, SPEC_MAX_CIPHERTEXT_BYTES);
    let maximum = exact_sized_body(
        SPEC_MAX_TRUST_BYTES,
        SPEC_MAX_MANIFEST_BYTES,
        SPEC_MAX_CIPHERTEXT_BYTES,
        SPEC_MAX_CIPHERTEXT_BYTES,
    );
    assert!(maximum.len() as u64 <= SPEC_MAX_RESPONSE_BYTES);
    assert!(parse_team_lookup_bundle_v1(&maximum, maximum.len() as u64).is_ok());
    assert_eq!(oracle_parse(&maximum, maximum.len() as u64), Ok(()));
    assert_eq!(
        parse_team_lookup_bundle_v1(&maximum, maximum.len() as u64 - 1),
        Err(TeamLookupBundleWireError::ResponseBudgetExceeded)
    );
}

#[test]
fn lookup_bundle_malformed_wire_oracle_additional_100k() {
    const SCENARIOS: usize = 20;
    assert_eq!(MALFORMED_CASES % SCENARIOS, 0);
    verify_literal_contract_boundaries();
    let mut rng = SplitMix64(MALFORMED_SEED);
    let mut errors = BTreeMap::<OracleWireError, usize>::new();
    for index in 0..MALFORMED_CASES {
        let scenario = index % SCENARIOS;
        let (bytes, budget, expected) = malformed_wire_case(&mut rng, scenario);
        assert_eq!(oracle_parse(&bytes, budget), Err(expected));
        let production = parse_team_lookup_bundle_v1(&bytes, budget).unwrap_err();
        assert_eq!(
            normalize_wire_error(production),
            expected,
            "malformed oracle mismatch at additional case {index}, scenario {scenario}"
        );
        assert!(
            !incremental_accepts(&bytes, budget, &mut rng),
            "incremental validator accepted malformed case {index}, scenario {scenario}"
        );
        *errors.entry(expected).or_default() += 1;
    }
    for required in [
        OracleWireError::ResponseBudgetExceeded,
        OracleWireError::HeaderTruncated,
        OracleWireError::InvalidMagic,
        OracleWireError::UnsupportedVersion,
        OracleWireError::UnsupportedFlags,
        OracleWireError::NonZeroReserved,
        OracleWireError::EmptyTrustBundle,
        OracleWireError::EmptyManifest,
        OracleWireError::TrustBundleTooLarge,
        OracleWireError::ManifestTooLarge,
        OracleWireError::StdoutCiphertextTooLarge,
        OracleWireError::StderrCiphertextTooLarge,
        OracleWireError::PayloadTruncated,
        OracleWireError::TrailingBytes,
    ] {
        assert!(errors.get(&required).copied().unwrap_or(0) > 0);
    }
    assert_eq!(errors.values().sum::<usize>(), MALFORMED_CASES);
    eprintln!(
        "lookup-bundle-v1 additional malformed wire: seed=0x{MALFORMED_SEED:016x} \
         cases={MALFORMED_CASES} scenarios={SCENARIOS} errors={errors:?}"
    );
}
