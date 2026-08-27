//! Interface-only admission for semantic or AI-generated result candidates.
//!
//! This module parses bounded untrusted suggestions and can emit only
//! [`DeterministicValidationRequestV1`] values.  It has no provider, model,
//! embedding, network, store, result-fetch, execution, replay, or serve API.
//! Successful deterministic validation is deliberately consumed elsewhere by
//! the canonical authority boundary; this module only maps failed or incomplete
//! validation to a fail-closed `execute_fresh` handoff.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

use crate::agent_gateway::{EffectClass, GatewayToolCallV1, RepositoryEnvironmentStateV1};
use crate::workspace_authority::CompleteToolStateV1;

pub const CANDIDATE_SUGGESTION_SCHEMA_VERSION_V1: u16 = 1;

const VALIDATION_REQUEST_DOMAIN_V1: &[u8] = b"again.agent-candidate-validation-request.v1\0";
const MODEL_PROVENANCE_DOMAIN_V1: &[u8] = b"again.agent-candidate-model-provenance.v1\0";
const DIGEST_BYTES: usize = 64;

/// Independent limits for the untrusted suggestion envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateSuggestionLimitsV1 {
    pub max_input_bytes: usize,
    pub max_json_depth: usize,
    pub max_json_nodes: usize,
    pub max_suggestions: usize,
    pub max_model_provenance_bytes: usize,
    pub max_suggestion_age_millis: u64,
    pub max_validity_window_millis: u64,
}

impl Default for CandidateSuggestionLimitsV1 {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_json_depth: 12,
            max_json_nodes: 1_024,
            max_suggestions: 64,
            max_model_provenance_bytes: 1_024,
            max_suggestion_age_millis: 5 * 60 * 1_000,
            max_validity_window_millis: 5 * 60 * 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshExecutionReasonV1 {
    MalformedSuggestion,
    DuplicateSuggestion,
    SuggestionTooLarge,
    StaleSuggestion,
    CrossRequest,
    CrossState,
    RetrievalEpochMismatch,
    IncompleteState,
    EffectNotDeterministicallyValidatable,
    ValidationFailed,
    ValidationIncomplete,
}

impl FreshExecutionReasonV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedSuggestion => "malformed_suggestion",
            Self::DuplicateSuggestion => "duplicate_suggestion",
            Self::SuggestionTooLarge => "suggestion_too_large",
            Self::StaleSuggestion => "stale_suggestion",
            Self::CrossRequest => "cross_request",
            Self::CrossState => "cross_state",
            Self::RetrievalEpochMismatch => "retrieval_epoch_mismatch",
            Self::IncompleteState => "incomplete_state",
            Self::EffectNotDeterministicallyValidatable => {
                "effect_not_deterministically_validatable"
            }
            Self::ValidationFailed => "validation_failed",
            Self::ValidationIncomplete => "validation_incomplete",
        }
    }
}

/// A fail-closed handoff to the canonical fresh-execution path.  This is a
/// reason token, not permission or an executable action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshExecutionRequiredV1 {
    reason: FreshExecutionReasonV1,
}

impl FreshExecutionRequiredV1 {
    #[must_use]
    pub const fn reason(self) -> FreshExecutionReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        "execute_fresh"
    }

    const fn new(reason: FreshExecutionReasonV1) -> Self {
        Self { reason }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateBindingErrorV1 {
    InvalidIdentifier,
    InvalidDigest,
    UnsupportedSchema,
}

/// Exact deterministic validator implementation identity.  The implementation
/// digest prevents a version label from silently changing meaning.
#[derive(Clone, Eq, PartialEq)]
pub struct DeterministicValidatorIdentityV1 {
    validator_id: String,
    validator_version: String,
    implementation_digest: String,
}

impl fmt::Debug for DeterministicValidatorIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeterministicValidatorIdentityV1(<redacted>)")
    }
}

impl DeterministicValidatorIdentityV1 {
    pub fn new(
        validator_id: &str,
        validator_version: &str,
        implementation_digest: &str,
    ) -> Result<Self, CandidateBindingErrorV1> {
        validate_identifier(validator_id)?;
        validate_identifier(validator_version)?;
        validate_digest(implementation_digest)?;
        Ok(Self {
            validator_id: validator_id.to_owned(),
            validator_version: validator_version.to_owned(),
            implementation_digest: implementation_digest.to_owned(),
        })
    }

    #[must_use]
    pub fn validator_id(&self) -> &str {
        &self.validator_id
    }

    #[must_use]
    pub fn validator_version(&self) -> &str {
        &self.validator_version
    }

    #[must_use]
    pub fn implementation_digest(&self) -> &str {
        &self.implementation_digest
    }
}

/// Opaque reference to the dependency proof that the deterministic validator
/// must verify.  This type does not validate or grant authority from the proof.
#[derive(Clone, Eq, PartialEq)]
pub struct DependencyProofReferenceV1 {
    schema_version: u16,
    proof_id: String,
    proof_version: String,
    proof_digest: String,
}

impl fmt::Debug for DependencyProofReferenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DependencyProofReferenceV1(<redacted>)")
    }
}

impl DependencyProofReferenceV1 {
    pub fn new(
        schema_version: u16,
        proof_id: &str,
        proof_version: &str,
        proof_digest: &str,
    ) -> Result<Self, CandidateBindingErrorV1> {
        if schema_version == 0 {
            return Err(CandidateBindingErrorV1::UnsupportedSchema);
        }
        validate_identifier(proof_id)?;
        validate_identifier(proof_version)?;
        validate_digest(proof_digest)?;
        Ok(Self {
            schema_version,
            proof_id: proof_id.to_owned(),
            proof_version: proof_version.to_owned(),
            proof_digest: proof_digest.to_owned(),
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    #[must_use]
    pub fn proof_version(&self) -> &str {
        &self.proof_version
    }

    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CandidateResultIdV1(String);

impl fmt::Debug for CandidateResultIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateResultIdV1(<redacted>)")
    }
}

impl CandidateResultIdV1 {
    fn parse(value: String) -> Result<Self, FreshExecutionRequiredV1> {
        validate_digest(&value).map_err(|_| malformed())?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueModelProvenanceV1(String);

impl fmt::Debug for OpaqueModelProvenanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueModelProvenanceV1(<redacted>)")
    }
}

impl OpaqueModelProvenanceV1 {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> String {
        tagged_digest(MODEL_PROVENANCE_DOMAIN_V1, [self.0.as_bytes()])
    }
}

/// Trusted inputs supplied separately from the untrusted suggestion document.
/// Requiring a `CompleteToolStateV1` makes an incomplete state unrepresentable
/// at this boundary.
pub struct CandidateValidationContextV1<'a> {
    pub canonical_request: &'a GatewayToolCallV1,
    pub complete_state: &'a CompleteToolStateV1,
    pub validator: &'a DeterministicValidatorIdentityV1,
    pub dependency_proof: &'a DependencyProofReferenceV1,
    pub expected_retrieval_epoch: u64,
    pub now_millis: u64,
}

/// The sole successful output artifact from this module.
#[derive(Clone, Eq, PartialEq)]
pub struct DeterministicValidationRequestV1 {
    validation_request_id: String,
    canonical_request_digest: String,
    canonical_request_bytes: Vec<u8>,
    complete_state_digest: String,
    complete_state_bytes: Vec<u8>,
    source_result_id: CandidateResultIdV1,
    model_provenance: OpaqueModelProvenanceV1,
    validator: DeterministicValidatorIdentityV1,
    dependency_proof: DependencyProofReferenceV1,
    retrieval_epoch: u64,
}

impl fmt::Debug for DeterministicValidationRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeterministicValidationRequestV1(<redacted>)")
    }
}

impl DeterministicValidationRequestV1 {
    #[must_use]
    pub fn validation_request_id(&self) -> &str {
        &self.validation_request_id
    }

    #[must_use]
    pub fn canonical_request_digest(&self) -> &str {
        &self.canonical_request_digest
    }

    #[must_use]
    pub fn canonical_request_bytes(&self) -> &[u8] {
        &self.canonical_request_bytes
    }

    #[must_use]
    pub fn complete_state_digest(&self) -> &str {
        &self.complete_state_digest
    }

    #[must_use]
    pub fn complete_state_bytes(&self) -> &[u8] {
        &self.complete_state_bytes
    }

    #[must_use]
    pub fn source_result_id(&self) -> &CandidateResultIdV1 {
        &self.source_result_id
    }

    #[must_use]
    pub fn model_provenance(&self) -> &OpaqueModelProvenanceV1 {
        &self.model_provenance
    }

    #[must_use]
    pub fn validator(&self) -> &DeterministicValidatorIdentityV1 {
        &self.validator
    }

    #[must_use]
    pub fn dependency_proof(&self) -> &DependencyProofReferenceV1 {
        &self.dependency_proof
    }

    #[must_use]
    pub const fn retrieval_epoch(&self) -> u64 {
        self.retrieval_epoch
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Compile-time marker for artifacts that carry no decision authority.
pub trait ValidationOnlyArtifactV1: sealed::Sealed {
    const GRANTS_EXACT: bool = false;
    const GRANTS_COVERAGE: bool = false;
    const GRANTS_REPLAY: bool = false;
    const GRANTS_EXECUTION: bool = false;
    const GRANTS_REUSE: bool = false;
    const GRANTS_SERVE: bool = false;
}

impl sealed::Sealed for DeterministicValidationRequestV1 {}
impl ValidationOnlyArtifactV1 for DeterministicValidationRequestV1 {}
impl sealed::Sealed for FreshExecutionRequiredV1 {}
impl ValidationOnlyArtifactV1 for FreshExecutionRequiredV1 {}

const _: () = {
    assert!(!DeterministicValidationRequestV1::GRANTS_EXACT);
    assert!(!DeterministicValidationRequestV1::GRANTS_COVERAGE);
    assert!(!DeterministicValidationRequestV1::GRANTS_REPLAY);
    assert!(!DeterministicValidationRequestV1::GRANTS_EXECUTION);
    assert!(!DeterministicValidationRequestV1::GRANTS_REUSE);
    assert!(!DeterministicValidationRequestV1::GRANTS_SERVE);
    assert!(!FreshExecutionRequiredV1::GRANTS_EXECUTION);
    assert!(!FreshExecutionRequiredV1::GRANTS_SERVE);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeterministicValidationStatusV1 {
    Complete,
    Failed,
    Incomplete,
}

/// A complete result has no output here and must return to the canonical
/// authority boundary.  Failure and incompleteness always request fresh work.
#[must_use]
pub const fn execute_fresh_after_validation_v1(
    status: DeterministicValidationStatusV1,
) -> Option<FreshExecutionRequiredV1> {
    match status {
        DeterministicValidationStatusV1::Complete => None,
        DeterministicValidationStatusV1::Failed => Some(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::ValidationFailed,
        )),
        DeterministicValidationStatusV1::Incomplete => Some(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::ValidationIncomplete,
        )),
    }
}

/// Parse and admit untrusted semantic/AI suggestions.  A successful return is
/// deterministically ordered and contains only validation requests.
pub fn build_deterministic_validation_requests_v1(
    input: &[u8],
    context: CandidateValidationContextV1<'_>,
    limits: &CandidateSuggestionLimitsV1,
) -> Result<Vec<DeterministicValidationRequestV1>, FreshExecutionRequiredV1> {
    let envelope = parse_suggestion_envelope(input, limits)?;
    validate_envelope_bindings(&envelope, &context, limits)?;

    let request_digest = context.canonical_request.request_digest();
    let canonical_request_digest = request_digest.as_str().to_owned();
    let canonical_request_bytes = context.canonical_request.canonical_bytes().to_vec();
    let complete_state_digest = context.complete_state.digest().to_hex();
    let complete_state_bytes = context.complete_state.canonical_bytes();

    let mut suggestions = envelope.suggestions;
    suggestions.sort_by(|left, right| left.result_id.cmp(&right.result_id));
    let mut seen = BTreeSet::new();
    let mut requests = Vec::with_capacity(suggestions.len());
    for suggestion in suggestions {
        let result_id = CandidateResultIdV1::parse(suggestion.result_id)?;
        if !seen.insert(result_id.clone()) {
            return Err(FreshExecutionRequiredV1::new(
                FreshExecutionReasonV1::DuplicateSuggestion,
            ));
        }
        if suggestion.model_provenance.is_empty() {
            return Err(malformed());
        }
        if suggestion.model_provenance.len() > limits.max_model_provenance_bytes {
            return Err(too_large());
        }
        let model_provenance = OpaqueModelProvenanceV1(suggestion.model_provenance);
        let validation_request_id = validation_request_id(
            &canonical_request_bytes,
            &complete_state_bytes,
            &result_id,
            &model_provenance,
            context.validator,
            context.dependency_proof,
            envelope.retrieval_epoch,
        );
        requests.push(DeterministicValidationRequestV1 {
            validation_request_id,
            canonical_request_digest: canonical_request_digest.clone(),
            canonical_request_bytes: canonical_request_bytes.clone(),
            complete_state_digest: complete_state_digest.clone(),
            complete_state_bytes: complete_state_bytes.clone(),
            source_result_id: result_id,
            model_provenance,
            validator: context.validator.clone(),
            dependency_proof: context.dependency_proof.clone(),
            retrieval_epoch: envelope.retrieval_epoch,
        });
    }
    Ok(requests)
}

fn validate_envelope_bindings(
    envelope: &SuggestionEnvelopeWireV1,
    context: &CandidateValidationContextV1<'_>,
    limits: &CandidateSuggestionLimitsV1,
) -> Result<(), FreshExecutionRequiredV1> {
    if envelope.schema_version != CANDIDATE_SUGGESTION_SCHEMA_VERSION_V1 {
        return Err(malformed());
    }
    if envelope.suggestions.is_empty() {
        return Err(malformed());
    }
    if envelope.suggestions.len() > limits.max_suggestions {
        return Err(too_large());
    }
    validate_digest(&envelope.request_digest).map_err(|_| malformed())?;
    validate_digest(&envelope.complete_state_digest).map_err(|_| malformed())?;
    if envelope.retrieval_epoch == 0 || envelope.retrieval_epoch != context.expected_retrieval_epoch
    {
        return Err(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::RetrievalEpochMismatch,
        ));
    }
    validate_freshness(envelope, context.now_millis, limits)?;

    let request_digest = context.canonical_request.request_digest();
    if envelope.request_digest != request_digest.as_str() {
        return Err(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::CrossRequest,
        ));
    }
    let complete_state_digest = context.complete_state.digest().to_hex();
    if envelope.complete_state_digest != complete_state_digest {
        return Err(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::CrossState,
        ));
    }
    validate_request_state_binding(context.canonical_request, context.complete_state)?;
    if !matches!(
        context.canonical_request.effect_class(),
        EffectClass::SnapshotRead
            | EffectClass::FreshnessBoundRead
            | EffectClass::DeterministicCompute
    ) {
        return Err(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::EffectNotDeterministicallyValidatable,
        ));
    }
    Ok(())
}

fn validate_request_state_binding(
    request: &GatewayToolCallV1,
    state: &CompleteToolStateV1,
) -> Result<(), FreshExecutionRequiredV1> {
    let RepositoryEnvironmentStateV1::Known { reference } = request.state() else {
        return Err(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::IncompleteState,
        ));
    };
    let expected_repository = state.agent_context().repository().digest().to_hex();
    let expected_environment = state.agent_context().environment().digest().to_hex();
    if reference.schema_version != state.schema_version()
        || reference.repository.algorithm != "blake3"
        || reference.repository.value != expected_repository
        || reference.environment.algorithm != "blake3"
        || reference.environment.value != expected_environment
    {
        return Err(FreshExecutionRequiredV1::new(
            FreshExecutionReasonV1::CrossState,
        ));
    }
    Ok(())
}

fn validate_freshness(
    envelope: &SuggestionEnvelopeWireV1,
    now_millis: u64,
    limits: &CandidateSuggestionLimitsV1,
) -> Result<(), FreshExecutionRequiredV1> {
    let Some(validity_window) = envelope
        .expires_at_millis
        .checked_sub(envelope.observed_at_millis)
    else {
        return Err(stale());
    };
    let Some(age) = now_millis.checked_sub(envelope.observed_at_millis) else {
        return Err(stale());
    };
    if now_millis > envelope.expires_at_millis
        || validity_window > limits.max_validity_window_millis
        || age > limits.max_suggestion_age_millis
    {
        return Err(stale());
    }
    Ok(())
}

fn validation_request_id(
    canonical_request: &[u8],
    complete_state: &[u8],
    result_id: &CandidateResultIdV1,
    provenance: &OpaqueModelProvenanceV1,
    validator: &DeterministicValidatorIdentityV1,
    dependency_proof: &DependencyProofReferenceV1,
    retrieval_epoch: u64,
) -> String {
    let schema_version = dependency_proof.schema_version.to_be_bytes();
    let epoch = retrieval_epoch.to_be_bytes();
    tagged_digest(
        VALIDATION_REQUEST_DOMAIN_V1,
        [
            canonical_request,
            complete_state,
            result_id.0.as_bytes(),
            provenance.0.as_bytes(),
            validator.validator_id.as_bytes(),
            validator.validator_version.as_bytes(),
            validator.implementation_digest.as_bytes(),
            &schema_version,
            dependency_proof.proof_id.as_bytes(),
            dependency_proof.proof_version.as_bytes(),
            dependency_proof.proof_digest.as_bytes(),
            &epoch,
        ],
    )
}

fn tagged_digest<'a>(domain: &[u8], fields: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_hex().to_string()
}

fn validate_identifier(value: &str) -> Result<(), CandidateBindingErrorV1> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\' && byte != b'"')
    {
        Err(CandidateBindingErrorV1::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), CandidateBindingErrorV1> {
    if value.len() == DIGEST_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CandidateBindingErrorV1::InvalidDigest)
    }
}

fn malformed() -> FreshExecutionRequiredV1 {
    FreshExecutionRequiredV1::new(FreshExecutionReasonV1::MalformedSuggestion)
}

fn too_large() -> FreshExecutionRequiredV1 {
    FreshExecutionRequiredV1::new(FreshExecutionReasonV1::SuggestionTooLarge)
}

fn stale() -> FreshExecutionRequiredV1 {
    FreshExecutionRequiredV1::new(FreshExecutionReasonV1::StaleSuggestion)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuggestionEnvelopeWireV1 {
    schema_version: u16,
    request_digest: String,
    complete_state_digest: String,
    retrieval_epoch: u64,
    observed_at_millis: u64,
    expires_at_millis: u64,
    suggestions: Vec<CandidateSuggestionWireV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateSuggestionWireV1 {
    result_id: String,
    model_provenance: String,
}

fn parse_suggestion_envelope(
    input: &[u8],
    limits: &CandidateSuggestionLimitsV1,
) -> Result<SuggestionEnvelopeWireV1, FreshExecutionRequiredV1> {
    if input.len() > limits.max_input_bytes {
        return Err(too_large());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = UniqueValueSeed
        .deserialize(&mut deserializer)
        .map_err(|error| {
            if error.to_string().starts_with("duplicate object key") {
                FreshExecutionRequiredV1::new(FreshExecutionReasonV1::DuplicateSuggestion)
            } else {
                malformed()
            }
        })?;
    deserializer.end().map_err(|_| malformed())?;
    validate_json_shape(&value, limits)?;
    serde_json::from_value(value).map_err(|_| malformed())
}

fn validate_json_shape(
    value: &Value,
    limits: &CandidateSuggestionLimitsV1,
) -> Result<(), FreshExecutionRequiredV1> {
    let mut stack = vec![(value, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        if depth > limits.max_json_depth {
            return Err(too_large());
        }
        nodes = nodes.checked_add(1).ok_or_else(too_large)?;
        if nodes > limits.max_json_nodes {
            return Err(too_large());
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

struct UniqueValueSeed;

impl<'de> DeserializeSeed<'de> for UniqueValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1_024));
        while let Some(value) = sequence.next_element_seed(UniqueValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut source: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = source.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate object key `{key}`")));
            }
            let value = source.next_value_seed(UniqueValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
