//! Fail-closed, execution-free routing decisions.

use std::fmt;

use super::profile_registry::{
    ClassifiedUniversalActionV1, ProfileSelectionStatusV1, SealedProfileRegistryV1,
};
use super::protocol::{
    CompleteToolStreamsV1, DigestReferenceV1, EffectClass, FreshnessRequirementV1,
    GatewayAdapterToolCallV1, GatewayToolCallV1, PermissionClass, RepositoryEnvironmentStateV1,
    RequestDigestV1, ToolCapabilityClassV1, ToolPolicyDispositionV1, UniversalActionContextV1,
    UniversalToolPolicyV1,
};
use super::{
    DeliveryReceiptV1, GatewayResultIdentityV1, PresentationContextV1, PresentationDecisionV1,
    PresentationRefusalV1, decide_presentation_v1,
};
use crate::store::{StoreExactResultProofV1, StoreInflightJoinProofV1};

const MAX_ORIGIN_IDENTIFIER_BYTES_V1: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayDecision {
    ServeExact,
    ServeDeterministicCoverage,
    JoinInflight,
    ValidateSemanticCandidate,
    Execute,
    ExecuteNonReplayable,
    RequireApproval,
    Refuse,
}

/// Stable product-level outcomes for a provider-neutral tool policy. These
/// outcomes add constraints to [`GatewayDecision`]; they never mint authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniversalGatewayDecisionV1 {
    /// Automatic-router hit after the sealed profile and existing store proof
    /// both agree. The profile identity alone can never produce this variant.
    ReusePromotedResult,
    ReuseExact,
    ReuseDeterministicCoverage,
    JoinInflight,
    ExecuteAndObserve,
    PassthroughWithoutStorage,
    RefuseByPolicy,
    RefuseDangerousInvalidConfiguration,
}

/// Conservative economics for the reusable lane. Missing or overflowing
/// measurements bypass lookup, validation, materialization, and storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReuseValueModelV1 {
    Unknown,
    Measured {
        native_execution_micros: u64,
        lookup_micros: u64,
        validation_micros: u64,
        materialization_micros: u64,
        minimum_savings_micros: u64,
    },
}

impl ReuseValueModelV1 {
    pub const fn unknown() -> Self {
        Self::Unknown
    }

    pub const fn measured(
        native_execution_micros: u64,
        lookup_micros: u64,
        validation_micros: u64,
        materialization_micros: u64,
        minimum_savings_micros: u64,
    ) -> Self {
        Self::Measured {
            native_execution_micros,
            lookup_micros,
            validation_micros,
            materialization_micros,
            minimum_savings_micros,
        }
    }

    pub const fn has_positive_value(self) -> bool {
        let Self::Measured {
            native_execution_micros,
            lookup_micros,
            validation_micros,
            materialization_micros,
            minimum_savings_micros,
        } = self
        else {
            return false;
        };
        let Some(cost) = lookup_micros.checked_add(validation_micros) else {
            return false;
        };
        let Some(cost) = cost.checked_add(materialization_micros) else {
            return false;
        };
        let Some(required) = cost.checked_add(minimum_savings_micros) else {
            return false;
        };
        native_execution_micros >= required
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniversalGatewayMetricEventV1 {
    Route,
    Miss,
    Join,
    Candidate,
    Promotion,
    Invalidation,
    Quarantine,
    Bytes(u64),
    MeasuredTimeMicros(u64),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UniversalGatewayMetricsV1 {
    routes: u64,
    misses: u64,
    joins: u64,
    candidates: u64,
    promotions: u64,
    invalidations: u64,
    quarantines: u64,
    bytes: u64,
    measured_time_micros: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniversalGatewayMetricOverflowV1;

impl UniversalGatewayMetricsV1 {
    pub fn record(
        &mut self,
        event: UniversalGatewayMetricEventV1,
    ) -> Result<(), UniversalGatewayMetricOverflowV1> {
        let counter = match event {
            UniversalGatewayMetricEventV1::Route => &mut self.routes,
            UniversalGatewayMetricEventV1::Miss => &mut self.misses,
            UniversalGatewayMetricEventV1::Join => &mut self.joins,
            UniversalGatewayMetricEventV1::Candidate => &mut self.candidates,
            UniversalGatewayMetricEventV1::Promotion => &mut self.promotions,
            UniversalGatewayMetricEventV1::Invalidation => &mut self.invalidations,
            UniversalGatewayMetricEventV1::Quarantine => &mut self.quarantines,
            UniversalGatewayMetricEventV1::Bytes(_) => &mut self.bytes,
            UniversalGatewayMetricEventV1::MeasuredTimeMicros(_) => &mut self.measured_time_micros,
        };
        let amount = match event {
            UniversalGatewayMetricEventV1::Bytes(bytes)
            | UniversalGatewayMetricEventV1::MeasuredTimeMicros(bytes) => bytes,
            _ => 1,
        };
        *counter = counter
            .checked_add(amount)
            .ok_or(UniversalGatewayMetricOverflowV1)?;
        Ok(())
    }

    pub const fn routes(&self) -> u64 {
        self.routes
    }

    pub const fn misses(&self) -> u64 {
        self.misses
    }

    pub const fn joins(&self) -> u64 {
        self.joins
    }

    pub const fn candidates(&self) -> u64 {
        self.candidates
    }

    pub const fn promotions(&self) -> u64 {
        self.promotions
    }

    pub const fn invalidations(&self) -> u64 {
        self.invalidations
    }

    pub const fn quarantines(&self) -> u64 {
        self.quarantines
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub const fn measured_time_micros(&self) -> u64 {
        self.measured_time_micros
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayCandidateKindV1 {
    Exact,
    Deterministic,
    Semantic,
    Ai,
}

impl GatewayCandidateKindV1 {
    pub const ALL: [Self; 4] = [Self::Exact, Self::Deterministic, Self::Semantic, Self::Ai];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayCandidateRequestV1 {
    ExecuteFresh,
    DeterministicValidation,
    Reuse,
}

impl GatewayCandidateRequestV1 {
    pub const ALL: [Self; 3] = [
        Self::ExecuteFresh,
        Self::DeterministicValidation,
        Self::Reuse,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRouteRefusalV1 {
    UnknownEffect,
    CandidateMayOnlyRequestValidation,
    EffectNotDeterministicallyValidatable,
    DirectReuseForbidden,
}

impl GatewayRouteRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownEffect => "unknown_effect",
            Self::CandidateMayOnlyRequestValidation => "candidate_may_only_request_validation",
            Self::EffectNotDeterministicallyValidatable => {
                "effect_not_deterministically_validatable"
            }
            Self::DirectReuseForbidden => "direct_reuse_forbidden",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRouteDecisionV1 {
    ExecuteFresh,
    RequireDeterministicValidation,
    Reject(GatewayRouteRefusalV1),
}

impl GatewayRouteDecisionV1 {
    pub const fn grants_reuse(self) -> bool {
        false
    }

    pub const fn executes_tool(self) -> bool {
        matches!(self, Self::ExecuteFresh)
    }
}

/// Route an untrusted candidate request. This adapter has no serve variant.
pub fn route_gateway_candidate_v1(
    call: &GatewayAdapterToolCallV1,
    candidate: GatewayCandidateKindV1,
    request: GatewayCandidateRequestV1,
) -> GatewayRouteDecisionV1 {
    if call.effect().is_unknown() {
        return GatewayRouteDecisionV1::Reject(GatewayRouteRefusalV1::UnknownEffect);
    }
    if matches!(
        candidate,
        GatewayCandidateKindV1::Semantic | GatewayCandidateKindV1::Ai
    ) && request != GatewayCandidateRequestV1::DeterministicValidation
    {
        return GatewayRouteDecisionV1::Reject(
            GatewayRouteRefusalV1::CandidateMayOnlyRequestValidation,
        );
    }
    match request {
        GatewayCandidateRequestV1::ExecuteFresh => GatewayRouteDecisionV1::ExecuteFresh,
        GatewayCandidateRequestV1::DeterministicValidation
            if call.effect().supports_deterministic_validation() =>
        {
            GatewayRouteDecisionV1::RequireDeterministicValidation
        }
        GatewayCandidateRequestV1::DeterministicValidation => GatewayRouteDecisionV1::Reject(
            GatewayRouteRefusalV1::EffectNotDeterministicallyValidatable,
        ),
        GatewayCandidateRequestV1::Reuse => {
            GatewayRouteDecisionV1::Reject(GatewayRouteRefusalV1::DirectReuseForbidden)
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
enum VerifiedCandidateOriginV1 {
    DeterministicCoverage {
        rule_id: String,
        rule_version: String,
        source_request_digest: RequestDigestV1,
        source_result_digest: DigestReferenceV1,
        validator_digest: DigestReferenceV1,
    },
    SemanticOrAiGenerated {
        provider_id: String,
        model_id: String,
        model_version: String,
    },
}

impl fmt::Debug for VerifiedCandidateOriginV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::DeterministicCoverage { .. } => "deterministic_coverage",
            Self::SemanticOrAiGenerated { .. } => "semantic_or_ai_generated",
        };
        formatter
            .debug_struct("VerifiedCandidateOriginV1")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateFreshnessV1 {
    ExactSnapshot,
    AgeMillis(u64),
    Revalidated,
}

/// Opaque candidate. Public callers can create only semantic/AI retrieval
/// candidates, which can never satisfy either serve branch.
#[derive(PartialEq, Eq)]
pub struct ReuseCandidateV1 {
    request_digest: RequestDigestV1,
    result_digest: DigestReferenceV1,
    origin: VerifiedCandidateOriginV1,
    freshness: CandidateFreshnessV1,
}

impl fmt::Debug for ReuseCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReuseCandidateV1(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateEvidenceRefusalV1 {
    Identifier,
    Digest,
}

impl ReuseCandidateV1 {
    /// Semantic/AI retrieval metadata is admitted only into the validation
    /// lane. It cannot be placed into exact or coverage slots by public APIs.
    pub fn semantic_or_ai_candidate(
        request_digest: RequestDigestV1,
        result_digest: DigestReferenceV1,
        provider_id: &str,
        model_id: &str,
        model_version: &str,
        freshness: CandidateFreshnessV1,
    ) -> Result<Self, CandidateEvidenceRefusalV1> {
        for value in [provider_id, model_id, model_version] {
            validate_origin_identifier(value)?;
        }
        result_digest
            .validate_bounded()
            .map_err(|_| CandidateEvidenceRefusalV1::Digest)?;
        Ok(Self {
            request_digest,
            result_digest,
            origin: VerifiedCandidateOriginV1::SemanticOrAiGenerated {
                provider_id: provider_id.to_owned(),
                model_id: model_id.to_owned(),
                model_version: model_version.to_owned(),
            },
            freshness,
        })
    }

    pub fn request_digest(&self) -> &RequestDigestV1 {
        &self.request_digest
    }

    pub fn result_digest(&self) -> &DigestReferenceV1 {
        &self.result_digest
    }

    pub const fn freshness(&self) -> CandidateFreshnessV1 {
        self.freshness
    }
}

fn validate_origin_identifier(value: &str) -> Result<(), CandidateEvidenceRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_ORIGIN_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CandidateEvidenceRefusalV1::Identifier);
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) struct VerifiedCoverageEvidenceV1 {
    pub(crate) request_digest: RequestDigestV1,
    pub(crate) result_digest: DigestReferenceV1,
    pub(crate) freshness: CandidateFreshnessV1,
    pub(crate) rule_id: String,
    pub(crate) rule_version: String,
    pub(crate) source_request_digest: RequestDigestV1,
    pub(crate) source_result_digest: DigestReferenceV1,
    pub(crate) validator_digest: DigestReferenceV1,
}

#[allow(dead_code)]
pub(crate) fn issue_coverage_candidate_v1(
    evidence: VerifiedCoverageEvidenceV1,
) -> Result<ReuseCandidateV1, CandidateEvidenceRefusalV1> {
    validate_origin_identifier(&evidence.rule_id)?;
    validate_origin_identifier(&evidence.rule_version)?;
    for digest in [
        &evidence.result_digest,
        &evidence.source_result_digest,
        &evidence.validator_digest,
    ] {
        digest
            .validate_bounded()
            .map_err(|_| CandidateEvidenceRefusalV1::Digest)?;
    }
    Ok(ReuseCandidateV1 {
        request_digest: evidence.request_digest,
        result_digest: evidence.result_digest,
        origin: VerifiedCandidateOriginV1::DeterministicCoverage {
            rule_id: evidence.rule_id,
            rule_version: evidence.rule_version,
            source_request_digest: evidence.source_request_digest,
            source_result_digest: evidence.source_result_digest,
            validator_digest: evidence.validator_digest,
        },
        freshness: evidence.freshness,
    })
}

#[derive(Default)]
pub struct RoutingCandidatesV1 {
    store_exact: Option<StoreExactResultProofV1>,
    deterministic_coverage: Option<ReuseCandidateV1>,
    store_inflight: Option<StoreInflightJoinProofV1>,
    semantic: Option<ReuseCandidateV1>,
}

impl fmt::Debug for RoutingCandidatesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RoutingCandidatesV1(<redacted>)")
    }
}

impl RoutingCandidatesV1 {
    pub fn with_semantic_candidate(mut self, candidate: ReuseCandidateV1) -> Self {
        if matches!(
            candidate.origin,
            VerifiedCandidateOriginV1::SemanticOrAiGenerated { .. }
        ) {
            self.semantic = Some(candidate);
        }
        self
    }

    pub fn with_store_exact_proof(mut self, proof: StoreExactResultProofV1) -> Self {
        self.store_exact = Some(proof);
        self
    }

    #[allow(dead_code)]
    pub(crate) fn with_coverage(mut self, candidate: ReuseCandidateV1) -> Self {
        if matches!(
            candidate.origin,
            VerifiedCandidateOriginV1::DeterministicCoverage { .. }
        ) {
            self.deterministic_coverage = Some(candidate);
        }
        self
    }

    pub fn with_store_inflight_proof(mut self, proof: StoreInflightJoinProofV1) -> Self {
        self.store_inflight = Some(proof);
        self
    }
}

pub fn route(call: &GatewayToolCallV1, candidates: &RoutingCandidatesV1) -> GatewayDecision {
    match call.permission_class() {
        PermissionClass::Denied => return GatewayDecision::Refuse,
        PermissionClass::RequiresApproval => return GatewayDecision::RequireApproval,
        PermissionClass::Preapproved => {}
    }
    match call.effect_class() {
        EffectClass::Mutation | EffectClass::ExternalSideEffect | EffectClass::Unknown => {
            return GatewayDecision::ExecuteNonReplayable;
        }
        EffectClass::SnapshotRead
        | EffectClass::FreshnessBoundRead
        | EffectClass::DeterministicCompute => {}
    }
    if matches!(call.state(), RepositoryEnvironmentStateV1::Unknown) {
        return GatewayDecision::Execute;
    }

    let request_digest = call.request_digest();
    if let Some(proof) = &candidates.store_exact
        && proof.authorizes_router_call_v1(call)
    {
        return GatewayDecision::ServeExact;
    }
    if let Some(candidate) = &candidates.deterministic_coverage
        && candidate.request_digest == request_digest
        && matches!(
            candidate.origin,
            VerifiedCandidateOriginV1::DeterministicCoverage { .. }
        )
        && freshness_satisfies(call.freshness(), candidate.freshness)
    {
        return GatewayDecision::ServeDeterministicCoverage;
    }
    if let Some(proof) = &candidates.store_inflight
        && proof.authorizes_router_call_v1(call)
    {
        return GatewayDecision::JoinInflight;
    }
    if candidates.semantic.is_some() {
        GatewayDecision::ValidateSemanticCandidate
    } else {
        GatewayDecision::Execute
    }
}

/// Apply local provider-neutral policy while delegating all reuse decisions to
/// the existing proof-gated router. Provider annotations and policy metadata
/// alone can therefore never produce a hit.
pub fn route_with_tool_policy_v1(
    call: &GatewayToolCallV1,
    candidates: &RoutingCandidatesV1,
    policy: &UniversalToolPolicyV1,
) -> UniversalGatewayDecisionV1 {
    let routed = route(call, candidates);
    if policy.disposition() == ToolPolicyDispositionV1::Deny
        || matches!(
            routed,
            GatewayDecision::RequireApproval | GatewayDecision::Refuse
        )
    {
        return UniversalGatewayDecisionV1::RefuseByPolicy;
    }

    if policy.capability().must_bypass_storage() {
        return UniversalGatewayDecisionV1::PassthroughWithoutStorage;
    }

    match policy.capability() {
        ToolCapabilityClassV1::ExactStateBoundRead
        | ToolCapabilityClassV1::DeterministicCommand => match routed {
            GatewayDecision::ServeExact => UniversalGatewayDecisionV1::ReuseExact,
            GatewayDecision::ServeDeterministicCoverage => {
                UniversalGatewayDecisionV1::ReuseDeterministicCoverage
            }
            GatewayDecision::JoinInflight => UniversalGatewayDecisionV1::JoinInflight,
            GatewayDecision::Execute
            | GatewayDecision::ValidateSemanticCandidate
            | GatewayDecision::ExecuteNonReplayable => {
                UniversalGatewayDecisionV1::ExecuteAndObserve
            }
            GatewayDecision::RequireApproval | GatewayDecision::Refuse => {
                UniversalGatewayDecisionV1::RefuseByPolicy
            }
        },
        // A declared freshness validator is not evidence that validation ran.
        // Until a proof type exists, freshness-bound reads execute every time.
        ToolCapabilityClassV1::FreshnessBoundRead | ToolCapabilityClassV1::NonReusableRead => {
            UniversalGatewayDecisionV1::ExecuteAndObserve
        }
        ToolCapabilityClassV1::Mutation
        | ToolCapabilityClassV1::CredentialOperation
        | ToolCapabilityClassV1::Communication
        | ToolCapabilityClassV1::Deployment
        | ToolCapabilityClassV1::Payment
        | ToolCapabilityClassV1::Interactive
        | ToolCapabilityClassV1::Unknown => UniversalGatewayDecisionV1::PassthroughWithoutStorage,
    }
}

/// Classify an action through the immutable built-in registry. This is the one
/// automatic classification entrance; callers cannot supply or register a
/// policy that upgrades profile authority.
pub fn classify_action_v1(
    call: &GatewayToolCallV1,
    context: &UniversalActionContextV1,
) -> ClassifiedUniversalActionV1 {
    SealedProfileRegistryV1::builtin().classify(call, context)
}

/// Route every action to one deterministic, safe product decision. This API
/// has no executor and never accepts a command string as authority.
pub fn route_automatically_v1(
    call: &GatewayToolCallV1,
    candidates: &RoutingCandidatesV1,
    context: &UniversalActionContextV1,
    value: ReuseValueModelV1,
) -> UniversalGatewayDecisionV1 {
    let classification = classify_action_v1(call, context);
    if classification.status() == ProfileSelectionStatusV1::DangerousInvalidConfiguration {
        return UniversalGatewayDecisionV1::RefuseDangerousInvalidConfiguration;
    }

    if !matches!(call.permission_class(), PermissionClass::Preapproved) {
        return UniversalGatewayDecisionV1::RefuseByPolicy;
    }

    // This branch precedes candidate inspection. Callers can therefore apply
    // the same value gate before store lookup and avoid lookup, validation,
    // materialization, and candidate storage together.
    if classification.status() == ProfileSelectionStatusV1::Qualified && !value.has_positive_value()
    {
        return UniversalGatewayDecisionV1::PassthroughWithoutStorage;
    }

    let policy_decision = route_with_tool_policy_v1(call, candidates, classification.policy());
    if matches!(policy_decision, UniversalGatewayDecisionV1::RefuseByPolicy) {
        return policy_decision;
    }

    match classification.status() {
        ProfileSelectionStatusV1::DangerousInvalidConfiguration => {
            UniversalGatewayDecisionV1::RefuseDangerousInvalidConfiguration
        }
        ProfileSelectionStatusV1::ContractOnly => {
            UniversalGatewayDecisionV1::PassthroughWithoutStorage
        }
        ProfileSelectionStatusV1::Unprofiled => match classification.capability() {
            ToolCapabilityClassV1::FreshnessBoundRead => {
                UniversalGatewayDecisionV1::ExecuteAndObserve
            }
            ToolCapabilityClassV1::NonReusableRead
            | ToolCapabilityClassV1::Mutation
            | ToolCapabilityClassV1::CredentialOperation
            | ToolCapabilityClassV1::Communication
            | ToolCapabilityClassV1::Deployment
            | ToolCapabilityClassV1::Payment
            | ToolCapabilityClassV1::Interactive
            | ToolCapabilityClassV1::Unknown => {
                UniversalGatewayDecisionV1::PassthroughWithoutStorage
            }
            ToolCapabilityClassV1::ExactStateBoundRead
            | ToolCapabilityClassV1::DeterministicCommand => {
                UniversalGatewayDecisionV1::PassthroughWithoutStorage
            }
        },
        ProfileSelectionStatusV1::Qualified => match policy_decision {
            UniversalGatewayDecisionV1::ReuseExact
            | UniversalGatewayDecisionV1::ReuseDeterministicCoverage => {
                UniversalGatewayDecisionV1::ReusePromotedResult
            }
            UniversalGatewayDecisionV1::JoinInflight => UniversalGatewayDecisionV1::JoinInflight,
            UniversalGatewayDecisionV1::ExecuteAndObserve => {
                UniversalGatewayDecisionV1::ExecuteAndObserve
            }
            UniversalGatewayDecisionV1::PassthroughWithoutStorage => {
                UniversalGatewayDecisionV1::PassthroughWithoutStorage
            }
            UniversalGatewayDecisionV1::RefuseByPolicy => {
                UniversalGatewayDecisionV1::RefuseByPolicy
            }
            UniversalGatewayDecisionV1::ReusePromotedResult
            | UniversalGatewayDecisionV1::RefuseDangerousInvalidConfiguration => {
                UniversalGatewayDecisionV1::RefuseDangerousInvalidConfiguration
            }
        },
    }
}

/// Select compact presentation only through the existing recipient-bound
/// complete-delivery receipt. Otherwise the exact complete streams remain the
/// required presentation.
pub fn decide_complete_stream_presentation_v1(
    context: &PresentationContextV1,
    call: &GatewayToolCallV1,
    streams: &CompleteToolStreamsV1,
    receipt: Option<&DeliveryReceiptV1>,
) -> Result<PresentationDecisionV1, PresentationRefusalV1> {
    let result = GatewayResultIdentityV1::from_streams(
        streams.status(),
        streams.stdout(),
        streams.stderr(),
    )?;
    Ok(decide_presentation_v1(context, call, result, receipt))
}

fn freshness_satisfies(
    requirement: FreshnessRequirementV1,
    evidence: CandidateFreshnessV1,
) -> bool {
    match requirement {
        FreshnessRequirementV1::Snapshot => evidence == CandidateFreshnessV1::ExactSnapshot,
        FreshnessRequirementV1::MaxAgeMillis(maximum) => match evidence {
            CandidateFreshnessV1::AgeMillis(age) => age <= maximum,
            CandidateFreshnessV1::Revalidated => true,
            CandidateFreshnessV1::ExactSnapshot => false,
        },
        FreshnessRequirementV1::RequireRevalidation => {
            evidence == CandidateFreshnessV1::Revalidated
        }
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::agent_gateway::protocol::{
        AgentCallIdentityV1, CanonicalArguments, GatewayToolCallInputV1, ModelIdentityV1,
        PresentationMode, ProviderIdentityV1, StateDigestReferenceV1, TaskIdentityV1,
        ToolIdentityV1, WorkspaceIdentityV1,
    };

    fn digest(value: &str) -> DigestReferenceV1 {
        DigestReferenceV1::new("blake3", value).unwrap()
    }

    fn call(effect: EffectClass, freshness: FreshnessRequirementV1) -> GatewayToolCallV1 {
        GatewayToolCallV1::from_input(GatewayToolCallInputV1 {
            schema_version: 1,
            provider: ProviderIdentityV1 {
                id: "provider".to_owned(),
                version: "1".to_owned(),
            },
            model: ModelIdentityV1 {
                id: "model".to_owned(),
                version: "1".to_owned(),
            },
            tool: ToolIdentityV1 {
                id: "tool".to_owned(),
                version: "1".to_owned(),
            },
            arguments: CanonicalArguments::from_json_str("{}").unwrap(),
            workspace: WorkspaceIdentityV1 {
                workspace_id: "workspace".to_owned(),
                cwd: ".".to_owned(),
            },
            call: AgentCallIdentityV1 {
                agent_id: "agent".to_owned(),
                session_id: "session".to_owned(),
                turn_id: "turn".to_owned(),
                call_id: "call".to_owned(),
            },
            task: Some(TaskIdentityV1 {
                task_id: "task".to_owned(),
                version: "1".to_owned(),
            }),
            state: RepositoryEnvironmentStateV1::Known {
                reference: StateDigestReferenceV1 {
                    schema_version: 1,
                    repository: digest("repository"),
                    environment: digest("environment"),
                },
            },
            permission_class: PermissionClass::Preapproved,
            effect_class: effect,
            freshness,
            presentation: PresentationMode::Exact,
        })
        .unwrap()
    }

    #[test]
    fn deterministic_coverage_stays_sealed() {
        let call = call(EffectClass::SnapshotRead, FreshnessRequirementV1::Snapshot);
        let coverage = issue_coverage_candidate_v1(VerifiedCoverageEvidenceV1 {
            request_digest: call.request_digest(),
            result_digest: digest("covered-result"),
            freshness: CandidateFreshnessV1::ExactSnapshot,
            rule_id: "excerpt".to_owned(),
            rule_version: "1".to_owned(),
            source_request_digest: call.request_digest(),
            source_result_digest: digest("source-result"),
            validator_digest: digest("validator"),
        })
        .unwrap();
        assert_eq!(
            route(
                &call,
                &RoutingCandidatesV1::default().with_coverage(coverage)
            ),
            GatewayDecision::ServeDeterministicCoverage
        );
    }
}
