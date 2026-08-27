//! Fail-closed, execution-free routing decisions.

use super::protocol::{
    DigestReferenceV1, EffectClass, FreshnessRequirementV1, GatewayEffectClassV1,
    GatewayToolCallV1, PermissionClass, RepositoryEnvironmentStateV1, RequestDigestV1,
};

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
    /// The untrusted-candidate adapter can never grant reuse by construction.
    pub const fn grants_reuse(self) -> bool {
        false
    }

    pub const fn executes_tool(self) -> bool {
        matches!(self, Self::ExecuteFresh)
    }
}

/// Route a candidate-originated request without trusting its claimed match.
/// Semantic and AI candidates may only ask for deterministic validation.
pub fn route_gateway_candidate_v1(
    call: &GatewayToolCallV1,
    candidate: GatewayCandidateKindV1,
    request: GatewayCandidateRequestV1,
) -> GatewayRouteDecisionV1 {
    if call.effect() == GatewayEffectClassV1::Unknown {
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

/// Provenance is checked independently of where a candidate was placed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateOriginV1 {
    RecordedExecution,
    DeterministicDerivation {
        rule_id: String,
        rule_version: String,
    },
    SemanticOrAiGenerated {
        provider_id: String,
        model_id: String,
        model_version: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateFreshnessV1 {
    ExactSnapshot,
    AgeMillis(u64),
    Revalidated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReuseCandidateV1 {
    request_digest: RequestDigestV1,
    result_digest: DigestReferenceV1,
    origin: CandidateOriginV1,
    freshness: CandidateFreshnessV1,
}

impl ReuseCandidateV1 {
    pub fn new(
        request_digest: RequestDigestV1,
        result_digest: DigestReferenceV1,
        origin: CandidateOriginV1,
        freshness: CandidateFreshnessV1,
    ) -> Self {
        Self {
            request_digest,
            result_digest,
            origin,
            freshness,
        }
    }

    pub fn request_digest(&self) -> &RequestDigestV1 {
        &self.request_digest
    }

    pub fn result_digest(&self) -> &DigestReferenceV1 {
        &self.result_digest
    }

    pub fn origin(&self) -> &CandidateOriginV1 {
        &self.origin
    }

    pub fn freshness(&self) -> CandidateFreshnessV1 {
        self.freshness
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InflightRequestV1 {
    request_digest: RequestDigestV1,
    replay_safe: bool,
}

impl InflightRequestV1 {
    pub fn new(request_digest: RequestDigestV1, replay_safe: bool) -> Self {
        Self {
            request_digest,
            replay_safe,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutingCandidatesV1 {
    pub exact: Option<ReuseCandidateV1>,
    pub deterministic_coverage: Option<ReuseCandidateV1>,
    pub inflight: Option<InflightRequestV1>,
    /// A retrieval candidate that always requires independent validation.
    pub semantic: Option<ReuseCandidateV1>,
}

/// Decide what may happen next without serving, executing, or validating data.
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
    let mut semantic_candidate_seen = candidates.semantic.is_some();

    if let Some(candidate) = &candidates.exact {
        semantic_candidate_seen |= is_semantic(candidate);
        if candidate.request_digest == request_digest
            && matches!(candidate.origin, CandidateOriginV1::RecordedExecution)
            && freshness_satisfies(call.freshness(), candidate.freshness)
        {
            return GatewayDecision::ServeExact;
        }
    }

    if let Some(candidate) = &candidates.deterministic_coverage {
        semantic_candidate_seen |= is_semantic(candidate);
        if candidate.request_digest == request_digest
            && matches!(
                candidate.origin,
                CandidateOriginV1::DeterministicDerivation { .. }
            )
            && freshness_satisfies(call.freshness(), candidate.freshness)
        {
            return GatewayDecision::ServeDeterministicCoverage;
        }
    }

    if candidates
        .inflight
        .as_ref()
        .is_some_and(|inflight| inflight.replay_safe && inflight.request_digest == request_digest)
    {
        return GatewayDecision::JoinInflight;
    }

    if semantic_candidate_seen {
        GatewayDecision::ValidateSemanticCandidate
    } else {
        GatewayDecision::Execute
    }
}

fn is_semantic(candidate: &ReuseCandidateV1) -> bool {
    matches!(
        candidate.origin,
        CandidateOriginV1::SemanticOrAiGenerated { .. }
    )
}

fn freshness_satisfies(
    requirement: FreshnessRequirementV1,
    evidence: CandidateFreshnessV1,
) -> bool {
    match requirement {
        FreshnessRequirementV1::Snapshot => true,
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
