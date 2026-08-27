//! Fail-closed, execution-free routing decisions.

use std::fmt;

use super::protocol::{
    DigestReferenceV1, EffectClass, FreshnessRequirementV1, GatewayAdapterToolCallV1,
    GatewayToolCallV1, PermissionClass, RepositoryEnvironmentStateV1, RequestDigestV1,
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
    RecordedExecution {
        store_record_digest: DigestReferenceV1,
    },
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
    LegacyUntrustedStoreObservation,
}

impl fmt::Debug for VerifiedCandidateOriginV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::RecordedExecution { .. } => "recorded_execution",
            Self::DeterministicCoverage { .. } => "deterministic_coverage",
            Self::SemanticOrAiGenerated { .. } => "semantic_or_ai_generated",
            Self::LegacyUntrustedStoreObservation => "legacy_untrusted_store_observation",
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
    Lifecycle,
    Effect,
    Freshness,
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

pub(crate) struct VerifiedStoreCandidateEvidenceV1 {
    pub(crate) request_digest: RequestDigestV1,
    pub(crate) result_digest: DigestReferenceV1,
    pub(crate) store_record_digest: DigestReferenceV1,
    pub(crate) freshness: CandidateFreshnessV1,
}

pub(crate) fn issue_recorded_candidate_v1(
    evidence: VerifiedStoreCandidateEvidenceV1,
) -> Result<ReuseCandidateV1, CandidateEvidenceRefusalV1> {
    evidence
        .result_digest
        .validate_bounded()
        .map_err(|_| CandidateEvidenceRefusalV1::Digest)?;
    evidence
        .store_record_digest
        .validate_bounded()
        .map_err(|_| CandidateEvidenceRefusalV1::Digest)?;
    Ok(ReuseCandidateV1 {
        request_digest: evidence.request_digest,
        result_digest: evidence.result_digest,
        origin: VerifiedCandidateOriginV1::LegacyUntrustedStoreObservation,
        freshness: evidence.freshness,
    })
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

#[derive(PartialEq, Eq)]
pub(crate) struct InflightJoinEvidenceV1 {
    request_digest: RequestDigestV1,
    effect_class: EffectClass,
    lifecycle_generation: u64,
    observed_generation: u64,
    started_at_millis: u64,
    observed_at_millis: u64,
    revalidated_at_generation: Option<u64>,
    freshness: CandidateFreshnessV1,
}

impl fmt::Debug for InflightJoinEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InflightJoinEvidenceV1(<redacted>)")
    }
}

pub(crate) struct CoordinatorJoinObservationV1 {
    pub(crate) request_digest: RequestDigestV1,
    pub(crate) effect_class: EffectClass,
    pub(crate) lifecycle_generation: u64,
    pub(crate) observed_generation: u64,
    pub(crate) started_at_millis: u64,
    pub(crate) observed_at_millis: u64,
    pub(crate) revalidated_at_generation: Option<u64>,
}

pub(crate) fn issue_inflight_join_evidence_v1(
    observation: CoordinatorJoinObservationV1,
) -> Result<InflightJoinEvidenceV1, CandidateEvidenceRefusalV1> {
    if observation.lifecycle_generation == 0
        || observation.lifecycle_generation != observation.observed_generation
    {
        return Err(CandidateEvidenceRefusalV1::Lifecycle);
    }
    if !matches!(
        observation.effect_class,
        EffectClass::SnapshotRead
            | EffectClass::FreshnessBoundRead
            | EffectClass::DeterministicCompute
    ) {
        return Err(CandidateEvidenceRefusalV1::Effect);
    }
    let age = observation
        .observed_at_millis
        .checked_sub(observation.started_at_millis)
        .ok_or(CandidateEvidenceRefusalV1::Freshness)?;
    let freshness =
        if observation.revalidated_at_generation == Some(observation.lifecycle_generation) {
            CandidateFreshnessV1::Revalidated
        } else if observation.effect_class == EffectClass::SnapshotRead {
            CandidateFreshnessV1::ExactSnapshot
        } else {
            CandidateFreshnessV1::AgeMillis(age)
        };
    Ok(InflightJoinEvidenceV1 {
        request_digest: observation.request_digest,
        effect_class: observation.effect_class,
        lifecycle_generation: observation.lifecycle_generation,
        observed_generation: observation.observed_generation,
        started_at_millis: observation.started_at_millis,
        observed_at_millis: observation.observed_at_millis,
        revalidated_at_generation: observation.revalidated_at_generation,
        freshness,
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

    pub(crate) fn with_exact(self, _candidate: ReuseCandidateV1) -> Self {
        // Compatibility only: caller-described evidence can no longer enter
        // the exact-serve slot. Store transactions issue the sealed proof.
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

    pub(crate) fn with_inflight(self, _evidence: InflightJoinEvidenceV1) -> Self {
        // Compatibility only; synthesized lifecycle observations do not grant
        // join authority.
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
    fn legacy_store_observations_cannot_serve_but_coverage_stays_sealed() {
        let call = call(EffectClass::SnapshotRead, FreshnessRequirementV1::Snapshot);
        let exact = issue_recorded_candidate_v1(VerifiedStoreCandidateEvidenceV1 {
            request_digest: call.request_digest(),
            result_digest: digest("result"),
            store_record_digest: digest("store-record"),
            freshness: CandidateFreshnessV1::ExactSnapshot,
        })
        .unwrap();
        assert_eq!(
            route(&call, &RoutingCandidatesV1::default().with_exact(exact)),
            GatewayDecision::Execute
        );
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

    #[test]
    fn legacy_coordinator_observations_cannot_join() {
        let bounded_call = call(
            EffectClass::FreshnessBoundRead,
            FreshnessRequirementV1::MaxAgeMillis(50),
        );
        let observation = |age: u64, revalidated: bool| CoordinatorJoinObservationV1 {
            request_digest: bounded_call.request_digest(),
            effect_class: EffectClass::FreshnessBoundRead,
            lifecycle_generation: 7,
            observed_generation: 7,
            started_at_millis: 100,
            observed_at_millis: 100 + age,
            revalidated_at_generation: revalidated.then_some(7),
        };
        let fresh = issue_inflight_join_evidence_v1(observation(50, false)).unwrap();
        assert_eq!(
            route(
                &bounded_call,
                &RoutingCandidatesV1::default().with_inflight(fresh)
            ),
            GatewayDecision::Execute
        );
        let stale = issue_inflight_join_evidence_v1(observation(51, false)).unwrap();
        assert_eq!(
            route(
                &bounded_call,
                &RoutingCandidatesV1::default().with_inflight(stale)
            ),
            GatewayDecision::Execute
        );

        let revalidation_call = call(
            EffectClass::FreshnessBoundRead,
            FreshnessRequirementV1::RequireRevalidation,
        );
        let evidence = issue_inflight_join_evidence_v1(CoordinatorJoinObservationV1 {
            request_digest: revalidation_call.request_digest(),
            effect_class: EffectClass::FreshnessBoundRead,
            lifecycle_generation: 9,
            observed_generation: 9,
            started_at_millis: 100,
            observed_at_millis: 200,
            revalidated_at_generation: Some(9),
        })
        .unwrap();
        assert_eq!(
            route(
                &revalidation_call,
                &RoutingCandidatesV1::default().with_inflight(evidence)
            ),
            GatewayDecision::Execute
        );
    }

    #[test]
    fn invalid_coordinator_observations_never_issue_join_evidence() {
        let call = call(EffectClass::SnapshotRead, FreshnessRequirementV1::Snapshot);
        for observation in [
            CoordinatorJoinObservationV1 {
                request_digest: call.request_digest(),
                effect_class: EffectClass::SnapshotRead,
                lifecycle_generation: 1,
                observed_generation: 2,
                started_at_millis: 0,
                observed_at_millis: 1,
                revalidated_at_generation: None,
            },
            CoordinatorJoinObservationV1 {
                request_digest: call.request_digest(),
                effect_class: EffectClass::Mutation,
                lifecycle_generation: 1,
                observed_generation: 1,
                started_at_millis: 0,
                observed_at_millis: 1,
                revalidated_at_generation: None,
            },
            CoordinatorJoinObservationV1 {
                request_digest: call.request_digest(),
                effect_class: EffectClass::SnapshotRead,
                lifecycle_generation: 1,
                observed_generation: 1,
                started_at_millis: 2,
                observed_at_millis: 1,
                revalidated_at_generation: None,
            },
        ] {
            assert!(issue_inflight_join_evidence_v1(observation).is_err());
        }
    }
}
