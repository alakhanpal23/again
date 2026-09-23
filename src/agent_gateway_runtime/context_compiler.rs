//! Pure, bounded context presentation for one content-addressed result.
//!
//! This module does not select results, execute tools, or grant reuse. The
//! compact form requires opaque evidence from the exact-delivery presenter.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use crate::agent_gateway::context::{
    CompletedReasoningObservationV1, FailedReasoningApproachV1, InflightReasoningWorkV1,
    InvalidatedReasoningFactV1, MAX_REASONING_BRIEF_BYTES_V1, MAX_REASONING_ITEMS_V1,
    MAX_REASONING_SOURCE_REFERENCES_V1, REASONING_BRIEF_SCHEMA_VERSION_V1, ReasoningBriefInputV1,
    ReasoningChangeV1, ReasoningContextRefusalV1, ReasoningEvidenceMetricsV1, ReasoningFactScopeV1,
    ReasoningFactV1, ReasoningInvalidationV1, ReasoningRecipientV1, ReasoningRetrievalIdentityV1,
    ReasoningRouteDecisionV1, ReasoningScopeV1, ReasoningUnknownV1, SuggestedReasoningToolCallV1,
};

const RESULT_DIGEST_DOMAIN_V1: &[u8] = b"again.agent-context.result.v1\0";
const REFERENCE_PREFIX_V1: &str = "again-result-v1:blake3:";
const MAX_CONTEXT_IDENTIFIER_BYTES_V1: usize = 128;
pub const MAX_CONTEXT_RESULT_BYTES_V1: usize = 8 * 1024 * 1024;
pub const MAX_CONTEXT_EXCERPT_BYTES_V1: usize = 64 * 1024;

/// Stable, payload-free compiler refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextCompilerRefusalV1 {
    Identifier,
    ResultBound,
    ExcerptRange,
    ExcerptBound,
    DeliveryIncomplete,
    DeliveryAuthority,
    GenerationOverflow,
}

impl ContextCompilerRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Identifier => "invalid_identifier",
            Self::ResultBound => "result_bound_exceeded",
            Self::ExcerptRange => "invalid_excerpt_range",
            Self::ExcerptBound => "excerpt_bound_exceeded",
            Self::DeliveryIncomplete => "delivery_incomplete",
            Self::DeliveryAuthority => "delivery_authority_mismatch",
            Self::GenerationOverflow => "compaction_generation_exhausted",
        }
    }
}

/// The exact context identity against which compact delivery is authorized.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextIdentityV1 {
    agent_id: String,
    session_id: String,
    turn_id: String,
    compaction_generation: u64,
}

impl fmt::Debug for ContextIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContextIdentityV1(<redacted>)")
    }
}

impl ContextIdentityV1 {
    pub fn new(
        agent_id: &str,
        session_id: &str,
        turn_id: &str,
        compaction_generation: u64,
    ) -> Result<Self, ContextCompilerRefusalV1> {
        for value in [agent_id, session_id, turn_id] {
            validate_identifier_v1(value)?;
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            compaction_generation,
        })
    }

    pub fn after_compaction(&self) -> Result<Self, ContextCompilerRefusalV1> {
        let next = self
            .compaction_generation
            .checked_add(1)
            .ok_or(ContextCompilerRefusalV1::GenerationOverflow)?;
        Self::new(&self.agent_id, &self.session_id, &self.turn_id, next)
    }

    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }
}

/// Immutable bounded source bytes and their content identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextResultV1 {
    identity: FullRetrievalIdentityV1,
    bytes: Vec<u8>,
}

impl fmt::Debug for ContextResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContextResultV1(<redacted>)")
    }
}

impl ContextResultV1 {
    pub fn new(result_id: &str, bytes: &[u8]) -> Result<Self, ContextCompilerRefusalV1> {
        validate_identifier_v1(result_id)?;
        if bytes.len() > MAX_CONTEXT_RESULT_BYTES_V1 {
            return Err(ContextCompilerRefusalV1::ResultBound);
        }
        let digest = digest_result_v1(bytes);
        Ok(Self {
            identity: FullRetrievalIdentityV1 {
                result_id: result_id.to_owned(),
                digest,
                total_bytes: bytes.len() as u64,
            },
            bytes: bytes.to_vec(),
        })
    }

    pub const fn identity(&self) -> &FullRetrievalIdentityV1 {
        &self.identity
    }
}

/// Identity retained by every presentation so the full result remains
/// retrievable without interpreting presented bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct FullRetrievalIdentityV1 {
    result_id: String,
    digest: [u8; 32],
    total_bytes: u64,
}

impl fmt::Debug for FullRetrievalIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FullRetrievalIdentityV1(<redacted>)")
    }
}

impl FullRetrievalIdentityV1 {
    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// Opaque presenter-issued proof of exact byte delivery into one context.
/// It is deliberately non-serializable and has no public constructor.
pub struct ExactDeliveryAuthorityV1 {
    context: ContextIdentityV1,
    result: FullRetrievalIdentityV1,
}

impl fmt::Debug for ExactDeliveryAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactDeliveryAuthorityV1(<redacted>)")
    }
}

/// Crate-local presenter completion boundary. Product composition must invoke
/// this only after the supplied bytes reached the named context and status is
/// complete; byte equality is rechecked here before authority is issued.
#[allow(dead_code)]
pub(crate) fn complete_exact_delivery_v1(
    context: &ContextIdentityV1,
    result: &ContextResultV1,
    delivered_bytes: &[u8],
    status_delivered: bool,
    completion_confirmed: bool,
) -> Result<ExactDeliveryAuthorityV1, ContextCompilerRefusalV1> {
    if delivered_bytes != result.bytes || !status_delivered || !completion_confirmed {
        return Err(ContextCompilerRefusalV1::DeliveryIncomplete);
    }
    Ok(ExactDeliveryAuthorityV1 {
        context: context.clone(),
        result: result.identity.clone(),
    })
}

#[derive(Clone, Copy, Debug)]
pub enum ContextPresentationRequestV1<'a> {
    ExactFull,
    DeterministicExcerpt {
        start: u64,
        max_bytes: u64,
    },
    CompactContentAddressed {
        authority: &'a ExactDeliveryAuthorityV1,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteOffsetsV1 {
    start: u64,
    end_exclusive: u64,
}

impl ByteOffsetsV1 {
    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end_exclusive(self) -> u64 {
        self.end_exclusive
    }
}

#[derive(Clone, PartialEq, Eq)]
enum PresentedContentV1 {
    Exact(Vec<u8>),
    Excerpt {
        bytes: Vec<u8>,
        offsets: ByteOffsetsV1,
    },
    CompactReference(Vec<u8>),
}

/// One deterministic presentation. Every variant retains the same full
/// retrieval identity and reports source bytes omitted plus a deterministic
/// payload/reference-only token estimate.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledContextPresentationV1 {
    identity: FullRetrievalIdentityV1,
    content: PresentedContentV1,
    source_bytes_omitted: u64,
    estimated_tokens: u64,
}

impl fmt::Debug for CompiledContextPresentationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompiledContextPresentationV1(<redacted>)")
    }
}

impl CompiledContextPresentationV1 {
    pub const fn identity(&self) -> &FullRetrievalIdentityV1 {
        &self.identity
    }

    pub fn exact_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            PresentedContentV1::Exact(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn excerpt(&self) -> Option<(&[u8], ByteOffsetsV1)> {
        match &self.content {
            PresentedContentV1::Excerpt { bytes, offsets } => Some((bytes, *offsets)),
            _ => None,
        }
    }

    pub fn compact_reference_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            PresentedContentV1::CompactReference(reference) => Some(reference),
            _ => None,
        }
    }

    pub const fn source_bytes_omitted(&self) -> u64 {
        self.source_bytes_omitted
    }

    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }

    pub const fn grants_reuse(&self) -> bool {
        false
    }

    pub const fn grants_execution(&self) -> bool {
        false
    }
}

pub fn compile_context_presentation_v1(
    context: &ContextIdentityV1,
    result: &ContextResultV1,
    request: ContextPresentationRequestV1<'_>,
) -> Result<CompiledContextPresentationV1, ContextCompilerRefusalV1> {
    let (content, included_source_bytes, presented_bytes) = match request {
        ContextPresentationRequestV1::ExactFull => {
            let bytes = result.bytes.clone();
            let length = bytes.len() as u64;
            (PresentedContentV1::Exact(bytes), length, length)
        }
        ContextPresentationRequestV1::DeterministicExcerpt { start, max_bytes } => {
            if max_bytes == 0 || max_bytes > MAX_CONTEXT_EXCERPT_BYTES_V1 as u64 {
                return Err(ContextCompilerRefusalV1::ExcerptBound);
            }
            if start > result.identity.total_bytes {
                return Err(ContextCompilerRefusalV1::ExcerptRange);
            }
            let end = start
                .checked_add(max_bytes)
                .unwrap_or(u64::MAX)
                .min(result.identity.total_bytes);
            let start_usize =
                usize::try_from(start).map_err(|_| ContextCompilerRefusalV1::ExcerptRange)?;
            let end_usize =
                usize::try_from(end).map_err(|_| ContextCompilerRefusalV1::ExcerptRange)?;
            let bytes = result.bytes[start_usize..end_usize].to_vec();
            let length = bytes.len() as u64;
            (
                PresentedContentV1::Excerpt {
                    bytes,
                    offsets: ByteOffsetsV1 {
                        start,
                        end_exclusive: end,
                    },
                },
                length,
                length,
            )
        }
        ContextPresentationRequestV1::CompactContentAddressed { authority } => {
            if authority.context != *context || authority.result != result.identity {
                return Err(ContextCompilerRefusalV1::DeliveryAuthority);
            }
            let reference = compact_reference_v1(&result.identity);
            let length = reference.len() as u64;
            (PresentedContentV1::CompactReference(reference), 0, length)
        }
    };
    let source_bytes_omitted = result
        .identity
        .total_bytes
        .checked_sub(included_source_bytes)
        .expect("included bytes never exceed the bounded result");
    Ok(CompiledContextPresentationV1 {
        identity: result.identity.clone(),
        content,
        source_bytes_omitted,
        estimated_tokens: token_estimate_v1(presented_bytes),
    })
}

fn validate_identifier_v1(value: &str) -> Result<(), ContextCompilerRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_CONTEXT_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ContextCompilerRefusalV1::Identifier);
    }
    Ok(())
}

fn digest_result_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESULT_DIGEST_DOMAIN_V1);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn compact_reference_v1(identity: &FullRetrievalIdentityV1) -> Vec<u8> {
    let mut reference = Vec::with_capacity(REFERENCE_PREFIX_V1.len() + 64 + 1 + 20);
    reference.extend_from_slice(REFERENCE_PREFIX_V1.as_bytes());
    for byte in identity.digest {
        reference.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    reference.push(b':');
    reference.extend_from_slice(identity.total_bytes.to_string().as_bytes());
    reference
}

const fn token_estimate_v1(presented_bytes: u64) -> u64 {
    presented_bytes.div_ceil(4)
}

const REASONING_BRIEF_DIGEST_DOMAIN_V1: &[u8] = b"again.reasoning-brief.v1\0";
const REASONING_BRIEF_REFERENCE_PREFIX_V1: &str = "again-reasoning-v1:blake3:";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasoningBriefPresentationV1 {
    Full,
    CompactReference,
}

#[derive(Clone, Copy, Debug)]
pub enum ReasoningBriefPresentationRequestV1<'a> {
    Full,
    PreferCompact {
        acknowledgment: Option<&'a ReasoningDeliveryAcknowledgmentV1>,
    },
}

/// Opaque evidence that an authenticated presenter delivered the complete,
/// canonical brief to one exact recipient generation. A result identifier or
/// digest cannot construct this value.
pub struct ReasoningDeliveryAcknowledgmentV1 {
    scope: ReasoningScopeV1,
    recipient: ReasoningRecipientV1,
    brief_digest: [u8; 32],
    full_bytes: u64,
}

impl fmt::Debug for ReasoningDeliveryAcknowledgmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReasoningDeliveryAcknowledgmentV1(<redacted>)")
    }
}

/// The trusted delivery boundary. Product code may call this only after its
/// recipient authentication and complete-write checks succeed. Exact byte
/// equality is repeated here; partial delivery never creates compact authority.
#[allow(dead_code)]
pub(crate) fn complete_reasoning_brief_delivery_v1(
    recipient: &ReasoningRecipientV1,
    compiled: &CompiledReasoningBriefV1,
    delivered_bytes: &[u8],
    recipient_authenticated: bool,
    status_delivered: bool,
    completion_confirmed: bool,
) -> Result<ReasoningDeliveryAcknowledgmentV1, ReasoningContextRefusalV1> {
    if compiled.presentation != ReasoningBriefPresentationV1::Full
        || !recipient.is_active()
        || *recipient != compiled.recipient
        || delivered_bytes != compiled.bytes
        || !recipient_authenticated
        || !status_delivered
        || !completion_confirmed
    {
        return Err(ReasoningContextRefusalV1::DeliveryIncomplete);
    }
    Ok(ReasoningDeliveryAcknowledgmentV1 {
        scope: compiled.scope.clone(),
        recipient: recipient.clone(),
        brief_digest: compiled.full_digest,
        full_bytes: compiled.full_bytes.len() as u64,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningContextMetricsV1 {
    pub facts_reused: u64,
    pub investigations_avoided: u64,
    pub provider_calls_avoided: u64,
    pub inflight_joins: u64,
    pub invalidated_facts: u64,
    pub context_bytes_delivered: u64,
    pub delivery_confirmed_bytes_omitted: u64,
    pub confirmed_tokens_avoided: u64,
    pub false_hit_quarantines: u64,
    pub estimated_execution_time_saved_ms: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CompiledReasoningBriefV1 {
    scope: ReasoningScopeV1,
    recipient: ReasoningRecipientV1,
    presentation: ReasoningBriefPresentationV1,
    bytes: Vec<u8>,
    full_bytes: Vec<u8>,
    full_digest: [u8; 32],
    full_retrieval: Vec<ReasoningRetrievalIdentityV1>,
    metrics: ReasoningContextMetricsV1,
}

impl fmt::Debug for CompiledReasoningBriefV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompiledReasoningBriefV1(<redacted>)")
    }
}

impl CompiledReasoningBriefV1 {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn full_exact_bytes(&self) -> &[u8] {
        &self.full_bytes
    }

    pub const fn full_digest(&self) -> [u8; 32] {
        self.full_digest
    }

    pub const fn presentation(&self) -> ReasoningBriefPresentationV1 {
        self.presentation
    }

    pub fn full_retrieval(&self) -> &[ReasoningRetrievalIdentityV1] {
        &self.full_retrieval
    }

    pub const fn metrics(&self) -> &ReasoningContextMetricsV1 {
        &self.metrics
    }

    pub const fn grants_reuse(&self) -> bool {
        false
    }

    pub const fn grants_execution(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalReasoningBriefV1 {
    format: &'static str,
    schema_version: u16,
    task: CanonicalTaskContextV1,
    repository: CanonicalRepositoryContextV1,
    authorization_scope: CanonicalAuthorizationContextV1,
    agent_delivery: CanonicalAgentDeliveryV1,
    session_turn_context: CanonicalSessionTurnContextV1,
    invalidated_or_quarantined_facts: Vec<InvalidatedReasoningFactV1>,
    explicit_unknowns: Vec<ReasoningUnknownV1>,
    completed_observations: Vec<CompletedReasoningObservationV1>,
    inflight_work_by_other_agents: Vec<InflightReasoningWorkV1>,
    failed_approaches: Vec<FailedReasoningApproachV1>,
    suggested_next_tool_calls: Vec<SuggestedReasoningToolCallV1>,
    route_explanations: Vec<CanonicalReasoningRouteV1>,
    full_result_retrieval: Vec<ReasoningRetrievalIdentityV1>,
    evidence_metrics: ReasoningEvidenceMetricsV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalTaskContextV1 {
    task_id: String,
    verified_facts: Vec<ReasoningFactV1>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRepositoryContextV1 {
    repository_id: String,
    workspace_id: String,
    state_digest: String,
    dependency_digest: String,
    verified_facts: Vec<ReasoningFactV1>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalAuthorizationContextV1 {
    scope_digest: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalAgentDeliveryV1 {
    agent_id: String,
    connection_generation: String,
    compaction_generation: u64,
    lifecycle_generation: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalSessionTurnContextV1 {
    session_id: String,
    turn_id: String,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalReasoningRouteV1 {
    code: &'static str,
    explanation: &'static str,
    grants_reuse: bool,
}

impl From<ReasoningRouteDecisionV1> for CanonicalReasoningRouteV1 {
    fn from(route: ReasoningRouteDecisionV1) -> Self {
        Self {
            code: route.code(),
            explanation: route.explanation(),
            grants_reuse: route.grants_reuse(),
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCompactReasoningBriefV1 {
    format: &'static str,
    schema_version: u16,
    brief_reference: String,
    task_id: String,
    repository_id: String,
    workspace_id: String,
    agent_id: String,
    session_id: String,
    turn_id: String,
    connection_generation: String,
    compaction_generation: u64,
    lifecycle_generation: u64,
    route_explanation: CanonicalReasoningRouteV1,
    full_result_retrieval: Vec<ReasoningRetrievalIdentityV1>,
}

pub fn compile_reasoning_brief_v1(
    input: &ReasoningBriefInputV1,
    request: ReasoningBriefPresentationRequestV1<'_>,
) -> Result<CompiledReasoningBriefV1, ReasoningContextRefusalV1> {
    validate_reasoning_input_bounds_v1(input)?;

    let mut repository_facts = Vec::new();
    let mut task_facts = Vec::new();
    let mut invalidated = input.invalidated_facts.clone();
    let mut routes = input.route_decisions.clone();
    let mut candidates = Vec::new();

    for fact in &input.known_facts {
        if let Some((reason, changes)) = stale_fact_reason_v1(fact, &input.scope)? {
            invalidated.push(InvalidatedReasoningFactV1::new(
                fact.clone(),
                reason,
                changes,
            )?);
            match reason {
                ReasoningInvalidationV1::AuthorizationChanged => {
                    routes.push(ReasoningRouteDecisionV1::ExecuteForAuthorization);
                }
                _ => routes.push(ReasoningRouteDecisionV1::ExecuteForStateChange),
            }
        } else {
            candidates.push(fact.clone());
        }
    }

    let mut values_by_topic: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for fact in &candidates {
        values_by_topic
            .entry(fact.topic().to_owned())
            .or_default()
            .insert(fact.value_digest().to_owned());
    }
    let contradictory_topics: BTreeSet<String> = values_by_topic
        .into_iter()
        .filter_map(|(topic, values)| (values.len() > 1).then_some(topic))
        .collect();
    let contradiction_count = contradictory_topics.len() as u64;

    for fact in candidates {
        if contradictory_topics.contains(fact.topic()) {
            invalidated.push(InvalidatedReasoningFactV1::new(
                fact,
                ReasoningInvalidationV1::ContradictoryEvidence,
                Vec::new(),
            )?);
            routes.push(ReasoningRouteDecisionV1::QuarantineContradiction);
            continue;
        }
        match fact.scope() {
            ReasoningFactScopeV1::RepositoryWide => {
                routes.push(ReasoningRouteDecisionV1::SharedVerifiedFact);
                repository_facts.push(fact);
            }
            ReasoningFactScopeV1::TaskSpecific => {
                routes.push(ReasoningRouteDecisionV1::ExactVerifiedFact);
                task_facts.push(fact);
            }
        }
    }

    let mut unknowns = input.explicit_unknowns.clone();
    let mut completed = input.completed_observations.clone();
    let mut inflight = input.inflight_work.clone();
    let mut failed = input.failed_approaches.clone();
    let mut suggestions = input.suggested_next_tool_calls.clone();
    if !unknowns.is_empty() {
        routes.push(ReasoningRouteDecisionV1::ExecuteForUnknown);
    }
    if !inflight.is_empty() {
        routes.push(ReasoningRouteDecisionV1::InflightJoin);
    }
    routes.retain(|route| {
        !matches!(
            route,
            ReasoningRouteDecisionV1::CompactDeliveryConfirmed
                | ReasoningRouteDecisionV1::FullDeliveryRequired
        )
    });
    routes.push(ReasoningRouteDecisionV1::FullDeliveryRequired);

    sort_and_deduplicate_v1(&mut repository_facts);
    sort_and_deduplicate_v1(&mut task_facts);
    sort_and_deduplicate_v1(&mut invalidated);
    sort_and_deduplicate_v1(&mut unknowns);
    sort_and_deduplicate_v1(&mut completed);
    sort_and_deduplicate_v1(&mut inflight);
    sort_and_deduplicate_v1(&mut failed);
    sort_and_deduplicate_v1(&mut suggestions);
    routes.sort_unstable();
    routes.dedup();

    let mut full_retrieval: Vec<_> = completed
        .iter()
        .map(|observation| observation.retrieval().clone())
        .collect();
    sort_and_deduplicate_v1(&mut full_retrieval);
    let route_explanations = routes
        .into_iter()
        .map(CanonicalReasoningRouteV1::from)
        .collect();
    let full = CanonicalReasoningBriefV1 {
        format: "again.reasoning-brief",
        schema_version: REASONING_BRIEF_SCHEMA_VERSION_V1,
        task: CanonicalTaskContextV1 {
            task_id: input.scope.task_id().to_owned(),
            verified_facts: task_facts.clone(),
        },
        repository: CanonicalRepositoryContextV1 {
            repository_id: input.scope.repository_id().to_owned(),
            workspace_id: input.scope.workspace_id().to_owned(),
            state_digest: input.scope.state_digest().to_owned(),
            dependency_digest: input.scope.dependency_digest().to_owned(),
            verified_facts: repository_facts.clone(),
        },
        authorization_scope: CanonicalAuthorizationContextV1 {
            scope_digest: input.scope.authorization_scope_digest().to_owned(),
        },
        agent_delivery: CanonicalAgentDeliveryV1 {
            agent_id: input.recipient.agent_id().to_owned(),
            connection_generation: input.recipient.connection_generation().to_owned(),
            compaction_generation: input.recipient.compaction_generation(),
            lifecycle_generation: input.recipient.lifecycle_generation(),
        },
        session_turn_context: CanonicalSessionTurnContextV1 {
            session_id: input.recipient.session_id().to_owned(),
            turn_id: input.recipient.turn_id().to_owned(),
        },
        invalidated_or_quarantined_facts: invalidated.clone(),
        explicit_unknowns: unknowns,
        completed_observations: completed,
        inflight_work_by_other_agents: inflight,
        failed_approaches: failed,
        suggested_next_tool_calls: suggestions,
        route_explanations,
        full_result_retrieval: full_retrieval.clone(),
        evidence_metrics: input.evidence_metrics.clone(),
    };
    let full_bytes =
        serde_json::to_vec(&full).map_err(|_| ReasoningContextRefusalV1::Canonicalization)?;
    if full_bytes.len() > MAX_REASONING_BRIEF_BYTES_V1 {
        return Err(ReasoningContextRefusalV1::ByteBound);
    }
    if contains_sensitive_reasoning_content_v1(&full_bytes) {
        return Err(ReasoningContextRefusalV1::SensitiveContent);
    }
    let full_digest = digest_reasoning_brief_v1(&full_bytes);

    let current_fact_count = repository_facts.len().saturating_add(task_facts.len()) as u64;
    let mut metrics = ReasoningContextMetricsV1 {
        facts_reused: current_fact_count,
        investigations_avoided: input.evidence_metrics.investigations_avoided,
        provider_calls_avoided: input.evidence_metrics.provider_calls_avoided,
        inflight_joins: input.evidence_metrics.inflight_joins,
        invalidated_facts: invalidated.len() as u64,
        context_bytes_delivered: full_bytes.len() as u64,
        delivery_confirmed_bytes_omitted: 0,
        confirmed_tokens_avoided: 0,
        false_hit_quarantines: input
            .evidence_metrics
            .false_hit_quarantines
            .saturating_add(contradiction_count),
        estimated_execution_time_saved_ms: input.evidence_metrics.estimated_execution_time_saved_ms,
    };

    let compact_authorized = match request {
        ReasoningBriefPresentationRequestV1::Full => false,
        ReasoningBriefPresentationRequestV1::PreferCompact { acknowledgment } => acknowledgment
            .is_some_and(|acknowledgment| {
                input.recipient.is_active()
                    && acknowledgment.scope == input.scope
                    && acknowledgment.recipient == input.recipient
                    && acknowledgment.brief_digest == full_digest
                    && acknowledgment.full_bytes == full_bytes.len() as u64
            }),
    };
    if compact_authorized {
        let compact = CanonicalCompactReasoningBriefV1 {
            format: "again.reasoning-brief-reference",
            schema_version: REASONING_BRIEF_SCHEMA_VERSION_V1,
            brief_reference: compact_reasoning_reference_v1(full_digest, full_bytes.len() as u64),
            task_id: input.scope.task_id().to_owned(),
            repository_id: input.scope.repository_id().to_owned(),
            workspace_id: input.scope.workspace_id().to_owned(),
            agent_id: input.recipient.agent_id().to_owned(),
            session_id: input.recipient.session_id().to_owned(),
            turn_id: input.recipient.turn_id().to_owned(),
            connection_generation: input.recipient.connection_generation().to_owned(),
            compaction_generation: input.recipient.compaction_generation(),
            lifecycle_generation: input.recipient.lifecycle_generation(),
            route_explanation: CanonicalReasoningRouteV1::from(
                ReasoningRouteDecisionV1::CompactDeliveryConfirmed,
            ),
            full_result_retrieval: full_retrieval.clone(),
        };
        let compact_bytes = serde_json::to_vec(&compact)
            .map_err(|_| ReasoningContextRefusalV1::Canonicalization)?;
        if compact_bytes.len() < full_bytes.len() {
            let omitted = (full_bytes.len() - compact_bytes.len()) as u64;
            metrics.context_bytes_delivered = compact_bytes.len() as u64;
            metrics.delivery_confirmed_bytes_omitted = omitted;
            metrics.confirmed_tokens_avoided = omitted / 4;
            return Ok(CompiledReasoningBriefV1 {
                scope: input.scope.clone(),
                recipient: input.recipient.clone(),
                presentation: ReasoningBriefPresentationV1::CompactReference,
                bytes: compact_bytes,
                full_bytes,
                full_digest,
                full_retrieval,
                metrics,
            });
        }
    }

    Ok(CompiledReasoningBriefV1 {
        scope: input.scope.clone(),
        recipient: input.recipient.clone(),
        presentation: ReasoningBriefPresentationV1::Full,
        bytes: full_bytes.clone(),
        full_bytes,
        full_digest,
        full_retrieval,
        metrics,
    })
}

fn validate_reasoning_input_bounds_v1(
    input: &ReasoningBriefInputV1,
) -> Result<(), ReasoningContextRefusalV1> {
    let item_count = [
        input.known_facts.len(),
        input.invalidated_facts.len(),
        input.explicit_unknowns.len(),
        input.completed_observations.len(),
        input.inflight_work.len(),
        input.failed_approaches.len(),
        input.suggested_next_tool_calls.len(),
        input.route_decisions.len(),
    ]
    .into_iter()
    .try_fold(0usize, |total, count| total.checked_add(count))
    .ok_or(ReasoningContextRefusalV1::ItemBound)?;
    if item_count > MAX_REASONING_ITEMS_V1 {
        return Err(ReasoningContextRefusalV1::ItemBound);
    }
    let source_count = input
        .known_facts
        .iter()
        .map(|fact| fact.sources().len())
        .chain(
            input
                .invalidated_facts
                .iter()
                .map(|fact| fact.fact().sources().len()),
        )
        .chain(
            input
                .completed_observations
                .iter()
                .map(|observation| observation.sources().len()),
        )
        .chain(
            input
                .failed_approaches
                .iter()
                .map(|approach| approach.sources().len()),
        )
        .try_fold(0usize, |total, count| total.checked_add(count))
        .ok_or(ReasoningContextRefusalV1::SourceReferenceBound)?;
    if source_count > MAX_REASONING_SOURCE_REFERENCES_V1 {
        return Err(ReasoningContextRefusalV1::SourceReferenceBound);
    }
    Ok(())
}

fn stale_fact_reason_v1(
    fact: &ReasoningFactV1,
    scope: &ReasoningScopeV1,
) -> Result<Option<(ReasoningInvalidationV1, Vec<ReasoningChangeV1>)>, ReasoningContextRefusalV1> {
    if fact.scope() == ReasoningFactScopeV1::TaskSpecific && fact.task_id() != Some(scope.task_id())
    {
        let prior = digest_reasoning_label_v1(fact.task_id().unwrap_or("missing"));
        let current = digest_reasoning_label_v1(scope.task_id());
        return Ok(Some((
            ReasoningInvalidationV1::TaskChanged,
            vec![ReasoningChangeV1::new("task", &prior, &current)?],
        )));
    }
    for source in fact.sources() {
        let mismatch = if source.repository_id() != scope.repository_id() {
            Some((
                ReasoningInvalidationV1::RepositoryChanged,
                "repository",
                digest_reasoning_label_v1(source.repository_id()),
                digest_reasoning_label_v1(scope.repository_id()),
            ))
        } else if source.workspace_id() != scope.workspace_id() {
            Some((
                ReasoningInvalidationV1::WorkspaceChanged,
                "workspace",
                digest_reasoning_label_v1(source.workspace_id()),
                digest_reasoning_label_v1(scope.workspace_id()),
            ))
        } else if source.state_digest() != scope.state_digest() {
            Some((
                ReasoningInvalidationV1::StateChanged,
                "state",
                source.state_digest().to_owned(),
                scope.state_digest().to_owned(),
            ))
        } else if source.dependency_digest() != scope.dependency_digest() {
            Some((
                ReasoningInvalidationV1::DependencyChanged,
                "dependencies",
                source.dependency_digest().to_owned(),
                scope.dependency_digest().to_owned(),
            ))
        } else if source.authorization_scope_digest() != scope.authorization_scope_digest() {
            Some((
                ReasoningInvalidationV1::AuthorizationChanged,
                "authorization",
                source.authorization_scope_digest().to_owned(),
                scope.authorization_scope_digest().to_owned(),
            ))
        } else {
            None
        };
        if let Some((reason, dimension, prior, current)) = mismatch {
            return Ok(Some((
                reason,
                vec![ReasoningChangeV1::new(dimension, &prior, &current)?],
            )));
        }
    }
    Ok(None)
}

fn sort_and_deduplicate_v1<T: Ord>(values: &mut Vec<T>) {
    values.sort_unstable();
    values.dedup();
}

fn digest_reasoning_brief_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REASONING_BRIEF_DIGEST_DOMAIN_V1);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn digest_reasoning_label_v1(value: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.reasoning-label.v1\0");
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn compact_reasoning_reference_v1(digest: [u8; 32], full_bytes: u64) -> String {
    format!(
        "{REASONING_BRIEF_REFERENCE_PREFIX_V1}{}:{full_bytes}",
        digest
            .as_slice()
            .iter()
            .fold(String::with_capacity(64), |mut encoded, byte| {
                use std::fmt::Write as _;
                write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
                encoded
            })
    )
}

fn contains_sensitive_reasoning_content_v1(bytes: &[u8]) -> bool {
    let lowercase = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "-----begin private key-----",
        "password",
        "credential",
        "bearer ",
        "api_key",
        "api-key",
        "access_token",
        "refresh_token",
        "private_key",
        "\"github_pat_",
        "\"ghp_",
        "\"sk-",
    ]
    .into_iter()
    .any(|marker| lowercase.contains(marker))
}
