//! Pure selection rules for presenting an already-selected exact result.

use std::fmt;

use serde::Serialize;

use super::protocol::{DigestReferenceV1, GatewayToolCallV1, PresentationMode};

pub const DELIVERY_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const MAX_PRESENTATION_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTEXT_IDENTIFIER_BYTES_V1: usize = 128;

/// Exact conversational context. Fields are private so deserialization or a
/// struct literal cannot manufacture a context that bypasses validation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentContextIdentityV1 {
    agent_id: String,
    session_id: String,
    turn_id: String,
    compaction_generation: u64,
}

impl fmt::Debug for AgentContextIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentContextIdentityV1(<redacted>)")
    }
}

impl AgentContextIdentityV1 {
    pub fn new(
        agent_id: &str,
        session_id: &str,
        turn_id: &str,
        compaction_generation: u64,
    ) -> Result<Self, PresentationRefusalV1> {
        for value in [agent_id, session_id, turn_id] {
            validate_context_identifier(value)?;
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            compaction_generation,
        })
    }

    pub fn after_compaction(&self) -> Result<Self, PresentationRefusalV1> {
        let generation = self
            .compaction_generation
            .checked_add(1)
            .ok_or(PresentationRefusalV1::CompactionGenerationExhausted)?;
        Self::new(&self.agent_id, &self.session_id, &self.turn_id, generation)
    }

    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PresentationContextV1 {
    session_id: String,
    turn_id: String,
    agent_id: Option<String>,
    environment_id: String,
    cwd_identity: [u8; 32],
    tty: bool,
    output_ceiling: u64,
    compaction_generation: u64,
}

impl fmt::Debug for PresentationContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PresentationContextV1(<redacted>)")
    }
}

impl PresentationContextV1 {
    pub fn new(
        session_id: &str,
        turn_id: &str,
        agent_id: Option<&str>,
        environment_id: &str,
        cwd_identity: [u8; 32],
        tty: bool,
        output_ceiling: u64,
    ) -> Result<Self, PresentationRefusalV1> {
        Self::new_at_generation(
            session_id,
            turn_id,
            agent_id,
            environment_id,
            cwd_identity,
            tty,
            output_ceiling,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_at_generation(
        session_id: &str,
        turn_id: &str,
        agent_id: Option<&str>,
        environment_id: &str,
        cwd_identity: [u8; 32],
        tty: bool,
        output_ceiling: u64,
        compaction_generation: u64,
    ) -> Result<Self, PresentationRefusalV1> {
        for value in [session_id, turn_id, environment_id] {
            validate_context_identifier(value)?;
        }
        if let Some(agent_id) = agent_id {
            validate_context_identifier(agent_id)?;
        }
        Ok(Self {
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            agent_id: agent_id.map(str::to_owned),
            environment_id: environment_id.to_owned(),
            cwd_identity,
            tty,
            output_ceiling,
            compaction_generation,
        })
    }

    pub fn after_compaction(&self) -> Result<Self, PresentationRefusalV1> {
        let generation = self
            .compaction_generation
            .checked_add(1)
            .ok_or(PresentationRefusalV1::CompactionGenerationExhausted)?;
        Self::new_at_generation(
            &self.session_id,
            &self.turn_id,
            self.agent_id.as_deref(),
            &self.environment_id,
            self.cwd_identity,
            self.tty,
            self.output_ceiling,
            generation,
        )
    }

    pub const fn output_ceiling(&self) -> u64 {
        self.output_ceiling
    }

    #[allow(dead_code)]
    fn compact_identity(&self) -> AgentContextIdentityV1 {
        AgentContextIdentityV1 {
            agent_id: self
                .agent_id
                .as_deref()
                .unwrap_or("unattributed")
                .to_owned(),
            session_id: self.session_id.clone(),
            turn_id: self.turn_id.clone(),
            compaction_generation: self.compaction_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationRefusalV1 {
    InvalidIdentifier,
    InvalidDeliveryCount,
    StreamBoundExceeded,
    IncompleteDelivery,
    CompactionGenerationExhausted,
}

impl PresentationRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidDeliveryCount => "invalid_delivery_count",
            Self::StreamBoundExceeded => "stream_bound_exceeded",
            Self::IncompleteDelivery => "incomplete_delivery",
            Self::CompactionGenerationExhausted => "compaction_generation_exhausted",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayResultIdentityV1 {
    exit_code: i32,
    stdout_bytes: u64,
    stderr_bytes: u64,
    digest: [u8; 32],
}

impl fmt::Debug for GatewayResultIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayResultIdentityV1(<redacted>)")
    }
}

impl GatewayResultIdentityV1 {
    pub fn from_streams(
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<Self, PresentationRefusalV1> {
        if stdout.len() > MAX_PRESENTATION_STREAM_BYTES
            || stderr.len() > MAX_PRESENTATION_STREAM_BYTES
        {
            return Err(PresentationRefusalV1::StreamBoundExceeded);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"again.agent-gateway.result.v1\0");
        hasher.update(&exit_code.to_be_bytes());
        put_stream(&mut hasher, stdout);
        put_stream(&mut hasher, stderr);
        Ok(Self {
            exit_code,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            digest: *hasher.finalize().as_bytes(),
        })
    }

    #[allow(dead_code)]
    fn digest_reference(self) -> DigestReferenceV1 {
        DigestReferenceV1 {
            algorithm: "blake3".to_owned(),
            value: self
                .digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct DetailedDeliveryV1 {
    context: PresentationContextV1Wire,
    call_digest: [u8; 32],
    result: GatewayResultIdentityV1,
    stdout_delivered: u64,
    stderr_delivered: u64,
    status_delivered: bool,
    completion_confirmed: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PresentationContextV1Wire {
    session_id: String,
    turn_id: String,
    agent_id: Option<String>,
    environment_id: String,
    cwd_identity: [u8; 32],
    tty: bool,
    output_ceiling: u64,
    compaction_generation: u64,
}

impl From<&PresentationContextV1> for PresentationContextV1Wire {
    fn from(context: &PresentationContextV1) -> Self {
        Self {
            session_id: context.session_id.clone(),
            turn_id: context.turn_id.clone(),
            agent_id: context.agent_id.clone(),
            environment_id: context.environment_id.clone(),
            cwd_identity: context.cwd_identity,
            tty: context.tty,
            output_ceiling: context.output_ceiling,
            compaction_generation: context.compaction_generation,
        }
    }
}

impl PartialEq<PresentationContextV1> for PresentationContextV1Wire {
    fn eq(&self, other: &PresentationContextV1) -> bool {
        self.session_id == other.session_id
            && self.turn_id == other.turn_id
            && self.agent_id == other.agent_id
            && self.environment_id == other.environment_id
            && self.cwd_identity == other.cwd_identity
            && self.tty == other.tty
            && self.output_ceiling == other.output_ceiling
            && self.compaction_generation == other.compaction_generation
    }
}

/// Presenter-issued evidence. It is serializable for display/storage but has
/// no `Deserialize` implementation and no public constructor.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReceiptV1 {
    schema_version: u16,
    context: AgentContextIdentityV1,
    exact_result: DigestReferenceV1,
    detailed: DetailedDeliveryV1,
}

impl fmt::Debug for DeliveryReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeliveryReceiptV1(<redacted>)")
    }
}

impl DeliveryReceiptV1 {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn context(&self) -> &AgentContextIdentityV1 {
        &self.context
    }

    pub const fn exact_result(&self) -> &DigestReferenceV1 {
        &self.exact_result
    }

    fn authorizes_compact_reference(
        &self,
        context: &AgentContextIdentityV1,
        exact_result: &DigestReferenceV1,
    ) -> bool {
        self.schema_version == DELIVERY_RECEIPT_SCHEMA_VERSION
            && self.context == *context
            && self.exact_result == *exact_result
            && self.detailed.stdout_delivered == self.detailed.result.stdout_bytes
            && self.detailed.stderr_delivered == self.detailed.result.stderr_bytes
            && self.detailed.status_delivered
            && self.detailed.completion_confirmed
    }
}

/// Narrow crate-private presenter completion boundary. Callers cannot mint a
/// receipt until exact stream counts, status delivery, and completion all hold.
#[allow(dead_code)]
pub(crate) fn presenter_complete_exact_delivery_v1(
    context: &PresentationContextV1,
    call: &GatewayToolCallV1,
    result: GatewayResultIdentityV1,
    stdout_delivered: u64,
    stderr_delivered: u64,
    status_delivered: bool,
    completion_confirmed: bool,
) -> Result<DeliveryReceiptV1, PresentationRefusalV1> {
    if stdout_delivered > result.stdout_bytes || stderr_delivered > result.stderr_bytes {
        return Err(PresentationRefusalV1::InvalidDeliveryCount);
    }
    if stdout_delivered != result.stdout_bytes
        || stderr_delivered != result.stderr_bytes
        || !status_delivered
        || !completion_confirmed
    {
        return Err(PresentationRefusalV1::IncompleteDelivery);
    }
    Ok(DeliveryReceiptV1 {
        schema_version: DELIVERY_RECEIPT_SCHEMA_VERSION,
        context: context.compact_identity(),
        exact_result: result.digest_reference(),
        detailed: DetailedDeliveryV1 {
            context: context.into(),
            call_digest: call.digest(),
            result,
            stdout_delivered,
            stderr_delivered,
            status_delivered,
            completion_confirmed,
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationDecisionV1 {
    FullResult,
    ExactPriorDeliveryReference,
}

impl PresentationDecisionV1 {
    pub const fn grants_reuse(self) -> bool {
        false
    }
}

pub fn decide_presentation_v1(
    context: &PresentationContextV1,
    call: &GatewayToolCallV1,
    result: GatewayResultIdentityV1,
    receipt: Option<&DeliveryReceiptV1>,
) -> PresentationDecisionV1 {
    let Some(delivery) = receipt.map(|receipt| &receipt.detailed) else {
        return PresentationDecisionV1::FullResult;
    };
    if delivery.context == *context
        && delivery.call_digest == call.digest()
        && delivery.result == result
        && delivery.stdout_delivered == result.stdout_bytes
        && delivery.stderr_delivered == result.stderr_bytes
        && delivery.status_delivered
        && delivery.completion_confirmed
    {
        PresentationDecisionV1::ExactPriorDeliveryReference
    } else {
        PresentationDecisionV1::FullResult
    }
}

pub fn select_presentation(
    requested: PresentationMode,
    context: &AgentContextIdentityV1,
    exact_result: &DigestReferenceV1,
    receipt: Option<&DeliveryReceiptV1>,
) -> PresentationMode {
    if requested != PresentationMode::CompactReference {
        return requested;
    }
    match receipt {
        Some(receipt) if receipt.authorizes_compact_reference(context, exact_result) => {
            PresentationMode::CompactReference
        }
        _ => PresentationMode::FullRetrievalRequired,
    }
}

pub const REASONING_BRIEF_SCHEMA_VERSION_V1: u16 = 1;
pub const MAX_REASONING_BRIEF_BYTES_V1: usize = 64 * 1024;
pub const MAX_REASONING_ITEMS_V1: usize = 64;
pub const MAX_REASONING_SOURCE_REFERENCES_V1: usize = 128;
pub const MAX_REASONING_SOURCES_PER_ITEM_V1: usize = 8;
pub const MAX_REASONING_DEPTH_V1: usize = 6;
pub const MAX_REASONING_TEXT_BYTES_V1: usize = 1024;
const MAX_REASONING_LOCATOR_BYTES_V1: usize = 512;

pub const CONTEXT_LEDGER_SCHEMA_VERSION_V1: u16 = 1;
pub const MAX_CONTEXT_LEDGER_EVENTS_PER_TASK_V1: usize = 4_096;
pub const MAX_CONTEXT_LEDGER_SNAPSHOT_ITEMS_V1: usize = 64;
pub const MAX_CONTEXT_LEDGER_DELTA_ITEMS_V1: usize = 256;
pub const MAX_CONTEXT_LEDGER_DEPENDENCIES_V1: usize = 64;

/// Complete identity for one local shared-context participant. Repository and
/// workspace identity scope shared truth; the remaining fields scope delivery
/// and lease authority. Private fields and validation prevent a deserialized
/// identifier from silently becoming an active recipient.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLedgerIdentityV1 {
    schema_version: u16,
    repository_id: String,
    workspace_id: String,
    task_id: String,
    authorization_scope_digest: String,
    agent_id: String,
    session_id: String,
    turn_id: String,
    connection_generation: String,
    compaction_generation: u64,
    lifecycle_generation: u64,
}

impl fmt::Debug for ContextLedgerIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContextLedgerIdentityV1(<redacted>)")
    }
}

impl ContextLedgerIdentityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: &str,
        workspace_id: &str,
        task_id: &str,
        authorization_scope_digest: &str,
        agent_id: &str,
        session_id: &str,
        turn_id: &str,
        connection_generation: &str,
        compaction_generation: u64,
        lifecycle_generation: u64,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        for value in [
            repository_id,
            workspace_id,
            task_id,
            agent_id,
            session_id,
            turn_id,
        ] {
            validate_reasoning_identifier_v1(value)?;
        }
        for value in [authorization_scope_digest, connection_generation] {
            validate_reasoning_digest_v1(value)?;
        }
        if lifecycle_generation == 0 {
            return Err(ReasoningContextRefusalV1::InvalidGeneration);
        }
        Ok(Self {
            schema_version: CONTEXT_LEDGER_SCHEMA_VERSION_V1,
            repository_id: repository_id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            task_id: task_id.to_owned(),
            authorization_scope_digest: authorization_scope_digest.to_owned(),
            agent_id: agent_id.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            connection_generation: connection_generation.to_owned(),
            compaction_generation,
            lifecycle_generation,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    pub fn authorization_scope_digest(&self) -> &str {
        &self.authorization_scope_digest
    }
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }
    pub fn connection_generation(&self) -> &str {
        &self.connection_generation
    }
    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }
    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub fn after_compaction(&self) -> Result<Self, ReasoningContextRefusalV1> {
        let mut next = self.clone();
        next.compaction_generation = next
            .compaction_generation
            .checked_add(1)
            .ok_or(ReasoningContextRefusalV1::InvalidGeneration)?;
        Ok(next)
    }

    pub fn after_lifecycle_change(
        &self,
        connection_generation: &str,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_digest_v1(connection_generation)?;
        let mut next = self.clone();
        next.connection_generation = connection_generation.to_owned();
        next.lifecycle_generation = next
            .lifecycle_generation
            .checked_add(1)
            .ok_or(ReasoningContextRefusalV1::InvalidGeneration)?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextLedgerEventKindV1 {
    VerifiedFactAdmission,
    UnverifiedSuggestion,
    CompletedObservation,
    InflightWork,
    FailedApproach,
    ExplicitUnknown,
    ResultReference,
    Invalidation,
    Retirement,
}

impl ContextLedgerEventKindV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::VerifiedFactAdmission => "verified_fact_admission",
            Self::UnverifiedSuggestion => "unverified_suggestion",
            Self::CompletedObservation => "completed_observation",
            Self::InflightWork => "inflight_work",
            Self::FailedApproach => "failed_approach",
            Self::ExplicitUnknown => "explicit_unknown",
            Self::ResultReference => "result_reference",
            Self::Invalidation => "invalidation",
            Self::Retirement => "retirement",
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLedgerSuggestionV1 {
    subject: String,
    statement: String,
    relevance_digest: String,
}

impl ContextLedgerSuggestionV1 {
    pub fn new(
        subject: &str,
        statement: &str,
        relevance_digest: &str,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(subject)?;
        validate_reasoning_text_v1(statement, MAX_REASONING_TEXT_BYTES_V1)?;
        validate_reasoning_digest_v1(relevance_digest)?;
        Ok(Self {
            subject: subject.to_owned(),
            statement: statement.to_owned(),
            relevance_digest: relevance_digest.to_owned(),
        })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn statement(&self) -> &str {
        &self.statement
    }
    pub fn relevance_digest(&self) -> &str {
        &self.relevance_digest
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLedgerEventV1 {
    sequence: u64,
    envelope_digest: String,
    kind: ContextLedgerEventKindV1,
    subject_id: String,
    subject_version: u64,
    summary: String,
    value_digest: Option<String>,
    created_ms: u64,
}

impl ContextLedgerEventV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_store(
        sequence: u64,
        envelope_digest: String,
        kind: ContextLedgerEventKindV1,
        subject_id: String,
        subject_version: u64,
        summary: String,
        value_digest: Option<String>,
        created_ms: u64,
    ) -> Self {
        Self {
            sequence,
            envelope_digest,
            kind,
            subject_id,
            subject_version,
            summary,
            value_digest,
            created_ms,
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
    pub const fn kind(&self) -> ContextLedgerEventKindV1 {
        self.kind
    }
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }
    pub const fn subject_version(&self) -> u64 {
        self.subject_version
    }
    pub fn summary(&self) -> &str {
        &self.summary
    }
    pub fn value_digest(&self) -> Option<&str> {
        self.value_digest.as_deref()
    }
    pub const fn created_ms(&self) -> u64 {
        self.created_ms
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ContextLedgerCursorV1(u64);

impl ContextLedgerCursorV1 {
    pub const fn new(sequence: u64) -> Self {
        Self(sequence)
    }
    pub const fn sequence(self) -> u64 {
        self.0
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLedgerTaskSnapshotV1 {
    cursor: ContextLedgerCursorV1,
    current_facts: Vec<ReasoningFactV1>,
    suggestions: Vec<ContextLedgerSuggestionV1>,
    explicit_unknowns: Vec<ReasoningUnknownV1>,
    result_references: Vec<ReasoningRetrievalIdentityV1>,
    inflight_work: Vec<InflightReasoningWorkV1>,
}

impl ContextLedgerTaskSnapshotV1 {
    pub(crate) fn from_store(
        cursor: ContextLedgerCursorV1,
        current_facts: Vec<ReasoningFactV1>,
        suggestions: Vec<ContextLedgerSuggestionV1>,
        explicit_unknowns: Vec<ReasoningUnknownV1>,
        result_references: Vec<ReasoningRetrievalIdentityV1>,
        inflight_work: Vec<InflightReasoningWorkV1>,
    ) -> Self {
        Self {
            cursor,
            current_facts,
            suggestions,
            explicit_unknowns,
            result_references,
            inflight_work,
        }
    }
    pub const fn cursor(&self) -> ContextLedgerCursorV1 {
        self.cursor
    }
    pub fn current_facts(&self) -> &[ReasoningFactV1] {
        &self.current_facts
    }
    pub fn suggestions(&self) -> &[ContextLedgerSuggestionV1] {
        &self.suggestions
    }
    pub fn explicit_unknowns(&self) -> &[ReasoningUnknownV1] {
        &self.explicit_unknowns
    }
    pub fn result_references(&self) -> &[ReasoningRetrievalIdentityV1] {
        &self.result_references
    }
    pub fn inflight_work(&self) -> &[InflightReasoningWorkV1] {
        &self.inflight_work
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLedgerDeltaV1 {
    after: ContextLedgerCursorV1,
    cursor: ContextLedgerCursorV1,
    has_more: bool,
    events: Vec<ContextLedgerEventV1>,
}

impl ContextLedgerDeltaV1 {
    pub(crate) fn from_store(
        after: ContextLedgerCursorV1,
        cursor: ContextLedgerCursorV1,
        has_more: bool,
        events: Vec<ContextLedgerEventV1>,
    ) -> Self {
        Self {
            after,
            cursor,
            has_more,
            events,
        }
    }
    pub const fn after(&self) -> ContextLedgerCursorV1 {
        self.after
    }
    pub const fn cursor(&self) -> ContextLedgerCursorV1 {
        self.cursor
    }
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
    pub fn events(&self) -> &[ContextLedgerEventV1] {
        &self.events
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningScopeV1 {
    task_id: String,
    repository_id: String,
    workspace_id: String,
    state_digest: String,
    dependency_digest: String,
    authorization_scope_digest: String,
}

impl fmt::Debug for ReasoningScopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReasoningScopeV1(<redacted>)")
    }
}

impl ReasoningScopeV1 {
    pub fn new(
        task_id: &str,
        repository_id: &str,
        workspace_id: &str,
        state_digest: &str,
        dependency_digest: &str,
        authorization_scope_digest: &str,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        for value in [task_id, repository_id, workspace_id] {
            validate_reasoning_identifier_v1(value)?;
        }
        for value in [state_digest, dependency_digest, authorization_scope_digest] {
            validate_reasoning_digest_v1(value)?;
        }
        Ok(Self {
            task_id: task_id.to_owned(),
            repository_id: repository_id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            state_digest: state_digest.to_owned(),
            dependency_digest: dependency_digest.to_owned(),
            authorization_scope_digest: authorization_scope_digest.to_owned(),
        })
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub fn state_digest(&self) -> &str {
        &self.state_digest
    }

    pub fn dependency_digest(&self) -> &str {
        &self.dependency_digest
    }

    pub fn authorization_scope_digest(&self) -> &str {
        &self.authorization_scope_digest
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningRecipientV1 {
    agent_id: String,
    session_id: String,
    turn_id: String,
    connection_generation: String,
    compaction_generation: u64,
    lifecycle_generation: u64,
    active: bool,
}

impl fmt::Debug for ReasoningRecipientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReasoningRecipientV1(<redacted>)")
    }
}

impl ReasoningRecipientV1 {
    pub fn new(
        agent_id: &str,
        session_id: &str,
        turn_id: &str,
        connection_generation: &str,
        compaction_generation: u64,
        lifecycle_generation: u64,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        for value in [agent_id, session_id, turn_id] {
            validate_reasoning_identifier_v1(value)?;
        }
        validate_reasoning_digest_v1(connection_generation)?;
        if lifecycle_generation == 0 {
            return Err(ReasoningContextRefusalV1::InvalidGeneration);
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            connection_generation: connection_generation.to_owned(),
            compaction_generation,
            lifecycle_generation,
            active: true,
        })
    }

    pub fn after_compaction(&self) -> Result<Self, ReasoningContextRefusalV1> {
        let mut next = self.clone();
        next.compaction_generation = next
            .compaction_generation
            .checked_add(1)
            .ok_or(ReasoningContextRefusalV1::InvalidGeneration)?;
        Ok(next)
    }

    pub fn after_restart(
        &self,
        connection_generation: &str,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_digest_v1(connection_generation)?;
        let mut next = self.clone();
        next.connection_generation = connection_generation.to_owned();
        next.lifecycle_generation = next
            .lifecycle_generation
            .checked_add(1)
            .ok_or(ReasoningContextRefusalV1::InvalidGeneration)?;
        Ok(next)
    }

    pub fn after_cancellation(&self) -> Result<Self, ReasoningContextRefusalV1> {
        let mut next = self.clone();
        next.lifecycle_generation = next
            .lifecycle_generation
            .checked_add(1)
            .ok_or(ReasoningContextRefusalV1::InvalidGeneration)?;
        next.active = false;
        Ok(next)
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub fn connection_generation(&self) -> &str {
        &self.connection_generation
    }

    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }

    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningFactScopeV1 {
    RepositoryWide,
    TaskSpecific,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningSourceReferenceV1 {
    result_id: String,
    result_digest: String,
    repository_id: String,
    workspace_id: String,
    state_digest: String,
    dependency_digest: String,
    authorization_scope_digest: String,
    locator: String,
}

impl fmt::Debug for ReasoningSourceReferenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReasoningSourceReferenceV1(<redacted>)")
    }
}

impl ReasoningSourceReferenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_id: &str,
        result_digest: &str,
        repository_id: &str,
        workspace_id: &str,
        state_digest: &str,
        dependency_digest: &str,
        authorization_scope_digest: &str,
        locator: &str,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        for value in [result_id, repository_id, workspace_id] {
            validate_reasoning_identifier_v1(value)?;
        }
        for value in [
            result_digest,
            state_digest,
            dependency_digest,
            authorization_scope_digest,
        ] {
            validate_reasoning_digest_v1(value)?;
        }
        validate_reasoning_text_v1(locator, MAX_REASONING_LOCATOR_BYTES_V1)?;
        Ok(Self {
            result_id: result_id.to_owned(),
            result_digest: result_digest.to_owned(),
            repository_id: repository_id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            state_digest: state_digest.to_owned(),
            dependency_digest: dependency_digest.to_owned(),
            authorization_scope_digest: authorization_scope_digest.to_owned(),
            locator: locator.to_owned(),
        })
    }

    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub fn state_digest(&self) -> &str {
        &self.state_digest
    }

    pub fn dependency_digest(&self) -> &str {
        &self.dependency_digest
    }

    pub fn authorization_scope_digest(&self) -> &str {
        &self.authorization_scope_digest
    }

    pub fn locator(&self) -> &str {
        &self.locator
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningFactV1 {
    fact_id: String,
    topic: String,
    statement: String,
    value_digest: String,
    scope: ReasoningFactScopeV1,
    task_id: Option<String>,
    sources: Vec<ReasoningSourceReferenceV1>,
}

impl fmt::Debug for ReasoningFactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReasoningFactV1(<redacted>)")
    }
}

impl ReasoningFactV1 {
    pub fn new(
        fact_id: &str,
        topic: &str,
        statement: &str,
        value_digest: &str,
        scope: ReasoningFactScopeV1,
        task_id: Option<&str>,
        sources: Vec<ReasoningSourceReferenceV1>,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(fact_id)?;
        validate_reasoning_identifier_v1(topic)?;
        validate_reasoning_text_v1(statement, MAX_REASONING_TEXT_BYTES_V1)?;
        validate_reasoning_digest_v1(value_digest)?;
        if sources.is_empty() || sources.len() > MAX_REASONING_SOURCES_PER_ITEM_V1 {
            return Err(ReasoningContextRefusalV1::SourceReferenceBound);
        }
        match (scope, task_id) {
            (ReasoningFactScopeV1::RepositoryWide, None) => {}
            (ReasoningFactScopeV1::TaskSpecific, Some(task_id)) => {
                validate_reasoning_identifier_v1(task_id)?;
            }
            _ => return Err(ReasoningContextRefusalV1::TaskScopeMismatch),
        }
        Ok(Self {
            fact_id: fact_id.to_owned(),
            topic: topic.to_owned(),
            statement: statement.to_owned(),
            value_digest: value_digest.to_owned(),
            scope,
            task_id: task_id.map(str::to_owned),
            sources,
        })
    }

    pub fn fact_id(&self) -> &str {
        &self.fact_id
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub fn statement(&self) -> &str {
        &self.statement
    }

    pub fn value_digest(&self) -> &str {
        &self.value_digest
    }

    pub const fn scope(&self) -> ReasoningFactScopeV1 {
        self.scope
    }

    pub fn task_id(&self) -> Option<&str> {
        self.task_id.as_deref()
    }

    pub fn sources(&self) -> &[ReasoningSourceReferenceV1] {
        &self.sources
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningInvalidationV1 {
    RepositoryChanged,
    WorkspaceChanged,
    StateChanged,
    DependencyChanged,
    AuthorizationChanged,
    TaskChanged,
    SourceUnavailable,
    ContradictoryEvidence,
    Quarantined,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningChangeV1 {
    dimension: String,
    prior_digest: String,
    current_digest: String,
}

impl ReasoningChangeV1 {
    pub fn new(
        dimension: &str,
        prior_digest: &str,
        current_digest: &str,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(dimension)?;
        validate_reasoning_digest_v1(prior_digest)?;
        validate_reasoning_digest_v1(current_digest)?;
        Ok(Self {
            dimension: dimension.to_owned(),
            prior_digest: prior_digest.to_owned(),
            current_digest: current_digest.to_owned(),
        })
    }

    pub fn dimension(&self) -> &str {
        &self.dimension
    }

    pub fn prior_digest(&self) -> &str {
        &self.prior_digest
    }

    pub fn current_digest(&self) -> &str {
        &self.current_digest
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidatedReasoningFactV1 {
    fact: ReasoningFactV1,
    reason: ReasoningInvalidationV1,
    changes_since_observation: Vec<ReasoningChangeV1>,
}

impl InvalidatedReasoningFactV1 {
    pub fn new(
        fact: ReasoningFactV1,
        reason: ReasoningInvalidationV1,
        changes_since_observation: Vec<ReasoningChangeV1>,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        if changes_since_observation.len() > MAX_REASONING_SOURCES_PER_ITEM_V1 {
            return Err(ReasoningContextRefusalV1::ItemBound);
        }
        Ok(Self {
            fact,
            reason,
            changes_since_observation,
        })
    }

    pub fn fact(&self) -> &ReasoningFactV1 {
        &self.fact
    }

    pub const fn reason(&self) -> ReasoningInvalidationV1 {
        self.reason
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningUnknownV1 {
    subject: String,
    explanation: String,
}

impl ReasoningUnknownV1 {
    pub fn new(subject: &str, explanation: &str) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(subject)?;
        validate_reasoning_text_v1(explanation, MAX_REASONING_TEXT_BYTES_V1)?;
        Ok(Self {
            subject: subject.to_owned(),
            explanation: explanation.to_owned(),
        })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn explanation(&self) -> &str {
        &self.explanation
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningRetrievalIdentityV1 {
    result_id: String,
    result_digest: String,
    total_bytes: u64,
}

impl ReasoningRetrievalIdentityV1 {
    pub fn new(
        result_id: &str,
        result_digest: &str,
        total_bytes: u64,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(result_id)?;
        validate_reasoning_digest_v1(result_digest)?;
        Ok(Self {
            result_id: result_id.to_owned(),
            result_digest: result_digest.to_owned(),
            total_bytes,
        })
    }

    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedReasoningObservationV1 {
    observation_id: String,
    summary: String,
    duration_ms: u64,
    retrieval: ReasoningRetrievalIdentityV1,
    sources: Vec<ReasoningSourceReferenceV1>,
}

impl CompletedReasoningObservationV1 {
    pub fn new(
        observation_id: &str,
        summary: &str,
        duration_ms: u64,
        retrieval: ReasoningRetrievalIdentityV1,
        sources: Vec<ReasoningSourceReferenceV1>,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(observation_id)?;
        validate_reasoning_text_v1(summary, MAX_REASONING_TEXT_BYTES_V1)?;
        if sources.is_empty() || sources.len() > MAX_REASONING_SOURCES_PER_ITEM_V1 {
            return Err(ReasoningContextRefusalV1::SourceReferenceBound);
        }
        Ok(Self {
            observation_id: observation_id.to_owned(),
            summary: summary.to_owned(),
            duration_ms,
            retrieval,
            sources,
        })
    }

    pub const fn retrieval(&self) -> &ReasoningRetrievalIdentityV1 {
        &self.retrieval
    }

    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    pub fn sources(&self) -> &[ReasoningSourceReferenceV1] {
        &self.sources
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InflightReasoningWorkV1 {
    call_id: String,
    agent_id: String,
    lifecycle_generation: u64,
    summary: String,
}

impl InflightReasoningWorkV1 {
    pub fn new(
        call_id: &str,
        agent_id: &str,
        lifecycle_generation: u64,
        summary: &str,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(call_id)?;
        validate_reasoning_identifier_v1(agent_id)?;
        validate_reasoning_text_v1(summary, MAX_REASONING_TEXT_BYTES_V1)?;
        if lifecycle_generation == 0 {
            return Err(ReasoningContextRefusalV1::InvalidGeneration);
        }
        Ok(Self {
            call_id: call_id.to_owned(),
            agent_id: agent_id.to_owned(),
            lifecycle_generation,
            summary: summary.to_owned(),
        })
    }

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailedReasoningApproachV1 {
    approach_id: String,
    approach: String,
    verified_cause: String,
    sources: Vec<ReasoningSourceReferenceV1>,
}

impl FailedReasoningApproachV1 {
    pub fn new(
        approach_id: &str,
        approach: &str,
        verified_cause: &str,
        sources: Vec<ReasoningSourceReferenceV1>,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(approach_id)?;
        validate_reasoning_text_v1(approach, MAX_REASONING_TEXT_BYTES_V1)?;
        validate_reasoning_text_v1(verified_cause, MAX_REASONING_TEXT_BYTES_V1)?;
        if sources.is_empty() || sources.len() > MAX_REASONING_SOURCES_PER_ITEM_V1 {
            return Err(ReasoningContextRefusalV1::SourceReferenceBound);
        }
        Ok(Self {
            approach_id: approach_id.to_owned(),
            approach: approach.to_owned(),
            verified_cause: verified_cause.to_owned(),
            sources,
        })
    }

    pub fn sources(&self) -> &[ReasoningSourceReferenceV1] {
        &self.sources
    }

    pub fn approach_id(&self) -> &str {
        &self.approach_id
    }

    pub fn approach(&self) -> &str {
        &self.approach
    }

    pub fn verified_cause(&self) -> &str {
        &self.verified_cause
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningRouteDecisionV1 {
    ExactVerifiedFact,
    SharedVerifiedFact,
    InflightJoin,
    ExecuteForUnknown,
    ExecuteForStateChange,
    ExecuteForAuthorization,
    QuarantineContradiction,
    FullDeliveryRequired,
    CompactDeliveryConfirmed,
}

impl ReasoningRouteDecisionV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExactVerifiedFact => "exact_verified_fact",
            Self::SharedVerifiedFact => "shared_verified_fact",
            Self::InflightJoin => "inflight_join",
            Self::ExecuteForUnknown => "execute_for_unknown",
            Self::ExecuteForStateChange => "execute_for_state_change",
            Self::ExecuteForAuthorization => "execute_for_authorization",
            Self::QuarantineContradiction => "quarantine_contradiction",
            Self::FullDeliveryRequired => "full_delivery_required",
            Self::CompactDeliveryConfirmed => "compact_delivery_confirmed",
        }
    }

    pub const fn explanation(self) -> &'static str {
        match self {
            Self::ExactVerifiedFact => "verified observation matches the exact bounded context",
            Self::SharedVerifiedFact => {
                "verified observation is shared under matching repository and authorization scope"
            }
            Self::InflightJoin => "matching active work exists; do not execute independently",
            Self::ExecuteForUnknown => "required evidence is unknown; execute an observation",
            Self::ExecuteForStateChange => {
                "prior evidence is stale for the current repository or dependency state"
            }
            Self::ExecuteForAuthorization => {
                "prior evidence was observed under a different authorization scope"
            }
            Self::QuarantineContradiction => {
                "verified sources disagree; no output is selected for reuse"
            }
            Self::FullDeliveryRequired => {
                "recipient has not authenticated complete delivery of this exact brief"
            }
            Self::CompactDeliveryConfirmed => {
                "recipient authenticated complete delivery of this exact brief"
            }
        }
    }

    pub const fn grants_reuse(self) -> bool {
        false
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuggestedReasoningToolCallV1 {
    provider: String,
    tool: String,
    purpose: String,
    route: ReasoningRouteDecisionV1,
}

impl SuggestedReasoningToolCallV1 {
    pub fn new(
        provider: &str,
        tool: &str,
        purpose: &str,
        route: ReasoningRouteDecisionV1,
    ) -> Result<Self, ReasoningContextRefusalV1> {
        validate_reasoning_identifier_v1(provider)?;
        validate_reasoning_identifier_v1(tool)?;
        validate_reasoning_text_v1(purpose, MAX_REASONING_TEXT_BYTES_V1)?;
        Ok(Self {
            provider: provider.to_owned(),
            tool: tool.to_owned(),
            purpose: purpose.to_owned(),
            route,
        })
    }

    pub const fn grants_reuse(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReasoningEvidenceMetricsV1 {
    pub investigations_avoided: u64,
    pub provider_calls_avoided: u64,
    pub inflight_joins: u64,
    pub false_hit_quarantines: u64,
    pub estimated_execution_time_saved_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningBriefInputV1 {
    pub(crate) scope: ReasoningScopeV1,
    pub(crate) recipient: ReasoningRecipientV1,
    pub(crate) known_facts: Vec<ReasoningFactV1>,
    pub(crate) invalidated_facts: Vec<InvalidatedReasoningFactV1>,
    pub(crate) explicit_unknowns: Vec<ReasoningUnknownV1>,
    pub(crate) completed_observations: Vec<CompletedReasoningObservationV1>,
    pub(crate) inflight_work: Vec<InflightReasoningWorkV1>,
    pub(crate) failed_approaches: Vec<FailedReasoningApproachV1>,
    pub(crate) suggested_next_tool_calls: Vec<SuggestedReasoningToolCallV1>,
    pub(crate) route_decisions: Vec<ReasoningRouteDecisionV1>,
    pub(crate) evidence_metrics: ReasoningEvidenceMetricsV1,
}

impl fmt::Debug for ReasoningBriefInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReasoningBriefInputV1(<redacted>)")
    }
}

impl ReasoningBriefInputV1 {
    pub(crate) fn empty(scope: ReasoningScopeV1, recipient: ReasoningRecipientV1) -> Self {
        Self {
            scope,
            recipient,
            known_facts: Vec::new(),
            invalidated_facts: Vec::new(),
            explicit_unknowns: Vec::new(),
            completed_observations: Vec::new(),
            inflight_work: Vec::new(),
            failed_approaches: Vec::new(),
            suggested_next_tool_calls: Vec::new(),
            route_decisions: Vec::new(),
            evidence_metrics: ReasoningEvidenceMetricsV1::default(),
        }
    }

    pub fn known_facts(&self) -> &[ReasoningFactV1] {
        &self.known_facts
    }

    pub fn invalidated_facts(&self) -> &[InvalidatedReasoningFactV1] {
        &self.invalidated_facts
    }

    pub fn explicit_unknowns(&self) -> &[ReasoningUnknownV1] {
        &self.explicit_unknowns
    }

    pub fn completed_observations(&self) -> &[CompletedReasoningObservationV1] {
        &self.completed_observations
    }

    pub fn inflight_work(&self) -> &[InflightReasoningWorkV1] {
        &self.inflight_work
    }

    pub fn failed_approaches(&self) -> &[FailedReasoningApproachV1] {
        &self.failed_approaches
    }

    pub fn suggested_next_tool_calls(&self) -> &[SuggestedReasoningToolCallV1] {
        &self.suggested_next_tool_calls
    }

    pub fn route_decisions(&self) -> &[ReasoningRouteDecisionV1] {
        &self.route_decisions
    }

    pub const fn evidence_metrics(&self) -> &ReasoningEvidenceMetricsV1 {
        &self.evidence_metrics
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasoningContextRefusalV1 {
    InvalidIdentifier,
    InvalidDigest,
    InvalidText,
    SensitiveContent,
    InvalidGeneration,
    ItemBound,
    SourceReferenceBound,
    TaskScopeMismatch,
    ByteBound,
    Canonicalization,
    DeliveryIncomplete,
}

impl ReasoningContextRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidDigest => "invalid_digest",
            Self::InvalidText => "invalid_text",
            Self::SensitiveContent => "sensitive_content",
            Self::InvalidGeneration => "invalid_generation",
            Self::ItemBound => "reasoning_item_bound_exceeded",
            Self::SourceReferenceBound => "source_reference_bound_exceeded",
            Self::TaskScopeMismatch => "task_scope_mismatch",
            Self::ByteBound => "reasoning_byte_bound_exceeded",
            Self::Canonicalization => "reasoning_canonicalization_failed",
            Self::DeliveryIncomplete => "reasoning_delivery_incomplete",
        }
    }
}

pub(crate) fn validate_reasoning_identifier_v1(
    value: &str,
) -> Result<(), ReasoningContextRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_CONTEXT_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ReasoningContextRefusalV1::InvalidIdentifier);
    }
    Ok(())
}

pub(crate) fn validate_reasoning_digest_v1(value: &str) -> Result<(), ReasoningContextRefusalV1> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReasoningContextRefusalV1::InvalidDigest);
    }
    Ok(())
}

pub(crate) fn validate_reasoning_text_v1(
    value: &str,
    maximum: usize,
) -> Result<(), ReasoningContextRefusalV1> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(ReasoningContextRefusalV1::InvalidText);
    }
    Ok(())
}

fn validate_context_identifier(value: &str) -> Result<(), PresentationRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_CONTEXT_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(PresentationRefusalV1::InvalidIdentifier);
    }
    Ok(())
}

fn put_stream(hasher: &mut blake3::Hasher, stream: &[u8]) {
    hasher.update(&(stream.len() as u64).to_be_bytes());
    hasher.update(stream);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_gateway::protocol::{
        AgentCallIdentityV1, CanonicalArguments, EffectClass, FreshnessRequirementV1,
        GatewayToolCallInputV1, ModelIdentityV1, PermissionClass, ProviderIdentityV1,
        RepositoryEnvironmentStateV1, ToolIdentityV1, WorkspaceIdentityV1,
    };

    fn call() -> GatewayToolCallV1 {
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
            task: None,
            state: RepositoryEnvironmentStateV1::Unknown,
            permission_class: PermissionClass::Preapproved,
            effect_class: EffectClass::SnapshotRead,
            freshness: FreshnessRequirementV1::Snapshot,
            presentation: PresentationMode::Exact,
        })
        .unwrap()
    }

    #[test]
    fn both_presentation_apis_refuse_after_compaction() {
        let context = PresentationContextV1::new(
            "session",
            "turn",
            Some("agent"),
            "local",
            [1; 32],
            false,
            4096,
        )
        .unwrap();
        let call = call();
        let result = GatewayResultIdentityV1::from_streams(0, b"out", b"err").unwrap();
        let receipt =
            presenter_complete_exact_delivery_v1(&context, &call, result, 3, 3, true, true)
                .unwrap();
        let compacted = context.after_compaction().unwrap();
        assert_eq!(
            decide_presentation_v1(&compacted, &call, result, Some(&receipt)),
            PresentationDecisionV1::FullResult
        );
        let compact_identity = compacted.compact_identity();
        assert_eq!(
            select_presentation(
                PresentationMode::CompactReference,
                &compact_identity,
                receipt.exact_result(),
                Some(&receipt)
            ),
            PresentationMode::FullRetrievalRequired
        );
    }

    #[test]
    fn presenter_refuses_every_incomplete_delivery_shape() {
        let context =
            PresentationContextV1::new("session", "turn", None, "local", [0; 32], false, 4096)
                .unwrap();
        let call = call();
        let result = GatewayResultIdentityV1::from_streams(0, b"out", b"err").unwrap();
        for arguments in [
            (2, 3, true, true),
            (3, 2, true, true),
            (3, 3, false, true),
            (3, 3, true, false),
        ] {
            assert_eq!(
                presenter_complete_exact_delivery_v1(
                    &context,
                    &call,
                    result,
                    arguments.0,
                    arguments.1,
                    arguments.2,
                    arguments.3,
                ),
                Err(PresentationRefusalV1::IncompleteDelivery)
            );
        }
    }

    #[test]
    fn compaction_generation_overflow_fails_closed() {
        let identity = AgentContextIdentityV1::new("agent", "session", "turn", u64::MAX).unwrap();
        assert_eq!(
            identity.after_compaction(),
            Err(PresentationRefusalV1::CompactionGenerationExhausted)
        );
    }
}
