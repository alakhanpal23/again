//! Local SQLite index and content-addressed output store.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent_gateway::context::{
    CompletedReasoningObservationV1, ContextLedgerCursorV1, ContextLedgerDeltaV1,
    ContextLedgerEventKindV1, ContextLedgerEventV1, ContextLedgerIdentityV1,
    ContextLedgerSuggestionV1, ContextLedgerTaskSnapshotV1, FailedReasoningApproachV1,
    InflightReasoningWorkV1, InvalidatedReasoningFactV1, MAX_CONTEXT_LEDGER_DELTA_ITEMS_V1,
    MAX_CONTEXT_LEDGER_DEPENDENCIES_V1, MAX_CONTEXT_LEDGER_EVENTS_PER_TASK_V1,
    MAX_CONTEXT_LEDGER_SNAPSHOT_ITEMS_V1, ReasoningBriefInputV1, ReasoningContextRefusalV1,
    ReasoningFactScopeV1, ReasoningFactV1, ReasoningInvalidationV1, ReasoningRecipientV1,
    ReasoningRetrievalIdentityV1, ReasoningRouteDecisionV1, ReasoningScopeV1,
    ReasoningSourceReferenceV1, ReasoningUnknownV1, SuggestedReasoningToolCallV1,
};
use crate::agent_gateway::protocol::{
    DeliveryAuthorityRefusalV1, EffectClass, FreshnessRequirementV1, GatewayToolCallV1,
    RequestDigestV1,
};
use crate::fingerprint::{FileDigestCache, FileIdentity};
use crate::mcp_gateway::{
    ConfirmedDeliveryV1, RecipientConnectionRetirementV2, RecipientRetrievalAuthorityV2,
};
use crate::task_lifecycle::{
    MAX_TASK_GRAPH_DEPTH_V1, MAX_TASK_LIST_ITEMS_V1, TaskBlockerV1, TaskClaimOutcomeV1,
    TaskDefinitionV1, TaskExportV1, TaskRecordV1, TaskRelationKindV1, TaskStateV1,
    TaskTransitionV1, screen_sensitive_text_v1, task_definition_digest_v1,
    validate_task_selector_v1,
};

const SCHEMA_VERSION: i64 = 19;
const MAX_BRAIN_EVENTS_V1: i64 = 10_000;
const MAX_BRAIN_EVENT_AGE_MS_V1: i64 = 90 * 24 * 60 * 60 * 1_000;
const MAX_CONTEXT_SOURCE_PLAN_BYTES_V1: usize = 64 * 1024;
const MAX_CONTEXT_TASKS_PER_WORKSPACE_V1: u64 = 4096;
const MAX_CONTEXT_TASK_ALIASES_PER_WORKSPACE_V1: u64 = 16_384;
const MAX_TASK_CONTEXT_LOGICAL_BYTES_V1: u64 = 256 * 1024 * 1024;
const MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1: u64 = 1024 * 1024 * 1024;
const MAX_FILE_DIGEST_ROWS: i64 = 50_000;
const FILE_DIGEST_PRUNE_INTERVAL: u16 = 256;
const PENDING_CALL_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const EVENT_TTL_MS: i64 = 90 * 24 * 60 * 60 * 1_000;
const ORPHAN_ARTIFACT_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const CLEANUP_INTERVAL_MS: i64 = 60 * 60 * 1_000;
const CLEANUP_ROW_LIMIT: i64 = 512;
const CLEANUP_ARTIFACT_LIMIT: i64 = 256;
const MAX_LOCAL_BLOB_BYTES: usize = 16 * 1024 * 1024;
const GATEWAY_LEASE_TTL_MS: i64 = 30_000;
const GATEWAY_FRESHNESS_MAX_MS: i64 = 5 * 60_000;
const GATEWAY_MAX_DEPENDENCIES: usize = 64;
const GATEWAY_MAX_OWNER_BYTES: usize = 128;
const RETRIEVAL_GRANT_TTL_MS_V2: i64 = 30_000;
const CONTEXT_LEASE_TTL_MAX_MS_V1: i64 = 5 * 60_000;
const CONTEXT_VERIFIED_FACT_TOPIC_V1: &str = "gateway-exact-observation";
const CONTEXT_VERIFIED_FACT_STATEMENT_V1: &str =
    "exact built-in observations are available under the attached complete provenance";
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupReport {
    pub pending_calls: u64,
    pub events: u64,
    pub gateway_events: u64,
    pub artifacts: u64,
}

/// Bounded metadata observed from a coding client's completed tool event.
/// Native client output is never authority for a cache hit or verified fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrainEventV1 {
    pub session_id: String,
    pub event_id: String,
    pub task_id: String,
    pub kind: String,
    pub path: Option<String>,
    pub source_digest: Option<String>,
    pub command_digest: Option<String>,
    pub command_hint: Option<String>,
    pub exit_code: Option<i32>,
    pub created_ms: i64,
    pub authorization_scope_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrainFileV1 {
    pub path: String,
    pub source_digest: String,
    pub task_id: String,
    pub observed_ms: i64,
    pub authorization_scope_digest: Option<String>,
}

/// Outcome metadata from one Codex launcher session. Counts and usage come
/// from the client's event stream; they do not prove task acceptance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrainRunV1 {
    pub session_id: String,
    pub task_id: String,
    pub authorization_scope_digest: String,
    pub started_ms: i64,
    pub completed_ms: i64,
    pub exit_code: i32,
    pub turn_completed: bool,
    pub completed_commands: u32,
    pub completed_source_reads: u32,
    pub completed_edits: u32,
    pub completed_mcp_calls: u32,
    pub successful_tests: u32,
    pub input_tokens: Option<i64>,
    pub cached_input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
}

fn brain_run_from_row_v1(row: &rusqlite::Row<'_>) -> rusqlite::Result<BrainRunV1> {
    Ok(BrainRunV1 {
        session_id: row.get(0)?,
        task_id: row.get(1)?,
        authorization_scope_digest: row.get(2)?,
        started_ms: row.get(3)?,
        completed_ms: row.get(4)?,
        exit_code: row.get(5)?,
        turn_completed: row.get(6)?,
        completed_commands: row.get(7)?,
        completed_source_reads: row.get(8)?,
        completed_edits: row.get(9)?,
        completed_mcp_calls: row.get(10)?,
        successful_tests: row.get(11)?,
        input_tokens: row.get(12)?,
        cached_input_tokens: row.get(13)?,
        output_tokens: row.get(14)?,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct BrainTaskFileV1 {
    pub observation: BrainFileV1,
    pub task_prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCall {
    pub id: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub context_id: Option<String>,
    pub cwd: PathBuf,
    pub raw_command: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredResult {
    pub id: String,
    pub request_key: String,
    pub stdout_digest: String,
    pub stderr_digest: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub policy_version: String,
    pub proof_json: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventDisposition {
    Executed,
    ReplayedFull,
    ReplayedCompact,
    PassedThrough,
    BypassedNoStore,
    Quarantined,
}

impl EventDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::ReplayedFull => "replayed_full",
            Self::ReplayedCompact => "replayed_compact",
            Self::PassedThrough => "passed_through",
            Self::BypassedNoStore => "bypassed_no_store",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct StoreStats {
    pub executions: u64,
    pub full_replays: u64,
    pub compact_replays: u64,
    pub bypasses: u64,
    pub quarantines: u64,
    pub duplicate_bytes_omitted: u64,
    /// Sum of positive `(recorded execution duration - observed replay wall
    /// time)` estimates. Slower replays contribute zero, never negative time.
    pub estimated_execution_ms_saved: u64,
    pub requested: u64,
    pub executed: u64,
    pub direct_observations_published: u64,
    pub exact_hits: u64,
    pub coverage_hits: u64,
    pub inflight_joins: u64,
    pub compact_deliveries: u64,
    pub estimated_tokens_avoided: u64,
    pub stale_or_divergent_quarantines: u64,
    pub facts_reused: u64,
    pub investigations_avoided: u64,
    pub provider_calls_avoided: u64,
    pub invalidated_facts: u64,
    pub context_bytes_delivered: u64,
    pub delivery_confirmed_bytes_omitted: u64,
    pub confirmed_tokens_avoided: u64,
    pub false_hit_quarantines: u64,
    pub estimated_execution_time_saved_ms: u64,
    pub context_events: u64,
    pub verified_facts_admitted: u64,
    pub suggestions_published: u64,
    pub completed_observations: u64,
    pub explicit_unknowns: u64,
    pub result_references_admitted: u64,
    pub invalidation_events: u64,
    pub current_verified_facts: u64,
    pub current_result_references: u64,
    pub active_work_leases: u64,
    pub context_delivery_receipts: u64,
    pub context_delivery_confirmed_bytes_omitted: u64,
    pub context_tasks: u64,
    pub context_task_aliases: u64,
    pub context_task_aliases_converged: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ContextLedgerStatsV1 {
    pub events: u64,
    pub verified_facts_admitted: u64,
    pub suggestions_published: u64,
    pub completed_observations: u64,
    pub explicit_unknowns: u64,
    pub result_references_admitted: u64,
    pub invalidation_events: u64,
    pub current_verified_facts: u64,
    pub current_result_references: u64,
    pub active_work_leases: u64,
    pub delivery_receipts: u64,
    pub delivery_confirmed_bytes_omitted: u64,
    pub tasks: u64,
    pub task_aliases: u64,
    pub task_aliases_converged: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextTaskMatchV1 {
    Created,
    JoinedByTaskId,
    JoinedByPrompt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextTaskResolutionV1 {
    pub canonical_task_id: String,
    pub requested_task_id: String,
    pub prompt: String,
    pub prompt_digest: String,
    pub matched_by: ContextTaskMatchV1,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskStartOutcomeV1 {
    pub task: TaskRecordV1,
    pub matched_by: ContextTaskMatchV1,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskQuotaStatusV1 {
    pub task_context_bytes: u64,
    pub task_context_limit_bytes: u64,
    pub workspace_state_bytes: u64,
    pub workspace_state_limit_bytes: u64,
    pub maintenance_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatestDecisionExplanationV1 {
    pub source: String,
    pub decision: String,
    pub reason: String,
    pub result_id: Option<String>,
    /// Backward-compatible durable event spelling used by existing scripts.
    pub disposition: String,
    pub raw_event: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayRefusalReason {
    InvalidCallKey,
    InvalidStateDigest,
    InvalidOwner,
    InvalidAgentContext,
    Quarantined,
    CallNotFound,
    LeaseNotFound,
    LeaseExpired,
    LeaseNotCurrent,
    OwnerMismatch,
    NotFollower,
    ResultNotFound,
    AlreadyTerminal,
    ExecutionNotStarted,
    BindingMismatch,
    FreshnessExpired,
    ResultCorrupt,
}

impl GatewayRefusalReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCallKey => "invalid_call_key",
            Self::InvalidStateDigest => "invalid_state_digest",
            Self::InvalidOwner => "invalid_owner",
            Self::InvalidAgentContext => "invalid_agent_context",
            Self::Quarantined => "quarantined",
            Self::CallNotFound => "call_not_found",
            Self::LeaseNotFound => "lease_not_found",
            Self::LeaseExpired => "lease_expired",
            Self::LeaseNotCurrent => "lease_not_current",
            Self::OwnerMismatch => "owner_mismatch",
            Self::NotFollower => "not_follower",
            Self::ResultNotFound => "result_not_found",
            Self::AlreadyTerminal => "already_terminal",
            Self::ExecutionNotStarted => "execution_not_started",
            Self::BindingMismatch => "binding_mismatch",
            Self::FreshnessExpired => "freshness_expired",
            Self::ResultCorrupt => "result_corrupt",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayOperationDispositionV1 {
    ReplayEligibleRead,
    Mutation,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GatewayDependencyV1 {
    pub key_digest: String,
    pub value_digest: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GatewayFreshnessEvidenceV1 {
    pub snapshot_digest: String,
    pub observed_at_ms: i64,
    pub valid_until_ms: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GatewayCoordinatorInputV1 {
    pub request_digest: String,
    pub state_digest: String,
    pub policy_digest: String,
    pub operation: GatewayOperationDispositionV1,
    pub freshness: GatewayFreshnessEvidenceV1,
    pub dependencies: Vec<GatewayDependencyV1>,
}

/// Store-local proof that a complete, canonical gateway binding was admitted
/// as a replay-eligible read. Its fields are private and it deliberately does
/// not implement `Deserialize`; callers cannot turn a bool or string into
/// replay authority.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidatedGatewayReadV1 {
    input: GatewayCoordinatorInputV1,
    binding_digest: String,
}

impl ValidatedGatewayReadV1 {
    pub fn validate(input: GatewayCoordinatorInputV1) -> Result<Self> {
        validate_digest(&input.request_digest, "gateway request digest")?;
        validate_digest(&input.state_digest, "gateway state digest")?;
        validate_digest(&input.policy_digest, "gateway policy digest")?;
        validate_digest(
            &input.freshness.snapshot_digest,
            "gateway freshness snapshot digest",
        )?;
        if input.freshness.snapshot_digest != input.state_digest {
            bail!("gateway freshness evidence is not bound to the complete state digest");
        }
        if input.operation != GatewayOperationDispositionV1::ReplayEligibleRead {
            bail!("gateway operation is not an admitted replay-eligible read");
        }
        if input.dependencies.len() > GATEWAY_MAX_DEPENDENCIES {
            bail!("gateway dependency bound exceeded");
        }
        for dependency in &input.dependencies {
            validate_digest(&dependency.key_digest, "gateway dependency key digest")?;
            validate_digest(&dependency.value_digest, "gateway dependency value digest")?;
        }
        if input
            .dependencies
            .windows(2)
            .any(|pair| pair[0].key_digest >= pair[1].key_digest)
        {
            bail!("gateway dependencies must be strictly ordered by unique key digest");
        }
        if input.freshness.observed_at_ms < 0
            || input.freshness.valid_until_ms < input.freshness.observed_at_ms
            || input
                .freshness
                .valid_until_ms
                .saturating_sub(input.freshness.observed_at_ms)
                > GATEWAY_FRESHNESS_MAX_MS
        {
            bail!("gateway freshness evidence has an invalid bounded interval");
        }
        let binding_digest = gateway_binding_digest(&input);
        Ok(Self {
            input,
            binding_digest,
        })
    }

    pub fn request_digest(&self) -> &str {
        &self.input.request_digest
    }

    pub fn state_digest(&self) -> &str {
        &self.input.state_digest
    }

    pub fn policy_digest(&self) -> &str {
        &self.input.policy_digest
    }

    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    pub fn dependencies(&self) -> &[GatewayDependencyV1] {
        &self.input.dependencies
    }

    pub fn dependency_digest(&self) -> String {
        gateway_dependency_digest_v1(&self.input.dependencies)
    }
}

/// Read-only request for a payload-safe reasoning brief derived from the
/// coordinator's verified rows. The validated gateway binding remains the
/// authority boundary; labels and result identifiers never grant reuse.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayReasoningContextQueryV1 {
    scope: ReasoningScopeV1,
    recipient: ReasoningRecipientV1,
    binding: ValidatedGatewayReadV1,
}

impl std::fmt::Debug for GatewayReasoningContextQueryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GatewayReasoningContextQueryV1(<redacted>)")
    }
}

impl GatewayReasoningContextQueryV1 {
    pub fn new(
        scope: ReasoningScopeV1,
        recipient: ReasoningRecipientV1,
        binding: ValidatedGatewayReadV1,
    ) -> Result<Self> {
        if scope.state_digest() != binding.state_digest()
            || scope.dependency_digest() != binding.dependency_digest()
        {
            bail!(GatewayRefusalReason::BindingMismatch.as_str());
        }
        Ok(Self {
            scope,
            recipient,
            binding,
        })
    }

    pub const fn scope(&self) -> &ReasoningScopeV1 {
        &self.scope
    }

    pub const fn recipient(&self) -> &ReasoningRecipientV1 {
        &self.recipient
    }

    pub const fn binding(&self) -> &ValidatedGatewayReadV1 {
        &self.binding
    }
}

/// Store-issued evidence for one exact, ready gateway observation. The token
/// is intentionally not deserializable and is revalidated in the admission
/// transaction; its result identifier alone grants neither retrieval nor fact
/// admission.
#[derive(Clone)]
pub struct ContextVerifiedObservationV1 {
    source: ReasoningSourceReferenceV1,
    binding_digest: String,
    dependencies: Vec<GatewayDependencyV1>,
    freshness_valid_until_ms: i64,
    total_bytes: u64,
}

impl std::fmt::Debug for ContextVerifiedObservationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ContextVerifiedObservationV1(<redacted>)")
    }
}

impl ContextVerifiedObservationV1 {
    pub fn source(&self) -> &ReasoningSourceReferenceV1 {
        &self.source
    }

    pub fn dependencies(&self) -> &[GatewayDependencyV1] {
        &self.dependencies
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextLedgerAppendOutcomeV1 {
    Appended { sequence: u64 },
    Duplicate { sequence: u64 },
}

impl ContextLedgerAppendOutcomeV1 {
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::Appended { sequence } | Self::Duplicate { sequence } => *sequence,
        }
    }
}

/// Typed non-fact context events. Verified fact admission has a separate API
/// so prose or model relevance can never select that event kind.
#[derive(Clone)]
pub enum ContextLedgerEventInputV1 {
    UnverifiedSuggestion(ContextLedgerSuggestionV1),
    CompletedObservation {
        observation: CompletedReasoningObservationV1,
        verified_sources: Vec<ContextVerifiedObservationV1>,
    },
    FailedApproach {
        approach: FailedReasoningApproachV1,
        verified_sources: Vec<ContextVerifiedObservationV1>,
    },
    ExplicitUnknown(ReasoningUnknownV1),
    ResultReference {
        reference: ReasoningRetrievalIdentityV1,
        reference_version: u64,
        verified_sources: Vec<ContextVerifiedObservationV1>,
    },
    Retirement {
        subject_id: String,
        subject_version: u64,
        reason: String,
    },
}

impl std::fmt::Debug for ContextLedgerEventInputV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ContextLedgerEventInputV1(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextDependencyChangeV1 {
    key_digest: String,
    current_value_digest: String,
}

impl ContextDependencyChangeV1 {
    pub fn new(key_digest: &str, current_value_digest: &str) -> Result<Self> {
        validate_digest(key_digest, "context dependency key digest")?;
        validate_digest(current_value_digest, "context dependency value digest")?;
        Ok(Self {
            key_digest: key_digest.to_owned(),
            current_value_digest: current_value_digest.to_owned(),
        })
    }

    pub fn key_digest(&self) -> &str {
        &self.key_digest
    }

    pub fn current_value_digest(&self) -> &str {
        &self.current_value_digest
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContextInvalidationReportV1 {
    pub sequence: u64,
    pub retired_facts: u64,
    pub retired_result_references: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContextLedgerGcReportV1 {
    pub events: u64,
    pub fact_versions: u64,
    pub result_references: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextLeaseAcquisitionV1 {
    Leader {
        lease_id: String,
        generation: u64,
        expires_at_ms: i64,
    },
    Join {
        lease_id: String,
        generation: u64,
        leader_agent_id: String,
        expires_at_ms: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextLeaseObservationV1 {
    Inflight {
        lease_id: String,
        generation: u64,
        leader_agent_id: String,
        expires_at_ms: i64,
    },
    Completed,
    Failed,
    Cancelled,
    Missing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFailureReason {
    ProviderUnavailable,
    Transport,
    Deadline,
    Cancelled,
    Protocol,
    Internal,
}

impl GatewayFailureReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Transport => "transport",
            Self::Deadline => "deadline",
            Self::Cancelled => "cancelled",
            Self::Protocol => "protocol",
            Self::Internal => "internal",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "provider_unavailable" => Self::ProviderUnavailable,
            "transport" => Self::Transport,
            "deadline" => Self::Deadline,
            "cancelled" => Self::Cancelled,
            "protocol" => Self::Protocol,
            "internal" => Self::Internal,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayCallAcquisition {
    Leader {
        call_id: String,
        lease_id: String,
        expires_at_ms: i64,
    },
    Follower {
        call_id: String,
        lease_id: String,
        leader_call_id: String,
        leader: String,
        expires_at_ms: i64,
    },
    Ready {
        call_id: String,
        gateway_result_id: String,
    },
    Refused {
        reason: GatewayRefusalReason,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayCallObservation {
    Inflight {
        leader_call_id: String,
        leader: String,
        expires_at_ms: i64,
        followers: u64,
    },
    Ready {
        gateway_result_id: String,
    },
    Failed {
        reason: GatewayFailureReason,
    },
    Quarantined {
        reason: String,
    },
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayExecutionStart {
    Started,
    AlreadyStarted,
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayHeartbeat {
    Extended { expires_at_ms: i64 },
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayCompletion {
    Completed {
        call_id: String,
        gateway_result_id: String,
    },
    AlreadyCompleted {
        call_id: String,
        gateway_result_id: String,
    },
    Quarantined {
        call_id: String,
        existing_gateway_result_id: String,
        conflicting_gateway_result_id: String,
    },
    Refused {
        reason: GatewayRefusalReason,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFailure {
    Failed { call_id: String },
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFollowerCancellation {
    Cancelled,
    AlreadyCancelled,
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayAgentContext {
    pub session_id: String,
    pub turn_id: String,
    pub agent_id: String,
    pub compaction_epoch: u64,
}

impl GatewayAgentContext {
    pub fn new(
        session_id: impl Into<String>,
        turn_id: impl Into<String>,
        agent_id: impl Into<String>,
        compaction_epoch: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            turn_id: turn_id.into(),
            agent_id: agent_id.into(),
            compaction_epoch,
        }
    }

    fn is_valid(&self) -> bool {
        !self.session_id.is_empty() && !self.turn_id.is_empty() && !self.agent_id.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct GatewayStats {
    pub requested: u64,
    pub executed: u64,
    pub direct_observations_published: u64,
    pub exact_hits: u64,
    pub coverage_hits: u64,
    pub inflight_joins: u64,
    pub compact_deliveries: u64,
    pub estimated_tokens_avoided: u64,
    pub stale_or_divergent_quarantines: u64,
    pub facts_reused: u64,
    pub investigations_avoided: u64,
    pub provider_calls_avoided: u64,
    pub invalidated_facts: u64,
    pub context_bytes_delivered: u64,
    pub delivery_confirmed_bytes_omitted: u64,
    pub confirmed_tokens_avoided: u64,
    pub false_hit_quarantines: u64,
    pub estimated_execution_time_saved_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayServedRouteV1 {
    Exact,
    Inflight,
}

impl GatewayServedRouteV1 {
    fn event_type(self) -> &'static str {
        match self {
            Self::Exact => "exact_hit",
            Self::Inflight => "inflight_join",
        }
    }

    fn request_role(self) -> &'static str {
        match self {
            Self::Exact => "ready",
            Self::Inflight => "follower",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayFullResultV1 {
    pub gateway_result_id: String,
    pub result: StoredResult,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub dependencies: Vec<GatewayDependencyV1>,
}

/// Store-created wire material for one same-connection retrieval. The token
/// is persisted only as a digest and the value is consumed when transferred
/// into the MCP response.
pub struct StoreRetrievalGrantV2 {
    grant_id: String,
    token: String,
    gateway_result_id: String,
    expires_at_ms: i64,
}

impl StoreRetrievalGrantV2 {
    pub(crate) fn into_wire_parts(self) -> (String, String, String, i64) {
        (
            self.grant_id,
            self.token,
            self.gateway_result_id,
            self.expires_at_ms,
        )
    }
}

/// Store-transaction-issued, one-shot exact result authority. The private
/// fields, lack of `Clone` and lack of `Deserialize` prevent caller-created or
/// duplicated serve claims.
pub struct StoreExactResultProofV1 {
    used: std::cell::Cell<bool>,
    request_digest: RequestDigestV1,
    binding_digest: String,
    state_digest: String,
    policy_digest: String,
    dependency_digest: String,
    effect: EffectClass,
    freshness: FreshnessRequirementV1,
    lifecycle_generation: u64,
    observed_generation: u64,
    execution_started_ms: u64,
    observed_at_ms: u64,
    gateway_result_id: String,
    store_record_digest: String,
}

impl std::fmt::Debug for StoreExactResultProofV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoreExactResultProofV1(<redacted>)")
    }
}

impl StoreExactResultProofV1 {
    pub fn gateway_result_id(&self) -> &str {
        &self.gateway_result_id
    }

    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub(crate) fn authorizes_router_call_v1(&self, call: &GatewayToolCallV1) -> bool {
        !self.used.replace(true)
            && self.proof_invariants_hold_v1()
            && self.request_digest == call.request_digest()
            && self.effect == call.effect_class()
            && self.freshness == call.freshness()
            && freshness_requirement_holds_v1(
                self.freshness,
                self.execution_started_ms,
                self.observed_at_ms,
            )
    }

    fn proof_invariants_hold_v1(&self) -> bool {
        self.lifecycle_generation != 0
            && self.lifecycle_generation == self.observed_generation
            && self.execution_started_ms <= self.observed_at_ms
            && valid_digest_v1(&self.binding_digest)
            && valid_digest_v1(&self.state_digest)
            && valid_digest_v1(&self.policy_digest)
            && valid_digest_v1(&self.dependency_digest)
            && valid_digest_v1(&self.gateway_result_id)
            && valid_digest_v1(&self.store_record_digest)
    }
}

/// Store-transaction-issued, one-shot authority to join one actual active
/// lease generation. It never carries result serve authority.
pub struct StoreInflightJoinProofV1 {
    used: std::cell::Cell<bool>,
    request_digest: RequestDigestV1,
    binding_digest: String,
    state_digest: String,
    policy_digest: String,
    dependency_digest: String,
    effect: EffectClass,
    freshness: FreshnessRequirementV1,
    lifecycle_generation: u64,
    observed_generation: u64,
    execution_started_ms: u64,
    observed_at_ms: u64,
    lease_id: String,
    lease_record_digest: String,
}

impl std::fmt::Debug for StoreInflightJoinProofV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoreInflightJoinProofV1(<redacted>)")
    }
}

impl StoreInflightJoinProofV1 {
    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub(crate) fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub(crate) fn authorizes_router_call_v1(&self, call: &GatewayToolCallV1) -> bool {
        !self.used.replace(true)
            && self.lifecycle_generation != 0
            && self.lifecycle_generation == self.observed_generation
            && self.execution_started_ms <= self.observed_at_ms
            && valid_digest_v1(&self.binding_digest)
            && valid_digest_v1(&self.state_digest)
            && valid_digest_v1(&self.policy_digest)
            && valid_digest_v1(&self.dependency_digest)
            && valid_digest_v1(&self.lease_record_digest)
            && self.request_digest == call.request_digest()
            && self.effect == call.effect_class()
            && self.freshness == call.freshness()
            && freshness_requirement_holds_v1(
                self.freshness,
                self.execution_started_ms,
                self.observed_at_ms,
            )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRouteProofUnavailableV1 {
    Missing,
    ExecutionNotStarted,
    BindingMismatch,
    Freshness,
    Quarantined,
}

pub enum GatewayRouteProofObservationV1 {
    Exact(StoreExactResultProofV1),
    Inflight(StoreInflightJoinProofV1),
    Unavailable(GatewayRouteProofUnavailableV1),
}

impl std::fmt::Debug for GatewayRouteProofObservationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Exact(_) => "exact",
            Self::Inflight(_) => "inflight",
            Self::Unavailable(_) => "unavailable",
        };
        formatter
            .debug_struct("GatewayRouteProofObservationV1")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

pub struct Store {
    root: PathBuf,
    blobs: PathBuf,
    conn: Connection,
    file_digest_writes_since_prune: u16,
    brain_writes_since_prune: Cell<u16>,
}

impl Store {
    /// Resolve state for a repository-scoped execution.
    ///
    /// The default is a private, per-user, per-workspace directory below the
    /// operating system temporary directory. State must never live inside the
    /// observed workspace: creating or updating it could otherwise change the
    /// output of commands such as `ls -A .` and recursive `rg`.
    ///
    /// `AGAIN_HOME` selects one exact persistent store. It must be absolute and
    /// external to the workspace.
    pub fn root_for_workspace(workspace: &Path) -> Result<PathBuf> {
        let workspace = fs::canonicalize(workspace)
            .with_context(|| format!("resolve Again workspace {}", workspace.display()))?;
        if !workspace.is_dir() {
            bail!(
                "Again workspace is not a directory: {}",
                workspace.display()
            );
        }
        if let Some(path) = std::env::var_os("AGAIN_HOME") {
            let requested = PathBuf::from(path);
            if !requested.is_absolute() {
                bail!("AGAIN_HOME must be an absolute path outside the active workspace");
            }
            let root = prospective_store_root(&requested)?;
            validate_external_state_root(&workspace, &root)?;
            validate_trusted_state_ancestors(&root)?;
            return Ok(root);
        }
        default_workspace_state_root(&workspace, &std::env::temp_dir())
    }

    pub fn open_for_workspace(workspace: &Path) -> Result<Self> {
        Self::open_with_policy(Self::root_for_workspace(workspace)?)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_policy(root)
    }

    fn open_with_policy(root: impl AsRef<Path>) -> Result<Self> {
        let root = prepare_store_root(root.as_ref())?;
        let blobs = prepare_private_child_dir(&root, "blobs")?;
        create_self_ignoring_gitignore(&root)?;

        let database = root.join("again.sqlite");
        reject_unsafe_existing_file(&database, "Again database")?;
        reject_unsafe_existing_file(&root.join("again.sqlite-wal"), "Again WAL")?;
        reject_unsafe_existing_file(&root.join("again.sqlite-shm"), "Again SHM")?;
        ensure_private_database_file(&database)?;
        let conn = Connection::open(&database)
            .with_context(|| format!("open Again database {}", database.display()))?;
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;

        let mut store = Self {
            root,
            blobs,
            conn,
            file_digest_writes_since_prune: FILE_DIGEST_PRUNE_INTERVAL - 1,
            brain_writes_since_prune: Cell::new(0),
        };
        store.migrate()?;
        store.verify_gateway_schema_current()?;
        verify_reasoning_metrics_accounting_v1(&store.conn)?;
        store.maybe_cleanup()?;
        set_private_file(&database)?;
        set_private_file(&store.root.join("again.sqlite-wal"))?;
        set_private_file(&store.root.join("again.sqlite-shm"))?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            bail!(
                "Again database schema {version} is newer than supported schema {SCHEMA_VERSION}"
            );
        }
        if version == 0 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE pending_calls (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    turn_id TEXT,
                    cwd TEXT NOT NULL,
                    raw_command TEXT NOT NULL,
                    argv_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL
                );
                CREATE TABLE results (
                    id TEXT PRIMARY KEY,
                    request_key TEXT NOT NULL UNIQUE,
                    stdout_digest TEXT NOT NULL,
                    stderr_digest TEXT NOT NULL,
                    stdout_bytes INTEGER NOT NULL,
                    stderr_bytes INTEGER NOT NULL,
                    exit_code INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    policy_version TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    quarantined INTEGER NOT NULL DEFAULT 0,
                    quarantine_reason TEXT,
                    created_ms INTEGER NOT NULL,
                    last_used_ms INTEGER NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE deliveries (
                    session_id TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    call_id TEXT,
                    result_id TEXT,
                    disposition TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL DEFAULT 0,
                    bytes_omitted INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL
                );
                CREATE INDEX events_created_idx ON events(created_ms);
                PRAGMA user_version = 1;
                COMMIT;
                "#,
            )?;
        }
        if version < 2 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE file_digests (
                    device BLOB NOT NULL CHECK(typeof(device) = 'blob' AND length(device) = 8),
                    inode BLOB NOT NULL CHECK(typeof(inode) = 'blob' AND length(inode) = 8),
                    mode INTEGER NOT NULL CHECK(mode >= 0),
                    uid INTEGER NOT NULL CHECK(uid >= 0),
                    gid INTEGER NOT NULL CHECK(gid >= 0),
                    size BLOB NOT NULL CHECK(typeof(size) = 'blob' AND length(size) = 8),
                    mtime_sec INTEGER NOT NULL,
                    mtime_nsec INTEGER NOT NULL CHECK(mtime_nsec >= 0 AND mtime_nsec < 1000000000),
                    ctime_sec INTEGER NOT NULL,
                    ctime_nsec INTEGER NOT NULL CHECK(ctime_nsec >= 0 AND ctime_nsec < 1000000000),
                    digest BLOB NOT NULL CHECK(typeof(digest) = 'blob' AND length(digest) = 32),
                    row_checksum BLOB NOT NULL CHECK(typeof(row_checksum) = 'blob' AND length(row_checksum) = 32),
                    last_used_ms INTEGER NOT NULL,
                    PRIMARY KEY (device, inode)
                ) WITHOUT ROWID;
                CREATE INDEX file_digests_lru_idx ON file_digests(last_used_ms);
                PRAGMA user_version = 2;
                COMMIT;
                "#,
            )?;
        }
        if version < 3 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE artifacts (
                    digest TEXT PRIMARY KEY CHECK(length(digest) = 64),
                    created_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE INDEX artifacts_created_idx ON artifacts(created_ms);
                CREATE INDEX pending_calls_created_idx ON pending_calls(created_ms);
                CREATE TABLE maintenance (
                    name TEXT PRIMARY KEY,
                    completed_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                PRAGMA user_version = 3;
                COMMIT;
                "#,
            )?;
        }
        if version < 4 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                ALTER TABLE pending_calls ADD COLUMN context_id TEXT;
                DELETE FROM pending_calls;
                DROP TABLE IF EXISTS deliveries;
                CREATE TABLE deliveries (
                    session_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, context_id, result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
                );
                PRAGMA user_version = 4;
                COMMIT;
                "#,
            )?;
        }
        if version < 5 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                -- Before schema v5, local full replays recorded the producer's
                -- gross duration rather than end-to-end net wall time saved.
                -- Team events were net estimates, but the shared column cannot
                -- distinguish the historical writers safely. Reset prior
                -- replay metrics instead of carrying an inflated claim forward.
                UPDATE events
                SET elapsed_ms = 0
                WHERE disposition IN ('replayed_full', 'replayed_compact');
                PRAGMA user_version = 5;
                COMMIT;
                "#,
            )?;
        }
        if version < 6 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE gateway_requests (
                    call_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                    state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
                    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
                    binding_digest TEXT NOT NULL CHECK(length(binding_digest) = 64),
                    freshness_valid_until_ms INTEGER NOT NULL,
                    owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 128),
                    role TEXT NOT NULL CHECK(role IN ('leader', 'follower', 'ready', 'refused')),
                    status TEXT NOT NULL CHECK(status IN ('inflight', 'waiting', 'ready', 'failed', 'cancelled', 'quarantined')),
                    joined_lease_id TEXT,
                    gateway_result_id TEXT,
                    reason TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL
                );
                CREATE INDEX gateway_requests_binding_idx
                    ON gateway_requests(binding_digest, created_ms);
                CREATE INDEX gateway_requests_lease_idx
                    ON gateway_requests(joined_lease_id, status);

                CREATE TABLE gateway_request_dependencies (
                    call_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 64),
                    dependency_key_digest TEXT NOT NULL CHECK(length(dependency_key_digest) = 64),
                    dependency_value_digest TEXT NOT NULL CHECK(length(dependency_value_digest) = 64),
                    PRIMARY KEY (call_id, ordinal),
                    UNIQUE (call_id, dependency_key_digest),
                    FOREIGN KEY (call_id) REFERENCES gateway_requests(call_id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE gateway_results (
                    gateway_result_id TEXT PRIMARY KEY CHECK(length(gateway_result_id) = 64),
                    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                    state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
                    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
                    binding_digest TEXT NOT NULL CHECK(length(binding_digest) = 64),
                    result_id TEXT NOT NULL,
                    stdout_digest TEXT NOT NULL CHECK(length(stdout_digest) = 64),
                    stderr_digest TEXT NOT NULL CHECK(length(stderr_digest) = 64),
                    stdout_bytes INTEGER NOT NULL CHECK(stdout_bytes >= 0),
                    stderr_bytes INTEGER NOT NULL CHECK(stderr_bytes >= 0),
                    exit_code INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0),
                    result_policy_version TEXT NOT NULL,
                    proof_digest TEXT NOT NULL CHECK(length(proof_digest) = 64),
                    lease_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ready', 'quarantined')),
                    quarantine_reason TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    UNIQUE (binding_digest, gateway_result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE RESTRICT
                );
                CREATE UNIQUE INDEX gateway_results_ready_idx
                    ON gateway_results(binding_digest) WHERE status = 'ready';
                CREATE INDEX gateway_results_result_idx ON gateway_results(result_id);

                CREATE TABLE result_dependencies (
                    gateway_result_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 64),
                    dependency_key_digest TEXT NOT NULL CHECK(length(dependency_key_digest) = 64),
                    dependency_value_digest TEXT NOT NULL CHECK(length(dependency_value_digest) = 64),
                    PRIMARY KEY (gateway_result_id, ordinal),
                    UNIQUE (gateway_result_id, dependency_key_digest),
                    FOREIGN KEY (gateway_result_id) REFERENCES gateway_results(gateway_result_id)
                        ON DELETE CASCADE
                ) WITHOUT ROWID;
                CREATE INDEX result_dependencies_digest_idx
                    ON result_dependencies(dependency_key_digest, dependency_value_digest);

                CREATE TABLE inflight_leases (
                    lease_id TEXT PRIMARY KEY,
                    call_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                    state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
                    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
                    binding_digest TEXT NOT NULL CHECK(length(binding_digest) = 64),
                    freshness_valid_until_ms INTEGER NOT NULL,
                    owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 128),
                    status TEXT NOT NULL CHECK(status IN ('active', 'completed', 'failed', 'expired', 'quarantined')),
                    gateway_result_id TEXT,
                    reason TEXT,
                    acquired_ms INTEGER NOT NULL,
                    heartbeat_ms INTEGER NOT NULL,
                    expires_ms INTEGER NOT NULL,
                    execution_started_ms INTEGER,
                    completed_ms INTEGER,
                    FOREIGN KEY (call_id) REFERENCES gateway_requests(call_id) ON DELETE RESTRICT
                );
                CREATE UNIQUE INDEX inflight_leases_active_idx
                    ON inflight_leases(binding_digest) WHERE status = 'active';
                CREATE INDEX inflight_leases_expiry_idx
                    ON inflight_leases(status, expires_ms);

                CREATE TABLE gateway_deliveries (
                    session_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    compaction_epoch INTEGER NOT NULL CHECK(compaction_epoch >= 0),
                    gateway_result_id TEXT NOT NULL,
                    presentation TEXT NOT NULL,
                    estimated_tokens_avoided INTEGER NOT NULL DEFAULT 0,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (
                        session_id, turn_id, agent_id, compaction_epoch, gateway_result_id, presentation
                    ),
                    FOREIGN KEY (gateway_result_id) REFERENCES gateway_results(gateway_result_id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE gateway_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    call_id TEXT,
                    lease_id TEXT,
                    gateway_result_id TEXT,
                    event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 64),
                    reason TEXT,
                    estimated_tokens_avoided INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL
                );
                CREATE INDEX gateway_events_created_idx ON gateway_events(created_ms);
                CREATE INDEX gateway_events_type_idx ON gateway_events(event_type);
                PRAGMA user_version = 6;
                COMMIT;
                "#,
            )?;
        }
        if version < 7 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                ALTER TABLE inflight_leases
                    ADD COLUMN lifecycle_generation INTEGER NOT NULL DEFAULT 1
                    CHECK(lifecycle_generation > 0);
                UPDATE inflight_leases AS current
                SET lifecycle_generation = (
                    SELECT COUNT(*)
                    FROM inflight_leases AS prior
                    WHERE prior.binding_digest = current.binding_digest
                      AND (
                          prior.acquired_ms < current.acquired_ms
                          OR (
                              prior.acquired_ms = current.acquired_ms
                              AND prior.lease_id <= current.lease_id
                          )
                      )
                );
                CREATE UNIQUE INDEX inflight_leases_generation_idx
                    ON inflight_leases(binding_digest, lifecycle_generation);
                PRAGMA user_version = 7;
                COMMIT;
                "#,
            )?;
        }
        if version < 8 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE gateway_delivery_receipts (
                    challenge_id TEXT PRIMARY KEY CHECK(length(challenge_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    connection_digest TEXT NOT NULL CHECK(length(connection_digest) = 64),
                    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
                    turn_id TEXT NOT NULL CHECK(length(turn_id) BETWEEN 1 AND 128),
                    agent_id TEXT NOT NULL CHECK(length(agent_id) BETWEEN 1 AND 128),
                    compaction_generation INTEGER NOT NULL CHECK(compaction_generation >= 0),
                    call_digest TEXT NOT NULL CHECK(length(call_digest) = 64),
                    gateway_result_id TEXT NOT NULL CHECK(length(gateway_result_id) = 64),
                    result_digest TEXT NOT NULL CHECK(length(result_digest) = 64),
                    exact_status INTEGER NOT NULL,
                    stdout_digest TEXT NOT NULL CHECK(length(stdout_digest) = 64),
                    stdout_bytes INTEGER NOT NULL CHECK(stdout_bytes >= 0),
                    stderr_digest TEXT NOT NULL CHECK(length(stderr_digest) = 64),
                    stderr_bytes INTEGER NOT NULL CHECK(stderr_bytes >= 0),
                    acknowledged_ms INTEGER NOT NULL,
                    FOREIGN KEY (gateway_result_id) REFERENCES gateway_results(gateway_result_id)
                        ON DELETE CASCADE
                ) WITHOUT ROWID;
                CREATE INDEX gateway_delivery_receipts_context_idx
                    ON gateway_delivery_receipts(
                        authorization_scope_digest, session_id, turn_id, agent_id,
                        compaction_generation, gateway_result_id
                    );
                PRAGMA user_version = 8;
                COMMIT;
                "#,
            )?;
        }
        if version < 9 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                UPDATE gateway_events
                SET estimated_tokens_avoided = 0
                WHERE event_type = 'compact_delivery';
                UPDATE gateway_deliveries
                SET estimated_tokens_avoided = 0
                WHERE presentation = 'compact';
                PRAGMA user_version = 9;
                COMMIT;
                "#,
            )?;
        }
        if version < 10 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                -- Schema v8 receipts are retained as immutable legacy audit
                -- records.  V10 authority is deliberately represented by new
                -- tables: adding meaning to a v8 row would turn old data into
                -- authority it never possessed.
                CREATE TABLE gateway_delivery_receipts_v2 (
                    receipt_id TEXT PRIMARY KEY CHECK(length(receipt_id) BETWEEN 1 AND 128),
                    challenge_id TEXT NOT NULL UNIQUE CHECK(length(challenge_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    connection_digest TEXT NOT NULL CHECK(length(connection_digest) = 64),
                    connection_generation TEXT NOT NULL CHECK(length(connection_generation) = 64),
                    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
                    turn_id TEXT NOT NULL CHECK(length(turn_id) BETWEEN 1 AND 128),
                    agent_id TEXT NOT NULL CHECK(length(agent_id) BETWEEN 1 AND 128),
                    compaction_generation INTEGER NOT NULL CHECK(compaction_generation >= 0),
                    response_request_id_digest TEXT NOT NULL CHECK(length(response_request_id_digest) = 64),
                    call_digest TEXT NOT NULL CHECK(length(call_digest) = 64),
                    gateway_result_id TEXT NOT NULL CHECK(length(gateway_result_id) = 64),
                    result_digest TEXT NOT NULL CHECK(length(result_digest) = 64),
                    exact_status INTEGER NOT NULL,
                    stdout_digest TEXT NOT NULL CHECK(length(stdout_digest) = 64),
                    stdout_bytes INTEGER NOT NULL CHECK(stdout_bytes >= 0),
                    stderr_digest TEXT NOT NULL CHECK(length(stderr_digest) = 64),
                    stderr_bytes INTEGER NOT NULL CHECK(stderr_bytes >= 0),
                    response_envelope_digest TEXT NOT NULL CHECK(length(response_envelope_digest) = 64),
                    presentation TEXT NOT NULL CHECK(presentation IN ('full', 'compact')),
                    source_receipt_id TEXT,
                    acknowledged_ms INTEGER NOT NULL,
                    FOREIGN KEY (gateway_result_id) REFERENCES gateway_results(gateway_result_id) ON DELETE CASCADE,
                    FOREIGN KEY (source_receipt_id) REFERENCES gateway_delivery_receipts_v2(receipt_id) ON DELETE RESTRICT,
                    CHECK(
                        (presentation = 'full' AND source_receipt_id IS NULL) OR
                        (presentation = 'compact' AND source_receipt_id IS NOT NULL)
                    )
                ) WITHOUT ROWID;
                CREATE INDEX gateway_delivery_receipts_v2_context_idx
                    ON gateway_delivery_receipts_v2(
                        authorization_scope_digest, connection_digest,
                        connection_generation, session_id, turn_id, agent_id,
                        compaction_generation, gateway_result_id, presentation
                    );

                CREATE TABLE gateway_retrieval_grants_v2 (
                    grant_id TEXT PRIMARY KEY CHECK(length(grant_id) BETWEEN 1 AND 128),
                    token_digest TEXT NOT NULL UNIQUE CHECK(length(token_digest) = 64),
                    source_receipt_id TEXT NOT NULL,
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    connection_digest TEXT NOT NULL CHECK(length(connection_digest) = 64),
                    connection_generation TEXT NOT NULL CHECK(length(connection_generation) = 64),
                    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
                    turn_id TEXT NOT NULL CHECK(length(turn_id) BETWEEN 1 AND 128),
                    agent_id TEXT NOT NULL CHECK(length(agent_id) BETWEEN 1 AND 128),
                    compaction_generation INTEGER NOT NULL CHECK(compaction_generation >= 0),
                    gateway_result_id TEXT NOT NULL CHECK(length(gateway_result_id) = 64),
                    issued_ms INTEGER NOT NULL,
                    expires_ms INTEGER NOT NULL CHECK(expires_ms > issued_ms),
                    consumed_ms INTEGER,
                    retired_ms INTEGER,
                    retire_reason TEXT,
                    FOREIGN KEY (source_receipt_id) REFERENCES gateway_delivery_receipts_v2(receipt_id) ON DELETE CASCADE,
                    FOREIGN KEY (gateway_result_id) REFERENCES gateway_results(gateway_result_id) ON DELETE CASCADE,
                    CHECK(consumed_ms IS NULL OR consumed_ms >= issued_ms),
                    CHECK(retired_ms IS NULL OR retired_ms >= issued_ms),
                    CHECK(consumed_ms IS NULL OR retired_ms IS NULL),
                    CHECK((retired_ms IS NULL) = (retire_reason IS NULL))
                ) WITHOUT ROWID;
                CREATE INDEX gateway_retrieval_grants_v2_context_idx
                    ON gateway_retrieval_grants_v2(
                        authorization_scope_digest, connection_digest,
                        connection_generation, session_id, turn_id, agent_id,
                        compaction_generation, gateway_result_id, expires_ms
                    );

                CREATE TABLE gateway_delivery_savings_v2 (
                    receipt_id TEXT PRIMARY KEY,
                    response_envelope_digest TEXT NOT NULL CHECK(length(response_envelope_digest) = 64),
                    bytes_omitted INTEGER NOT NULL CHECK(bytes_omitted > 0),
                    estimated_tokens_avoided INTEGER NOT NULL CHECK(estimated_tokens_avoided >= 0),
                    recorded_ms INTEGER NOT NULL,
                    FOREIGN KEY (receipt_id) REFERENCES gateway_delivery_receipts_v2(receipt_id) ON DELETE CASCADE
                ) WITHOUT ROWID;
                PRAGMA user_version = 10;
                COMMIT;
                "#,
            )?;
        }
        if version < 11 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE context_ledger_recipients_v1 (
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    agent_id TEXT NOT NULL CHECK(length(agent_id) BETWEEN 1 AND 128),
                    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
                    turn_id TEXT NOT NULL CHECK(length(turn_id) BETWEEN 1 AND 128),
                    connection_generation TEXT NOT NULL CHECK(length(connection_generation) = 64),
                    compaction_generation INTEGER NOT NULL CHECK(compaction_generation >= 0),
                    lifecycle_generation INTEGER NOT NULL CHECK(lifecycle_generation > 0),
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    updated_ms INTEGER NOT NULL,
                    PRIMARY KEY (
                        repository_id, workspace_id, task_id, authorization_scope_digest,
                        agent_id, session_id
                    )
                ) WITHOUT ROWID;

                CREATE TABLE context_ledger_events_v1 (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    envelope_digest TEXT NOT NULL UNIQUE CHECK(length(envelope_digest) = 64),
                    canonical_digest TEXT NOT NULL CHECK(length(canonical_digest) = 64),
                    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    agent_id TEXT NOT NULL CHECK(length(agent_id) BETWEEN 1 AND 128),
                    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
                    turn_id TEXT NOT NULL CHECK(length(turn_id) BETWEEN 1 AND 128),
                    connection_generation TEXT NOT NULL CHECK(length(connection_generation) = 64),
                    compaction_generation INTEGER NOT NULL CHECK(compaction_generation >= 0),
                    lifecycle_generation INTEGER NOT NULL CHECK(lifecycle_generation > 0),
                    kind TEXT NOT NULL CHECK(kind IN (
                        'verified_fact_admission', 'unverified_suggestion',
                        'completed_observation', 'inflight_work', 'failed_approach',
                        'explicit_unknown', 'result_reference', 'invalidation', 'retirement'
                    )),
                    subject_id TEXT NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 128),
                    subject_version INTEGER NOT NULL CHECK(subject_version > 0),
                    summary TEXT NOT NULL CHECK(length(summary) BETWEEN 1 AND 1024),
                    value_digest TEXT CHECK(value_digest IS NULL OR length(value_digest) = 64),
                    result_id TEXT,
                    result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest) = 64),
                    total_bytes INTEGER CHECK(total_bytes IS NULL OR total_bytes >= 0),
                    duration_ms INTEGER CHECK(duration_ms IS NULL OR duration_ms >= 0),
                    created_ms INTEGER NOT NULL
                );
                CREATE INDEX context_ledger_events_task_idx
                    ON context_ledger_events_v1(repository_id, workspace_id, task_id, sequence);
                CREATE INDEX context_ledger_events_result_idx
                    ON context_ledger_events_v1(result_id, sequence);

                CREATE TABLE context_ledger_event_sources_v1 (
                    event_sequence INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 8),
                    result_id TEXT NOT NULL CHECK(length(result_id) BETWEEN 1 AND 128),
                    result_digest TEXT NOT NULL CHECK(length(result_digest) = 64),
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
                    dependency_digest TEXT NOT NULL CHECK(length(dependency_digest) = 64),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    locator TEXT NOT NULL CHECK(length(locator) BETWEEN 1 AND 512),
                    binding_digest TEXT NOT NULL CHECK(length(binding_digest) = 64),
                    PRIMARY KEY(event_sequence, ordinal),
                    UNIQUE(event_sequence, result_id, locator),
                    FOREIGN KEY(event_sequence) REFERENCES context_ledger_events_v1(sequence) ON DELETE CASCADE,
                    FOREIGN KEY(result_id) REFERENCES gateway_results(gateway_result_id) ON DELETE RESTRICT
                ) WITHOUT ROWID;
                CREATE INDEX context_ledger_sources_result_idx
                    ON context_ledger_event_sources_v1(result_id, event_sequence);

                CREATE TABLE context_ledger_event_dependencies_v1 (
                    event_sequence INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 64),
                    dependency_key_digest TEXT NOT NULL CHECK(length(dependency_key_digest) = 64),
                    dependency_value_digest TEXT NOT NULL CHECK(length(dependency_value_digest) = 64),
                    PRIMARY KEY(event_sequence, ordinal),
                    UNIQUE(event_sequence, dependency_key_digest),
                    FOREIGN KEY(event_sequence) REFERENCES context_ledger_events_v1(sequence) ON DELETE CASCADE
                ) WITHOUT ROWID;
                CREATE INDEX context_ledger_dependency_reverse_idx
                    ON context_ledger_event_dependencies_v1(
                        dependency_key_digest, dependency_value_digest, event_sequence
                    );

                CREATE TABLE context_ledger_fact_versions_v1 (
                    repository_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    fact_id TEXT NOT NULL CHECK(length(fact_id) BETWEEN 1 AND 128),
                    fact_version INTEGER NOT NULL CHECK(fact_version > 0),
                    admission_event_sequence INTEGER NOT NULL UNIQUE,
                    topic TEXT NOT NULL CHECK(length(topic) BETWEEN 1 AND 128),
                    statement TEXT NOT NULL CHECK(length(statement) BETWEEN 1 AND 1024),
                    value_digest TEXT NOT NULL CHECK(length(value_digest) = 64),
                    fact_scope TEXT NOT NULL CHECK(fact_scope IN ('repository_wide', 'task_specific')),
                    fact_task_id TEXT,
                    retired_event_sequence INTEGER,
                    retirement_reason TEXT,
                    PRIMARY KEY(repository_id, workspace_id, task_id, fact_id, fact_version),
                    FOREIGN KEY(admission_event_sequence) REFERENCES context_ledger_events_v1(sequence) ON DELETE RESTRICT,
                    FOREIGN KEY(retired_event_sequence) REFERENCES context_ledger_events_v1(sequence) ON DELETE RESTRICT,
                    CHECK((retired_event_sequence IS NULL) = (retirement_reason IS NULL)),
                    CHECK(
                        (fact_scope = 'repository_wide' AND fact_task_id IS NULL) OR
                        (fact_scope = 'task_specific' AND fact_task_id = task_id)
                    )
                ) WITHOUT ROWID;
                CREATE INDEX context_ledger_facts_current_idx
                    ON context_ledger_fact_versions_v1(repository_id, workspace_id, task_id, fact_id)
                    WHERE retired_event_sequence IS NULL;

                CREATE TABLE context_ledger_result_references_v1 (
                    repository_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    result_id TEXT NOT NULL CHECK(length(result_id) BETWEEN 1 AND 128),
                    reference_version INTEGER NOT NULL CHECK(reference_version > 0),
                    admission_event_sequence INTEGER NOT NULL UNIQUE,
                    result_digest TEXT NOT NULL CHECK(length(result_digest) = 64),
                    total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0),
                    retired_event_sequence INTEGER,
                    retirement_reason TEXT,
                    PRIMARY KEY(repository_id, workspace_id, task_id, result_id, reference_version),
                    FOREIGN KEY(admission_event_sequence) REFERENCES context_ledger_events_v1(sequence) ON DELETE RESTRICT,
                    FOREIGN KEY(retired_event_sequence) REFERENCES context_ledger_events_v1(sequence) ON DELETE RESTRICT,
                    CHECK((retired_event_sequence IS NULL) = (retirement_reason IS NULL))
                ) WITHOUT ROWID;
                CREATE INDEX context_ledger_results_current_idx
                    ON context_ledger_result_references_v1(repository_id, workspace_id, task_id, result_id)
                    WHERE retired_event_sequence IS NULL;

                CREATE TABLE context_ledger_leases_v1 (
                    lease_id TEXT PRIMARY KEY CHECK(length(lease_id) BETWEEN 1 AND 128),
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    work_key_digest TEXT NOT NULL CHECK(length(work_key_digest) = 64),
                    generation INTEGER NOT NULL CHECK(generation > 0),
                    leader_agent_id TEXT NOT NULL CHECK(length(leader_agent_id) BETWEEN 1 AND 128),
                    leader_session_id TEXT NOT NULL CHECK(length(leader_session_id) BETWEEN 1 AND 128),
                    leader_lifecycle_generation INTEGER NOT NULL CHECK(leader_lifecycle_generation > 0),
                    summary TEXT NOT NULL CHECK(length(summary) BETWEEN 1 AND 1024),
                    status TEXT NOT NULL CHECK(status IN ('active', 'completed', 'failed', 'cancelled', 'expired')),
                    acquired_ms INTEGER NOT NULL,
                    heartbeat_ms INTEGER NOT NULL,
                    deadline_ms INTEGER NOT NULL,
                    expires_ms INTEGER NOT NULL,
                    completed_ms INTEGER,
                    UNIQUE(repository_id, workspace_id, task_id, authorization_scope_digest, work_key_digest, generation),
                    CHECK(expires_ms <= deadline_ms),
                    CHECK((status = 'active') = (completed_ms IS NULL))
                );
                CREATE UNIQUE INDEX context_ledger_leases_active_idx
                    ON context_ledger_leases_v1(
                        repository_id, workspace_id, task_id,
                        authorization_scope_digest, work_key_digest
                    ) WHERE status = 'active';
                CREATE INDEX context_ledger_leases_expiry_idx
                    ON context_ledger_leases_v1(status, expires_ms);

                CREATE TABLE context_ledger_delivery_receipts_v1 (
                    receipt_digest TEXT PRIMARY KEY CHECK(length(receipt_digest) = 64),
                    response_envelope_digest TEXT NOT NULL UNIQUE CHECK(length(response_envelope_digest) = 64),
                    repository_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    connection_generation TEXT NOT NULL CHECK(length(connection_generation) = 64),
                    compaction_generation INTEGER NOT NULL CHECK(compaction_generation >= 0),
                    lifecycle_generation INTEGER NOT NULL CHECK(lifecycle_generation > 0),
                    through_sequence INTEGER NOT NULL CHECK(through_sequence >= 0),
                    delivered_bytes INTEGER NOT NULL CHECK(delivered_bytes >= 0),
                    acknowledged_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE INDEX context_ledger_receipts_task_idx
                    ON context_ledger_delivery_receipts_v1(
                        repository_id, workspace_id, task_id, through_sequence
                    );

                CREATE TABLE context_ledger_delivery_savings_v1 (
                    receipt_digest TEXT PRIMARY KEY,
                    response_envelope_digest TEXT NOT NULL UNIQUE CHECK(length(response_envelope_digest) = 64),
                    bytes_omitted INTEGER NOT NULL CHECK(bytes_omitted > 0),
                    recorded_ms INTEGER NOT NULL,
                    FOREIGN KEY(receipt_digest) REFERENCES context_ledger_delivery_receipts_v1(receipt_digest) ON DELETE CASCADE
                ) WITHOUT ROWID;
                PRAGMA user_version = 11;
                COMMIT;
                "#,
            )?;
        }
        if version < 12 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE context_tasks_v1 (
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    canonical_task_id TEXT NOT NULL CHECK(length(canonical_task_id) BETWEEN 1 AND 128),
                    prompt_digest TEXT NOT NULL CHECK(length(prompt_digest) = 64),
                    prompt_text TEXT NOT NULL CHECK(length(CAST(prompt_text AS BLOB)) BETWEEN 1 AND 8192),
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    PRIMARY KEY(repository_id, workspace_id, authorization_scope_digest, canonical_task_id)
                ) WITHOUT ROWID;
                CREATE UNIQUE INDEX context_tasks_prompt_idx
                    ON context_tasks_v1(
                        repository_id, workspace_id, authorization_scope_digest, prompt_digest
                    );

                CREATE TABLE context_task_aliases_v1 (
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    requested_task_id TEXT NOT NULL CHECK(length(requested_task_id) BETWEEN 1 AND 128),
                    canonical_task_id TEXT NOT NULL CHECK(length(canonical_task_id) BETWEEN 1 AND 128),
                    created_ms INTEGER NOT NULL,
                    PRIMARY KEY(repository_id, workspace_id, authorization_scope_digest, requested_task_id),
                    FOREIGN KEY(repository_id, workspace_id, authorization_scope_digest, canonical_task_id)
                        REFERENCES context_tasks_v1(
                            repository_id, workspace_id, authorization_scope_digest, canonical_task_id
                        ) ON DELETE RESTRICT
                ) WITHOUT ROWID;
                CREATE INDEX context_task_aliases_canonical_idx
                    ON context_task_aliases_v1(
                        repository_id, workspace_id, authorization_scope_digest, canonical_task_id
                    );
                PRAGMA user_version = 12;
                COMMIT;
                "#,
            )?;
        }
        if version < 13 {
            let transaction =
                Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                r#"
                DROP INDEX context_tasks_prompt_idx;
                ALTER TABLE context_tasks_v1 ADD COLUMN definition_digest TEXT
                    CHECK(definition_digest IS NULL OR length(definition_digest) = 64);
                ALTER TABLE context_tasks_v1 ADD COLUMN acceptance_criteria_json TEXT NOT NULL
                    DEFAULT '[]' CHECK(json_valid(acceptance_criteria_json));
                ALTER TABLE context_tasks_v1 ADD COLUMN revision INTEGER NOT NULL
                    DEFAULT 1 CHECK(revision > 0);
                ALTER TABLE context_tasks_v1 ADD COLUMN state TEXT NOT NULL
                    DEFAULT 'active' CHECK(state IN (
                        'waiting', 'active', 'blocked', 'completed', 'failed', 'cancelled'
                    ));
                ALTER TABLE context_tasks_v1 ADD COLUMN state_generation INTEGER NOT NULL
                    DEFAULT 1 CHECK(state_generation > 0);
                CREATE UNIQUE INDEX context_tasks_definition_idx
                    ON context_tasks_v1(
                        repository_id, workspace_id, authorization_scope_digest,
                        definition_digest
                    );
                CREATE INDEX context_tasks_state_idx
                    ON context_tasks_v1(repository_id, workspace_id, state, created_ms);

                CREATE TABLE context_task_relations_v1 (
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    source_task_id TEXT NOT NULL CHECK(length(source_task_id) BETWEEN 1 AND 128),
                    relation_kind TEXT NOT NULL CHECK(relation_kind IN ('parent', 'dependency', 'supersedes')),
                    target_task_id TEXT NOT NULL CHECK(length(target_task_id) BETWEEN 1 AND 128),
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 64),
                    created_ms INTEGER NOT NULL,
                    PRIMARY KEY(
                        repository_id, workspace_id, authorization_scope_digest,
                        source_task_id, relation_kind, target_task_id
                    ),
                    UNIQUE(
                        repository_id, workspace_id, authorization_scope_digest,
                        source_task_id, relation_kind, ordinal
                    ),
                    FOREIGN KEY(repository_id, workspace_id, authorization_scope_digest, source_task_id)
                        REFERENCES context_tasks_v1(
                            repository_id, workspace_id, authorization_scope_digest,
                            canonical_task_id
                        ) ON DELETE CASCADE,
                    FOREIGN KEY(repository_id, workspace_id, authorization_scope_digest, target_task_id)
                        REFERENCES context_tasks_v1(
                            repository_id, workspace_id, authorization_scope_digest,
                            canonical_task_id
                        ) ON DELETE RESTRICT,
                    CHECK(source_task_id != target_task_id)
                ) WITHOUT ROWID;
                CREATE INDEX context_task_relations_target_idx
                    ON context_task_relations_v1(
                        repository_id, workspace_id, authorization_scope_digest,
                        target_task_id, relation_kind
                    );

                CREATE TABLE context_task_transitions_v1 (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    canonical_task_id TEXT NOT NULL CHECK(length(canonical_task_id) BETWEEN 1 AND 128),
                    from_state TEXT CHECK(from_state IS NULL OR from_state IN (
                        'waiting', 'active', 'blocked', 'completed', 'failed', 'cancelled'
                    )),
                    to_state TEXT NOT NULL CHECK(to_state IN (
                        'waiting', 'active', 'blocked', 'completed', 'failed', 'cancelled'
                    )),
                    state_generation INTEGER NOT NULL CHECK(state_generation > 0),
                    lease_id TEXT,
                    agent_id TEXT,
                    session_id TEXT,
                    lifecycle_generation INTEGER,
                    reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB)) BETWEEN 1 AND 512),
                    created_ms INTEGER NOT NULL,
                    UNIQUE(
                        repository_id, workspace_id, authorization_scope_digest,
                        canonical_task_id, state_generation
                    ),
                    FOREIGN KEY(repository_id, workspace_id, authorization_scope_digest, canonical_task_id)
                        REFERENCES context_tasks_v1(
                            repository_id, workspace_id, authorization_scope_digest,
                            canonical_task_id
                        ) ON DELETE CASCADE,
                    CHECK((agent_id IS NULL) = (session_id IS NULL)),
                    CHECK((agent_id IS NULL) = (lifecycle_generation IS NULL)),
                    CHECK(lifecycle_generation IS NULL OR lifecycle_generation > 0)
                );
                CREATE INDEX context_task_transitions_task_idx
                    ON context_task_transitions_v1(
                        repository_id, workspace_id, authorization_scope_digest,
                        canonical_task_id, sequence
                    );

                CREATE TABLE context_workspace_quota_v1 (
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    task_context_bytes INTEGER NOT NULL CHECK(task_context_bytes >= 0),
                    workspace_state_bytes INTEGER NOT NULL CHECK(workspace_state_bytes >= 0),
                    maintenance_mode INTEGER NOT NULL CHECK(maintenance_mode IN (0, 1)),
                    counter_checksum TEXT NOT NULL CHECK(length(counter_checksum) = 64),
                    reconciled_ms INTEGER NOT NULL,
                    PRIMARY KEY(repository_id, workspace_id)
                ) WITHOUT ROWID;
                "#,
            )?;
            let legacy_tasks = {
                let mut statement = transaction.prepare(
                    "SELECT repository_id, workspace_id, authorization_scope_digest,
                            canonical_task_id, prompt_text, created_ms
                     FROM context_tasks_v1
                     ORDER BY repository_id, workspace_id,
                              authorization_scope_digest, canonical_task_id",
                )?;
                statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (repository, workspace, authorization, task_id, prompt, created_ms) in legacy_tasks
            {
                let digest = task_definition_digest_v1(&prompt, &[], None, &[], None);
                transaction.execute(
                    "UPDATE context_tasks_v1 SET definition_digest = ?5
                     WHERE repository_id = ?1 AND workspace_id = ?2
                       AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
                    params![repository, workspace, authorization, task_id, digest],
                )?;
                transaction.execute(
                    "INSERT INTO context_task_transitions_v1 (
                        repository_id, workspace_id, authorization_scope_digest,
                        canonical_task_id, from_state, to_state, state_generation,
                        reason, created_ms
                     ) VALUES (?1, ?2, ?3, ?4, NULL, 'active', 1,
                               'schema_v12_migration', ?5)",
                    params![repository, workspace, authorization, task_id, created_ms],
                )?;
            }
            reconcile_all_task_quotas_v1_tx(&transaction, now_ms())?;
            transaction.pragma_update(None, "user_version", 13)?;
            transaction.commit()?;
        }
        if version < 14 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE gateway_context_source_recipes_v1 (
                    result_id TEXT PRIMARY KEY CHECK(length(result_id) = 64),
                    repository_id TEXT NOT NULL CHECK(length(repository_id) BETWEEN 1 AND 128),
                    workspace_id TEXT NOT NULL CHECK(length(workspace_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    repository_digest TEXT NOT NULL CHECK(length(repository_digest) = 64),
                    plan_json TEXT NOT NULL CHECK(json_valid(plan_json)
                        AND length(CAST(plan_json AS BLOB)) BETWEEN 1 AND 65536),
                    plan_digest TEXT NOT NULL CHECK(length(plan_digest) = 64),
                    created_ms INTEGER NOT NULL CHECK(created_ms >= 0),
                    FOREIGN KEY(result_id) REFERENCES gateway_results(gateway_result_id) ON DELETE CASCADE
                ) WITHOUT ROWID;
                PRAGMA user_version = 14;
                COMMIT;
                "#,
            )?;
        }
        if version < 15 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                ALTER TABLE gateway_results ADD COLUMN origin TEXT NOT NULL DEFAULT 'leased'
                    CHECK(origin IN ('leased', 'direct_observation'));
                DROP INDEX gateway_results_ready_idx;
                CREATE UNIQUE INDEX gateway_results_ready_idx
                    ON gateway_results(binding_digest)
                    WHERE status = 'ready' AND origin = 'leased';
                CREATE UNIQUE INDEX gateway_results_direct_idx
                    ON gateway_results(binding_digest)
                    WHERE status = 'ready' AND origin = 'direct_observation';
                PRAGMA user_version = 15;
                COMMIT;
                "#,
            )?;
        }
        if version < 16 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS brain_events_v1 (
                    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
                    event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 1 AND 128),
                    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
                    kind TEXT NOT NULL CHECK(kind IN ('file_change', 'command', 'test')),
                    path TEXT NOT NULL CHECK(length(path) <= 512),
                    source_digest TEXT CHECK(source_digest IS NULL OR length(source_digest) = 64),
                    command_digest TEXT CHECK(command_digest IS NULL OR length(command_digest) = 64),
                    command_hint TEXT CHECK(command_hint IS NULL OR length(command_hint) BETWEEN 1 AND 256),
                    exit_code INTEGER,
                    created_ms INTEGER NOT NULL CHECK(created_ms >= 0),
                    PRIMARY KEY(session_id, event_id, kind, path)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS brain_events_recent_idx ON brain_events_v1(created_ms DESC);
                CREATE INDEX IF NOT EXISTS brain_events_task_idx ON brain_events_v1(task_id, created_ms DESC);
                PRAGMA user_version = 16;
                COMMIT;
                "#,
            )?;
        }
        if version < 17 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS brain_files_v1 (
                    path TEXT PRIMARY KEY CHECK(length(path) BETWEEN 1 AND 512),
                    source_digest TEXT NOT NULL CHECK(length(source_digest) = 64),
                    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
                    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
                    event_id TEXT NOT NULL CHECK(length(event_id) BETWEEN 1 AND 128),
                    observed_ms INTEGER NOT NULL CHECK(observed_ms >= 0)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS brain_files_recent_idx
                    ON brain_files_v1(observed_ms DESC);
                CREATE TABLE IF NOT EXISTS brain_test_commands_v1 (
                    command_hint TEXT PRIMARY KEY CHECK(length(command_hint) BETWEEN 1 AND 256),
                    command_digest TEXT NOT NULL CHECK(length(command_digest) = 64),
                    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
                    observed_ms INTEGER NOT NULL CHECK(observed_ms >= 0)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS brain_test_commands_recent_idx
                    ON brain_test_commands_v1(observed_ms DESC);
                PRAGMA user_version = 17;
                COMMIT;
                "#,
            )?;
        }
        if version < 18 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                ALTER TABLE brain_events_v1 ADD COLUMN authorization_scope_digest TEXT
                    CHECK(authorization_scope_digest IS NULL OR length(authorization_scope_digest) = 64);
                ALTER TABLE brain_files_v1 ADD COLUMN authorization_scope_digest TEXT
                    CHECK(authorization_scope_digest IS NULL OR length(authorization_scope_digest) = 64);
                ALTER TABLE brain_test_commands_v1 ADD COLUMN authorization_scope_digest TEXT
                    CHECK(authorization_scope_digest IS NULL OR length(authorization_scope_digest) = 64);
                CREATE INDEX brain_files_scope_recent_idx
                    ON brain_files_v1(authorization_scope_digest, observed_ms DESC);
                CREATE INDEX brain_test_commands_scope_recent_idx
                    ON brain_test_commands_v1(authorization_scope_digest, observed_ms DESC);
                PRAGMA user_version = 18;
                COMMIT;
                "#,
            )?;
        }
        if version < 19 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS brain_runs_v1 (
                    session_id TEXT PRIMARY KEY CHECK(length(session_id) BETWEEN 1 AND 128),
                    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
                    authorization_scope_digest TEXT NOT NULL CHECK(length(authorization_scope_digest) = 64),
                    started_ms INTEGER NOT NULL CHECK(started_ms >= 0),
                    completed_ms INTEGER NOT NULL CHECK(completed_ms >= started_ms),
                    exit_code INTEGER NOT NULL,
                    turn_completed INTEGER NOT NULL CHECK(turn_completed IN (0, 1)),
                    completed_commands INTEGER NOT NULL CHECK(completed_commands >= 0),
                    completed_source_reads INTEGER NOT NULL CHECK(completed_source_reads >= 0),
                    completed_edits INTEGER NOT NULL CHECK(completed_edits >= 0),
                    completed_mcp_calls INTEGER NOT NULL CHECK(completed_mcp_calls >= 0),
                    successful_tests INTEGER NOT NULL CHECK(successful_tests >= 0),
                    input_tokens INTEGER CHECK(input_tokens IS NULL OR input_tokens >= 0),
                    cached_input_tokens INTEGER CHECK(cached_input_tokens IS NULL OR cached_input_tokens >= 0),
                    output_tokens INTEGER CHECK(output_tokens IS NULL OR output_tokens >= 0),
                    CHECK(cached_input_tokens IS NULL OR input_tokens IS NOT NULL),
                    CHECK(cached_input_tokens IS NULL OR cached_input_tokens <= input_tokens)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS brain_runs_scope_recent_idx
                    ON brain_runs_v1(authorization_scope_digest, completed_ms DESC);
                PRAGMA user_version = 19;
                COMMIT;
                "#,
            )?;
        }
        Ok(())
    }

    fn verify_gateway_schema_current(&self) -> Result<()> {
        verify_gateway_schema_current(&self.conn)
    }

    pub fn create_call(
        &self,
        session_id: &str,
        turn_id: Option<&str>,
        context_id: Option<&str>,
        cwd: &Path,
        raw_command: &str,
        argv: &[String],
    ) -> Result<PendingCall> {
        let id = Uuid::new_v4().simple().to_string();
        let call = PendingCall {
            id,
            session_id: session_id.to_owned(),
            turn_id: turn_id.map(ToOwned::to_owned),
            context_id: context_id.map(ToOwned::to_owned),
            cwd: cwd.to_path_buf(),
            raw_command: raw_command.to_owned(),
            argv: argv.to_vec(),
        };
        self.conn.execute(
            "INSERT INTO pending_calls (id, session_id, turn_id, context_id, cwd, raw_command, argv_json, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                call.id,
                call.session_id,
                call.turn_id,
                call.context_id,
                call.cwd.to_string_lossy(),
                call.raw_command,
                serde_json::to_string(&call.argv)?,
                now_ms(),
            ],
        )?;
        Ok(call)
    }

    pub fn get_call(&self, id: &str) -> Result<Option<PendingCall>> {
        self.conn
            .query_row(
                "SELECT id, session_id, turn_id, context_id, cwd, raw_command, argv_json FROM pending_calls WHERE id = ?1",
                [id],
                |row| {
                    let argv_json: String = row.get(6)?;
                    let argv = serde_json::from_str(&argv_json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(PendingCall {
                        id: row.get(0)?,
                        session_id: row.get(1)?,
                        turn_id: row.get(2)?,
                        context_id: row.get(3)?,
                        cwd: PathBuf::from(row.get::<_, String>(4)?),
                        raw_command: row.get(5)?,
                        argv,
                    })
                },
            )
            .optional()
            .context("read pending call")
    }

    pub fn delete_call(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_calls WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        if bytes.len() > MAX_LOCAL_BLOB_BYTES {
            bail!("Again blob exceeds the local 16 MiB limit");
        }
        let digest = blake3::hash(bytes).to_hex().to_string();
        let target = self.blob_path(&digest)?;
        // File publication and lifecycle cleanup share the SQLite write lock. This
        // prevents a cleaner from deleting an old orphan between verification and
        // publication in the artifact inventory.
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_blob_file(&target, &digest, bytes)?;
        transaction.execute(
            "INSERT INTO artifacts (digest, created_ms) VALUES (?1, ?2) ON CONFLICT(digest) DO UPDATE SET created_ms = excluded.created_ms",
            params![digest, now_ms()],
        )?;
        transaction.commit()?;
        Ok(digest)
    }

    pub fn get_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest)?;
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("inspect blob {digest}"))?;
        validate_owned_regular_file(&path, &metadata, "Again blob")?;
        let bytes = read_blob_bounded(&path, digest)?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != digest {
            bail!("CAS corruption: blob {digest} hashes to {actual}");
        }
        Ok(bytes)
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        blob_path_under(&self.blobs, digest)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_result(
        &mut self,
        request_key: &str,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
        duration_ms: u64,
        policy_version: &str,
        proof_json: &str,
    ) -> Result<StoredResult> {
        // Refuse known maintenance/quota exhaustion before publishing even an
        // orphan-eligible CAS blob. The serialized check below remains the
        // authoritative race fence immediately before the result row.
        {
            let preflight = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
            enforce_workspace_result_capacity_v1(
                &preflight,
                (stdout.len() as u64).saturating_add(stderr.len() as u64),
            )?;
            preflight.commit()?;
        }
        let stdout_digest = self.put_blob(stdout)?;
        let stderr_digest = self.put_blob(stderr)?;
        let result = StoredResult {
            id: format!("r_{}", Uuid::new_v4().simple()),
            request_key: request_key.to_owned(),
            stdout_digest,
            stderr_digest,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            exit_code,
            duration_ms,
            policy_version: policy_version.to_owned(),
            proof_json: proof_json.to_owned(),
        };
        let now = now_ms();
        // Serialize the read/compare/insert decision. A deferred transaction lets
        // two writers both observe absence and turns divergence into a bare UNIQUE
        // error instead of quarantine.
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, quarantined FROM results WHERE request_key = ?1",
                [request_key],
                |row| Ok((row_to_result(row)?, row.get::<_, bool>(10)?)),
            )
            .optional()?;
        if let Some((existing, quarantined)) = existing {
            if quarantined {
                bail!("request key {request_key} is quarantined");
            }
            if existing.stdout_digest != result.stdout_digest
                || existing.stderr_digest != result.stderr_digest
                || existing.stdout_bytes != result.stdout_bytes
                || existing.stderr_bytes != result.stderr_bytes
                || existing.exit_code != result.exit_code
                || existing.policy_version != result.policy_version
                || existing.proof_json != result.proof_json
            {
                transaction.execute(
                    "UPDATE results SET quarantined = 1, quarantine_reason = ?2 WHERE id = ?1",
                    params![existing.id, "same_key_different_result"],
                )?;
                transaction.execute(
                    "INSERT INTO events (call_id, result_id, disposition, reason_code, elapsed_ms, bytes_omitted, created_ms) VALUES (NULL, ?1, ?2, ?3, 0, 0, ?4)",
                    params![
                        existing.id,
                        EventDisposition::Quarantined.as_str(),
                        "same_key_different_result",
                        now,
                    ],
                )?;
                transaction.commit()?;
                bail!("differential mismatch for request key {request_key}; entry quarantined");
            }
            transaction.commit()?;
            return Ok(existing);
        }
        enforce_workspace_result_capacity_v1(
            &transaction,
            result.stdout_bytes.saturating_add(result.stderr_bytes),
        )?;
        transaction.execute(
            "INSERT INTO results (id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, created_ms, last_used_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                result.id,
                result.request_key,
                result.stdout_digest,
                result.stderr_digest,
                result.stdout_bytes,
                result.stderr_bytes,
                result.exit_code,
                result.duration_ms,
                result.policy_version,
                result.proof_json,
                now,
            ],
        )?;
        refresh_workspace_state_quota_v1_tx(&transaction, now)?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn get_result(&self, request_key: &str) -> Result<Option<StoredResult>> {
        self.conn
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE request_key = ?1 AND quarantined = 0",
                [request_key],
                row_to_result,
            )
            .optional()
            .context("lookup cached result")
    }

    pub fn get_result_by_id(&self, id: &str) -> Result<Option<StoredResult>> {
        self.conn
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE id = ?1 AND quarantined = 0",
                [id],
                row_to_result,
            )
            .optional()
            .context("lookup result by id")
    }

    pub fn note_hit(&self, result_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE results SET hit_count = hit_count + 1, last_used_ms = ?2 WHERE id = ?1",
            params![result_id, now_ms()],
        )?;
        Ok(())
    }

    /// Returns true only when the exact result was already delivered in full to
    /// this Codex session, turn and root/subagent context.
    pub fn was_delivered(
        &self,
        session_id: &str,
        context_id: &str,
        result_id: &str,
    ) -> Result<bool> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE session_id = ?1 AND context_id = ?2 AND result_id = ?3)",
            params![session_id, context_id, result_id],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    pub fn mark_delivered(
        &self,
        session_id: &str,
        context_id: &str,
        result_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO deliveries (session_id, context_id, result_id, delivered_ms) VALUES (?1, ?2, ?3, ?4)",
            params![session_id, context_id, result_id, now_ms()],
        )?;
        Ok(())
    }

    /// Invalidate full-output visibility evidence for the exact active Codex
    /// turn and root/subagent context. Both compaction events call this
    /// idempotently. Turn scoping also prevents stale evidence from surviving a
    /// workspace change where another repository-local store received compact.
    pub fn clear_deliveries_for_context(&self, session_id: &str, context_id: &str) -> Result<u64> {
        let removed = self.conn.execute(
            "DELETE FROM deliveries WHERE session_id = ?1 AND context_id = ?2",
            params![session_id, context_id],
        )?;
        Ok(removed as u64)
    }

    /// Validate every durable authority edge before a ready row can be
    /// classified as a hit. A process crash leaves rows behind but cannot leave
    /// an in-memory capability, so reopen reconstructs authority from the exact
    /// completed lease generation and the bounded CAS bytes. A result id or a
    /// syntactically valid row is deliberately insufficient.
    fn gateway_result_is_servable_v1(
        &self,
        transaction: &Transaction<'_>,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
    ) -> Result<bool> {
        let result = match self.load_gateway_result_with_origin_v1(
            transaction,
            binding,
            gateway_result_id,
        ) {
            Ok(Some(result)) => result,
            Ok(None) | Err(_) => return Ok(false),
        };
        Ok(source_result_blobs_valid_v1(self, &result))
    }

    fn load_gateway_result_with_origin_v1(
        &self,
        transaction: &Transaction<'_>,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
    ) -> Result<Option<StoredResult>> {
        let Some(result) =
            load_gateway_result_snapshot_v1(transaction, binding, gateway_result_id)?
        else {
            return Ok(None);
        };
        let dependencies = load_result_dependencies_v1(transaction, gateway_result_id)?;
        if dependencies != binding.input.dependencies {
            return Ok(None);
        }
        let (lease_id, origin) = transaction
            .query_row(
                "SELECT lease_id, origin FROM gateway_results WHERE gateway_result_id = ?1 AND status = 'ready'",
                [gateway_result_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            ?;
        if origin == "direct_observation" {
            return Ok((lease_id == "direct_observation").then_some(result));
        }
        if origin != "leased" {
            return Ok(None);
        }
        let Some(lease) = gateway_lease_row_v1(transaction, &lease_id)? else {
            return Ok(None);
        };
        let current_generation = transaction.query_row(
            "SELECT MAX(lifecycle_generation) FROM inflight_leases WHERE binding_digest = ?1",
            [binding.binding_digest()],
            |row| row.get::<_, Option<u64>>(0),
        )?;
        let valid_completion = lease.status == "completed"
            && lease.gateway_result_id.as_deref() == Some(gateway_result_id)
            && lease.request_digest == binding.input.request_digest
            && lease.state_digest == binding.input.state_digest
            && lease.policy_digest == binding.input.policy_digest
            && lease.binding_digest == binding.binding_digest
            && current_generation == Some(lease.lifecycle_generation)
            && matches!(
                (lease.execution_started_ms, lease.completed_ms),
                (Some(started), Some(completed)) if started >= 0 && completed >= started
            );
        Ok(valid_completion.then_some(result))
    }

    pub fn acquire_gateway_call(
        &self,
        binding: &ValidatedGatewayReadV1,
        owner: &str,
    ) -> Result<GatewayCallAcquisition> {
        validate_gateway_owner(owner)?;
        let now = now_ms();
        if !freshness_is_current(binding, now) {
            return Ok(GatewayCallAcquisition::Refused {
                reason: GatewayRefusalReason::FreshnessExpired,
            });
        }
        let call_id = format!("gc_{}", Uuid::new_v4().simple());
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        expire_gateway_leases_v1_tx(&transaction, now, Some(binding.binding_digest()))?;

        let ready = transaction
            .query_row(
                "SELECT gateway_result_id FROM gateway_results WHERE binding_digest = ?1 AND status = 'ready' AND origin = 'leased'",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(gateway_result_id) = ready {
            if self.gateway_result_is_servable_v1(&transaction, binding, &gateway_result_id)? {
                insert_gateway_request_v1(
                    &transaction,
                    &call_id,
                    binding,
                    owner,
                    "ready",
                    "ready",
                    None,
                    Some(&gateway_result_id),
                    None,
                    now,
                )?;
                record_gateway_event_v1_tx(
                    &transaction,
                    Some(&call_id),
                    None,
                    Some(&gateway_result_id),
                    "requested",
                    None,
                    0,
                    now,
                )?;
                record_gateway_event_v1_tx(
                    &transaction,
                    Some(&call_id),
                    None,
                    Some(&gateway_result_id),
                    "exact_candidate",
                    None,
                    0,
                    now,
                )?;
                transaction.commit()?;
                return Ok(GatewayCallAcquisition::Ready {
                    call_id,
                    gateway_result_id,
                });
            }
            quarantine_invalid_gateway_result_v1_tx(
                &transaction,
                Some(&call_id),
                &gateway_result_id,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCallAcquisition::Refused {
                reason: GatewayRefusalReason::Quarantined,
            });
        }

        let quarantined: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results WHERE binding_digest = ?1 AND status = 'quarantined')",
            [binding.binding_digest()],
            |row| row.get(0),
        )?;
        if quarantined {
            transaction.commit()?;
            return Ok(GatewayCallAcquisition::Refused {
                reason: GatewayRefusalReason::Quarantined,
            });
        }

        let active = transaction
            .query_row(
                "SELECT lease_id, call_id, owner, expires_ms FROM inflight_leases WHERE binding_digest = ?1 AND status = 'active'",
                [binding.binding_digest()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((lease_id, leader_call_id, leader, expires_at_ms)) = active {
            insert_gateway_request_v1(
                &transaction,
                &call_id,
                binding,
                owner,
                "follower",
                "waiting",
                Some(&lease_id),
                None,
                None,
                now,
            )?;
            record_gateway_event_v1_tx(
                &transaction,
                Some(&call_id),
                Some(&lease_id),
                None,
                "requested",
                None,
                0,
                now,
            )?;
            record_gateway_event_v1_tx(
                &transaction,
                Some(&call_id),
                Some(&lease_id),
                None,
                "inflight_candidate",
                None,
                0,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCallAcquisition::Follower {
                call_id,
                lease_id,
                leader_call_id,
                leader,
                expires_at_ms,
            });
        }

        let lease_id = format!("gl_{}", Uuid::new_v4().simple());
        let prior_generation = transaction.query_row(
            "SELECT COALESCE(MAX(lifecycle_generation), 0) FROM inflight_leases WHERE binding_digest = ?1",
            [binding.binding_digest()],
            |row| row.get::<_, i64>(0),
        )?;
        let lifecycle_generation = prior_generation
            .checked_add(1)
            .filter(|generation| *generation > 0)
            .ok_or_else(|| anyhow!("gateway lease lifecycle generation exhausted"))?;
        let expires_at_ms = now
            .saturating_add(GATEWAY_LEASE_TTL_MS)
            .min(binding.input.freshness.valid_until_ms);
        insert_gateway_request_v1(
            &transaction,
            &call_id,
            binding,
            owner,
            "leader",
            "inflight",
            Some(&lease_id),
            None,
            None,
            now,
        )?;
        transaction.execute(
            "INSERT INTO inflight_leases (lease_id, call_id, request_digest, state_digest, policy_digest, binding_digest, freshness_valid_until_ms, owner, status, acquired_ms, heartbeat_ms, expires_ms, lifecycle_generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?9, ?10, ?11)",
            params![
                lease_id,
                call_id,
                binding.request_digest(),
                binding.state_digest(),
                binding.policy_digest(),
                binding.binding_digest(),
                binding.input.freshness.valid_until_ms,
                owner,
                now,
                expires_at_ms,
                lifecycle_generation
            ],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(&call_id),
            Some(&lease_id),
            None,
            "requested",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayCallAcquisition::Leader {
            call_id,
            lease_id,
            expires_at_ms,
        })
    }

    pub fn start_gateway_execution(
        &self,
        lease_id: &str,
        owner: &str,
    ) -> Result<GatewayExecutionStart> {
        validate_gateway_owner(owner)?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        if lease.owner != owner {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::OwnerMismatch,
            });
        }
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        if lease.execution_started_ms.is_some() {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::AlreadyStarted);
        }
        let changed = transaction.execute(
            "UPDATE inflight_leases SET execution_started_ms = ?2 WHERE lease_id = ?1 AND status = 'active' AND execution_started_ms IS NULL",
            params![lease_id, now],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::LeaseNotCurrent,
            });
        }
        record_gateway_event_v1_tx(
            &transaction,
            Some(&lease.call_id),
            Some(lease_id),
            None,
            "executed",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayExecutionStart::Started)
    }

    pub fn heartbeat_gateway_call(&self, lease_id: &str, owner: &str) -> Result<GatewayHeartbeat> {
        validate_gateway_owner(owner)?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        if lease.owner != owner {
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::OwnerMismatch,
            });
        }
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        let expires_at_ms = now
            .saturating_add(GATEWAY_LEASE_TTL_MS)
            .min(lease.freshness_valid_until_ms);
        let changed = transaction.execute(
            "UPDATE inflight_leases SET heartbeat_ms = ?3, expires_ms = ?4 WHERE lease_id = ?1 AND owner = ?2 AND status = 'active' AND expires_ms > ?3",
            params![lease_id, owner, now, expires_at_ms],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::LeaseNotCurrent,
            });
        }
        transaction.commit()?;
        Ok(GatewayHeartbeat::Extended { expires_at_ms })
    }

    pub fn observe_gateway_call(
        &self,
        binding: &ValidatedGatewayReadV1,
    ) -> Result<GatewayCallObservation> {
        let now = now_ms();
        if !freshness_is_current(binding, now) {
            return Ok(GatewayCallObservation::Failed {
                reason: GatewayFailureReason::Deadline,
            });
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        expire_gateway_leases_v1_tx(&transaction, now, Some(binding.binding_digest()))?;
        let quarantined = transaction
            .query_row(
                "SELECT COALESCE(quarantine_reason, 'binding_mismatch') FROM gateway_results WHERE binding_digest = ?1 AND status = 'quarantined' ORDER BY updated_ms DESC LIMIT 1",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(reason) = quarantined {
            transaction.commit()?;
            return Ok(GatewayCallObservation::Quarantined { reason });
        }
        let ready = transaction
            .query_row(
                "SELECT gateway_result_id FROM gateway_results WHERE binding_digest = ?1 AND status = 'ready' AND origin = 'leased'",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(gateway_result_id) = ready {
            if !self.gateway_result_is_servable_v1(&transaction, binding, &gateway_result_id)? {
                quarantine_invalid_gateway_result_v1_tx(
                    &transaction,
                    None,
                    &gateway_result_id,
                    now,
                )?;
                transaction.commit()?;
                return Ok(GatewayCallObservation::Quarantined {
                    reason: GatewayRefusalReason::ResultCorrupt.as_str().to_owned(),
                });
            }
            transaction.commit()?;
            return Ok(GatewayCallObservation::Ready { gateway_result_id });
        }
        let inflight = transaction
            .query_row(
                "SELECT call_id, owner, expires_ms, (SELECT COUNT(*) FROM gateway_requests WHERE joined_lease_id = inflight_leases.lease_id AND role = 'follower' AND status = 'waiting') FROM inflight_leases WHERE binding_digest = ?1 AND status = 'active'",
                [binding.binding_digest()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((leader_call_id, leader, expires_at_ms, followers)) = inflight {
            transaction.commit()?;
            return Ok(GatewayCallObservation::Inflight {
                leader_call_id,
                leader,
                expires_at_ms,
                followers,
            });
        }
        let failure = transaction
            .query_row(
                "SELECT reason FROM gateway_requests WHERE binding_digest = ?1 AND status = 'failed' ORDER BY updated_ms DESC LIMIT 1",
                [binding.binding_digest()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        transaction.commit()?;
        Ok(
            match failure.and_then(|reason| GatewayFailureReason::from_str(&reason)) {
                Some(reason) => GatewayCallObservation::Failed { reason },
                None => GatewayCallObservation::Missing,
            },
        )
    }

    /// Make this exact recipient generation current for ledger reads and
    /// leases. Lower lifecycle/compaction generations can never reactivate.
    /// Resolve caller task aliases onto one durable exact-prompt identity.
    /// Prompt equality can converge work; prompt similarity never does.
    pub fn resolve_context_task_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        requested_task_id: &str,
        supplied_prompt: Option<&str>,
    ) -> Result<ContextTaskResolutionV1> {
        validate_context_task_selector_v1(repository_id)?;
        validate_context_task_selector_v1(workspace_id)?;
        validate_context_task_selector_v1(requested_task_id)?;
        validate_digest(
            authorization_scope_digest,
            "context task authorization scope",
        )?;
        let prompt = supplied_prompt.unwrap_or(requested_task_id);
        reasoning_item_v1(crate::agent_gateway::context::validate_reasoning_text_v1(
            prompt, 8192,
        ))?;
        screen_sensitive_text_v1(prompt)?;
        let prompt_digest = context_task_prompt_digest_v1(prompt);
        let definition_digest = task_definition_digest_v1(prompt, &[], None, &[], None);
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let existing_alias = transaction
            .query_row(
                "SELECT alias.canonical_task_id, task.prompt_digest, task.prompt_text,
                        task.definition_digest
                 FROM context_task_aliases_v1 AS alias
                 JOIN context_tasks_v1 AS task
                   ON task.repository_id = alias.repository_id
                  AND task.workspace_id = alias.workspace_id
                  AND task.authorization_scope_digest = alias.authorization_scope_digest
                  AND task.canonical_task_id = alias.canonical_task_id
                 WHERE alias.repository_id = ?1 AND alias.workspace_id = ?2
                   AND alias.authorization_scope_digest = ?3 AND alias.requested_task_id = ?4",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    requested_task_id
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((canonical_task_id, stored_digest, stored_prompt, stored_definition_digest)) =
            existing_alias
        {
            if context_task_prompt_digest_v1(&stored_prompt) != stored_digest {
                bail!("context_task_corrupt");
            }
            if supplied_prompt.is_some()
                && (stored_digest != prompt_digest
                    || stored_definition_digest.as_deref() != Some(&definition_digest))
            {
                bail!("task_definition_conflict");
            }
            transaction.execute(
                "UPDATE context_tasks_v1 SET updated_ms = ?5
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    canonical_task_id,
                    now
                ],
            )?;
            transaction.commit()?;
            return Ok(ContextTaskResolutionV1 {
                canonical_task_id,
                requested_task_id: requested_task_id.to_owned(),
                prompt: stored_prompt,
                prompt_digest: stored_digest,
                matched_by: ContextTaskMatchV1::JoinedByTaskId,
            });
        }

        let prompt_match = transaction
            .query_row(
                "SELECT canonical_task_id, prompt_text FROM context_tasks_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND definition_digest = ?4",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    definition_digest
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((canonical_task_id, stored_prompt)) = prompt_match {
            if context_task_prompt_digest_v1(&stored_prompt) != prompt_digest {
                bail!("context_task_corrupt");
            }
            let alias_count: u64 = transaction.query_row(
                "SELECT COUNT(*) FROM context_task_aliases_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2",
                params![repository_id, workspace_id],
                |row| row.get(0),
            )?;
            if alias_count >= MAX_CONTEXT_TASK_ALIASES_PER_WORKSPACE_V1 {
                bail!("context_task_alias_capacity_exceeded");
            }
            reserve_task_context_bytes_v1(
                &transaction,
                repository_id,
                workspace_id,
                task_alias_logical_bytes_v1(requested_task_id, &canonical_task_id),
            )?;
            transaction.execute(
                "INSERT INTO context_task_aliases_v1 (
                    repository_id, workspace_id, authorization_scope_digest,
                    requested_task_id, canonical_task_id, created_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    requested_task_id,
                    canonical_task_id,
                    now
                ],
            )?;
            transaction.execute(
                "UPDATE context_tasks_v1 SET updated_ms = ?5
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    canonical_task_id,
                    now
                ],
            )?;
            transaction.commit()?;
            return Ok(ContextTaskResolutionV1 {
                canonical_task_id,
                requested_task_id: requested_task_id.to_owned(),
                prompt: stored_prompt,
                prompt_digest,
                matched_by: ContextTaskMatchV1::JoinedByPrompt,
            });
        }

        let count: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM context_tasks_v1
             WHERE repository_id = ?1 AND workspace_id = ?2",
            params![repository_id, workspace_id],
            |row| row.get(0),
        )?;
        if count >= MAX_CONTEXT_TASKS_PER_WORKSPACE_V1 {
            bail!("context_task_capacity_exceeded");
        }
        let alias_count: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM context_task_aliases_v1
             WHERE repository_id = ?1 AND workspace_id = ?2",
            params![repository_id, workspace_id],
            |row| row.get(0),
        )?;
        if alias_count >= MAX_CONTEXT_TASK_ALIASES_PER_WORKSPACE_V1 {
            bail!("context_task_alias_capacity_exceeded");
        }
        let acceptance_json = "[]";
        let initial_bytes = task_row_logical_bytes_v1(requested_task_id, prompt, acceptance_json)
            .saturating_add(task_alias_logical_bytes_v1(
                requested_task_id,
                requested_task_id,
            ))
            .saturating_add(task_transition_logical_bytes_v1(
                requested_task_id,
                "task_started",
                None,
            ));
        reserve_task_context_bytes_v1(&transaction, repository_id, workspace_id, initial_bytes)?;
        transaction.execute(
            "INSERT INTO context_tasks_v1 (
                repository_id, workspace_id, authorization_scope_digest,
                canonical_task_id, prompt_digest, prompt_text, created_ms, updated_ms,
                definition_digest, acceptance_criteria_json, revision, state, state_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, '[]', 1, 'active', 1)",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                requested_task_id,
                prompt_digest,
                prompt,
                now,
                definition_digest
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_task_aliases_v1 (
                repository_id, workspace_id, authorization_scope_digest,
                requested_task_id, canonical_task_id, created_ms
             ) VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                requested_task_id,
                now
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_task_transitions_v1 (
                repository_id, workspace_id, authorization_scope_digest,
                canonical_task_id, from_state, to_state, state_generation,
                reason, created_ms
             ) VALUES (?1, ?2, ?3, ?4, NULL, 'active', 1, 'task_started', ?5)",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                requested_task_id,
                now
            ],
        )?;
        transaction.commit()?;
        Ok(ContextTaskResolutionV1 {
            canonical_task_id: requested_task_id.to_owned(),
            requested_task_id: requested_task_id.to_owned(),
            prompt: prompt.to_owned(),
            prompt_digest,
            matched_by: ContextTaskMatchV1::Created,
        })
    }

    pub fn context_task_by_alias_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        requested_task_id: &str,
    ) -> Result<Option<ContextTaskResolutionV1>> {
        validate_context_task_selector_v1(repository_id)?;
        validate_context_task_selector_v1(workspace_id)?;
        validate_context_task_selector_v1(requested_task_id)?;
        validate_digest(
            authorization_scope_digest,
            "context task authorization scope",
        )?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let Some(canonical_task_id) = resolve_task_alias_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
        )?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let task = load_task_record_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            &canonical_task_id,
            requested_task_id,
        )?;
        let prompt_digest = context_task_prompt_digest_v1(task.definition.prompt());
        let prompt = task.definition.prompt().to_owned();
        transaction.commit()?;
        Ok(Some(ContextTaskResolutionV1 {
            canonical_task_id,
            requested_task_id: requested_task_id.to_owned(),
            prompt,
            prompt_digest,
            matched_by: ContextTaskMatchV1::JoinedByTaskId,
        }))
    }

    /// Start or converge one immutable task definition in the authenticated scope.
    pub fn start_task_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        requested_task_id: &str,
        supplied: &TaskDefinitionV1,
    ) -> Result<TaskStartOutcomeV1> {
        validate_task_selector_v1(repository_id)?;
        validate_task_selector_v1(workspace_id)?;
        validate_task_selector_v1(requested_task_id)?;
        validate_digest(
            authorization_scope_digest,
            "task authorization scope digest",
        )?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let resolve_relation = |selector: Option<&str>| -> Result<Option<String>> {
            selector
                .map(|selector| {
                    if selector == requested_task_id {
                        bail!("task_graph_self_edge");
                    }
                    resolve_task_alias_tx_v1(
                        &transaction,
                        repository_id,
                        workspace_id,
                        authorization_scope_digest,
                        selector,
                    )?
                    .ok_or_else(|| anyhow!("task_relation_unavailable"))
                })
                .transpose()
        };
        let parent = resolve_relation(supplied.parent_task_id())?;
        let supersedes = resolve_relation(supplied.supersedes_task_id())?;
        let mut dependencies = Vec::with_capacity(supplied.dependency_task_ids().len());
        for dependency in supplied.dependency_task_ids() {
            if dependency == requested_task_id {
                bail!("task_graph_self_edge");
            }
            dependencies.push(
                resolve_task_alias_tx_v1(
                    &transaction,
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    dependency,
                )?
                .ok_or_else(|| anyhow!("task_relation_unavailable"))?,
            );
        }
        dependencies.sort();
        if dependencies.windows(2).any(|pair| pair[0] == pair[1]) {
            bail!("duplicate_task_dependency");
        }
        let definition = TaskDefinitionV1::new(
            supplied.prompt(),
            supplied.acceptance_criteria().to_vec(),
            parent,
            dependencies,
            supersedes,
        )?;

        if let Some(canonical) = resolve_task_alias_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
        )? {
            let task = load_task_record_tx_v1(
                &transaction,
                repository_id,
                workspace_id,
                authorization_scope_digest,
                &canonical,
                requested_task_id,
            )?;
            if task.definition.definition_digest() != definition.definition_digest() {
                bail!("task_definition_conflict");
            }
            transaction.commit()?;
            return Ok(TaskStartOutcomeV1 {
                task,
                matched_by: ContextTaskMatchV1::JoinedByTaskId,
            });
        }

        let definition_match = transaction
            .query_row(
                "SELECT canonical_task_id FROM context_tasks_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND definition_digest = ?4",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    definition.definition_digest()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(canonical) = definition_match {
            enforce_task_alias_capacity_tx_v1(&transaction, repository_id, workspace_id)?;
            reserve_task_context_bytes_v1(
                &transaction,
                repository_id,
                workspace_id,
                task_alias_logical_bytes_v1(requested_task_id, &canonical),
            )?;
            transaction.execute(
                "INSERT INTO context_task_aliases_v1 (
                    repository_id, workspace_id, authorization_scope_digest,
                    requested_task_id, canonical_task_id, created_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    requested_task_id,
                    canonical,
                    now
                ],
            )?;
            let task = load_task_record_tx_v1(
                &transaction,
                repository_id,
                workspace_id,
                authorization_scope_digest,
                &canonical,
                requested_task_id,
            )?;
            transaction.commit()?;
            return Ok(TaskStartOutcomeV1 {
                task,
                matched_by: ContextTaskMatchV1::JoinedByPrompt,
            });
        }

        enforce_task_capacity_tx_v1(&transaction, repository_id, workspace_id)?;
        enforce_task_alias_capacity_tx_v1(&transaction, repository_id, workspace_id)?;
        for target in definition
            .parent_task_id()
            .into_iter()
            .chain(definition.dependency_task_ids().iter().map(String::as_str))
            .chain(definition.supersedes_task_id())
        {
            ensure_task_graph_edge_v1(
                &transaction,
                repository_id,
                workspace_id,
                authorization_scope_digest,
                requested_task_id,
                target,
            )?;
        }
        let blockers = dependency_blockers_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            definition.dependency_task_ids(),
        )?;
        let state = if blockers.is_empty() {
            TaskStateV1::Active
        } else {
            TaskStateV1::Waiting
        };
        let revision = match definition.supersedes_task_id() {
            Some(task_id) => transaction.query_row(
                "SELECT revision + 1 FROM context_tasks_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    task_id
                ],
                |row| row.get::<_, u64>(0),
            )?,
            None => 1,
        };
        let acceptance_json = serde_json::to_string(definition.acceptance_criteria())?;
        let relation_bytes = definition
            .parent_task_id()
            .into_iter()
            .chain(definition.dependency_task_ids().iter().map(String::as_str))
            .chain(definition.supersedes_task_id())
            .map(|target| task_relation_logical_bytes_v1(requested_task_id, target))
            .fold(0_u64, u64::saturating_add);
        let initial_reason = if state == TaskStateV1::Waiting {
            "task_started_waiting_for_dependencies"
        } else {
            "task_started"
        };
        let logical_bytes =
            task_row_logical_bytes_v1(requested_task_id, definition.prompt(), &acceptance_json)
                .saturating_add(task_alias_logical_bytes_v1(
                    requested_task_id,
                    requested_task_id,
                ))
                .saturating_add(relation_bytes)
                .saturating_add(task_transition_logical_bytes_v1(
                    requested_task_id,
                    initial_reason,
                    None,
                ));
        reserve_task_context_bytes_v1(&transaction, repository_id, workspace_id, logical_bytes)?;
        transaction.execute(
            "INSERT INTO context_tasks_v1 (
                repository_id, workspace_id, authorization_scope_digest,
                canonical_task_id, prompt_digest, prompt_text, created_ms, updated_ms,
                definition_digest, acceptance_criteria_json, revision, state, state_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, ?10, ?11, 1)",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                requested_task_id,
                context_task_prompt_digest_v1(definition.prompt()),
                definition.prompt(),
                now,
                definition.definition_digest(),
                acceptance_json,
                revision,
                state.code()
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_task_aliases_v1 (
                repository_id, workspace_id, authorization_scope_digest,
                requested_task_id, canonical_task_id, created_ms
             ) VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                requested_task_id,
                now
            ],
        )?;
        insert_task_relations_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
            &definition,
            now,
        )?;
        insert_task_transition_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
            None,
            state,
            1,
            None,
            None,
            initial_reason,
            now,
        )?;
        let task = load_task_record_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
            requested_task_id,
        )?;
        transaction.commit()?;
        Ok(TaskStartOutcomeV1 {
            task,
            matched_by: ContextTaskMatchV1::Created,
        })
    }

    pub fn inspect_task_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        requested_task_id: &str,
    ) -> Result<Option<TaskRecordV1>> {
        validate_task_selector_v1(requested_task_id)?;
        validate_digest(
            authorization_scope_digest,
            "task authorization scope digest",
        )?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let Some(canonical) = resolve_task_alias_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
        )?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let task = load_task_record_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            &canonical,
            requested_task_id,
        )?;
        transaction.commit()?;
        Ok(Some(task))
    }

    pub fn list_tasks_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        limit: usize,
    ) -> Result<Vec<TaskRecordV1>> {
        if !(1..=MAX_TASK_LIST_ITEMS_V1).contains(&limit) {
            bail!("invalid_task_list_limit");
        }
        validate_digest(
            authorization_scope_digest,
            "task authorization scope digest",
        )?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let task_ids = {
            let mut statement = transaction.prepare(
                "SELECT canonical_task_id FROM context_tasks_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3
                 ORDER BY created_ms DESC, canonical_task_id ASC LIMIT ?4",
            )?;
            statement
                .query_map(
                    params![
                        repository_id,
                        workspace_id,
                        authorization_scope_digest,
                        limit
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let tasks = task_ids
            .iter()
            .map(|task_id| {
                load_task_record_tx_v1(
                    &transaction,
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    task_id,
                    task_id,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        transaction.commit()?;
        Ok(tasks)
    }

    /// Return a bounded oldest-first batch that is safe for explicit human
    /// pruning. This is discovery only: deletion rechecks every invariant in
    /// the same immediate transaction used by `delete_task_v1`.
    pub fn list_deletable_terminal_tasks_before_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        terminal_before_ms: i64,
        limit: usize,
    ) -> Result<Vec<TaskRecordV1>> {
        if !(1..=MAX_TASK_LIST_ITEMS_V1).contains(&limit) {
            bail!("invalid_task_list_limit");
        }
        validate_digest(
            authorization_scope_digest,
            "task authorization scope digest",
        )?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let task_ids = {
            let mut statement = transaction.prepare(
                "SELECT task.canonical_task_id FROM context_tasks_v1 AS task
                 WHERE task.repository_id = ?1 AND task.workspace_id = ?2
                   AND task.authorization_scope_digest = ?3
                   AND task.state IN ('completed', 'failed', 'cancelled')
                   AND task.updated_ms < ?4
                   AND NOT EXISTS (
                       SELECT 1 FROM context_task_relations_v1 AS relation
                       WHERE relation.repository_id = task.repository_id
                         AND relation.workspace_id = task.workspace_id
                         AND relation.authorization_scope_digest = task.authorization_scope_digest
                         AND relation.target_task_id = task.canonical_task_id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM context_ledger_leases_v1 AS lease
                       WHERE lease.repository_id = task.repository_id
                         AND lease.workspace_id = task.workspace_id
                         AND lease.authorization_scope_digest = task.authorization_scope_digest
                         AND lease.task_id = task.canonical_task_id
                         AND lease.status = 'active'
                   )
                 ORDER BY task.updated_ms ASC, task.canonical_task_id ASC LIMIT ?5",
            )?;
            statement
                .query_map(
                    params![
                        repository_id,
                        workspace_id,
                        authorization_scope_digest,
                        terminal_before_ms,
                        limit
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let tasks = task_ids
            .iter()
            .map(|task_id| {
                load_task_record_tx_v1(
                    &transaction,
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    task_id,
                    task_id,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        transaction.commit()?;
        Ok(tasks)
    }

    /// Advisory lease observation for a preview-only launch. This grants no
    /// ownership; a later task claim must still perform its authenticated CAS.
    pub fn preview_task_leader_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
    ) -> Result<Option<(String, i64)>> {
        validate_context_identity_v1(identity)?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let leader = transaction
            .query_row(
                "SELECT leader_agent_id, expires_ms FROM context_ledger_leases_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
                   AND authorization_scope_digest = ?4 AND status = 'active'
                   AND expires_ms > ?5
                 LIMIT 1",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    identity.authorization_scope_digest(),
                    now_ms()
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        transaction.commit()?;
        Ok(leader)
    }

    pub fn claim_task_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        expected_state_generation: u64,
        ttl_ms: u64,
        deadline_ms: i64,
    ) -> Result<TaskClaimOutcomeV1> {
        validate_context_identity_v1(identity)?;
        let ttl_ms = i64::try_from(ttl_ms).context("task lease ttl overflow")?;
        if ttl_ms <= 0 || ttl_ms > CONTEXT_LEASE_TTL_MAX_MS_V1 {
            bail!("context lease ttl is outside the bounded interval");
        }
        let now = now_ms();
        if deadline_ms <= now {
            bail!(GatewayRefusalReason::LeaseExpired.as_str());
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        expire_context_leases_v1(&transaction, now)?;
        let mut task = load_task_record_tx_v1(
            &transaction,
            identity.repository_id(),
            identity.workspace_id(),
            identity.authorization_scope_digest(),
            identity.task_id(),
            identity.task_id(),
        )?;
        if task.state_generation != expected_state_generation {
            bail!("task_state_cas_mismatch");
        }
        if task.state.is_terminal() {
            transaction.commit()?;
            return Ok(TaskClaimOutcomeV1::Terminal {
                state: task.state,
                state_generation: task.state_generation,
            });
        }
        if task.state == TaskStateV1::Waiting && !task.blockers.is_empty() {
            transaction.commit()?;
            return Ok(TaskClaimOutcomeV1::Waiting {
                state_generation: task.state_generation,
                blockers: task.blockers,
            });
        }
        if matches!(task.state, TaskStateV1::Waiting | TaskStateV1::Blocked) {
            let previous = task.state;
            task.state_generation = task
                .state_generation
                .checked_add(1)
                .ok_or_else(|| anyhow!("task_state_generation_overflow"))?;
            task.state = TaskStateV1::Active;
            let changed = transaction.execute(
                "UPDATE context_tasks_v1 SET state = 'active', state_generation = ?6,
                        updated_ms = ?7
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND canonical_task_id = ?4
                   AND state_generation = ?5 AND state = ?8",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.authorization_scope_digest(),
                    identity.task_id(),
                    expected_state_generation,
                    task.state_generation,
                    now,
                    previous.code()
                ],
            )?;
            if changed != 1 {
                bail!("task_state_cas_mismatch");
            }
            let reason = if previous == TaskStateV1::Blocked {
                "task_reclaimed"
            } else {
                "dependencies_completed"
            };
            reserve_task_context_bytes_v1(
                &transaction,
                identity.repository_id(),
                identity.workspace_id(),
                task_transition_logical_bytes_v1(identity.task_id(), reason, None),
            )?;
            insert_task_transition_tx_v1(
                &transaction,
                identity.repository_id(),
                identity.workspace_id(),
                identity.authorization_scope_digest(),
                identity.task_id(),
                Some(previous),
                TaskStateV1::Active,
                task.state_generation,
                None,
                Some(identity),
                reason,
                now,
            )?;
        }
        let work_key_digest = task.definition.definition_digest();
        if let Some((lease_id, generation, leader_agent_id, expires_at_ms)) = transaction
            .query_row(
                "SELECT lease_id, generation, leader_agent_id, expires_ms
                 FROM context_ledger_leases_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
                   AND authorization_scope_digest = ?4 AND work_key_digest = ?5
                   AND status = 'active'",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    identity.authorization_scope_digest(),
                    work_key_digest
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
        {
            transaction.commit()?;
            return Ok(TaskClaimOutcomeV1::Join {
                lease_id,
                lease_generation: generation,
                state_generation: task.state_generation,
                leader_agent_id,
                expires_at_ms,
            });
        }
        let lease_generation = transaction.query_row(
            "SELECT COALESCE(MAX(generation), 0) + 1 FROM context_ledger_leases_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4 AND work_key_digest = ?5",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                work_key_digest
            ],
            |row| row.get::<_, u64>(0),
        )?;
        let expires_at_ms = deadline_ms.min(now.saturating_add(ttl_ms));
        let lease_id = format!("cl_{}", Uuid::new_v4().simple());
        let summary = task_lease_summary_v1(task.definition.prompt());
        transaction.execute(
            "INSERT INTO context_ledger_leases_v1 (
                lease_id, repository_id, workspace_id, task_id, authorization_scope_digest,
                work_key_digest, generation, leader_agent_id, leader_session_id,
                leader_lifecycle_generation, summary, status, acquired_ms, heartbeat_ms,
                deadline_ms, expires_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       'active', ?12, ?12, ?13, ?14)",
            params![
                lease_id,
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                work_key_digest,
                lease_generation,
                identity.agent_id(),
                identity.session_id(),
                identity.lifecycle_generation(),
                summary,
                now,
                deadline_ms,
                expires_at_ms
            ],
        )?;
        let envelope_digest = blake3::hash(format!("context-lease:{lease_id}").as_bytes())
            .to_hex()
            .to_string();
        let fields = ContextEventFieldsV1 {
            kind: ContextLedgerEventKindV1::InflightWork,
            subject_id: &lease_id,
            subject_version: lease_generation,
            summary: &summary,
            value_digest: Some(work_key_digest),
            result_id: None,
            result_digest: None,
            total_bytes: None,
            duration_ms: None,
        };
        let canonical_digest =
            context_event_canonical_digest_v1(identity, &fields, work_key_digest.as_bytes(), &[]);
        insert_context_event_v1(
            &transaction,
            identity,
            &envelope_digest,
            &canonical_digest,
            &fields,
            now,
        )?;
        transaction.commit()?;
        Ok(TaskClaimOutcomeV1::Leader {
            lease_id,
            lease_generation,
            state_generation: task.state_generation,
            expires_at_ms,
        })
    }

    pub fn transition_task_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        lease_id: &str,
        expected_state_generation: u64,
        target: TaskStateV1,
        reason: &str,
    ) -> Result<TaskRecordV1> {
        validate_context_identity_v1(identity)?;
        crate::agent_gateway::context::validate_reasoning_text_v1(reason, 512)
            .map_err(|refusal| anyhow!(refusal.code()))?;
        screen_sensitive_text_v1(reason)?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        expire_context_leases_v1(&transaction, now)?;
        let task = load_task_record_tx_v1(
            &transaction,
            identity.repository_id(),
            identity.workspace_id(),
            identity.authorization_scope_digest(),
            identity.task_id(),
            identity.task_id(),
        )?;
        if task.state_generation != expected_state_generation {
            bail!("task_state_cas_mismatch");
        }
        if task.state.is_terminal() {
            bail!("task_terminal_immutable");
        }
        if task.state != TaskStateV1::Active
            || !matches!(
                target,
                TaskStateV1::Blocked
                    | TaskStateV1::Completed
                    | TaskStateV1::Failed
                    | TaskStateV1::Cancelled
            )
        {
            bail!("invalid_task_transition");
        }
        context_owned_lease_deadline_v1(&transaction, identity, lease_id)?;
        let next_generation = expected_state_generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("task_state_generation_overflow"))?;
        let changed = transaction.execute(
            "UPDATE context_tasks_v1 SET state = ?6, state_generation = ?7, updated_ms = ?8
             WHERE repository_id = ?1 AND workspace_id = ?2
               AND authorization_scope_digest = ?3 AND canonical_task_id = ?4
               AND state = 'active' AND state_generation = ?5",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.authorization_scope_digest(),
                identity.task_id(),
                expected_state_generation,
                target.code(),
                next_generation,
                now
            ],
        )?;
        if changed != 1 {
            bail!("task_state_cas_mismatch");
        }
        reserve_task_context_bytes_v1(
            &transaction,
            identity.repository_id(),
            identity.workspace_id(),
            task_transition_logical_bytes_v1(identity.task_id(), reason, Some(lease_id)),
        )?;
        insert_task_transition_tx_v1(
            &transaction,
            identity.repository_id(),
            identity.workspace_id(),
            identity.authorization_scope_digest(),
            identity.task_id(),
            Some(TaskStateV1::Active),
            target,
            next_generation,
            Some(lease_id),
            Some(identity),
            reason,
            now,
        )?;
        let lease_status = match target {
            TaskStateV1::Completed => "completed",
            TaskStateV1::Failed => "failed",
            TaskStateV1::Blocked | TaskStateV1::Cancelled => "cancelled",
            TaskStateV1::Waiting | TaskStateV1::Active => unreachable!(),
        };
        transaction.execute(
            "UPDATE context_ledger_leases_v1 SET status = ?2, completed_ms = ?3
             WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, lease_status, now],
        )?;
        if target.is_terminal() {
            transaction.execute(
                "UPDATE context_ledger_leases_v1 SET status = 'cancelled', completed_ms = ?5
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
                   AND authorization_scope_digest = ?4 AND status = 'active'",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    identity.authorization_scope_digest(),
                    now
                ],
            )?;
        }
        let updated = load_task_record_tx_v1(
            &transaction,
            identity.repository_id(),
            identity.workspace_id(),
            identity.authorization_scope_digest(),
            identity.task_id(),
            identity.task_id(),
        )?;
        transaction.commit()?;
        Ok(updated)
    }

    pub fn export_task_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        requested_task_id: &str,
    ) -> Result<Option<TaskExportV1>> {
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let Some(canonical) = resolve_task_alias_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
        )?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let task = load_task_record_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            &canonical,
            requested_task_id,
        )?;
        let aliases = {
            let mut statement = transaction.prepare(
                "SELECT requested_task_id FROM context_task_aliases_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND canonical_task_id = ?4
                 ORDER BY requested_task_id",
            )?;
            statement
                .query_map(
                    params![
                        repository_id,
                        workspace_id,
                        authorization_scope_digest,
                        canonical
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let transitions = load_task_transitions_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            &canonical,
        )?;
        transaction.commit()?;
        Ok(Some(TaskExportV1 {
            task,
            aliases,
            transitions,
        }))
    }

    /// Explicitly delete one terminal, unreferenced task and its bounded local
    /// context. Result blobs remain subject to the existing unreferenced CAS GC.
    pub fn delete_task_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
        requested_task_id: &str,
    ) -> Result<bool> {
        validate_task_selector_v1(requested_task_id)?;
        validate_digest(
            authorization_scope_digest,
            "task authorization scope digest",
        )?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(canonical) = resolve_task_alias_tx_v1(
            &transaction,
            repository_id,
            workspace_id,
            authorization_scope_digest,
            requested_task_id,
        )?
        else {
            transaction.commit()?;
            return Ok(false);
        };
        let state = transaction.query_row(
            "SELECT state FROM context_tasks_v1
             WHERE repository_id = ?1 AND workspace_id = ?2
               AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                canonical
            ],
            |row| row.get::<_, String>(0),
        )?;
        if !TaskStateV1::parse(&state)?.is_terminal() {
            bail!("task_delete_requires_terminal");
        }
        let referenced: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM context_task_relations_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND target_task_id = ?4
             )",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                canonical
            ],
            |row| row.get(0),
        )?;
        if referenced {
            bail!("task_delete_referenced");
        }
        let active_lease: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM context_ledger_leases_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
                   AND authorization_scope_digest = ?4 AND status = 'active'
             )",
            params![
                repository_id,
                workspace_id,
                canonical,
                authorization_scope_digest
            ],
            |row| row.get(0),
        )?;
        if active_lease {
            bail!("task_delete_active_lease");
        }
        transaction.execute(
            "DELETE FROM context_ledger_delivery_savings_v1
             WHERE receipt_digest IN (
                 SELECT receipt_digest FROM context_ledger_delivery_receipts_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
             )",
            params![repository_id, workspace_id, canonical],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_delivery_receipts_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3",
            params![repository_id, workspace_id, canonical],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_fact_versions_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3",
            params![repository_id, workspace_id, canonical],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_result_references_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3",
            params![repository_id, workspace_id, canonical],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_event_dependencies_v1
             WHERE event_sequence IN (
                 SELECT sequence FROM context_ledger_events_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
             )",
            params![repository_id, workspace_id, canonical],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_event_sources_v1
             WHERE event_sequence IN (
                 SELECT sequence FROM context_ledger_events_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
             )",
            params![repository_id, workspace_id, canonical],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_events_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3",
            params![repository_id, workspace_id, canonical],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_recipients_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4",
            params![
                repository_id,
                workspace_id,
                canonical,
                authorization_scope_digest
            ],
        )?;
        transaction.execute(
            "DELETE FROM context_ledger_leases_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4",
            params![
                repository_id,
                workspace_id,
                canonical,
                authorization_scope_digest
            ],
        )?;
        transaction.execute(
            "DELETE FROM context_task_aliases_v1
             WHERE repository_id = ?1 AND workspace_id = ?2
               AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                canonical
            ],
        )?;
        let changed = transaction.execute(
            "DELETE FROM context_tasks_v1
             WHERE repository_id = ?1 AND workspace_id = ?2
               AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                canonical
            ],
        )?;
        if changed != 1 {
            bail!("context_task_corrupt");
        }
        reconcile_task_quota_scope_v1_tx(&transaction, repository_id, workspace_id, now)?;
        transaction.commit()?;
        Ok(true)
    }

    pub fn task_quota_status_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
    ) -> Result<TaskQuotaStatusV1> {
        let row = self
            .conn
            .query_row(
                "SELECT task_context_bytes, workspace_state_bytes, maintenance_mode,
                        counter_checksum
                 FROM context_workspace_quota_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2",
                params![repository_id, workspace_id],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let (task_context_bytes, workspace_state_bytes, maintenance_mode) =
            if let Some((task_bytes, workspace_bytes, maintenance, checksum)) = row {
                if checksum
                    != task_quota_checksum_v1(
                        repository_id,
                        workspace_id,
                        task_bytes,
                        workspace_bytes,
                        maintenance,
                    )
                {
                    bail!("task_quota_counter_corrupt");
                }
                (task_bytes, workspace_bytes, maintenance)
            } else {
                (0, 0, false)
            };
        Ok(TaskQuotaStatusV1 {
            task_context_bytes,
            task_context_limit_bytes: MAX_TASK_CONTEXT_LOGICAL_BYTES_V1,
            workspace_state_bytes,
            workspace_state_limit_bytes: MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1,
            maintenance_mode,
        })
    }

    pub fn activate_context_recipient_v1(&self, identity: &ContextLedgerIdentityV1) -> Result<()> {
        validate_context_identity_v1(identity)?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let existing = context_recipient_row_v1(&transaction, identity)?;
        if let Some(existing) = existing {
            if (!existing.active
                && existing.lifecycle_generation >= identity.lifecycle_generation())
                || existing.lifecycle_generation > identity.lifecycle_generation()
                || (existing.lifecycle_generation == identity.lifecycle_generation()
                    && existing.compaction_generation > identity.compaction_generation())
                || (existing.lifecycle_generation == identity.lifecycle_generation()
                    && existing.compaction_generation == identity.compaction_generation()
                    && (existing.connection_generation != identity.connection_generation()
                        || existing.turn_id != identity.turn_id()))
            {
                bail!(GatewayRefusalReason::InvalidAgentContext.as_str());
            }
        }
        transaction.execute(
            "INSERT INTO context_ledger_recipients_v1 (
                repository_id, workspace_id, task_id, authorization_scope_digest,
                agent_id, session_id, turn_id, connection_generation,
                compaction_generation, lifecycle_generation, active, updated_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11)
             ON CONFLICT(repository_id, workspace_id, task_id, authorization_scope_digest, agent_id, session_id)
             DO UPDATE SET turn_id = excluded.turn_id,
                 connection_generation = excluded.connection_generation,
                 compaction_generation = excluded.compaction_generation,
                 lifecycle_generation = excluded.lifecycle_generation,
                 active = 1, updated_ms = excluded.updated_ms",
            params![
                identity.repository_id(), identity.workspace_id(), identity.task_id(),
                identity.authorization_scope_digest(), identity.agent_id(), identity.session_id(),
                identity.turn_id(), identity.connection_generation(), identity.compaction_generation(),
                identity.lifecycle_generation(), now,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn retire_context_recipient_v1(&self, identity: &ContextLedgerIdentityV1) -> Result<bool> {
        validate_context_identity_v1(identity)?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE context_ledger_recipients_v1 SET active = 0, updated_ms = ?11
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4 AND agent_id = ?5 AND session_id = ?6
               AND turn_id = ?7 AND connection_generation = ?8
               AND compaction_generation = ?9 AND lifecycle_generation = ?10 AND active = 1",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                identity.agent_id(),
                identity.session_id(),
                identity.turn_id(),
                identity.connection_generation(),
                identity.compaction_generation(),
                identity.lifecycle_generation(),
                now,
            ],
        )?;
        transaction.execute(
            "UPDATE context_ledger_leases_v1 SET status = 'cancelled', completed_ms = ?7
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4 AND leader_agent_id = ?5
               AND leader_session_id = ?6 AND leader_lifecycle_generation = ?8
               AND status = 'active'",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                identity.agent_id(),
                identity.session_id(),
                now,
                identity.lifecycle_generation(),
            ],
        )?;
        transaction.commit()?;
        Ok(changed == 1)
    }

    /// Adapt one exact ready gateway result into source evidence. Admission
    /// rechecks every row, dependency and freshness interval later.
    pub fn context_verified_observation_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
        locator: &str,
    ) -> Result<ContextVerifiedObservationV1> {
        validate_context_identity_v1(identity)?;
        if !freshness_is_current(binding, now_ms()) {
            bail!(GatewayRefusalReason::FreshnessExpired.as_str());
        }
        let result = self
            .get_gateway_result(binding, gateway_result_id)?
            .ok_or_else(|| anyhow!(GatewayRefusalReason::ResultNotFound.as_str()))?;
        let source = reasoning_item_v1(ReasoningSourceReferenceV1::new(
            gateway_result_id,
            gateway_result_id,
            identity.repository_id(),
            identity.workspace_id(),
            binding.state_digest(),
            binding.dependency_digest().as_str(),
            identity.authorization_scope_digest(),
            locator,
        ))?;
        Ok(ContextVerifiedObservationV1 {
            source,
            binding_digest: binding.binding_digest().to_owned(),
            dependencies: result.dependencies,
            freshness_valid_until_ms: binding.input.freshness.valid_until_ms,
            total_bytes: result
                .result
                .stdout_bytes
                .checked_add(result.result.stderr_bytes)
                .ok_or_else(|| anyhow!("context source byte count overflow"))?,
        })
    }

    /// Retain the exact bounded repository observation plan that authorized a
    /// source-backed result. It is private metadata, never model supplied.
    pub fn admit_context_source_recipe_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
        repository_digest: &str,
        plan_json: &[u8],
    ) -> Result<()> {
        validate_digest(gateway_result_id, "context source recipe result")?;
        validate_digest(repository_digest, "context source repository digest")?;
        if plan_json.is_empty() || plan_json.len() > MAX_CONTEXT_SOURCE_PLAN_BYTES_V1 {
            bail!("context source observation plan exceeds its bound");
        }
        let _: serde_json::Value = serde_json::from_slice(plan_json)
            .context("context source observation plan is not JSON")?;
        let plan_text = std::str::from_utf8(plan_json)?;
        let plan_digest = blake3::hash(plan_json).to_hex().to_string();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let ready: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results
                           WHERE gateway_result_id = ?1 AND binding_digest = ?2
                             AND status = 'ready' AND quarantine_reason IS NULL)",
            params![gateway_result_id, binding.binding_digest()],
            |row| row.get(0),
        )?;
        if !ready {
            bail!(GatewayRefusalReason::ResultNotFound.as_str());
        }
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_context_source_recipes_v1 WHERE result_id = ?1)",
            [gateway_result_id],
            |row| row.get(0),
        )?;
        if !exists {
            reserve_task_context_bytes_v1(
                &transaction,
                identity.repository_id(),
                identity.workspace_id(),
                0,
            )?;
            let additional = (plan_json.len() as u64).saturating_add(256);
            let task_bytes: u64 = transaction.query_row(
                "SELECT task_context_bytes FROM context_workspace_quota_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2",
                params![identity.repository_id(), identity.workspace_id()],
                |row| row.get(0),
            )?;
            let total = task_bytes
                .checked_add(stored_result_logical_bytes_v1(&transaction)?)
                .and_then(|bytes| bytes.checked_add(additional))
                .ok_or_else(|| anyhow!("workspace_state_quota_exceeded"))?;
            if total > MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1 {
                bail!("workspace_state_quota_exceeded");
            }
            transaction.execute(
                "INSERT INTO gateway_context_source_recipes_v1 (
                result_id, repository_id, workspace_id, authorization_scope_digest,
                repository_digest, plan_json, plan_digest, created_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    gateway_result_id,
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.authorization_scope_digest(),
                    repository_digest,
                    plan_text,
                    plan_digest,
                    now_ms()
                ],
            )?;
            reconcile_task_quota_scope_v1_tx(
                &transaction,
                identity.repository_id(),
                identity.workspace_id(),
                now_ms(),
            )?;
        }
        let current: (String, String, String, String, String, String) = transaction.query_row(
            "SELECT repository_id, workspace_id, authorization_scope_digest,
                    repository_digest, plan_json, plan_digest
             FROM gateway_context_source_recipes_v1 WHERE result_id = ?1",
            [gateway_result_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
        if current
            != (
                identity.repository_id().to_owned(),
                identity.workspace_id().to_owned(),
                identity.authorization_scope_digest().to_owned(),
                repository_digest.to_owned(),
                plan_text.to_owned(),
                plan_digest,
            )
        {
            bail!("context source recipe conflicts with prior admission");
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn context_source_recipe_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        gateway_result_id: &str,
    ) -> Result<Option<(String, Vec<u8>)>> {
        validate_digest(gateway_result_id, "context source recipe selector")?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let recipe: Option<(String, String, String)> = transaction
            .query_row(
                "SELECT repository_digest, plan_json, plan_digest
                 FROM gateway_context_source_recipes_v1
                 WHERE result_id = ?1 AND repository_id = ?2 AND workspace_id = ?3
                   AND authorization_scope_digest = ?4",
                params![
                    gateway_result_id,
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.authorization_scope_digest()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        transaction.commit()?;
        let Some((repository_digest, plan_json, plan_digest)) = recipe else {
            return Ok(None);
        };
        if blake3::hash(plan_json.as_bytes()).to_hex().as_str() != plan_digest {
            bail!("context source recipe digest mismatch");
        }
        Ok(Some((repository_digest, plan_json.into_bytes())))
    }

    pub fn current_context_source_ids_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        limit: usize,
    ) -> Result<Vec<String>> {
        if limit == 0 || limit > MAX_CONTEXT_LEDGER_EVENTS_PER_TASK_V1 {
            bail!(ReasoningContextRefusalV1::ItemBound.code());
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let mut statement = transaction.prepare(
            "SELECT DISTINCT source.result_id
             FROM context_ledger_event_sources_v1 AS source
             JOIN context_ledger_events_v1 AS event ON event.sequence = source.event_sequence
             WHERE event.repository_id = ?1 AND event.workspace_id = ?2
               AND event.task_id = ?3 AND event.authorization_scope_digest = ?4
               AND (EXISTS(SELECT 1 FROM context_ledger_fact_versions_v1 AS fact
                           WHERE fact.admission_event_sequence = event.sequence
                             AND fact.retired_event_sequence IS NULL)
                    OR EXISTS(SELECT 1 FROM context_ledger_result_references_v1 AS reference
                              WHERE reference.admission_event_sequence = event.sequence
                                AND reference.retired_event_sequence IS NULL))
             ORDER BY source.result_id LIMIT ?5",
        )?;
        let ids = statement
            .query_map(
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    identity.authorization_scope_digest(),
                    limit + 1
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        transaction.commit()?;
        if ids.len() > limit {
            bail!("context_freshness_capacity_exceeded");
        }
        Ok(ids)
    }

    /// Select the current task reference version, or the next version after
    /// an explicit retirement. A restored source must create a new ledger
    /// admission even when its exact gateway result bytes match an older one.
    pub fn context_result_admission_version_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        gateway_result_id: &str,
    ) -> Result<u64> {
        validate_digest(gateway_result_id, "context result admission selector")?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let (maximum, current): (Option<u64>, Option<u64>) = transaction.query_row(
            "SELECT MAX(reference_version),
                    MAX(CASE WHEN retired_event_sequence IS NULL THEN reference_version END)
             FROM context_ledger_result_references_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3 AND result_id = ?4",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                gateway_result_id
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        transaction.commit()?;
        let version = match current {
            Some(current) => current,
            None => maximum
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| anyhow!("context reference version overflow"))?,
        };
        if version == 0 || version > i64::MAX as u64 {
            bail!("context reference version exhausted");
        }
        Ok(version)
    }

    /// Determine whether a direct observation already backs the current task
    /// fact, and allocate the next version after retirement or source change.
    /// The caller still admits under the ledger's uniqueness checks and must
    /// retry if a separate store handle wins the race.
    pub fn context_direct_fact_admission_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        fact_id: &str,
        source_result_id: &str,
    ) -> Result<Option<u64>> {
        validate_digest(source_result_id, "direct context source")?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let current: Option<(u64, u64)> = transaction
            .query_row(
                "SELECT fact.fact_version, fact.admission_event_sequence
             FROM context_ledger_fact_versions_v1 AS fact
             WHERE fact.repository_id = ?1 AND fact.workspace_id = ?2
               AND fact.task_id = ?3 AND fact.fact_id = ?4
               AND fact.retired_event_sequence IS NULL
             ORDER BY fact.fact_version DESC LIMIT 1",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    fact_id
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((_, event)) = current {
            let same_source: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM context_ledger_event_sources_v1
                 WHERE event_sequence = ?1 AND result_id = ?2)",
                params![event, source_result_id],
                |row| row.get(0),
            )?;
            if same_source && context_event_provenance_current_v1(&transaction, identity, event)? {
                transaction.commit()?;
                return Ok(None);
            }
        }
        let maximum: Option<u64> = transaction.query_row(
            "SELECT MAX(fact_version) FROM context_ledger_fact_versions_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3 AND fact_id = ?4",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                fact_id
            ],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        let next = maximum
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow!("direct context fact version overflow"))?;
        if next > i64::MAX as u64 {
            bail!("direct context fact version exhausted");
        }
        Ok(Some(next))
    }

    /// A warm direct read may bypass context admission only while its own
    /// task still holds a current, provenance-checked result reference.
    pub fn context_result_reference_current_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        gateway_result_id: &str,
    ) -> Result<bool> {
        validate_digest(gateway_result_id, "context result reference selector")?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let event: Option<u64> = transaction
            .query_row(
                "SELECT reference.admission_event_sequence
                 FROM context_ledger_result_references_v1 AS reference
                 JOIN gateway_results AS result
                   ON result.gateway_result_id = reference.result_id
                  AND result.status = 'ready' AND result.origin = 'leased'
                 WHERE reference.repository_id = ?1 AND reference.workspace_id = ?2
                   AND reference.task_id = ?3 AND reference.result_id = ?4
                   AND reference.retired_event_sequence IS NULL
                 ORDER BY reference_version DESC LIMIT 1",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    gateway_result_id
                ],
                |row| row.get(0),
            )
            .optional()?;
        let current = match event {
            Some(event) => context_event_provenance_current_v1(&transaction, identity, event)?,
            None => false,
        };
        transaction.commit()?;
        Ok(current)
    }

    /// Narrow typed adapter for exact built-in observations. Callers choose
    /// only an identifier and scope; the statement/topic/value are derived by
    /// deterministic code, never copied from agent or model prose.
    pub fn context_fact_from_verified_observations_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        fact_id: &str,
        task_specific: bool,
        verified_sources: &[ContextVerifiedObservationV1],
    ) -> Result<ReasoningFactV1> {
        if verified_sources.is_empty() {
            bail!(ReasoningContextRefusalV1::SourceReferenceBound.code());
        }
        let value_digest = context_verified_fact_value_digest_v1(verified_sources);
        reasoning_item_v1(ReasoningFactV1::new(
            fact_id,
            CONTEXT_VERIFIED_FACT_TOPIC_V1,
            CONTEXT_VERIFIED_FACT_STATEMENT_V1,
            &value_digest,
            if task_specific {
                ReasoningFactScopeV1::TaskSpecific
            } else {
                ReasoningFactScopeV1::RepositoryWide
            },
            task_specific.then(|| identity.task_id()),
            verified_sources
                .iter()
                .map(|source| source.source().clone())
                .collect(),
        ))
    }

    /// Admit one fact only from store-issued exact observations. A duplicate
    /// envelope returns the original cursor and cannot duplicate a fact.
    pub fn admit_context_fact_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        envelope_digest: &str,
        fact_version: u64,
        fact: &ReasoningFactV1,
        verified_sources: &[ContextVerifiedObservationV1],
    ) -> Result<ContextLedgerAppendOutcomeV1> {
        validate_context_envelope_v1(envelope_digest, fact_version)?;
        if fact.sources().len() != verified_sources.len()
            || fact.sources().is_empty()
            || fact
                .sources()
                .iter()
                .zip(verified_sources)
                .any(|(source, verified)| source != verified.source())
            || (fact.scope() == ReasoningFactScopeV1::TaskSpecific
                && fact.task_id() != Some(identity.task_id()))
            || fact.topic() != CONTEXT_VERIFIED_FACT_TOPIC_V1
            || fact.statement() != CONTEXT_VERIFIED_FACT_STATEMENT_V1
            || fact.value_digest() != context_verified_fact_value_digest_v1(verified_sources)
        {
            bail!("verified fact was not produced by the exact built-in adapter");
        }
        let fields = ContextEventFieldsV1 {
            kind: ContextLedgerEventKindV1::VerifiedFactAdmission,
            subject_id: fact.fact_id(),
            subject_version: fact_version,
            summary: fact.statement(),
            value_digest: Some(fact.value_digest()),
            result_id: None,
            result_digest: None,
            total_bytes: None,
            duration_ms: None,
        };
        let canonical_digest = context_event_canonical_digest_v1(
            identity,
            &fields,
            &serde_json::to_vec(fact)?,
            verified_sources,
        );
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        if let Some(outcome) =
            duplicate_context_envelope_v1(&transaction, envelope_digest, &canonical_digest)?
        {
            transaction.commit()?;
            return Ok(outcome);
        }
        enforce_context_quota_v1(&transaction, identity)?;
        let dependencies =
            verify_context_sources_v1(&transaction, identity, verified_sources, now)?;
        let sequence = insert_context_event_v1(
            &transaction,
            identity,
            envelope_digest,
            &canonical_digest,
            &fields,
            now,
        )?;
        insert_context_provenance_v1(&transaction, sequence, verified_sources, &dependencies)?;
        let fact_scope = match fact.scope() {
            ReasoningFactScopeV1::RepositoryWide => "repository_wide",
            ReasoningFactScopeV1::TaskSpecific => "task_specific",
        };
        transaction.execute(
            "UPDATE context_ledger_fact_versions_v1
             SET retired_event_sequence = ?1, retirement_reason = 'superseded'
             WHERE repository_id = ?2 AND workspace_id = ?3 AND task_id = ?4
               AND fact_id = ?5 AND retired_event_sequence IS NULL AND fact_version < ?6",
            params![
                sequence,
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                fact.fact_id(),
                fact_version
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_ledger_fact_versions_v1 (
                repository_id, workspace_id, task_id, fact_id, fact_version,
                admission_event_sequence, topic, statement, value_digest, fact_scope, fact_task_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                fact.fact_id(),
                fact_version,
                sequence,
                fact.topic(),
                fact.statement(),
                fact.value_digest(),
                fact_scope,
                fact.task_id(),
            ],
        )?;
        transaction.commit()?;
        Ok(ContextLedgerAppendOutcomeV1::Appended { sequence })
    }

    pub fn append_context_event_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        envelope_digest: &str,
        input: &ContextLedgerEventInputV1,
    ) -> Result<ContextLedgerAppendOutcomeV1> {
        validate_digest(envelope_digest, "context envelope digest")?;
        let (fields, serialized, sources) = context_event_input_fields_v1(input)?;
        validate_context_envelope_v1(envelope_digest, fields.subject_version)?;
        let canonical_digest =
            context_event_canonical_digest_v1(identity, &fields, &serialized, sources);
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        if let Some(outcome) =
            duplicate_context_envelope_v1(&transaction, envelope_digest, &canonical_digest)?
        {
            transaction.commit()?;
            return Ok(outcome);
        }
        enforce_context_quota_v1(&transaction, identity)?;
        let dependencies = verify_context_sources_v1(&transaction, identity, sources, now)?;
        if matches!(
            input,
            ContextLedgerEventInputV1::CompletedObservation { .. }
                | ContextLedgerEventInputV1::ResultReference { .. }
        ) {
            for source in sources {
                let leased: bool = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM gateway_results
                     WHERE gateway_result_id = ?1 AND status = 'ready' AND origin = 'leased')",
                    [source.source().result_id()],
                    |row| row.get(0),
                )?;
                if !leased {
                    bail!("direct context observation cannot grant retrieval authority");
                }
            }
        }
        let sequence = insert_context_event_v1(
            &transaction,
            identity,
            envelope_digest,
            &canonical_digest,
            &fields,
            now,
        )?;
        insert_context_provenance_v1(&transaction, sequence, sources, &dependencies)?;
        match input {
            ContextLedgerEventInputV1::ResultReference {
                reference,
                reference_version,
                ..
            } => {
                transaction.execute(
                    "UPDATE context_ledger_result_references_v1
                     SET retired_event_sequence = ?1, retirement_reason = 'superseded'
                     WHERE repository_id = ?2 AND workspace_id = ?3 AND task_id = ?4
                       AND result_id = ?5 AND retired_event_sequence IS NULL
                       AND reference_version < ?6",
                    params![
                        sequence,
                        identity.repository_id(),
                        identity.workspace_id(),
                        identity.task_id(),
                        reference.result_id(),
                        reference_version
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO context_ledger_result_references_v1 (
                        repository_id, workspace_id, task_id, result_id, reference_version,
                        admission_event_sequence, result_digest, total_bytes
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        identity.repository_id(),
                        identity.workspace_id(),
                        identity.task_id(),
                        reference.result_id(),
                        reference_version,
                        sequence,
                        reference.result_digest(),
                        reference.total_bytes()
                    ],
                )?;
            }
            ContextLedgerEventInputV1::Retirement {
                subject_id,
                subject_version,
                reason,
            } => {
                let facts = transaction.execute(
                    "UPDATE context_ledger_fact_versions_v1
                     SET retired_event_sequence = ?1, retirement_reason = ?2
                     WHERE repository_id = ?3 AND workspace_id = ?4 AND task_id = ?5
                       AND fact_id = ?6 AND fact_version = ?7 AND retired_event_sequence IS NULL",
                    params![
                        sequence,
                        reason,
                        identity.repository_id(),
                        identity.workspace_id(),
                        identity.task_id(),
                        subject_id,
                        subject_version
                    ],
                )?;
                let references = transaction.execute(
                    "UPDATE context_ledger_result_references_v1
                     SET retired_event_sequence = ?1, retirement_reason = ?2
                     WHERE repository_id = ?3 AND workspace_id = ?4 AND task_id = ?5
                       AND result_id = ?6 AND reference_version = ?7 AND retired_event_sequence IS NULL",
                    params![sequence, reason, identity.repository_id(), identity.workspace_id(), identity.task_id(), subject_id, subject_version],
                )?;
                if facts + references == 0 {
                    bail!("context retirement target is not current");
                }
            }
            _ => {}
        }
        transaction.commit()?;
        Ok(ContextLedgerAppendOutcomeV1::Appended { sequence })
    }

    /// Retire every current derived fact/reference whose stored dependency
    /// value differs from the newly observed value. Reverse-edge traversal is
    /// exact by dependency key; unrelated derivations remain current.
    pub fn invalidate_context_dependencies_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        envelope_digest: &str,
        changes: &[ContextDependencyChangeV1],
    ) -> Result<ContextInvalidationReportV1> {
        validate_digest(envelope_digest, "context invalidation envelope digest")?;
        if changes.is_empty()
            || changes.len() > MAX_CONTEXT_LEDGER_DEPENDENCIES_V1
            || changes
                .windows(2)
                .any(|pair| pair[0].key_digest >= pair[1].key_digest)
        {
            bail!("context invalidation dependencies must be non-empty and strictly ordered");
        }
        let serialized = serde_json::to_vec(
            &changes
                .iter()
                .map(|change| (&change.key_digest, &change.current_value_digest))
                .collect::<Vec<_>>(),
        )?;
        let change_digest = blake3::hash(&serialized).to_hex().to_string();
        let fields = ContextEventFieldsV1 {
            kind: ContextLedgerEventKindV1::Invalidation,
            subject_id: "dependency-change",
            subject_version: 1,
            summary: "verified dependency values changed",
            value_digest: Some(&change_digest),
            result_id: None,
            result_digest: None,
            total_bytes: None,
            duration_ms: None,
        };
        let canonical_digest =
            context_event_canonical_digest_v1(identity, &fields, &serialized, &[]);
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        if let Some(outcome) =
            duplicate_context_envelope_v1(&transaction, envelope_digest, &canonical_digest)?
        {
            let sequence = outcome.sequence();
            let (facts, references) = context_invalidation_counts_v1(&transaction, sequence)?;
            transaction.commit()?;
            return Ok(ContextInvalidationReportV1 {
                sequence,
                retired_facts: facts,
                retired_result_references: references,
            });
        }
        enforce_context_quota_v1(&transaction, identity)?;
        let sequence = insert_context_event_v1(
            &transaction,
            identity,
            envelope_digest,
            &canonical_digest,
            &fields,
            now,
        )?;
        for (ordinal, change) in changes.iter().enumerate() {
            transaction.execute(
                "INSERT INTO context_ledger_event_dependencies_v1 (
                    event_sequence, ordinal, dependency_key_digest, dependency_value_digest
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    sequence,
                    ordinal,
                    change.key_digest,
                    change.current_value_digest
                ],
            )?;
        }
        let retired_facts =
            retire_context_facts_for_changes_v1(&transaction, identity, sequence, changes)?;
        let retired_result_references =
            retire_context_results_for_changes_v1(&transaction, identity, sequence, changes)?;
        transaction.commit()?;
        Ok(ContextInvalidationReportV1 {
            sequence,
            retired_facts,
            retired_result_references,
        })
    }

    /// Conservatively retire current task facts and retrieval references from
    /// one previously verified result when its built-in provider can no longer
    /// reproduce that observation. This asserts no replacement dependency
    /// value: an unavailable read is uncertainty, not a fabricated digest.
    pub fn invalidate_context_source_observation_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        envelope_digest: &str,
        gateway_result_id: &str,
    ) -> Result<ContextInvalidationReportV1> {
        validate_digest(envelope_digest, "context source invalidation envelope")?;
        validate_digest(gateway_result_id, "context source result")?;
        let serialized = serde_json::to_vec(&("source_changed_or_unavailable", gateway_result_id))?;
        let fields = ContextEventFieldsV1 {
            kind: ContextLedgerEventKindV1::Invalidation,
            subject_id: gateway_result_id,
            subject_version: 1,
            summary: "verified source observation changed or became unavailable",
            value_digest: Some(gateway_result_id),
            result_id: None,
            result_digest: None,
            total_bytes: None,
            duration_ms: None,
        };
        let canonical_digest =
            context_event_canonical_digest_v1(identity, &fields, &serialized, &[]);
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        if let Some(outcome) =
            duplicate_context_envelope_v1(&transaction, envelope_digest, &canonical_digest)?
        {
            let sequence = outcome.sequence();
            let (facts, references) = context_invalidation_counts_v1(&transaction, sequence)?;
            transaction.commit()?;
            return Ok(ContextInvalidationReportV1 {
                sequence,
                retired_facts: facts,
                retired_result_references: references,
            });
        }
        let current: bool = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM context_ledger_event_sources_v1 AS source
                WHERE source.result_id = ?4
                  AND source.repository_id = ?1 AND source.workspace_id = ?2
                  AND source.authorization_scope_digest = ?5
                  AND (
                    EXISTS(SELECT 1 FROM context_ledger_fact_versions_v1 AS fact
                           WHERE fact.admission_event_sequence = source.event_sequence
                             AND fact.repository_id = ?1 AND fact.workspace_id = ?2
                             AND fact.task_id = ?3 AND fact.retired_event_sequence IS NULL)
                    OR EXISTS(SELECT 1 FROM context_ledger_result_references_v1 AS reference
                              WHERE reference.admission_event_sequence = source.event_sequence
                                AND reference.repository_id = ?1 AND reference.workspace_id = ?2
                                AND reference.task_id = ?3 AND reference.retired_event_sequence IS NULL)
                  )
            )",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                gateway_result_id,
                identity.authorization_scope_digest()
            ],
            |row| row.get(0),
        )?;
        if !current {
            transaction.commit()?;
            return Ok(ContextInvalidationReportV1::default());
        }
        enforce_context_quota_v1(&transaction, identity)?;
        let sequence = insert_context_event_v1(
            &transaction,
            identity,
            envelope_digest,
            &canonical_digest,
            &fields,
            now,
        )?;
        let mut retired_facts =
            retire_context_source_facts_v1(&transaction, identity, sequence, gateway_result_id)?;
        let mut retired_result_references =
            retire_context_source_results_v1(&transaction, identity, sequence, gateway_result_id)?;
        // Another task can admit the same source under a different result ID.
        // Match its admitted dependency key and old value, within the same
        // repository and authorization scope. A task that has already admitted
        // a newer value remains current.
        let affected_tasks = {
            let mut statement = transaction.prepare(
                "SELECT event.task_id, event.agent_id, event.session_id, event.turn_id,
                        event.connection_generation, event.compaction_generation,
                        event.lifecycle_generation
                 FROM context_ledger_events_v1 AS event
                 WHERE event.repository_id = ?1 AND event.workspace_id = ?2
                   AND event.authorization_scope_digest = ?3 AND event.task_id != ?4
                   AND (EXISTS(SELECT 1 FROM context_ledger_fact_versions_v1 AS fact
                               WHERE fact.admission_event_sequence = event.sequence
                                 AND fact.retired_event_sequence IS NULL)
                        OR EXISTS(SELECT 1 FROM context_ledger_result_references_v1 AS reference
                                  WHERE reference.admission_event_sequence = event.sequence
                                    AND reference.retired_event_sequence IS NULL))
                   AND (EXISTS(SELECT 1 FROM context_ledger_event_sources_v1 AS source
                               WHERE source.event_sequence = event.sequence
                                 AND source.result_id = ?5)
                        OR EXISTS(SELECT 1 FROM context_ledger_event_dependencies_v1 AS dependency
                                  JOIN result_dependencies AS changed
                                    ON changed.gateway_result_id = ?5
                                   AND changed.dependency_key_digest = dependency.dependency_key_digest
                                   AND changed.dependency_value_digest = dependency.dependency_value_digest
                                  WHERE dependency.event_sequence = event.sequence))
                 ORDER BY event.task_id, event.sequence",
            )?;
            let rows = statement.query_map(
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.authorization_scope_digest(),
                    identity.task_id(),
                    gateway_result_id
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, u64>(5)?,
                        row.get::<_, u64>(6)?,
                    ))
                },
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut last_task = None::<String>;
        for (task_id, agent_id, session_id, turn_id, connection, compaction, lifecycle) in
            affected_tasks
        {
            if last_task.as_deref() == Some(&task_id) {
                continue;
            }
            last_task = Some(task_id.clone());
            let target = ContextLedgerIdentityV1::new(
                identity.repository_id(),
                identity.workspace_id(),
                &task_id,
                identity.authorization_scope_digest(),
                &agent_id,
                &session_id,
                &turn_id,
                &connection,
                compaction,
                lifecycle,
            )
            .map_err(|refusal| anyhow!(refusal.code()))?;
            enforce_context_quota_v1(&transaction, &target)?;
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"again.context.cross-task-source-invalidation.v1\0");
            hash_field(&mut hasher, envelope_digest.as_bytes());
            hash_field(&mut hasher, task_id.as_bytes());
            let target_envelope = hasher.finalize().to_hex().to_string();
            let target_digest =
                context_event_canonical_digest_v1(&target, &fields, &serialized, &[]);
            let target_sequence = insert_context_event_v1(
                &transaction,
                &target,
                &target_envelope,
                &target_digest,
                &fields,
                now,
            )?;
            retired_facts += retire_context_source_facts_v1(
                &transaction,
                &target,
                target_sequence,
                gateway_result_id,
            )?;
            retired_result_references += retire_context_source_results_v1(
                &transaction,
                &target,
                target_sequence,
                gateway_result_id,
            )?;
        }
        transaction.commit()?;
        Ok(ContextInvalidationReportV1 {
            sequence,
            retired_facts,
            retired_result_references,
        })
    }

    /// Compile a bounded current task projection. Every fact and result
    /// reference is rechecked against its exact ready source observations.
    pub fn context_task_snapshot_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
    ) -> Result<ContextLedgerTaskSnapshotV1> {
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let cursor = context_latest_cursor_v1(&transaction, identity)?;
        let current_facts = load_current_context_facts_v1(&transaction, identity)?;
        let suggestions = load_context_suggestions_v1(&transaction, identity)?;
        let explicit_unknowns = load_context_unknowns_v1(&transaction, identity)?;
        let result_references = load_current_context_results_v1(&transaction, identity)?;
        let inflight_work = load_context_inflight_v1(&transaction, identity, now_ms())?;
        transaction.commit()?;
        Ok(ContextLedgerTaskSnapshotV1::from_store(
            ContextLedgerCursorV1::new(cursor),
            current_facts,
            suggestions,
            explicit_unknowns,
            result_references,
            inflight_work,
        ))
    }

    pub fn record_brain_event_v1(&self, event: &BrainEventV1) -> Result<()> {
        for value in [&event.session_id, &event.event_id, &event.task_id] {
            if value.is_empty() || value.len() > 128 {
                bail!("brain_event_invalid_identity");
            }
        }
        if !matches!(event.kind.as_str(), "file_change" | "command" | "test")
            || event.created_ms < 0
            || event.path.as_ref().is_some_and(|path| {
                path.is_empty()
                    || path.len() > 512
                    || !Path::new(path)
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
            })
            || [event.source_digest.as_ref(), event.command_digest.as_ref()]
                .into_iter()
                .flatten()
                .any(|digest| {
                    digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            || event
                .authorization_scope_digest
                .as_ref()
                .is_none_or(|digest| {
                    digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            || event.command_hint.as_ref().is_some_and(|hint| {
                hint.is_empty() || hint.len() > 256 || screen_sensitive_text_v1(hint).is_err()
            })
        {
            bail!("brain_event_invalid_metadata");
        }
        let path = event.path.as_deref().unwrap_or("");
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO brain_events_v1 (
                session_id, event_id, task_id, kind, path, source_digest,
                command_digest, command_hint, exit_code, created_ms,
                authorization_scope_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.session_id,
                event.event_id,
                event.task_id,
                event.kind,
                path,
                event.source_digest,
                event.command_digest,
                event.command_hint,
                event.exit_code,
                event.created_ms,
                event.authorization_scope_digest
            ],
        )?;
        let stored: BrainEventV1 = transaction.query_row(
            "SELECT session_id, event_id, task_id, kind, path, source_digest,
                    command_digest, command_hint, exit_code, created_ms,
                    authorization_scope_digest
             FROM brain_events_v1
             WHERE session_id = ?1 AND event_id = ?2 AND kind = ?3 AND path = ?4",
            params![event.session_id, event.event_id, event.kind, path],
            |row| {
                let path: String = row.get(4)?;
                Ok(BrainEventV1 {
                    session_id: row.get(0)?,
                    event_id: row.get(1)?,
                    task_id: row.get(2)?,
                    kind: row.get(3)?,
                    path: (!path.is_empty()).then_some(path),
                    source_digest: row.get(5)?,
                    command_digest: row.get(6)?,
                    command_hint: row.get(7)?,
                    exit_code: row.get(8)?,
                    created_ms: row.get(9)?,
                    authorization_scope_digest: row.get(10)?,
                })
            },
        )?;
        if &stored != event {
            bail!("brain_event_id_collision");
        }
        if inserted == 1 {
            if (event.kind == "file_change"
                || (event.kind == "command" && event.exit_code == Some(0)))
                && let (Some(path), Some(digest)) = (&event.path, &event.source_digest)
            {
                transaction.execute(
                    "INSERT INTO brain_files_v1 (
                        path, source_digest, task_id, session_id, event_id, observed_ms,
                        authorization_scope_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(path) DO UPDATE SET
                        source_digest = excluded.source_digest,
                        task_id = excluded.task_id,
                        session_id = excluded.session_id,
                        event_id = excluded.event_id,
                        observed_ms = excluded.observed_ms,
                        authorization_scope_digest = excluded.authorization_scope_digest
                     WHERE excluded.observed_ms >= brain_files_v1.observed_ms",
                    params![
                        path,
                        digest,
                        event.task_id,
                        event.session_id,
                        event.event_id,
                        event.created_ms,
                        event.authorization_scope_digest
                    ],
                )?;
            }
            if event.kind == "test"
                && event.exit_code == Some(0)
                && let (Some(hint), Some(digest)) = (&event.command_hint, &event.command_digest)
            {
                transaction.execute(
                    "INSERT INTO brain_test_commands_v1 (
                        command_hint, command_digest, task_id, observed_ms,
                        authorization_scope_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(command_hint) DO UPDATE SET
                        command_digest = excluded.command_digest,
                        task_id = excluded.task_id,
                        observed_ms = excluded.observed_ms,
                        authorization_scope_digest = excluded.authorization_scope_digest
                     WHERE excluded.observed_ms >= brain_test_commands_v1.observed_ms",
                    params![
                        hint,
                        digest,
                        event.task_id,
                        event.created_ms,
                        event.authorization_scope_digest
                    ],
                )?;
            }
        }
        let prune = self.brain_writes_since_prune.get() >= 127;
        if prune {
            let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
            transaction.execute(
                "DELETE FROM brain_events_v1 WHERE created_ms < ?1",
                [cutoff],
            )?;
            transaction.execute(
                "DELETE FROM brain_events_v1 WHERE (session_id, event_id, kind, path) IN (
                    SELECT session_id, event_id, kind, path FROM brain_events_v1
                    ORDER BY created_ms DESC LIMIT -1 OFFSET ?1
                )",
                [MAX_BRAIN_EVENTS_V1],
            )?;
            transaction.execute(
                "DELETE FROM brain_files_v1 WHERE observed_ms < ?1",
                [cutoff],
            )?;
            transaction.execute(
                "DELETE FROM brain_test_commands_v1 WHERE observed_ms < ?1",
                [cutoff],
            )?;
            transaction.execute(
                "DELETE FROM brain_files_v1 WHERE path IN (
                    SELECT path FROM brain_files_v1
                    ORDER BY observed_ms DESC LIMIT -1 OFFSET ?1
                )",
                [MAX_BRAIN_EVENTS_V1],
            )?;
        }
        transaction.commit()?;
        self.brain_writes_since_prune.set(if prune {
            0
        } else {
            self.brain_writes_since_prune.get() + 1
        });
        Ok(())
    }

    pub fn recent_brain_events_v1(&self, limit: usize) -> Result<Vec<BrainEventV1>> {
        if limit == 0 || limit > 128 {
            bail!("brain_event_limit_invalid");
        }
        let mut statement = self.conn.prepare(
            "SELECT session_id, event_id, task_id, kind, path, source_digest,
                    command_digest, command_hint, exit_code, created_ms,
                    authorization_scope_digest
             FROM brain_events_v1 ORDER BY created_ms DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            let path: String = row.get(4)?;
            Ok(BrainEventV1 {
                session_id: row.get(0)?,
                event_id: row.get(1)?,
                task_id: row.get(2)?,
                kind: row.get(3)?,
                path: (!path.is_empty()).then_some(path),
                source_digest: row.get(5)?,
                command_digest: row.get(6)?,
                command_hint: row.get(7)?,
                exit_code: row.get(8)?,
                created_ms: row.get(9)?,
                authorization_scope_digest: row.get(10)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn brain_file_v1(
        &self,
        path: &str,
        authorization_scope_digest: &str,
    ) -> Result<Option<BrainFileV1>> {
        if path.is_empty()
            || path.len() > 512
            || !Path::new(path)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
        {
            bail!("brain_file_invalid_path");
        }
        validate_digest(authorization_scope_digest, "brain file authorization scope")?;
        let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
        self.conn
            .query_row(
                "SELECT path, source_digest, task_id, observed_ms, authorization_scope_digest
                 FROM brain_files_v1 WHERE path = ?1 AND observed_ms >= ?2
                   AND authorization_scope_digest = ?3",
                params![path, cutoff, authorization_scope_digest],
                |row| {
                    Ok(BrainFileV1 {
                        path: row.get(0)?,
                        source_digest: row.get(1)?,
                        task_id: row.get(2)?,
                        observed_ms: row.get(3)?,
                        authorization_scope_digest: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn brain_test_hints_v1(
        &self,
        authorization_scope_digest: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        if limit == 0 || limit > 32 {
            bail!("brain_test_hint_limit_invalid");
        }
        validate_digest(authorization_scope_digest, "brain test authorization scope")?;
        let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
        let mut statement = self.conn.prepare(
            "SELECT command_hint FROM brain_test_commands_v1
             WHERE observed_ms >= ?1 AND authorization_scope_digest = ?2
             ORDER BY observed_ms DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![cutoff, authorization_scope_digest, limit as i64],
            |row| row.get(0),
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn brain_test_hint_v1(&self) -> Result<Option<String>> {
        let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
        self.conn
            .query_row(
                "SELECT command_hint FROM brain_test_commands_v1
             WHERE observed_ms >= ?1 ORDER BY observed_ms DESC LIMIT 1",
                [cutoff],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Retained repository observations with the attributed task's own prompt.
    /// The caller may use prompt similarity to nominate a path, but must
    /// independently recheck the source before presenting it as current.
    pub(crate) fn brain_files_with_task_prompts_v1(
        &self,
        repository_id: &str,
        workspace_id: &str,
        authorization_scope_digest: &str,
    ) -> Result<Vec<BrainTaskFileV1>> {
        validate_task_selector_v1(repository_id)?;
        validate_task_selector_v1(workspace_id)?;
        validate_digest(authorization_scope_digest, "brain task authorization scope")?;
        let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
        let mut statement = self.conn.prepare(
            "SELECT file.path, file.source_digest, file.task_id, file.observed_ms,
                    file.authorization_scope_digest,
                    substr(task.prompt_text, 1, 1024)
             FROM brain_files_v1 AS file
             JOIN context_tasks_v1 AS task ON task.canonical_task_id = file.task_id
             WHERE task.repository_id = ?1 AND task.workspace_id = ?2
               AND task.authorization_scope_digest = ?3
               AND file.authorization_scope_digest = ?3
               AND file.observed_ms >= ?4
             ORDER BY file.observed_ms DESC LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                cutoff,
                MAX_BRAIN_EVENTS_V1
            ],
            |row| {
                Ok(BrainTaskFileV1 {
                    observation: BrainFileV1 {
                        path: row.get(0)?,
                        source_digest: row.get(1)?,
                        task_id: row.get(2)?,
                        observed_ms: row.get(3)?,
                        authorization_scope_digest: row.get(4)?,
                    },
                    task_prompt: row.get(5)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn recent_brain_files_v1(&self, limit: usize) -> Result<Vec<BrainFileV1>> {
        if limit == 0 || limit > 128 {
            bail!("brain_file_limit_invalid");
        }
        let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
        let mut statement = self.conn.prepare(
            "SELECT path, source_digest, task_id, observed_ms, authorization_scope_digest
             FROM brain_files_v1 WHERE observed_ms >= ?1
             ORDER BY observed_ms DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![cutoff, limit as i64], |row| {
            Ok(BrainFileV1 {
                path: row.get(0)?,
                source_digest: row.get(1)?,
                task_id: row.get(2)?,
                observed_ms: row.get(3)?,
                authorization_scope_digest: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn record_brain_run_v1(&self, run: &BrainRunV1) -> Result<()> {
        if run.session_id.is_empty()
            || run.session_id.len() > 128
            || run.task_id.is_empty()
            || run.task_id.len() > 128
            || run.started_ms < 0
            || run.completed_ms < run.started_ms
            || run.completed_source_reads > run.completed_commands
            || run.successful_tests > run.completed_commands
            || run.input_tokens.is_some() != run.cached_input_tokens.is_some()
            || run.input_tokens.is_some() != run.output_tokens.is_some()
            || run.input_tokens.is_some_and(|tokens| tokens < 0)
            || run
                .cached_input_tokens
                .is_some_and(|tokens| tokens < 0 || Some(tokens) > run.input_tokens)
            || run.output_tokens.is_some_and(|tokens| tokens < 0)
        {
            bail!("brain_run_invalid_metadata");
        }
        validate_digest(
            &run.authorization_scope_digest,
            "brain run authorization scope",
        )?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO brain_runs_v1 (
                session_id, task_id, authorization_scope_digest, started_ms, completed_ms,
                exit_code, turn_completed, completed_commands, completed_source_reads,
                completed_edits, completed_mcp_calls, successful_tests,
                input_tokens, cached_input_tokens, output_tokens
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                run.session_id,
                run.task_id,
                run.authorization_scope_digest,
                run.started_ms,
                run.completed_ms,
                run.exit_code,
                run.turn_completed,
                run.completed_commands,
                run.completed_source_reads,
                run.completed_edits,
                run.completed_mcp_calls,
                run.successful_tests,
                run.input_tokens,
                run.cached_input_tokens,
                run.output_tokens
            ],
        )?;
        let stored = transaction.query_row(
            "SELECT session_id, task_id, authorization_scope_digest, started_ms, completed_ms,
                    exit_code, turn_completed, completed_commands, completed_source_reads,
                    completed_edits, completed_mcp_calls, successful_tests,
                    input_tokens, cached_input_tokens, output_tokens
             FROM brain_runs_v1 WHERE session_id = ?1",
            [&run.session_id],
            brain_run_from_row_v1,
        )?;
        if &stored != run {
            bail!("brain_run_session_collision");
        }
        if inserted == 1 {
            let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
            transaction.execute(
                "DELETE FROM brain_runs_v1 WHERE completed_ms < ?1",
                [cutoff],
            )?;
            transaction.execute(
                "DELETE FROM brain_runs_v1 WHERE session_id IN (
                    SELECT session_id FROM brain_runs_v1
                    ORDER BY completed_ms DESC LIMIT -1 OFFSET ?1
                )",
                [MAX_BRAIN_EVENTS_V1],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn recent_brain_runs_v1(&self, limit: usize) -> Result<Vec<BrainRunV1>> {
        if limit == 0 || limit > 128 {
            bail!("brain_run_limit_invalid");
        }
        let cutoff = now_ms().saturating_sub(MAX_BRAIN_EVENT_AGE_MS_V1);
        let mut statement = self.conn.prepare(
            "SELECT session_id, task_id, authorization_scope_digest, started_ms, completed_ms,
                    exit_code, turn_completed, completed_commands, completed_source_reads,
                    completed_edits, completed_mcp_calls, successful_tests,
                    input_tokens, cached_input_tokens, output_tokens
             FROM brain_runs_v1 WHERE completed_ms >= ?1
             ORDER BY completed_ms DESC, session_id ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![cutoff, limit as i64], brain_run_from_row_v1)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn clear_brain_events_v1(&self) -> Result<u64> {
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let runs = transaction.execute("DELETE FROM brain_runs_v1", [])? as u64;
        let files = transaction.execute("DELETE FROM brain_files_v1", [])? as u64;
        let tests = transaction.execute("DELETE FROM brain_test_commands_v1", [])? as u64;
        let events = transaction.execute("DELETE FROM brain_events_v1", [])? as u64;
        transaction.commit()?;
        Ok(runs + files + tests + events)
    }

    pub fn context_delta_after_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        after: ContextLedgerCursorV1,
        limit: usize,
    ) -> Result<ContextLedgerDeltaV1> {
        if limit == 0 || limit > MAX_CONTEXT_LEDGER_DELTA_ITEMS_V1 {
            bail!(ReasoningContextRefusalV1::ItemBound.code());
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let events = load_context_delta_v1(&transaction, identity, after.sequence(), limit + 1)?;
        let has_more = events.len() > limit;
        let events = events.into_iter().take(limit).collect::<Vec<_>>();
        let cursor = events
            .last()
            .map_or(after.sequence(), ContextLedgerEventV1::sequence);
        transaction.commit()?;
        Ok(ContextLedgerDeltaV1::from_store(
            after,
            ContextLedgerCursorV1::new(cursor),
            has_more,
            events,
        ))
    }

    /// Retrieve one exact result only through a current task-scoped ledger
    /// reference and a live recipient generation. The result identifier is a
    /// selector, not a capability: absent, retired, stale, cross-task, or
    /// authorization-mismatched references fail closed before bytes are read.
    pub fn retrieve_context_result_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        gateway_result_id: &str,
    ) -> Result<GatewayFullResultV1> {
        validate_digest(gateway_result_id, "context result selector")?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let reference = transaction
            .query_row(
                "SELECT admission_event_sequence, result_digest, total_bytes
                 FROM context_ledger_result_references_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
                   AND result_id = ?4 AND retired_event_sequence IS NULL
                 ORDER BY reference_version DESC LIMIT 1",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    gateway_result_id
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((event_sequence, result_digest, total_bytes)) = reference else {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        };
        if result_digest != gateway_result_id
            || !context_event_provenance_current_v1(&transaction, identity, event_sequence)?
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        let (result, dependencies) =
            load_gateway_result_unbound_snapshot_v2(&transaction, gateway_result_id)?;
        let observed_total = result
            .stdout_bytes
            .checked_add(result.stderr_bytes)
            .ok_or_else(|| anyhow!(DeliveryAuthorityRefusalV1::InvalidBinding.code()))?;
        if observed_total != total_bytes {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        let stdout = self.get_blob(&result.stdout_digest);
        let stderr = self.get_blob(&result.stderr_digest);
        let valid = matches!((&stdout, &stderr), (Ok(stdout), Ok(stderr))
            if stdout.len() as u64 == result.stdout_bytes
                && stderr.len() as u64 == result.stderr_bytes);
        if !valid {
            transaction.rollback()?;
            let quarantine =
                Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
            quarantine_invalid_gateway_result_v1_tx(
                &quarantine,
                None,
                gateway_result_id,
                now_ms(),
            )?;
            quarantine.commit()?;
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        let stdout = stdout?;
        let stderr = stderr?;
        transaction.commit()?;
        Ok(GatewayFullResultV1 {
            gateway_result_id: gateway_result_id.to_owned(),
            result,
            stdout,
            stderr,
            dependencies,
        })
    }

    pub fn acquire_context_lease_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        work_key_digest: &str,
        summary: &str,
        ttl_ms: u64,
        deadline_ms: i64,
    ) -> Result<ContextLeaseAcquisitionV1> {
        validate_digest(work_key_digest, "context work key digest")?;
        reasoning_item_v1(crate::agent_gateway::context::validate_reasoning_text_v1(
            summary, 1024,
        ))?;
        screen_sensitive_text_v1(summary)?;
        let ttl_ms = i64::try_from(ttl_ms).context("context lease ttl overflow")?;
        if ttl_ms <= 0 || ttl_ms > CONTEXT_LEASE_TTL_MAX_MS_V1 {
            bail!("context lease ttl is outside the bounded interval");
        }
        let now = now_ms();
        if deadline_ms <= now {
            bail!(GatewayRefusalReason::LeaseExpired.as_str());
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        expire_context_leases_v1(&transaction, now)?;
        enforce_context_quota_v1(&transaction, identity)?;
        let active = transaction
            .query_row(
                "SELECT lease_id, generation, leader_agent_id, expires_ms
                 FROM context_ledger_leases_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
                   AND authorization_scope_digest = ?4 AND work_key_digest = ?5
                   AND status = 'active'",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    identity.authorization_scope_digest(),
                    work_key_digest
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((lease_id, generation, leader_agent_id, expires_at_ms)) = active {
            transaction.commit()?;
            return Ok(ContextLeaseAcquisitionV1::Join {
                lease_id,
                generation,
                leader_agent_id,
                expires_at_ms,
            });
        }
        let generation = transaction.query_row(
            "SELECT COALESCE(MAX(generation), 0) + 1 FROM context_ledger_leases_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4 AND work_key_digest = ?5",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                work_key_digest
            ],
            |row| row.get::<_, u64>(0),
        )?;
        let expires_at_ms = deadline_ms.min(now.saturating_add(ttl_ms));
        let lease_id = format!("cl_{}", Uuid::new_v4().simple());
        transaction.execute(
            "INSERT INTO context_ledger_leases_v1 (
                lease_id, repository_id, workspace_id, task_id, authorization_scope_digest,
                work_key_digest, generation, leader_agent_id, leader_session_id,
                leader_lifecycle_generation, summary, status, acquired_ms, heartbeat_ms,
                deadline_ms, expires_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'active', ?12, ?12, ?13, ?14)",
            params![
                lease_id,
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                work_key_digest,
                generation,
                identity.agent_id(),
                identity.session_id(),
                identity.lifecycle_generation(),
                summary,
                now,
                deadline_ms,
                expires_at_ms
            ],
        )?;
        let envelope_digest = blake3::hash(format!("context-lease:{lease_id}").as_bytes())
            .to_hex()
            .to_string();
        let fields = ContextEventFieldsV1 {
            kind: ContextLedgerEventKindV1::InflightWork,
            subject_id: &lease_id,
            subject_version: generation,
            summary,
            value_digest: Some(work_key_digest),
            result_id: None,
            result_digest: None,
            total_bytes: None,
            duration_ms: None,
        };
        let canonical_digest =
            context_event_canonical_digest_v1(identity, &fields, work_key_digest.as_bytes(), &[]);
        insert_context_event_v1(
            &transaction,
            identity,
            &envelope_digest,
            &canonical_digest,
            &fields,
            now,
        )?;
        transaction.commit()?;
        Ok(ContextLeaseAcquisitionV1::Leader {
            lease_id,
            generation,
            expires_at_ms,
        })
    }

    pub fn observe_context_lease_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        work_key_digest: &str,
    ) -> Result<ContextLeaseObservationV1> {
        validate_digest(work_key_digest, "context work key digest")?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        expire_context_leases_v1(&transaction, now)?;
        let row = transaction
            .query_row(
                "SELECT lease_id, generation, leader_agent_id, status, expires_ms
             FROM context_ledger_leases_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4 AND work_key_digest = ?5
             ORDER BY generation DESC LIMIT 1",
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    identity.authorization_scope_digest(),
                    work_key_digest
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        transaction.commit()?;
        Ok(match row {
            Some((lease_id, generation, leader_agent_id, status, expires_at_ms))
                if status == "active" =>
            {
                ContextLeaseObservationV1::Inflight {
                    lease_id,
                    generation,
                    leader_agent_id,
                    expires_at_ms,
                }
            }
            Some((_, _, _, status, _)) if status == "completed" => {
                ContextLeaseObservationV1::Completed
            }
            Some((_, _, _, status, _)) if status == "failed" || status == "expired" => {
                ContextLeaseObservationV1::Failed
            }
            Some((_, _, _, status, _)) if status == "cancelled" => {
                ContextLeaseObservationV1::Cancelled
            }
            _ => ContextLeaseObservationV1::Missing,
        })
    }

    pub fn heartbeat_context_lease_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        lease_id: &str,
        ttl_ms: u64,
    ) -> Result<i64> {
        let ttl_ms = i64::try_from(ttl_ms).context("context lease ttl overflow")?;
        if ttl_ms <= 0 || ttl_ms > CONTEXT_LEASE_TTL_MAX_MS_V1 {
            bail!("context lease ttl is outside the bounded interval");
        }
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        expire_context_leases_v1(&transaction, now)?;
        let deadline = context_owned_lease_deadline_v1(&transaction, identity, lease_id)?;
        let expires = deadline.min(now.saturating_add(ttl_ms));
        let changed = transaction.execute(
            "UPDATE context_ledger_leases_v1 SET heartbeat_ms = ?2, expires_ms = ?3
             WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, now, expires],
        )?;
        if changed != 1 {
            bail!(GatewayRefusalReason::LeaseNotCurrent.as_str());
        }
        transaction.commit()?;
        Ok(expires)
    }

    pub fn finish_context_lease_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        lease_id: &str,
        succeeded: bool,
    ) -> Result<()> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        expire_context_leases_v1(&transaction, now)?;
        context_owned_lease_deadline_v1(&transaction, identity, lease_id)?;
        let status = if succeeded { "completed" } else { "failed" };
        let changed = transaction.execute(
            "UPDATE context_ledger_leases_v1 SET status = ?2, completed_ms = ?3
             WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, status, now],
        )?;
        if changed != 1 {
            bail!(GatewayRefusalReason::LeaseNotCurrent.as_str());
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn cancel_context_lease_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        lease_id: &str,
    ) -> Result<()> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        context_owned_lease_deadline_v1(&transaction, identity, lease_id)?;
        let changed = transaction.execute(
            "UPDATE context_ledger_leases_v1 SET status = 'cancelled', completed_ms = ?2
             WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, now],
        )?;
        if changed != 1 {
            bail!(GatewayRefusalReason::LeaseNotCurrent.as_str());
        }
        transaction.commit()?;
        Ok(())
    }

    /// Record a complete snapshot/delta delivery. The response envelope is
    /// globally idempotent, so retries cannot duplicate savings.
    pub fn acknowledge_context_delivery_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        response_envelope_digest: &str,
        through: ContextLedgerCursorV1,
        delivered_bytes: u64,
        bytes_omitted: u64,
    ) -> Result<bool> {
        validate_digest(response_envelope_digest, "context response envelope digest")?;
        let delivered_bytes =
            i64::try_from(delivered_bytes).context("context delivery bytes overflow")?;
        let bytes_omitted =
            i64::try_from(bytes_omitted).context("context omitted bytes overflow")?;
        let now = now_ms();
        let receipt_digest = context_delivery_receipt_digest_v1(
            identity,
            response_envelope_digest,
            through,
            delivered_bytes as u64,
        );
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        if through.sequence() > context_latest_cursor_v1(&transaction, identity)? {
            bail!(ReasoningContextRefusalV1::DeliveryIncomplete.code());
        }
        let inserted = transaction.execute(
            "INSERT INTO context_ledger_delivery_receipts_v1 (
                receipt_digest, response_envelope_digest, repository_id, workspace_id, task_id,
                authorization_scope_digest, agent_id, session_id, turn_id,
                connection_generation, compaction_generation, lifecycle_generation,
                through_sequence, delivered_bytes, acknowledged_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(response_envelope_digest) DO NOTHING",
            params![
                receipt_digest,
                response_envelope_digest,
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                identity.agent_id(),
                identity.session_id(),
                identity.turn_id(),
                identity.connection_generation(),
                identity.compaction_generation(),
                identity.lifecycle_generation(),
                through.sequence(),
                delivered_bytes,
                now
            ],
        )?;
        if inserted == 0 {
            let existing: String = transaction.query_row(
                "SELECT receipt_digest FROM context_ledger_delivery_receipts_v1 WHERE response_envelope_digest = ?1",
                [response_envelope_digest],
                |row| row.get(0),
            )?;
            if existing != receipt_digest {
                bail!("context delivery envelope conflicts with prior receipt");
            }
            transaction.commit()?;
            return Ok(false);
        }
        reserve_task_context_bytes_v1(
            &transaction,
            identity.repository_id(),
            identity.workspace_id(),
            512,
        )?;
        if bytes_omitted > 0 {
            transaction.execute(
                "INSERT INTO context_ledger_delivery_savings_v1 (
                    receipt_digest, response_envelope_digest, bytes_omitted, recorded_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![receipt_digest, response_envelope_digest, bytes_omitted, now],
            )?;
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn gc_context_ledger_v1(
        &self,
        identity: &ContextLedgerIdentityV1,
        maximum_events: usize,
    ) -> Result<ContextLedgerGcReportV1> {
        if maximum_events == 0 || maximum_events > MAX_CONTEXT_LEDGER_EVENTS_PER_TASK_V1 {
            bail!(ReasoningContextRefusalV1::ItemBound.code());
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_current_context_recipient_v1(&transaction, identity)?;
        let report = gc_context_ledger_tx_v1(&transaction, identity, maximum_events)?;
        reconcile_task_quota_scope_v1_tx(
            &transaction,
            identity.repository_id(),
            identity.workspace_id(),
            now_ms(),
        )?;
        transaction.commit()?;
        Ok(report)
    }

    /// Compile the coordinator's durable state into a bounded, payload-safe
    /// reasoning read model. This method never returns provider output and
    /// never issues a routing proof: callers must still use the exact store
    /// proof and full-result APIs before reuse or retrieval.
    pub fn reasoning_context_v1(
        &self,
        query: &GatewayReasoningContextQueryV1,
    ) -> Result<ReasoningBriefInputV1> {
        let mut brief = ReasoningBriefInputV1::empty(query.scope.clone(), query.recipient.clone());
        match self.observe_gateway_call(&query.binding)? {
            GatewayCallObservation::Ready { gateway_result_id } => {
                let Some(result) = self.get_gateway_result(&query.binding, &gateway_result_id)?
                else {
                    add_reasoning_unknown_v1(
                        &mut brief,
                        ReasoningRouteDecisionV1::ExecuteForUnknown,
                    )?;
                    return Ok(brief);
                };
                if !has_matching_reasoning_delivery_v1(
                    &self.conn,
                    query.scope.authorization_scope_digest(),
                    &result,
                )? {
                    brief.explicit_unknowns.push(reasoning_item_v1(
                        ReasoningUnknownV1::new(
                            "authorization-scope-evidence",
                            "the current authorization scope has no authenticated full-delivery evidence for this observation",
                        ),
                    )?);
                    brief.suggested_next_tool_calls.push(reasoning_item_v1(
                        SuggestedReasoningToolCallV1::new(
                            "gateway",
                            "execute-observation",
                            "obtain a verified observation under the current authorization scope",
                            ReasoningRouteDecisionV1::ExecuteForAuthorization,
                        ),
                    )?);
                    brief
                        .route_decisions
                        .push(ReasoningRouteDecisionV1::ExecuteForAuthorization);
                    return Ok(brief);
                }

                let source = reasoning_gateway_source_v1(
                    query.scope(),
                    &gateway_result_id,
                    &gateway_result_id,
                    &format!("gateway-result:{gateway_result_id}"),
                )?;
                brief.known_facts.push(reasoning_item_v1(ReasoningFactV1::new(
                    &format!("gateway-result-{}", &gateway_result_id[..16]),
                    "gateway-exact-observation",
                    "a verified result is available for the exact request, state, policy, dependencies, and authorization scope",
                    &gateway_result_id,
                    ReasoningFactScopeV1::RepositoryWide,
                    None,
                    vec![source.clone()],
                ))?);
                let total_bytes = result
                    .result
                    .stdout_bytes
                    .checked_add(result.result.stderr_bytes)
                    .ok_or_else(|| anyhow!("gateway result byte count overflow"))?;
                let retrieval = reasoning_item_v1(ReasoningRetrievalIdentityV1::new(
                    &gateway_result_id,
                    &gateway_result_id,
                    total_bytes,
                ))?;
                brief.completed_observations.push(reasoning_item_v1(
                    CompletedReasoningObservationV1::new(
                        &gateway_result_id,
                        "provider execution completed and the exact result remains available through binding-checked retrieval",
                        result.result.duration_ms,
                        retrieval,
                        vec![source],
                    ),
                )?);
                brief
                    .route_decisions
                    .push(ReasoningRouteDecisionV1::SharedVerifiedFact);
                brief.evidence_metrics.investigations_avoided = 1;
                brief.evidence_metrics.provider_calls_avoided = 1;
                brief.evidence_metrics.estimated_execution_time_saved_ms =
                    result.result.duration_ms;
            }
            GatewayCallObservation::Inflight {
                leader_call_id,
                leader,
                ..
            } => {
                let generation = self
                    .conn
                    .query_row(
                        "SELECT lifecycle_generation FROM inflight_leases WHERE call_id = ?1 AND binding_digest = ?2 AND status = 'active'",
                        params![leader_call_id, query.binding.binding_digest()],
                        |row| row.get::<_, u64>(0),
                    )
                    .optional()?;
                if leader != query.recipient.agent_id() {
                    let generation = generation
                        .ok_or_else(|| anyhow!(GatewayRefusalReason::LeaseNotCurrent.as_str()))?;
                    brief
                        .inflight_work
                        .push(reasoning_item_v1(InflightReasoningWorkV1::new(
                            &leader_call_id,
                            &leader,
                            generation,
                            "another agent is executing the exact current binding",
                        ))?);
                    brief
                        .route_decisions
                        .push(ReasoningRouteDecisionV1::InflightJoin);
                    brief.evidence_metrics.inflight_joins = 1;
                    brief.evidence_metrics.provider_calls_avoided = 1;
                }
            }
            GatewayCallObservation::Failed { reason } => {
                let call_id = self
                    .conn
                    .query_row(
                        "SELECT call_id FROM gateway_requests WHERE binding_digest = ?1 AND status = 'failed' ORDER BY updated_ms DESC, call_id DESC LIMIT 1",
                        [query.binding.binding_digest()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .unwrap_or_else(|| query.binding.binding_digest().to_owned());
                let row_digest = reasoning_store_row_digest_v1(
                    "failed-request",
                    query.binding.binding_digest(),
                    &call_id,
                    reason.as_str(),
                );
                let source = reasoning_gateway_source_v1(
                    query.scope(),
                    &call_id,
                    &row_digest,
                    &format!("gateway-request:{call_id}"),
                )?;
                brief
                    .failed_approaches
                    .push(reasoning_item_v1(FailedReasoningApproachV1::new(
                        &format!("failed-{}", &row_digest[..16]),
                        "execute the exact gateway observation",
                        gateway_failure_explanation_v1(reason),
                        vec![source],
                    ))?);
                add_reasoning_unknown_v1(&mut brief, ReasoningRouteDecisionV1::ExecuteForUnknown)?;
            }
            GatewayCallObservation::Quarantined { .. } => {
                let gateway_result_id = self
                    .conn
                    .query_row(
                        "SELECT gateway_result_id FROM gateway_results WHERE binding_digest = ?1 AND status = 'quarantined' ORDER BY updated_ms DESC, gateway_result_id DESC LIMIT 1",
                        [query.binding.binding_digest()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .unwrap_or_else(|| query.binding.binding_digest().to_owned());
                let source = reasoning_gateway_source_v1(
                    query.scope(),
                    &gateway_result_id,
                    &gateway_result_id,
                    &format!("gateway-result:{gateway_result_id}"),
                )?;
                let fact = reasoning_item_v1(ReasoningFactV1::new(
                    &format!("quarantined-{}", &gateway_result_id[..16]),
                    "gateway-exact-observation",
                    "a prior observation for this exact binding is quarantined and cannot be current context",
                    &gateway_result_id,
                    ReasoningFactScopeV1::RepositoryWide,
                    None,
                    vec![source],
                ))?;
                brief
                    .invalidated_facts
                    .push(reasoning_item_v1(InvalidatedReasoningFactV1::new(
                        fact,
                        ReasoningInvalidationV1::Quarantined,
                        Vec::new(),
                    ))?);
                brief
                    .route_decisions
                    .push(ReasoningRouteDecisionV1::QuarantineContradiction);
                brief.evidence_metrics.false_hit_quarantines = 1;
            }
            GatewayCallObservation::Missing => {
                add_reasoning_unknown_v1(&mut brief, ReasoningRouteDecisionV1::ExecuteForUnknown)?;
            }
        }
        Ok(brief)
    }

    /// Observe one validated binding and issue at most one transaction-time
    /// router proof from the exact committed store rows. This does not load or
    /// present result bytes and grants no authority by itself.
    pub fn observe_gateway_route_proof_v1(
        &self,
        binding: &ValidatedGatewayReadV1,
        call: &GatewayToolCallV1,
    ) -> Result<GatewayRouteProofObservationV1> {
        if call.request_digest().as_str() != binding.request_digest()
            || !matches!(
                call.effect_class(),
                EffectClass::SnapshotRead
                    | EffectClass::FreshnessBoundRead
                    | EffectClass::DeterministicCompute
            )
        {
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::BindingMismatch,
            ));
        }
        let now = now_ms();
        if !freshness_is_current(binding, now) {
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Freshness,
            ));
        }
        let observed_at_ms = u64::try_from(now)
            .map_err(|_| anyhow!("gateway proof observation time is negative"))?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        expire_gateway_leases_v1_tx(&transaction, now, Some(binding.binding_digest()))?;
        let quarantined: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results WHERE binding_digest = ?1 AND status = 'quarantined')",
            [binding.binding_digest()],
            |row| row.get(0),
        )?;
        if quarantined {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Quarantined,
            ));
        }
        let ready = transaction
            .query_row(
                "SELECT gateway_result_id, lease_id FROM gateway_results WHERE binding_digest = ?1 AND status = 'ready' AND origin = 'leased'",
                [binding.binding_digest()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((gateway_result_id, lease_id)) = ready {
            if !self.gateway_result_is_servable_v1(&transaction, binding, &gateway_result_id)? {
                quarantine_invalid_gateway_result_v1_tx(
                    &transaction,
                    None,
                    &gateway_result_id,
                    now,
                )?;
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::Quarantined,
                ));
            }
            let Some(lease) = gateway_lease_row_v1(&transaction, &lease_id)? else {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::BindingMismatch,
                ));
            };
            let Some(started_at_ms) = lease
                .execution_started_ms
                .and_then(|value| value.try_into().ok())
            else {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::ExecutionNotStarted,
                ));
            };
            let Some(completed_at_ms) = lease
                .completed_ms
                .and_then(|value| u64::try_from(value).ok())
            else {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::BindingMismatch,
                ));
            };
            let current_generation = transaction.query_row(
                "SELECT MAX(lifecycle_generation) FROM inflight_leases WHERE binding_digest = ?1",
                [binding.binding_digest()],
                |row| row.get::<_, u64>(0),
            )?;
            if lease.status != "completed"
                || lease.gateway_result_id.as_deref() != Some(&gateway_result_id)
                || lease.request_digest != binding.input.request_digest
                || lease.state_digest != binding.input.state_digest
                || lease.policy_digest != binding.input.policy_digest
                || lease.binding_digest != binding.binding_digest
                || current_generation != lease.lifecycle_generation
                || completed_at_ms < started_at_ms
                || completed_at_ms > observed_at_ms
                || !freshness_requirement_holds_v1(call.freshness(), started_at_ms, observed_at_ms)
            {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::Freshness,
                ));
            }
            let dependency_digest = gateway_dependency_digest_v1(&binding.input.dependencies);
            let store_record_digest = exact_store_record_digest_v1(
                binding,
                &lease,
                &gateway_result_id,
                &dependency_digest,
            );
            let proof = StoreExactResultProofV1 {
                used: std::cell::Cell::new(false),
                request_digest: call.request_digest(),
                binding_digest: binding.binding_digest.clone(),
                state_digest: binding.input.state_digest.clone(),
                policy_digest: binding.input.policy_digest.clone(),
                dependency_digest,
                effect: call.effect_class(),
                freshness: call.freshness(),
                lifecycle_generation: lease.lifecycle_generation,
                observed_generation: current_generation,
                execution_started_ms: started_at_ms,
                observed_at_ms,
                gateway_result_id,
                store_record_digest,
            };
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Exact(proof));
        }

        let active_lease_id = transaction
            .query_row(
                "SELECT lease_id FROM inflight_leases WHERE binding_digest = ?1 AND status = 'active'",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(active_lease_id) = active_lease_id else {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Missing,
            ));
        };
        let Some(lease) = gateway_lease_row_v1(&transaction, &active_lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Missing,
            ));
        };
        let Some(started_at_ms) = lease
            .execution_started_ms
            .and_then(|value| value.try_into().ok())
        else {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::ExecutionNotStarted,
            ));
        };
        let current_generation = transaction.query_row(
            "SELECT MAX(lifecycle_generation) FROM inflight_leases WHERE binding_digest = ?1",
            [binding.binding_digest()],
            |row| row.get::<_, u64>(0),
        )?;
        if current_generation != lease.lifecycle_generation
            || lease.request_digest != binding.input.request_digest
            || lease.state_digest != binding.input.state_digest
            || lease.policy_digest != binding.input.policy_digest
            || !freshness_requirement_holds_v1(call.freshness(), started_at_ms, observed_at_ms)
        {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Freshness,
            ));
        }
        let dependency_digest = gateway_dependency_digest_v1(&binding.input.dependencies);
        let lease_record_digest =
            inflight_store_record_digest_v1(binding, &lease, observed_at_ms, &dependency_digest);
        let proof = StoreInflightJoinProofV1 {
            used: std::cell::Cell::new(false),
            request_digest: call.request_digest(),
            binding_digest: binding.binding_digest.clone(),
            state_digest: binding.input.state_digest.clone(),
            policy_digest: binding.input.policy_digest.clone(),
            dependency_digest,
            effect: call.effect_class(),
            freshness: call.freshness(),
            lifecycle_generation: lease.lifecycle_generation,
            observed_generation: current_generation,
            execution_started_ms: started_at_ms,
            observed_at_ms,
            lease_id: lease.lease_id.clone(),
            lease_record_digest,
        };
        transaction.commit()?;
        Ok(GatewayRouteProofObservationV1::Inflight(proof))
    }

    pub fn complete_gateway_call(
        &self,
        lease_id: &str,
        result_id: &str,
    ) -> Result<GatewayCompletion> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        let result = load_visible_result_tx(&transaction, result_id)?;
        let Some(result) = result else {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::ResultNotFound,
            });
        };
        if !source_result_blobs_valid_v1(self, &result) {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::ResultCorrupt,
            });
        }
        let dependencies = load_request_dependencies_v1(&transaction, &lease.call_id)?;
        let gateway_result_id = gateway_result_content_digest(&lease, &result, &dependencies);
        if lease.status == "completed" {
            if lease.gateway_result_id.as_deref() == Some(&gateway_result_id) {
                transaction.commit()?;
                return Ok(GatewayCompletion::AlreadyCompleted {
                    call_id: lease.call_id,
                    gateway_result_id,
                });
            }
            let existing = lease.gateway_result_id.clone().unwrap_or_default();
            quarantine_gateway_divergence_v1_tx(
                &transaction,
                &lease,
                &existing,
                &gateway_result_id,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCompletion::Quarantined {
                call_id: lease.call_id,
                existing_gateway_result_id: existing,
                conflicting_gateway_result_id: gateway_result_id,
            });
        }
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            record_gateway_event_v1_tx(
                &transaction,
                Some(&lease.call_id),
                Some(lease_id),
                None,
                "stale_completion",
                Some(reason.as_str()),
                0,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            record_gateway_event_v1_tx(
                &transaction,
                Some(&lease.call_id),
                Some(lease_id),
                None,
                "stale_completion",
                Some(GatewayRefusalReason::LeaseExpired.as_str()),
                0,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        if lease.execution_started_ms.is_none() {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::ExecutionNotStarted,
            });
        }
        if result.request_key != lease.request_digest
            || gateway_policy_digest(&result.policy_version) != lease.policy_digest
        {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::BindingMismatch,
            });
        }
        let proof_digest = blake3::hash(result.proof_json.as_bytes())
            .to_hex()
            .to_string();
        transaction.execute(
            "INSERT INTO gateway_results (gateway_result_id, request_digest, state_digest, policy_digest, binding_digest, result_id, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, result_policy_version, proof_digest, lease_id, status, created_ms, updated_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 'ready', ?16, ?16)",
            params![
                gateway_result_id,
                lease.request_digest,
                lease.state_digest,
                lease.policy_digest,
                lease.binding_digest,
                result.id,
                result.stdout_digest,
                result.stderr_digest,
                result.stdout_bytes,
                result.stderr_bytes,
                result.exit_code,
                result.duration_ms,
                result.policy_version,
                proof_digest,
                lease_id,
                now
            ],
        )?;
        for (ordinal, dependency) in dependencies.iter().enumerate() {
            transaction.execute(
                "INSERT INTO result_dependencies (gateway_result_id, ordinal, dependency_key_digest, dependency_value_digest) VALUES (?1, ?2, ?3, ?4)",
                params![
                    gateway_result_id,
                    i64::try_from(ordinal)?,
                    dependency.key_digest,
                    dependency.value_digest
                ],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE inflight_leases SET status = 'completed', gateway_result_id = ?2, completed_ms = ?3 WHERE lease_id = ?1 AND status = 'active' AND execution_started_ms IS NOT NULL",
            params![lease_id, gateway_result_id, now],
        )?;
        if changed != 1 {
            bail!("gateway completion CAS failed after validated active lease");
        }
        transaction.execute(
            "UPDATE gateway_requests SET status = 'ready', gateway_result_id = ?2, updated_ms = ?3 WHERE joined_lease_id = ?1 AND status IN ('inflight', 'waiting')",
            params![lease_id, gateway_result_id, now],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(&lease.call_id),
            Some(lease_id),
            Some(&gateway_result_id),
            "completed",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayCompletion::Completed {
            call_id: lease.call_id,
            gateway_result_id,
        })
    }

    pub fn fail_gateway_call(
        &self,
        lease_id: &str,
        reason: GatewayFailureReason,
    ) -> Result<GatewayFailure> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayFailure::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            transaction.commit()?;
            return Ok(GatewayFailure::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            transaction.commit()?;
            return Ok(GatewayFailure::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        let changed = transaction.execute(
            "UPDATE inflight_leases SET status = 'failed', reason = ?2, completed_ms = ?3 WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, reason.as_str(), now],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(GatewayFailure::Refused {
                reason: GatewayRefusalReason::LeaseNotCurrent,
            });
        }
        transaction.execute(
            "UPDATE gateway_requests SET status = 'failed', reason = ?2, updated_ms = ?3 WHERE joined_lease_id = ?1 AND status IN ('inflight', 'waiting')",
            params![lease_id, reason.as_str(), now],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(&lease.call_id),
            Some(lease_id),
            None,
            "failed",
            Some(reason.as_str()),
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayFailure::Failed {
            call_id: lease.call_id,
        })
    }

    pub fn cancel_gateway_follower(&self, call_id: &str) -> Result<GatewayFollowerCancellation> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let request = transaction
            .query_row(
                "SELECT role, status, joined_lease_id FROM gateway_requests WHERE call_id = ?1",
                [call_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((role, status, lease_id)) = request else {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::Refused {
                reason: GatewayRefusalReason::CallNotFound,
            });
        };
        if role != "follower" {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::Refused {
                reason: GatewayRefusalReason::NotFollower,
            });
        }
        if status == "cancelled" {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::AlreadyCancelled);
        }
        if status != "waiting" {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::Refused {
                reason: GatewayRefusalReason::AlreadyTerminal,
            });
        }
        transaction.execute(
            "UPDATE gateway_requests SET status = 'cancelled', reason = 'cancelled', updated_ms = ?2 WHERE call_id = ?1 AND status = 'waiting'",
            params![call_id, now],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(call_id),
            lease_id.as_deref(),
            None,
            "follower_cancelled",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayFollowerCancellation::Cancelled)
    }

    pub fn get_gateway_result(
        &self,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
    ) -> Result<Option<GatewayFullResultV1>> {
        validate_digest(gateway_result_id, "gateway result digest")?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results WHERE gateway_result_id = ?1 AND status = 'ready')",
            [gateway_result_id],
            |row| row.get(0),
        )?;
        if !exists {
            transaction.commit()?;
            return Ok(None);
        }
        let result =
            match self.load_gateway_result_with_origin_v1(&transaction, binding, gateway_result_id)
            {
                Ok(Some(result)) => result,
                Ok(None) | Err(_) => bail!(GatewayRefusalReason::ResultCorrupt.as_str()),
            };
        let dependencies = load_result_dependencies_v1(&transaction, gateway_result_id)?;
        let stdout = self.get_blob(&result.stdout_digest)?;
        let stderr = self.get_blob(&result.stderr_digest)?;
        if stdout.len() as u64 != result.stdout_bytes || stderr.len() as u64 != result.stderr_bytes
        {
            bail!("gateway result blob length mismatch");
        }
        transaction.commit()?;
        Ok(Some(GatewayFullResultV1 {
            gateway_result_id: gateway_result_id.to_owned(),
            result,
            stdout,
            stderr,
            dependencies,
        }))
    }

    /// Publish one freshly executed built-in read as context evidence without
    /// acquiring a cache lease. A direct observation can back a task fact, but
    /// its origin is never eligible for an exact hit or an in-flight join.
    pub fn publish_gateway_direct_observation_v1(
        &self,
        binding: &ValidatedGatewayReadV1,
        result_id: &str,
    ) -> Result<String> {
        let now = now_ms();
        if !freshness_is_current(binding, now) {
            bail!(GatewayRefusalReason::FreshnessExpired.as_str());
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let result = load_visible_result_tx(&transaction, result_id)?
            .ok_or_else(|| anyhow!(GatewayRefusalReason::ResultNotFound.as_str()))?;
        if result.request_key != direct_observation_request_key_v1(binding)
            || gateway_policy_digest(&result.policy_version) != binding.policy_digest()
            || !source_result_blobs_valid_v1(self, &result)
        {
            bail!(GatewayRefusalReason::BindingMismatch.as_str());
        }
        let dependencies = binding.dependencies();
        let gateway_result_id = direct_observation_content_digest_v1(binding, &result);
        let existing: Option<String> = transaction
            .query_row(
                "SELECT gateway_result_id FROM gateway_results
                 WHERE binding_digest = ?1 AND status = 'ready' AND origin = 'direct_observation'",
                [binding.binding_digest()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != gateway_result_id {
                bail!("direct context observation conflicts with prior publication");
            }
            transaction.commit()?;
            return Ok(existing);
        }
        let proof_digest = blake3::hash(result.proof_json.as_bytes())
            .to_hex()
            .to_string();
        transaction.execute(
            "INSERT INTO gateway_results (gateway_result_id, request_digest, state_digest,
             policy_digest, binding_digest, result_id, stdout_digest, stderr_digest,
             stdout_bytes, stderr_bytes, exit_code, duration_ms, result_policy_version,
             proof_digest, lease_id, status, created_ms, updated_ms, origin)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     'direct_observation', 'ready', ?15, ?15, 'direct_observation')",
            params![
                gateway_result_id,
                binding.request_digest(),
                binding.state_digest(),
                binding.policy_digest(),
                binding.binding_digest(),
                result.id,
                result.stdout_digest,
                result.stderr_digest,
                result.stdout_bytes,
                result.stderr_bytes,
                result.exit_code,
                result.duration_ms,
                result.policy_version,
                proof_digest,
                now,
            ],
        )?;
        for (ordinal, dependency) in dependencies.iter().enumerate() {
            transaction.execute(
                "INSERT INTO result_dependencies (gateway_result_id, ordinal,
                 dependency_key_digest, dependency_value_digest) VALUES (?1, ?2, ?3, ?4)",
                params![
                    gateway_result_id,
                    i64::try_from(ordinal)?,
                    dependency.key_digest,
                    dependency.value_digest,
                ],
            )?;
        }
        record_gateway_event_v1_tx(
            &transaction,
            None,
            None,
            Some(&gateway_result_id),
            "direct_observation_published",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(gateway_result_id)
    }

    /// Record a provider execution that bypassed coordinator authority. A
    /// caller may emit this before dispatch or after a fresh direct response;
    /// it does not imply success or reusable evidence.
    pub fn record_gateway_direct_execution(&self, record_request: bool) -> Result<()> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if record_request {
            record_gateway_event_v1_tx(
                &transaction,
                None,
                None,
                None,
                "requested",
                Some("direct"),
                0,
                now,
            )?;
        }
        record_gateway_event_v1_tx(
            &transaction,
            None,
            None,
            None,
            "executed",
            Some("direct"),
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Promote an acquisition candidate to a served route only after the
    /// caller has consumed the one-use proof, loaded the exact result, and
    /// revalidated repository state. Repeated promotion is idempotent.
    pub fn record_gateway_route_served(
        &self,
        call_id: &str,
        gateway_result_id: &str,
        route: GatewayServedRouteV1,
    ) -> Result<bool> {
        validate_digest(gateway_result_id, "gateway result digest")?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let request = transaction
            .query_row(
                "SELECT role, status, gateway_result_id, joined_lease_id FROM gateway_requests WHERE call_id = ?1",
                [call_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((role, status, request_result_id, lease_id)) = request else {
            transaction.commit()?;
            return Ok(false);
        };
        let visible: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results WHERE gateway_result_id = ?1 AND status = 'ready')",
            [gateway_result_id],
            |row| row.get(0),
        )?;
        let route_shape_valid = match route {
            GatewayServedRouteV1::Exact => lease_id.is_none(),
            GatewayServedRouteV1::Inflight => lease_id.is_some(),
        };
        if role != route.request_role()
            || status != "ready"
            || request_result_id.as_deref() != Some(gateway_result_id)
            || !route_shape_valid
            || !visible
        {
            transaction.commit()?;
            return Ok(false);
        }
        let already_recorded: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_events WHERE call_id = ?1 AND event_type = ?2)",
            params![call_id, route.event_type()],
            |row| row.get(0),
        )?;
        if already_recorded {
            transaction.commit()?;
            return Ok(false);
        }
        record_gateway_event_v1_tx(
            &transaction,
            Some(call_id),
            lease_id.as_deref(),
            Some(gateway_result_id),
            route.event_type(),
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Persist complete recipient delivery only from an opaque confirmation
    /// issued by the live MCP connection ledger. Callers cannot construct this
    /// authority from a result ID or content digest.
    #[cfg(test)]
    pub(crate) fn confirm_gateway_delivery_v1(
        &self,
        delivery: &ConfirmedDeliveryV1,
    ) -> Result<bool> {
        let binding = delivery.binding();
        validate_digest(delivery.gateway_result_id(), "gateway result digest")?;
        if delivery.gateway_result_id() != binding.result_digest()
            || binding.compaction_generation() > i64::MAX as u64
            || binding.streams().stdout_bytes() > i64::MAX as u64
            || binding.streams().stderr_bytes() > i64::MAX as u64
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let stored = transaction
            .query_row(
                "SELECT gateway_results.status, gateway_results.stdout_digest, gateway_results.stdout_bytes, gateway_results.stderr_digest, gateway_results.stderr_bytes, results.exit_code, results.quarantined, results.stdout_digest, results.stdout_bytes, results.stderr_digest, results.stderr_bytes FROM gateway_results JOIN results ON results.id = gateway_results.result_id WHERE gateway_results.gateway_result_id = ?1",
                [delivery.gateway_result_id()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, i32>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, u64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, u64>(10)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            status,
            gateway_stdout_digest,
            gateway_stdout_bytes,
            gateway_stderr_digest,
            gateway_stderr_bytes,
            exit_code,
            source_quarantined,
            source_stdout_digest,
            source_stdout_bytes,
            source_stderr_digest,
            source_stderr_bytes,
        )) = stored
        else {
            transaction.commit()?;
            bail!(GatewayRefusalReason::ResultNotFound.as_str());
        };
        let streams = binding.streams();
        if status != "ready"
            || source_quarantined
            || exit_code != streams.exact_status()
            || gateway_stdout_digest != streams.stdout_digest()
            || gateway_stdout_bytes != streams.stdout_bytes()
            || gateway_stderr_digest != streams.stderr_digest()
            || gateway_stderr_bytes != streams.stderr_bytes()
            || source_stdout_digest != streams.stdout_digest()
            || source_stdout_bytes != streams.stdout_bytes()
            || source_stderr_digest != streams.stderr_digest()
            || source_stderr_bytes != streams.stderr_bytes()
        {
            transaction.commit()?;
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO gateway_delivery_receipts (challenge_id, authorization_scope_digest, connection_digest, session_id, turn_id, agent_id, compaction_generation, call_digest, gateway_result_id, result_digest, exact_status, stdout_digest, stdout_bytes, stderr_digest, stderr_bytes, acknowledged_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                delivery.challenge_id(),
                binding.authorization_scope_digest(),
                binding.connection_digest(),
                binding.session_id(),
                binding.turn_id(),
                binding.agent_id(),
                binding.compaction_generation(),
                binding.call_digest(),
                delivery.gateway_result_id(),
                binding.result_digest(),
                streams.exact_status(),
                streams.stdout_digest(),
                streams.stdout_bytes(),
                streams.stderr_digest(),
                streams.stderr_bytes(),
                now
            ],
        )? == 1;
        if inserted {
            transaction.execute(
                "INSERT OR IGNORE INTO gateway_deliveries (session_id, turn_id, agent_id, compaction_epoch, gateway_result_id, presentation, estimated_tokens_avoided, delivered_ms) VALUES (?1, ?2, ?3, ?4, ?5, 'full', 0, ?6)",
                params![
                    binding.session_id(),
                    binding.turn_id(),
                    binding.agent_id(),
                    binding.compaction_generation(),
                    delivery.gateway_result_id(),
                    now
                ],
            )?;
        }
        transaction.commit()?;
        Ok(inserted)
    }

    /// Atomically persist an exact response-bound receipt and create the only
    /// retrieval grant derived from it. A crash can therefore leave neither
    /// object or both objects, never an acknowledged receipt with a lost
    /// follow-up authority.
    pub(crate) fn confirm_gateway_delivery_and_issue_retrieval_v2(
        &self,
        delivery: &ConfirmedDeliveryV1,
    ) -> Result<StoreRetrievalGrantV2> {
        let binding = delivery.binding();
        for digest in [
            delivery.gateway_result_id(),
            binding.authorization_scope_digest(),
            binding.connection_digest(),
            binding.connection_generation(),
            binding.call_digest(),
            binding.response_request_id_digest(),
            binding.result_digest(),
            binding.streams().stdout_digest(),
            binding.streams().stderr_digest(),
            binding.response_envelope_digest(),
        ] {
            validate_digest(digest, "delivery authority digest")?;
        }
        if delivery.gateway_result_id() != binding.result_digest()
            || binding.compaction_generation() > i64::MAX as u64
            || binding.streams().stdout_bytes() > i64::MAX as u64
            || binding.streams().stderr_bytes() > i64::MAX as u64
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }

        let now = now_ms();
        let expires_at_ms = now
            .checked_add(RETRIEVAL_GRANT_TTL_MS_V2)
            .ok_or_else(|| anyhow!(DeliveryAuthorityRefusalV1::InvalidBinding.code()))?;
        let receipt_id = format!("dr2_{}", Uuid::new_v4().simple());
        let grant_id = format!("gr2_{}", Uuid::new_v4().simple());
        let token = format!("rt2_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token_digest = delivery_token_digest_v2(&token);

        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let (result, _) =
            load_gateway_result_unbound_snapshot_v2(&transaction, delivery.gateway_result_id())?;
        let streams = binding.streams();
        if result.exit_code != streams.exact_status()
            || result.stdout_digest != streams.stdout_digest()
            || result.stdout_bytes != streams.stdout_bytes()
            || result.stderr_digest != streams.stderr_digest()
            || result.stderr_bytes != streams.stderr_bytes()
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        let stdout = self.get_blob(&result.stdout_digest)?;
        let stderr = self.get_blob(&result.stderr_digest)?;
        if stdout.len() as u64 != result.stdout_bytes || stderr.len() as u64 != result.stderr_bytes
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }

        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO gateway_delivery_receipts_v2 (receipt_id, challenge_id, authorization_scope_digest, connection_digest, connection_generation, session_id, turn_id, agent_id, compaction_generation, response_request_id_digest, call_digest, gateway_result_id, result_digest, exact_status, stdout_digest, stdout_bytes, stderr_digest, stderr_bytes, response_envelope_digest, presentation, source_receipt_id, acknowledged_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, 'full', NULL, ?20)",
            params![
                receipt_id,
                delivery.challenge_id(),
                binding.authorization_scope_digest(),
                binding.connection_digest(),
                binding.connection_generation(),
                binding.session_id(),
                binding.turn_id(),
                binding.agent_id(),
                binding.compaction_generation(),
                binding.response_request_id_digest(),
                binding.call_digest(),
                delivery.gateway_result_id(),
                binding.result_digest(),
                streams.exact_status(),
                streams.stdout_digest(),
                streams.stdout_bytes(),
                streams.stderr_digest(),
                streams.stderr_bytes(),
                binding.response_envelope_digest(),
                now,
            ],
        )?;
        if inserted != 1 {
            bail!(DeliveryAuthorityRefusalV1::AcknowledgementReplayed.code());
        }
        transaction.execute(
            "INSERT INTO gateway_retrieval_grants_v2 (grant_id, token_digest, source_receipt_id, authorization_scope_digest, connection_digest, connection_generation, session_id, turn_id, agent_id, compaction_generation, gateway_result_id, issued_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                grant_id,
                token_digest,
                receipt_id,
                binding.authorization_scope_digest(),
                binding.connection_digest(),
                binding.connection_generation(),
                binding.session_id(),
                binding.turn_id(),
                binding.agent_id(),
                binding.compaction_generation(),
                delivery.gateway_result_id(),
                now,
                expires_at_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(StoreRetrievalGrantV2 {
            grant_id,
            token,
            gateway_result_id: delivery.gateway_result_id().to_owned(),
            expires_at_ms,
        })
    }

    /// Consume a connection- and generation-bound observation grant in one
    /// transaction. This operation returns bytes only; it grants neither reuse
    /// nor execution authority.
    pub(crate) fn consume_gateway_retrieval_grant_v2(
        &self,
        authority: &RecipientRetrievalAuthorityV2,
    ) -> Result<GatewayFullResultV1> {
        if authority.grant_id().is_empty()
            || authority.grant_id().len() > 128
            || authority.token().is_empty()
            || authority.token().len() > 128
            || authority.expires_at_ms() <= 0
            || authority.compaction_generation() > i64::MAX as u64
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        validate_digest(authority.gateway_result_id(), "gateway result digest")?;
        for digest in [
            authority.authorization_scope_digest(),
            authority.connection_digest(),
            authority.connection_generation(),
        ] {
            validate_digest(digest, "retrieval authority digest")?;
        }

        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let grant = transaction
            .query_row(
                "SELECT token_digest, authorization_scope_digest, connection_digest, connection_generation, session_id, turn_id, agent_id, compaction_generation, gateway_result_id, expires_ms, consumed_ms, retired_ms, source_receipt_id FROM gateway_retrieval_grants_v2 WHERE grant_id = ?1",
                [authority.grant_id()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, String>(6)?, row.get::<_, u64>(7)?, row.get::<_, String>(8)?, row.get::<_, i64>(9)?, row.get::<_, Option<i64>>(10)?, row.get::<_, Option<i64>>(11)?, row.get::<_, String>(12)?)),
            )
            .optional()?;
        let Some((
            token_digest,
            scope,
            connection,
            connection_generation,
            session,
            turn,
            agent,
            generation,
            result_id,
            expires_ms,
            consumed_ms,
            retired_ms,
            source_receipt_id,
        )) = grant
        else {
            bail!(DeliveryAuthorityRefusalV1::Retired.code());
        };
        if consumed_ms.is_some() {
            bail!(DeliveryAuthorityRefusalV1::AcknowledgementReplayed.code());
        }
        if retired_ms.is_some() {
            bail!(DeliveryAuthorityRefusalV1::Retired.code());
        }
        if expires_ms <= now {
            transaction.execute(
                "UPDATE gateway_retrieval_grants_v2 SET retired_ms = ?2, retire_reason = 'expired' WHERE grant_id = ?1 AND consumed_ms IS NULL AND retired_ms IS NULL",
                params![authority.grant_id(), now],
            )?;
            transaction.commit()?;
            return Err(anyhow!(DeliveryAuthorityRefusalV1::Retired.code()));
        }
        if !constant_time_digest_eq_v2(
            token_digest.as_bytes(),
            delivery_token_digest_v2(authority.token()).as_bytes(),
        ) || scope != authority.authorization_scope_digest()
            || connection != authority.connection_digest()
            || connection_generation != authority.connection_generation()
            || session != authority.session_id()
            || turn != authority.turn_id()
            || agent != authority.agent_id()
            || generation != authority.compaction_generation()
            || result_id != authority.gateway_result_id()
            || expires_ms != authority.expires_at_ms()
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        let receipt_matches: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_delivery_receipts_v2 WHERE receipt_id = ?1 AND authorization_scope_digest = ?2 AND connection_digest = ?3 AND connection_generation = ?4 AND session_id = ?5 AND turn_id = ?6 AND agent_id = ?7 AND compaction_generation = ?8 AND gateway_result_id = ?9 AND result_digest = ?9 AND presentation = 'full' AND source_receipt_id IS NULL)",
            params![source_receipt_id, scope, connection, connection_generation, session, turn, agent, generation, result_id],
            |row| row.get(0),
        )?;
        if !receipt_matches {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }

        let integrity = (|| -> Result<_> {
            let (result, dependencies) =
                load_gateway_result_unbound_snapshot_v2(&transaction, &result_id)?;
            let stdout = self.get_blob(&result.stdout_digest)?;
            let stderr = self.get_blob(&result.stderr_digest)?;
            if stdout.len() as u64 != result.stdout_bytes
                || stderr.len() as u64 != result.stderr_bytes
            {
                bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
            }
            Ok((result, dependencies, stdout, stderr))
        })();
        let (result, dependencies, stdout, stderr) = match integrity {
            Ok(integrity) => integrity,
            Err(_) => {
                transaction.execute(
                    "UPDATE gateway_retrieval_grants_v2 SET retired_ms = ?2, retire_reason = 'integrity_refused' WHERE gateway_result_id = ?1 AND consumed_ms IS NULL AND retired_ms IS NULL",
                    params![result_id, now],
                )?;
                transaction.commit()?;
                return Err(anyhow!(DeliveryAuthorityRefusalV1::InvalidBinding.code()));
            }
        };
        let changed = transaction.execute(
            "UPDATE gateway_retrieval_grants_v2 SET consumed_ms = ?2 WHERE grant_id = ?1 AND consumed_ms IS NULL AND retired_ms IS NULL AND expires_ms > ?2",
            params![authority.grant_id(), now],
        )?;
        if changed != 1 {
            bail!(DeliveryAuthorityRefusalV1::Retired.code());
        }
        transaction.commit()?;
        Ok(GatewayFullResultV1 {
            gateway_result_id: result_id,
            result,
            stdout,
            stderr,
            dependencies,
        })
    }

    pub(crate) fn retire_gateway_retrieval_grants_v2(
        &self,
        retirement: &RecipientConnectionRetirementV2,
        reason: &'static str,
    ) -> Result<u64> {
        if !matches!(
            reason,
            "connection_closed" | "context_compacted" | "request_cancelled"
        ) || retirement.compaction_generation() > i64::MAX as u64
        {
            bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
        }
        for digest in [
            retirement.authorization_scope_digest(),
            retirement.connection_digest(),
            retirement.connection_generation(),
        ] {
            validate_digest(digest, "retrieval retirement digest")?;
        }
        let now = now_ms();
        let changed = self.conn.execute(
            "UPDATE gateway_retrieval_grants_v2 SET retired_ms = ?1, retire_reason = ?2 WHERE authorization_scope_digest = ?3 AND connection_digest = ?4 AND connection_generation = ?5 AND compaction_generation = ?6 AND consumed_ms IS NULL AND retired_ms IS NULL",
            params![now, reason, retirement.authorization_scope_digest(), retirement.connection_digest(), retirement.connection_generation(), retirement.compaction_generation()],
        )?;
        Ok(changed as u64)
    }

    pub fn clear_gateway_deliveries(&self, agent_context: &GatewayAgentContext) -> Result<u64> {
        if !agent_context.is_valid() || agent_context.compaction_epoch > i64::MAX as u64 {
            bail!(GatewayRefusalReason::InvalidAgentContext.as_str());
        }
        // This legacy, caller-constructed context may clear only the old
        // presentation cache. Recipient acknowledgements are immutable here:
        // deleting them will require a future consuming compaction authority
        // bound to the authenticated transport scope and generation change.
        let cleared = self.conn.execute(
            "DELETE FROM gateway_deliveries WHERE session_id = ?1 AND turn_id = ?2 AND agent_id = ?3 AND compaction_epoch = ?4",
            params![
                agent_context.session_id,
                agent_context.turn_id,
                agent_context.agent_id,
                agent_context.compaction_epoch
            ],
        )?;
        Ok(cleared as u64)
    }

    pub fn gateway_stats(&self) -> Result<GatewayStats> {
        verify_reasoning_metrics_accounting_v1(&self.conn)?;
        let mut stats = GatewayStats::default();
        let mut statement = self.conn.prepare(
            "SELECT event_type, COUNT(*), COALESCE(SUM(estimated_tokens_avoided), 0) FROM gateway_events GROUP BY event_type",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })?;
        for row in rows {
            let (event_type, count, tokens) = row?;
            match event_type.as_str() {
                "requested" => stats.requested += count,
                "executed" => stats.executed += count,
                "direct_observation_published" => stats.direct_observations_published += count,
                "exact_hit" => stats.exact_hits += count,
                "coverage_hit" => stats.coverage_hits += count,
                "inflight_join" => stats.inflight_joins += count,
                // Legacy compact-delivery events predate recipient-bound
                // acknowledgements. They remain audit history, but neither
                // their count nor their estimated savings is delivery proof.
                // A future compact path must derive these counters from an
                // authenticated receipt rather than from a producer event.
                "compact_delivery" => {
                    let _ = (count, tokens);
                }
                "stale_completion" | "divergent_result" | "binding_quarantined" => {
                    stats.stale_or_divergent_quarantines += count;
                }
                _ => {}
            }
        }
        let legacy_context_bytes: u64 = self.conn.query_row(
            "SELECT COALESCE(SUM(stdout_bytes + stderr_bytes), 0)
             FROM gateway_delivery_receipts",
            [],
            |row| row.get(0),
        )?;
        let (v2_context_bytes, compact_deliveries): (u64, u64) = self.conn.query_row(
            "WITH unique_deliveries AS (
                 SELECT response_envelope_digest, presentation,
                        MAX(stdout_bytes + stderr_bytes) AS delivered_bytes
                 FROM gateway_delivery_receipts_v2
                 GROUP BY response_envelope_digest, presentation
             )
             SELECT
                 COALESCE(SUM(CASE WHEN presentation = 'full' THEN delivered_bytes ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN presentation = 'compact' THEN 1 ELSE 0 END), 0)
             FROM unique_deliveries",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (confirmed_bytes_omitted, confirmed_tokens_avoided): (u64, u64) = self.conn.query_row(
            "WITH unique_savings AS (
                     SELECT receipts.response_envelope_digest,
                            MAX(savings.bytes_omitted) AS bytes_omitted,
                            MAX(savings.estimated_tokens_avoided) AS estimated_tokens_avoided
                     FROM gateway_delivery_savings_v2 AS savings
                     JOIN gateway_delivery_receipts_v2 AS receipts
                       ON receipts.receipt_id = savings.receipt_id
                     WHERE receipts.presentation = 'compact'
                     GROUP BY receipts.response_envelope_digest
                 )
                 SELECT COALESCE(SUM(bytes_omitted), 0),
                        COALESCE(SUM(estimated_tokens_avoided), 0)
                 FROM unique_savings",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let estimated_execution_time_saved_ms: u64 = self.conn.query_row(
            "SELECT COALESCE(SUM(gateway_results.duration_ms), 0)
             FROM gateway_events
             JOIN gateway_results
               ON gateway_results.gateway_result_id = gateway_events.gateway_result_id
             WHERE gateway_events.event_type IN ('exact_hit', 'coverage_hit', 'inflight_join')
               AND gateway_results.status = 'ready'",
            [],
            |row| row.get(0),
        )?;
        stats.facts_reused = stats.exact_hits.saturating_add(stats.coverage_hits);
        stats.investigations_avoided = stats.facts_reused.saturating_add(stats.inflight_joins);
        stats.provider_calls_avoided = stats.investigations_avoided;
        stats.invalidated_facts = stats.stale_or_divergent_quarantines;
        stats.context_bytes_delivered = legacy_context_bytes.saturating_add(v2_context_bytes);
        stats.compact_deliveries = compact_deliveries;
        stats.delivery_confirmed_bytes_omitted = confirmed_bytes_omitted;
        stats.confirmed_tokens_avoided = confirmed_tokens_avoided;
        stats.estimated_tokens_avoided = confirmed_tokens_avoided;
        // Quarantine is a prevented serve, not evidence that a false result
        // reached a caller. No durable false-hit event exists in schema v10.
        stats.false_hit_quarantines = 0;
        stats.estimated_execution_time_saved_ms = estimated_execution_time_saved_ms;
        Ok(stats)
    }

    #[cfg(test)]
    pub fn expire_abandoned_gateway_calls_at_for_test(&self, now: i64) -> Result<u64> {
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let expired = expire_gateway_leases_v1_tx(&transaction, now, None)?;
        transaction.commit()?;
        Ok(expired)
    }

    pub fn quarantine(&self, result_id: &str, reason: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE results SET quarantined = 1, quarantine_reason = ?2 WHERE id = ?1",
            params![result_id, reason],
        )?;
        self.record_event(
            None,
            Some(result_id),
            EventDisposition::Quarantined,
            reason,
            0,
            0,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &self,
        call_id: Option<&str>,
        result_id: Option<&str>,
        disposition: EventDisposition,
        reason_code: &str,
        metric_ms: u64,
        bytes_omitted: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (call_id, result_id, disposition, reason_code, elapsed_ms, bytes_omitted, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                call_id,
                result_id,
                disposition.as_str(),
                reason_code,
                metric_ms,
                bytes_omitted,
                now_ms(),
            ],
        )?;
        Ok(())
    }

    pub fn last_event(&self) -> Result<Option<(String, String, Option<String>)>> {
        self.conn
            .query_row(
                "SELECT disposition, reason_code, result_id FROM events ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context("read last event")
    }

    /// Explain the latest terminal product decision across both the explicit
    /// execution path and the repository gateway. Intermediate gateway events
    /// (request and candidate discovery) are deliberately excluded.
    pub fn latest_decision_explanation_v1(&self) -> Result<Option<LatestDecisionExplanationV1>> {
        let row: Option<(String, String, String, Option<String>, i64)> = self
            .conn
            .query_row(
                "SELECT source, raw_event, reason, result_id, created_ms FROM (
                     SELECT 'explicit' AS source, disposition AS raw_event,
                            reason_code AS reason, result_id, created_ms, id
                     FROM events
                     UNION ALL
                     SELECT 'gateway' AS source, event_type AS raw_event,
                            COALESCE(reason, 'unspecified') AS reason,
                            gateway_result_id AS result_id, created_ms, id
                     FROM gateway_events
                     WHERE event_type IN (
                         'executed', 'exact_hit', 'coverage_hit', 'inflight_join',
                         'stale_completion', 'divergent_result', 'binding_quarantined'
                     )
                 ) ORDER BY created_ms DESC, id DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .context("read latest product decision")?;
        Ok(
            row.map(|(source, raw_event, reason, result_id, created_ms)| {
                let decision = match (source.as_str(), raw_event.as_str(), reason.as_str()) {
                    ("explicit", "executed", _) => "executed",
                    ("gateway", "executed", reason) if reason != "direct" => "executed",
                    ("explicit", "replayed_full" | "replayed_compact", _)
                    | ("gateway", "exact_hit" | "coverage_hit", _) => "reused",
                    ("gateway", "inflight_join", _) => "joined",
                    ("explicit", "passed_through" | "bypassed_no_store", _)
                    | ("gateway", "executed", "direct") => "bypassed",
                    ("explicit", "quarantined", _)
                    | (
                        "gateway",
                        "stale_completion" | "divergent_result" | "binding_quarantined",
                        _,
                    ) => "refused",
                    _ => "unknown",
                };
                LatestDecisionExplanationV1 {
                    source,
                    decision: decision.to_owned(),
                    reason,
                    result_id,
                    disposition: raw_event.clone(),
                    raw_event,
                    created_ms,
                }
            }),
        )
    }

    pub fn context_ledger_stats_v1(&self) -> Result<ContextLedgerStatsV1> {
        let mut stats = ContextLedgerStatsV1::default();
        let mut statement = self
            .conn
            .prepare("SELECT kind, COUNT(*) FROM context_ledger_events_v1 GROUP BY kind")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })?;
        for row in rows {
            let (kind, count) = row?;
            stats.events = stats.events.saturating_add(count);
            match kind.as_str() {
                "verified_fact_admission" => stats.verified_facts_admitted = count,
                "unverified_suggestion" => stats.suggestions_published = count,
                "completed_observation" => stats.completed_observations = count,
                "explicit_unknown" => stats.explicit_unknowns = count,
                "result_reference" => stats.result_references_admitted = count,
                "invalidation" => stats.invalidation_events = count,
                _ => {}
            }
        }
        stats.current_verified_facts = self.conn.query_row(
            "SELECT COUNT(*) FROM context_ledger_fact_versions_v1 WHERE retired_event_sequence IS NULL",
            [],
            |row| row.get(0),
        )?;
        stats.current_result_references = self.conn.query_row(
            "SELECT COUNT(*) FROM context_ledger_result_references_v1 WHERE retired_event_sequence IS NULL",
            [],
            |row| row.get(0),
        )?;
        stats.active_work_leases = self.conn.query_row(
            "SELECT COUNT(*) FROM context_ledger_leases_v1 WHERE status = 'active'",
            [],
            |row| row.get(0),
        )?;
        stats.delivery_receipts = self.conn.query_row(
            "SELECT COUNT(*) FROM context_ledger_delivery_receipts_v1",
            [],
            |row| row.get(0),
        )?;
        stats.delivery_confirmed_bytes_omitted = self.conn.query_row(
            "SELECT COALESCE(SUM(bytes_omitted), 0) FROM context_ledger_delivery_savings_v1",
            [],
            |row| row.get(0),
        )?;
        stats.tasks = self
            .conn
            .query_row("SELECT COUNT(*) FROM context_tasks_v1", [], |row| {
                row.get(0)
            })?;
        stats.task_aliases =
            self.conn
                .query_row("SELECT COUNT(*) FROM context_task_aliases_v1", [], |row| {
                    row.get(0)
                })?;
        stats.task_aliases_converged = stats.task_aliases.saturating_sub(stats.tasks);
        Ok(stats)
    }

    /// Run one bounded lifecycle-maintenance pass immediately.
    ///
    /// Results, deliveries, quarantined evidence, and referenced CAS blobs are
    /// deliberately retained. Only expired pending calls, expired telemetry, and
    /// old tracked blobs with no result reference are eligible.
    pub fn cleanup(&mut self) -> Result<CleanupReport> {
        self.cleanup_at(now_ms(), true)
    }

    fn maybe_cleanup(&mut self) -> Result<()> {
        self.cleanup_at(now_ms(), false).map(|_| ())
    }

    fn cleanup_at(&mut self, now: i64, force: bool) -> Result<CleanupReport> {
        let blobs = self.blobs.clone();
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !force {
            let last: Option<i64> = transaction
                .query_row(
                    "SELECT completed_ms FROM maintenance WHERE name = 'lifecycle_cleanup'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if last.is_some_and(|last| now.saturating_sub(last) < CLEANUP_INTERVAL_MS) {
                transaction.commit()?;
                return Ok(CleanupReport::default());
            }
        }

        let pending_cutoff = now.saturating_sub(PENDING_CALL_TTL_MS);
        let event_cutoff = now.saturating_sub(EVENT_TTL_MS);
        let artifact_cutoff = now.saturating_sub(ORPHAN_ARTIFACT_TTL_MS);
        let pending_calls = transaction.execute(
            "DELETE FROM pending_calls WHERE id IN (SELECT id FROM pending_calls WHERE created_ms < ?1 ORDER BY created_ms ASC LIMIT ?2)",
            params![pending_cutoff, CLEANUP_ROW_LIMIT],
        )? as u64;
        let events = transaction.execute(
            "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE created_ms < ?1 ORDER BY created_ms ASC, id ASC LIMIT ?2)",
            params![event_cutoff, CLEANUP_ROW_LIMIT],
        )? as u64;
        let gateway_events = transaction.execute(
            "DELETE FROM gateway_events WHERE id IN (SELECT id FROM gateway_events WHERE created_ms < ?1 ORDER BY created_ms ASC, id ASC LIMIT ?2)",
            params![event_cutoff, CLEANUP_ROW_LIMIT],
        )? as u64;

        let candidates: Vec<String> = {
            let mut statement = transaction.prepare(
                r#"
                SELECT digest FROM artifacts
                WHERE created_ms < ?1
                  AND NOT EXISTS (
                    SELECT 1 FROM results
                    WHERE stdout_digest = artifacts.digest OR stderr_digest = artifacts.digest
                  )
                ORDER BY created_ms ASC, digest ASC LIMIT ?2
                "#,
            )?;
            statement
                .query_map(params![artifact_cutoff, CLEANUP_ARTIFACT_LIMIT], |row| {
                    row.get(0)
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut artifacts = 0_u64;
        for digest in candidates {
            let Ok(path) = blob_path_under(&blobs, &digest) else {
                // A malformed inventory row cannot name a filesystem target.
                transaction.execute("DELETE FROM artifacts WHERE digest = ?1", [&digest])?;
                artifacts += 1;
                continue;
            };
            let removable = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() => metadata
                    .modified()
                    .ok()
                    .and_then(system_time_ms)
                    .is_some_and(|modified| modified < artifact_cutoff),
                Ok(_) => false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if !removable {
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => continue,
            }
            transaction.execute("DELETE FROM artifacts WHERE digest = ?1", [&digest])?;
            artifacts += 1;
        }
        transaction.execute(
            "INSERT INTO maintenance (name, completed_ms) VALUES ('lifecycle_cleanup', ?1) ON CONFLICT(name) DO UPDATE SET completed_ms = excluded.completed_ms",
            [now],
        )?;
        transaction.commit()?;
        Ok(CleanupReport {
            pending_calls,
            events,
            gateway_events,
            artifacts,
        })
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let mut stats = StoreStats::default();
        let mut statement = self.conn.prepare(
            "SELECT disposition, COUNT(*), COALESCE(SUM(bytes_omitted), 0), COALESCE(SUM(elapsed_ms), 0) FROM events GROUP BY disposition",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        for row in rows {
            let (disposition, count, omitted, elapsed) = row?;
            match disposition.as_str() {
                "executed" => stats.executions += count,
                "replayed_full" => {
                    stats.full_replays += count;
                    stats.estimated_execution_ms_saved += elapsed;
                }
                "replayed_compact" => {
                    stats.compact_replays += count;
                    stats.duplicate_bytes_omitted += omitted;
                    stats.estimated_execution_ms_saved += elapsed;
                }
                "passed_through" | "bypassed_no_store" => stats.bypasses += count,
                "quarantined" => stats.quarantines += count,
                _ => {}
            }
        }
        let gateway = self.gateway_stats()?;
        stats.requested = gateway.requested;
        stats.executed = gateway.executed;
        stats.direct_observations_published = gateway.direct_observations_published;
        stats.exact_hits = gateway.exact_hits;
        stats.coverage_hits = gateway.coverage_hits;
        stats.inflight_joins = gateway.inflight_joins;
        stats.compact_deliveries = gateway.compact_deliveries;
        stats.estimated_tokens_avoided = gateway.estimated_tokens_avoided;
        stats.stale_or_divergent_quarantines = gateway.stale_or_divergent_quarantines;
        stats.facts_reused = gateway.facts_reused;
        stats.investigations_avoided = gateway.investigations_avoided;
        stats.provider_calls_avoided = gateway.provider_calls_avoided;
        stats.invalidated_facts = gateway.invalidated_facts;
        stats.context_bytes_delivered = gateway.context_bytes_delivered;
        stats.delivery_confirmed_bytes_omitted = gateway.delivery_confirmed_bytes_omitted;
        stats.confirmed_tokens_avoided = gateway.confirmed_tokens_avoided;
        stats.false_hit_quarantines = gateway.false_hit_quarantines;
        stats.estimated_execution_time_saved_ms = gateway.estimated_execution_time_saved_ms;
        let context = self.context_ledger_stats_v1()?;
        stats.context_events = context.events;
        stats.verified_facts_admitted = context.verified_facts_admitted;
        stats.suggestions_published = context.suggestions_published;
        stats.completed_observations = context.completed_observations;
        stats.explicit_unknowns = context.explicit_unknowns;
        stats.result_references_admitted = context.result_references_admitted;
        stats.invalidation_events = context.invalidation_events;
        stats.current_verified_facts = context.current_verified_facts;
        stats.current_result_references = context.current_result_references;
        stats.active_work_leases = context.active_work_leases;
        stats.context_delivery_receipts = context.delivery_receipts;
        stats.context_delivery_confirmed_bytes_omitted = context.delivery_confirmed_bytes_omitted;
        stats.context_tasks = context.tasks;
        stats.context_task_aliases = context.task_aliases;
        stats.context_task_aliases_converged = context.task_aliases_converged;
        Ok(stats)
    }
}

#[derive(Debug)]
struct GatewayLeaseRowV1 {
    lease_id: String,
    call_id: String,
    request_digest: String,
    state_digest: String,
    policy_digest: String,
    binding_digest: String,
    freshness_valid_until_ms: i64,
    owner: String,
    status: String,
    gateway_result_id: Option<String>,
    expires_ms: i64,
    execution_started_ms: Option<i64>,
    completed_ms: Option<i64>,
    lifecycle_generation: u64,
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_gateway_owner(owner: &str) -> Result<()> {
    if owner.is_empty()
        || owner.len() > GATEWAY_MAX_OWNER_BYTES
        || !owner.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
    {
        bail!(GatewayRefusalReason::InvalidOwner.as_str());
    }
    Ok(())
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn gateway_binding_digest(input: &GatewayCoordinatorInputV1) -> String {
    gateway_binding_content_digest(
        &input.request_digest,
        &input.state_digest,
        &input.policy_digest,
        &input.dependencies,
    )
}

fn gateway_binding_content_digest(
    request_digest: &str,
    state_digest: &str,
    policy_digest: &str,
    dependencies: &[GatewayDependencyV1],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.binding.v1\0");
    hash_field(&mut hasher, request_digest.as_bytes());
    hash_field(&mut hasher, state_digest.as_bytes());
    hash_field(&mut hasher, policy_digest.as_bytes());
    hash_field(&mut hasher, b"replay_eligible_read");
    hasher.update(&(dependencies.len() as u64).to_le_bytes());
    for dependency in dependencies {
        hash_field(&mut hasher, dependency.key_digest.as_bytes());
        hash_field(&mut hasher, dependency.value_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

pub fn gateway_policy_digest(policy_version: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.policy.v1\0");
    hash_field(&mut hasher, policy_version.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn freshness_is_current(binding: &ValidatedGatewayReadV1, now: i64) -> bool {
    binding.input.freshness.observed_at_ms <= now
        && now <= binding.input.freshness.valid_until_ms
        && binding
            .input
            .freshness
            .valid_until_ms
            .saturating_sub(binding.input.freshness.observed_at_ms)
            <= GATEWAY_FRESHNESS_MAX_MS
}

fn freshness_requirement_holds_v1(
    requirement: FreshnessRequirementV1,
    execution_started_ms: u64,
    observed_at_ms: u64,
) -> bool {
    let Some(age) = observed_at_ms.checked_sub(execution_started_ms) else {
        return false;
    };
    match requirement {
        FreshnessRequirementV1::Snapshot => true,
        FreshnessRequirementV1::MaxAgeMillis(maximum) => age <= maximum,
        // The store can validate its own rows, but it cannot manufacture a
        // fresh external-state revalidation. A later validator must issue a
        // separate bound proof before this mode can route to reuse.
        FreshnessRequirementV1::RequireRevalidation => false,
    }
}

fn valid_digest_v1(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn gateway_dependency_digest_v1(dependencies: &[GatewayDependencyV1]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.dependencies.v1\0");
    hasher.update(&(dependencies.len() as u64).to_le_bytes());
    for dependency in dependencies {
        hash_field(&mut hasher, dependency.key_digest.as_bytes());
        hash_field(&mut hasher, dependency.value_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

struct ContextRecipientRowV1 {
    turn_id: String,
    connection_generation: String,
    compaction_generation: u64,
    lifecycle_generation: u64,
    active: bool,
}

struct ContextEventFieldsV1<'a> {
    kind: ContextLedgerEventKindV1,
    subject_id: &'a str,
    subject_version: u64,
    summary: &'a str,
    value_digest: Option<&'a str>,
    result_id: Option<&'a str>,
    result_digest: Option<&'a str>,
    total_bytes: Option<u64>,
    duration_ms: Option<u64>,
}

fn resolve_task_alias_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    authorization_scope_digest: &str,
    requested_task_id: &str,
) -> Result<Option<String>> {
    transaction
        .query_row(
            "SELECT canonical_task_id FROM context_task_aliases_v1
             WHERE repository_id = ?1 AND workspace_id = ?2
               AND authorization_scope_digest = ?3 AND requested_task_id = ?4",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                requested_task_id
            ],
            |row| row.get(0),
        )
        .optional()
        .context("resolve task alias")
}

fn enforce_task_capacity_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
) -> Result<()> {
    let count: u64 = transaction.query_row(
        "SELECT COUNT(*) FROM context_tasks_v1
         WHERE repository_id = ?1 AND workspace_id = ?2",
        params![repository_id, workspace_id],
        |row| row.get(0),
    )?;
    if count >= MAX_CONTEXT_TASKS_PER_WORKSPACE_V1 {
        bail!("context_task_capacity_exceeded");
    }
    Ok(())
}

fn enforce_task_alias_capacity_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
) -> Result<()> {
    let count: u64 = transaction.query_row(
        "SELECT COUNT(*) FROM context_task_aliases_v1
         WHERE repository_id = ?1 AND workspace_id = ?2",
        params![repository_id, workspace_id],
        |row| row.get(0),
    )?;
    if count >= MAX_CONTEXT_TASK_ALIASES_PER_WORKSPACE_V1 {
        bail!("context_task_alias_capacity_exceeded");
    }
    Ok(())
}

fn ensure_task_graph_edge_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    authorization_scope_digest: &str,
    source_task_id: &str,
    target_task_id: &str,
) -> Result<()> {
    if source_task_id == target_task_id {
        bail!("task_graph_self_edge");
    }
    let (cycle, maximum_depth): (bool, u64) = transaction.query_row(
        "WITH RECURSIVE reachable(task_id, depth) AS (
             SELECT ?5, 1
             UNION ALL
             SELECT relation.target_task_id, reachable.depth + 1
             FROM reachable
             JOIN context_task_relations_v1 AS relation
               ON relation.repository_id = ?1 AND relation.workspace_id = ?2
              AND relation.authorization_scope_digest = ?3
              AND relation.source_task_id = reachable.task_id
             WHERE reachable.depth <= ?6
         )
         SELECT COALESCE(MAX(task_id = ?4), 0), COALESCE(MAX(depth), 1)
         FROM reachable",
        params![
            repository_id,
            workspace_id,
            authorization_scope_digest,
            source_task_id,
            target_task_id,
            MAX_TASK_GRAPH_DEPTH_V1
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if cycle {
        bail!("task_graph_cycle");
    }
    if maximum_depth >= MAX_TASK_GRAPH_DEPTH_V1 as u64 {
        bail!("task_graph_depth_exceeded");
    }
    Ok(())
}

fn insert_task_relations_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    authorization_scope_digest: &str,
    source_task_id: &str,
    definition: &TaskDefinitionV1,
    now: i64,
) -> Result<()> {
    let insert = |kind: TaskRelationKindV1, target: &str, ordinal: usize| -> Result<()> {
        transaction.execute(
            "INSERT INTO context_task_relations_v1 (
                repository_id, workspace_id, authorization_scope_digest,
                source_task_id, relation_kind, target_task_id, ordinal, created_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                source_task_id,
                kind.code(),
                target,
                ordinal,
                now
            ],
        )?;
        Ok(())
    };
    if let Some(parent) = definition.parent_task_id() {
        insert(TaskRelationKindV1::Parent, parent, 0)?;
    }
    for (ordinal, dependency) in definition.dependency_task_ids().iter().enumerate() {
        insert(TaskRelationKindV1::Dependency, dependency, ordinal)?;
    }
    if let Some(supersedes) = definition.supersedes_task_id() {
        insert(TaskRelationKindV1::Supersedes, supersedes, 0)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_task_transition_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    authorization_scope_digest: &str,
    canonical_task_id: &str,
    from_state: Option<TaskStateV1>,
    to_state: TaskStateV1,
    state_generation: u64,
    lease_id: Option<&str>,
    identity: Option<&ContextLedgerIdentityV1>,
    reason: &str,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO context_task_transitions_v1 (
            repository_id, workspace_id, authorization_scope_digest,
            canonical_task_id, from_state, to_state, state_generation,
            lease_id, agent_id, session_id, lifecycle_generation, reason, created_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            repository_id,
            workspace_id,
            authorization_scope_digest,
            canonical_task_id,
            from_state.map(TaskStateV1::code),
            to_state.code(),
            state_generation,
            lease_id,
            identity.map(ContextLedgerIdentityV1::agent_id),
            identity.map(ContextLedgerIdentityV1::session_id),
            identity.map(ContextLedgerIdentityV1::lifecycle_generation),
            reason,
            now
        ],
    )?;
    Ok(())
}

fn load_task_record_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    authorization_scope_digest: &str,
    canonical_task_id: &str,
    requested_task_id: &str,
) -> Result<TaskRecordV1> {
    type TaskRow = (
        String,
        String,
        Option<String>,
        String,
        u64,
        String,
        u64,
        i64,
        i64,
    );
    let row: TaskRow = transaction.query_row(
        "SELECT prompt_text, prompt_digest, definition_digest,
                acceptance_criteria_json, revision, state, state_generation,
                created_ms, updated_ms
         FROM context_tasks_v1
         WHERE repository_id = ?1 AND workspace_id = ?2
           AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
        params![
            repository_id,
            workspace_id,
            authorization_scope_digest,
            canonical_task_id
        ],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        },
    )?;
    if context_task_prompt_digest_v1(&row.0) != row.1 {
        bail!("context_task_corrupt");
    }
    let acceptance_criteria: Vec<String> =
        serde_json::from_str(&row.3).context("context_task_corrupt")?;
    let mut parent = None;
    let mut supersedes = None;
    let mut dependencies = Vec::new();
    {
        let mut statement = transaction.prepare(
            "SELECT relation_kind, target_task_id, ordinal
             FROM context_task_relations_v1
             WHERE repository_id = ?1 AND workspace_id = ?2
               AND authorization_scope_digest = ?3 AND source_task_id = ?4
             ORDER BY relation_kind, ordinal, target_task_id",
        )?;
        let relations = statement
            .query_map(
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    canonical_task_id
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (kind, target, ordinal) in relations {
            match TaskRelationKindV1::parse(&kind)? {
                TaskRelationKindV1::Parent if ordinal == 0 && parent.is_none() => {
                    parent = Some(target)
                }
                TaskRelationKindV1::Dependency if ordinal == dependencies.len() as u64 => {
                    dependencies.push(target)
                }
                TaskRelationKindV1::Supersedes if ordinal == 0 && supersedes.is_none() => {
                    supersedes = Some(target)
                }
                _ => bail!("context_task_relation_corrupt"),
            }
        }
    }
    let definition = TaskDefinitionV1::new(
        &row.0,
        acceptance_criteria,
        parent,
        dependencies,
        supersedes,
    )?;
    if row.2.as_deref() != Some(definition.definition_digest()) {
        bail!("context_task_corrupt");
    }
    let state = TaskStateV1::parse(&row.5)?;
    let blockers = dependency_blockers_tx_v1(
        transaction,
        repository_id,
        workspace_id,
        authorization_scope_digest,
        definition.dependency_task_ids(),
    )?;
    Ok(TaskRecordV1 {
        canonical_task_id: canonical_task_id.to_owned(),
        requested_task_id: requested_task_id.to_owned(),
        definition,
        revision: row.4,
        state,
        state_generation: row.6,
        blockers,
        created_ms: row.7,
        updated_ms: row.8,
    })
}

fn dependency_blockers_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    authorization_scope_digest: &str,
    dependencies: &[String],
) -> Result<Vec<TaskBlockerV1>> {
    let mut blockers = Vec::new();
    for dependency in dependencies {
        let state = transaction
            .query_row(
                "SELECT state FROM context_tasks_v1
                 WHERE repository_id = ?1 AND workspace_id = ?2
                   AND authorization_scope_digest = ?3 AND canonical_task_id = ?4",
                params![
                    repository_id,
                    workspace_id,
                    authorization_scope_digest,
                    dependency
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| anyhow!("context_task_relation_corrupt"))?;
        let state = TaskStateV1::parse(&state)?;
        if state != TaskStateV1::Completed {
            let reason = match state {
                TaskStateV1::Failed => "dependency_failed",
                TaskStateV1::Cancelled => "dependency_cancelled",
                _ => "dependency_incomplete",
            };
            blockers.push(TaskBlockerV1 {
                task_id: dependency.clone(),
                state,
                reason: reason.to_owned(),
            });
        }
    }
    Ok(blockers)
}

fn load_task_transitions_tx_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    authorization_scope_digest: &str,
    canonical_task_id: &str,
) -> Result<Vec<TaskTransitionV1>> {
    type TransitionRow = (
        u64,
        Option<String>,
        String,
        u64,
        Option<String>,
        String,
        i64,
    );
    let mut statement = transaction.prepare(
        "SELECT sequence, from_state, to_state, state_generation, lease_id, reason, created_ms
         FROM context_task_transitions_v1
         WHERE repository_id = ?1 AND workspace_id = ?2
           AND authorization_scope_digest = ?3 AND canonical_task_id = ?4
         ORDER BY sequence",
    )?;
    statement
        .query_map(
            params![
                repository_id,
                workspace_id,
                authorization_scope_digest,
                canonical_task_id
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?
        .map(|row| {
            let row: TransitionRow = row?;
            Ok(TaskTransitionV1 {
                sequence: row.0,
                task_id: canonical_task_id.to_owned(),
                from_state: row.1.as_deref().map(TaskStateV1::parse).transpose()?,
                to_state: TaskStateV1::parse(&row.2)?,
                state_generation: row.3,
                lease_id: row.4,
                reason: row.5,
                created_ms: row.6,
            })
        })
        .collect()
}

fn task_lease_summary_v1(prompt: &str) -> String {
    let prefix = "task intent: ";
    let mut summary = String::with_capacity(1024.min(prompt.len().saturating_add(prefix.len())));
    summary.push_str(prefix);
    for character in prompt.chars() {
        if summary.len().saturating_add(character.len_utf8()) > 1024 {
            break;
        }
        summary.push(character);
    }
    summary
}

fn task_row_logical_bytes_v1(task_id: &str, prompt: &str, acceptance_json: &str) -> u64 {
    (task_id.len() as u64)
        .saturating_add(prompt.len() as u64)
        .saturating_add(acceptance_json.len() as u64)
        .saturating_add(256)
}

fn task_alias_logical_bytes_v1(requested: &str, canonical: &str) -> u64 {
    (requested.len() as u64)
        .saturating_add(canonical.len() as u64)
        .saturating_add(128)
}

fn task_relation_logical_bytes_v1(source: &str, target: &str) -> u64 {
    (source.len() as u64)
        .saturating_add(target.len() as u64)
        .saturating_add(128)
}

fn task_transition_logical_bytes_v1(task_id: &str, reason: &str, lease_id: Option<&str>) -> u64 {
    (task_id.len() as u64)
        .saturating_add(reason.len() as u64)
        .saturating_add(lease_id.map_or(0, |lease| lease.len() as u64))
        .saturating_add(256)
}

fn context_event_logical_bytes_v1(subject_id: &str, summary: &str) -> u64 {
    (subject_id.len() as u64)
        .saturating_add(summary.len() as u64)
        .saturating_add(512)
}

fn task_quota_checksum_v1(
    repository_id: &str,
    workspace_id: &str,
    task_context_bytes: u64,
    workspace_state_bytes: u64,
    maintenance_mode: bool,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.context-workspace-quota.v1\0");
    hash_field(&mut hasher, repository_id.as_bytes());
    hash_field(&mut hasher, workspace_id.as_bytes());
    hasher.update(&task_context_bytes.to_le_bytes());
    hasher.update(&workspace_state_bytes.to_le_bytes());
    hasher.update(&[u8::from(maintenance_mode)]);
    hasher.finalize().to_hex().to_string()
}

fn reserve_task_context_bytes_v1(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    additional_bytes: u64,
) -> Result<()> {
    let existing = transaction
        .query_row(
            "SELECT task_context_bytes, workspace_state_bytes, maintenance_mode,
                    counter_checksum
             FROM context_workspace_quota_v1
             WHERE repository_id = ?1 AND workspace_id = ?2",
            params![repository_id, workspace_id],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let (current_task_bytes, current_workspace_bytes, maintenance_mode) = existing
        .as_ref()
        .map_or((0, 0, false), |row| (row.0, row.1, row.2));
    if let Some((task_bytes, workspace_bytes, maintenance, checksum)) = existing {
        if checksum
            != task_quota_checksum_v1(
                repository_id,
                workspace_id,
                task_bytes,
                workspace_bytes,
                maintenance,
            )
        {
            bail!("task_quota_counter_corrupt");
        }
    }
    if maintenance_mode {
        bail!("workspace_maintenance_mode");
    }
    let next_task_bytes = current_task_bytes
        .checked_add(additional_bytes)
        .ok_or_else(|| anyhow!("task_context_quota_exceeded"))?;
    let stored_result_bytes = stored_result_logical_bytes_v1(transaction)?;
    let next_workspace_bytes = next_task_bytes
        .checked_add(stored_result_bytes)
        .ok_or_else(|| anyhow!("workspace_state_quota_exceeded"))?;
    if next_task_bytes > MAX_TASK_CONTEXT_LOGICAL_BYTES_V1 {
        bail!("task_context_quota_exceeded");
    }
    if next_workspace_bytes > MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1 {
        bail!("workspace_state_quota_exceeded");
    }
    let checksum = task_quota_checksum_v1(
        repository_id,
        workspace_id,
        next_task_bytes,
        next_workspace_bytes,
        false,
    );
    transaction.execute(
        "INSERT INTO context_workspace_quota_v1 (
            repository_id, workspace_id, task_context_bytes, workspace_state_bytes,
            maintenance_mode, counter_checksum, reconciled_ms
         ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)
         ON CONFLICT(repository_id, workspace_id) DO UPDATE SET
            task_context_bytes = excluded.task_context_bytes,
            workspace_state_bytes = excluded.workspace_state_bytes,
            maintenance_mode = 0,
            counter_checksum = excluded.counter_checksum,
            reconciled_ms = excluded.reconciled_ms",
        params![
            repository_id,
            workspace_id,
            next_task_bytes,
            next_workspace_bytes,
            checksum,
            now_ms()
        ],
    )?;
    let _ = current_workspace_bytes;
    Ok(())
}

fn stored_result_logical_bytes_v1(transaction: &Transaction<'_>) -> Result<u64> {
    let complete_columns: u64 = transaction.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('results')
         WHERE name IN ('stdout_bytes', 'stderr_bytes')",
        [],
        |row| row.get(0),
    )?;
    if complete_columns != 2 {
        return Ok(0);
    }
    let result_bytes: u64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(stdout_bytes + stderr_bytes), 0) FROM results",
            [],
            |row| row.get(0),
        )
        .context("count logical result bytes")?;
    let recipes_exist: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                       WHERE type = 'table' AND name = 'gateway_context_source_recipes_v1')",
        [],
        |row| row.get(0),
    )?;
    let recipe_bytes: u64 = if recipes_exist {
        transaction.query_row(
            "SELECT COALESCE(SUM(length(CAST(plan_json AS BLOB)) + 256), 0)
             FROM gateway_context_source_recipes_v1",
            [],
            |row| row.get(0),
        )?
    } else {
        0
    };
    result_bytes
        .checked_add(recipe_bytes)
        .ok_or_else(|| anyhow!("workspace_state_quota_exceeded"))
}

fn enforce_workspace_result_capacity_v1(
    transaction: &Transaction<'_>,
    additional_bytes: u64,
) -> Result<()> {
    let current_results = stored_result_logical_bytes_v1(transaction)?;
    let next_results = current_results
        .checked_add(additional_bytes)
        .ok_or_else(|| anyhow!("workspace_state_quota_exceeded"))?;
    if next_results > MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1 {
        bail!("workspace_state_quota_exceeded");
    }
    let mut statement = transaction.prepare(
        "SELECT repository_id, workspace_id, task_context_bytes,
                workspace_state_bytes, maintenance_mode, counter_checksum
         FROM context_workspace_quota_v1",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (repository, workspace, task_bytes, workspace_bytes, maintenance, checksum) in rows {
        if checksum
            != task_quota_checksum_v1(
                &repository,
                &workspace,
                task_bytes,
                workspace_bytes,
                maintenance,
            )
        {
            bail!("task_quota_counter_corrupt");
        }
        if maintenance {
            bail!("workspace_maintenance_mode");
        }
        if task_bytes.saturating_add(next_results) > MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1 {
            bail!("workspace_state_quota_exceeded");
        }
    }
    Ok(())
}

fn refresh_workspace_state_quota_v1_tx(transaction: &Transaction<'_>, now: i64) -> Result<()> {
    let result_bytes = stored_result_logical_bytes_v1(transaction)?;
    let scopes = {
        let mut statement = transaction.prepare(
            "SELECT repository_id, workspace_id, task_context_bytes
             FROM context_workspace_quota_v1",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (repository, workspace, task_bytes) in scopes {
        let workspace_bytes = task_bytes.saturating_add(result_bytes);
        let maintenance = task_bytes > MAX_TASK_CONTEXT_LOGICAL_BYTES_V1
            || workspace_bytes > MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1;
        let checksum = task_quota_checksum_v1(
            &repository,
            &workspace,
            task_bytes,
            workspace_bytes,
            maintenance,
        );
        transaction.execute(
            "UPDATE context_workspace_quota_v1
             SET workspace_state_bytes = ?3, maintenance_mode = ?4,
                 counter_checksum = ?5, reconciled_ms = ?6
             WHERE repository_id = ?1 AND workspace_id = ?2",
            params![
                repository,
                workspace,
                workspace_bytes,
                maintenance,
                checksum,
                now
            ],
        )?;
    }
    Ok(())
}

fn reconcile_all_task_quotas_v1_tx(transaction: &Transaction<'_>, now: i64) -> Result<()> {
    let scopes = {
        let mut statement = transaction.prepare(
            "SELECT repository_id, workspace_id FROM context_tasks_v1
             UNION
             SELECT repository_id, workspace_id FROM context_ledger_events_v1
             ORDER BY repository_id, workspace_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (repository_id, workspace_id) in scopes {
        reconcile_task_quota_scope_v1_tx(transaction, &repository_id, &workspace_id, now)?;
    }
    Ok(())
}

fn reconcile_task_quota_scope_v1_tx(
    transaction: &Transaction<'_>,
    repository_id: &str,
    workspace_id: &str,
    now: i64,
) -> Result<()> {
    let task_bytes: u64 = transaction.query_row(
        "SELECT
            COALESCE((SELECT SUM(length(canonical_task_id) + length(CAST(prompt_text AS BLOB)) +
                        length(CAST(acceptance_criteria_json AS BLOB)) + 256)
                      FROM context_tasks_v1
                      WHERE repository_id = ?1 AND workspace_id = ?2), 0) +
            COALESCE((SELECT SUM(length(requested_task_id) + length(canonical_task_id) + 128)
                      FROM context_task_aliases_v1
                      WHERE repository_id = ?1 AND workspace_id = ?2), 0) +
            COALESCE((SELECT SUM(length(source_task_id) + length(target_task_id) + 128)
                      FROM context_task_relations_v1
                      WHERE repository_id = ?1 AND workspace_id = ?2), 0) +
            COALESCE((SELECT SUM(length(canonical_task_id) + length(CAST(reason AS BLOB)) +
                        COALESCE(length(lease_id), 0) + 256)
                      FROM context_task_transitions_v1
                      WHERE repository_id = ?1 AND workspace_id = ?2), 0) +
            COALESCE((SELECT SUM(length(subject_id) + length(CAST(summary AS BLOB)) + 512)
                      FROM context_ledger_events_v1
                      WHERE repository_id = ?1 AND workspace_id = ?2), 0) +
            COALESCE((SELECT COUNT(*) * 512
                      FROM context_ledger_delivery_receipts_v1
                      WHERE repository_id = ?1 AND workspace_id = ?2), 0)",
        params![repository_id, workspace_id],
        |row| row.get(0),
    )?;
    let stored_result_bytes = stored_result_logical_bytes_v1(transaction)?;
    let workspace_bytes = task_bytes.saturating_add(stored_result_bytes);
    let maintenance_mode = task_bytes > MAX_TASK_CONTEXT_LOGICAL_BYTES_V1
        || workspace_bytes > MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1;
    let checksum = task_quota_checksum_v1(
        repository_id,
        workspace_id,
        task_bytes,
        workspace_bytes,
        maintenance_mode,
    );
    transaction.execute(
        "INSERT INTO context_workspace_quota_v1 (
            repository_id, workspace_id, task_context_bytes, workspace_state_bytes,
            maintenance_mode, counter_checksum, reconciled_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(repository_id, workspace_id) DO UPDATE SET
            task_context_bytes = excluded.task_context_bytes,
            workspace_state_bytes = excluded.workspace_state_bytes,
            maintenance_mode = excluded.maintenance_mode,
            counter_checksum = excluded.counter_checksum,
            reconciled_ms = excluded.reconciled_ms",
        params![
            repository_id,
            workspace_id,
            task_bytes,
            workspace_bytes,
            maintenance_mode,
            checksum,
            now
        ],
    )?;
    Ok(())
}

fn validate_context_task_selector_v1(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b' ')
        })
    {
        bail!("invalid_context_task_selector");
    }
    Ok(())
}

fn context_task_prompt_digest_v1(prompt: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.context.task-prompt.v1\0");
    hash_field(&mut hasher, prompt.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn validate_context_identity_v1(identity: &ContextLedgerIdentityV1) -> Result<()> {
    if identity.schema_version() != crate::agent_gateway::context::CONTEXT_LEDGER_SCHEMA_VERSION_V1
        || identity.compaction_generation() > i64::MAX as u64
        || identity.lifecycle_generation() == 0
        || identity.lifecycle_generation() > i64::MAX as u64
    {
        bail!(GatewayRefusalReason::InvalidAgentContext.as_str());
    }
    Ok(())
}

fn validate_context_envelope_v1(envelope_digest: &str, subject_version: u64) -> Result<()> {
    validate_digest(envelope_digest, "context envelope digest")?;
    if subject_version == 0 || subject_version > i64::MAX as u64 {
        bail!(ReasoningContextRefusalV1::InvalidGeneration.code());
    }
    Ok(())
}

fn context_recipient_row_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<Option<ContextRecipientRowV1>> {
    transaction
        .query_row(
            "SELECT turn_id, connection_generation, compaction_generation,
                    lifecycle_generation, active
             FROM context_ledger_recipients_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND authorization_scope_digest = ?4 AND agent_id = ?5 AND session_id = ?6",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                identity.agent_id(),
                identity.session_id()
            ],
            |row| {
                Ok(ContextRecipientRowV1 {
                    turn_id: row.get(0)?,
                    connection_generation: row.get(1)?,
                    compaction_generation: row.get(2)?,
                    lifecycle_generation: row.get(3)?,
                    active: row.get(4)?,
                })
            },
        )
        .optional()
        .context("read current context recipient")
}

fn ensure_current_context_recipient_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<()> {
    validate_context_identity_v1(identity)?;
    let Some(current) = context_recipient_row_v1(transaction, identity)? else {
        bail!(GatewayRefusalReason::InvalidAgentContext.as_str());
    };
    if !current.active
        || current.turn_id != identity.turn_id()
        || current.connection_generation != identity.connection_generation()
        || current.compaction_generation != identity.compaction_generation()
        || current.lifecycle_generation != identity.lifecycle_generation()
    {
        bail!(GatewayRefusalReason::InvalidAgentContext.as_str());
    }
    Ok(())
}

fn context_event_canonical_digest_v1(
    identity: &ContextLedgerIdentityV1,
    fields: &ContextEventFieldsV1<'_>,
    payload: &[u8],
    sources: &[ContextVerifiedObservationV1],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.context-ledger.event.v1\0");
    for value in [
        identity.repository_id(),
        identity.workspace_id(),
        identity.task_id(),
        identity.authorization_scope_digest(),
        identity.agent_id(),
        identity.session_id(),
        identity.turn_id(),
        identity.connection_generation(),
        fields.kind.code(),
        fields.subject_id,
        fields.summary,
        fields.value_digest.unwrap_or(""),
        fields.result_id.unwrap_or(""),
        fields.result_digest.unwrap_or(""),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    for number in [
        identity.compaction_generation(),
        identity.lifecycle_generation(),
        fields.subject_version,
        fields.total_bytes.unwrap_or(0),
        fields.duration_ms.unwrap_or(0),
    ] {
        hasher.update(&number.to_le_bytes());
    }
    hash_field(&mut hasher, payload);
    hasher.update(&(sources.len() as u64).to_le_bytes());
    for source in sources {
        hash_field(&mut hasher, source.source.result_id().as_bytes());
        hash_field(&mut hasher, source.source.result_digest().as_bytes());
        hash_field(&mut hasher, source.source.locator().as_bytes());
        hash_field(&mut hasher, source.binding_digest.as_bytes());
        for dependency in &source.dependencies {
            hash_field(&mut hasher, dependency.key_digest.as_bytes());
            hash_field(&mut hasher, dependency.value_digest.as_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn context_verified_fact_value_digest_v1(sources: &[ContextVerifiedObservationV1]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.context-ledger.verified-fact-value.v1\0");
    hasher.update(&(sources.len() as u64).to_le_bytes());
    for source in sources {
        hash_field(&mut hasher, source.source.result_id().as_bytes());
        hash_field(&mut hasher, source.source.result_digest().as_bytes());
        hash_field(&mut hasher, source.source.locator().as_bytes());
        hash_field(&mut hasher, source.binding_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn context_event_input_fields_v1(
    input: &ContextLedgerEventInputV1,
) -> Result<(
    ContextEventFieldsV1<'_>,
    Vec<u8>,
    &[ContextVerifiedObservationV1],
)> {
    match input {
        ContextLedgerEventInputV1::UnverifiedSuggestion(suggestion) => {
            screen_sensitive_text_v1(suggestion.statement())?;
            Ok((
                ContextEventFieldsV1 {
                    kind: ContextLedgerEventKindV1::UnverifiedSuggestion,
                    subject_id: suggestion.subject(),
                    subject_version: 1,
                    summary: suggestion.statement(),
                    value_digest: Some(suggestion.relevance_digest()),
                    result_id: None,
                    result_digest: None,
                    total_bytes: None,
                    duration_ms: None,
                },
                serde_json::to_vec(suggestion)?,
                &[],
            ))
        }
        ContextLedgerEventInputV1::CompletedObservation {
            observation,
            verified_sources,
        } => {
            if observation.sources().len() != verified_sources.len()
                || observation
                    .sources()
                    .iter()
                    .zip(verified_sources)
                    .any(|(source, verified)| source != verified.source())
                || !verified_sources.iter().any(|verified| {
                    verified.source.result_id() == observation.retrieval().result_id()
                        && verified.source.result_digest()
                            == observation.retrieval().result_digest()
                        && verified.total_bytes == observation.retrieval().total_bytes()
                })
            {
                bail!("completed observation sources are not exact verified sources");
            }
            Ok((
                ContextEventFieldsV1 {
                    kind: ContextLedgerEventKindV1::CompletedObservation,
                    subject_id: observation.observation_id(),
                    subject_version: 1,
                    summary: observation.summary(),
                    value_digest: Some(observation.retrieval().result_digest()),
                    result_id: Some(observation.retrieval().result_id()),
                    result_digest: Some(observation.retrieval().result_digest()),
                    total_bytes: Some(observation.retrieval().total_bytes()),
                    duration_ms: Some(observation.duration_ms()),
                },
                serde_json::to_vec(observation)?,
                verified_sources,
            ))
        }
        ContextLedgerEventInputV1::FailedApproach {
            approach,
            verified_sources,
        } => {
            screen_sensitive_text_v1(approach.verified_cause())?;
            if approach.sources().len() != verified_sources.len()
                || approach
                    .sources()
                    .iter()
                    .zip(verified_sources)
                    .any(|(source, verified)| source != verified.source())
            {
                bail!("failed approach sources are not exact verified sources");
            }
            Ok((
                ContextEventFieldsV1 {
                    kind: ContextLedgerEventKindV1::FailedApproach,
                    subject_id: approach.approach_id(),
                    subject_version: 1,
                    summary: approach.verified_cause(),
                    value_digest: None,
                    result_id: None,
                    result_digest: None,
                    total_bytes: None,
                    duration_ms: None,
                },
                serde_json::to_vec(approach)?,
                verified_sources,
            ))
        }
        ContextLedgerEventInputV1::ExplicitUnknown(unknown) => {
            screen_sensitive_text_v1(unknown.explanation())?;
            Ok((
                ContextEventFieldsV1 {
                    kind: ContextLedgerEventKindV1::ExplicitUnknown,
                    subject_id: unknown.subject(),
                    subject_version: 1,
                    summary: unknown.explanation(),
                    value_digest: None,
                    result_id: None,
                    result_digest: None,
                    total_bytes: None,
                    duration_ms: None,
                },
                serde_json::to_vec(unknown)?,
                &[],
            ))
        }
        ContextLedgerEventInputV1::ResultReference {
            reference,
            reference_version,
            verified_sources,
        } => {
            if verified_sources.is_empty()
                || !verified_sources.iter().any(|verified| {
                    verified.source.result_id() == reference.result_id()
                        && verified.source.result_digest() == reference.result_digest()
                        && verified.total_bytes == reference.total_bytes()
                })
            {
                bail!(ReasoningContextRefusalV1::SourceReferenceBound.code());
            }
            Ok((
                ContextEventFieldsV1 {
                    kind: ContextLedgerEventKindV1::ResultReference,
                    subject_id: reference.result_id(),
                    subject_version: *reference_version,
                    summary: "verified result reference; retrieval authority is still required",
                    value_digest: Some(reference.result_digest()),
                    result_id: Some(reference.result_id()),
                    result_digest: Some(reference.result_digest()),
                    total_bytes: Some(reference.total_bytes()),
                    duration_ms: None,
                },
                serde_json::to_vec(reference)?,
                verified_sources,
            ))
        }
        ContextLedgerEventInputV1::Retirement {
            subject_id,
            subject_version,
            reason,
        } => {
            crate::agent_gateway::context::validate_reasoning_identifier_v1(subject_id)
                .map_err(|error| anyhow!(error.code()))?;
            crate::agent_gateway::context::validate_reasoning_text_v1(reason, 1024)
                .map_err(|error| anyhow!(error.code()))?;
            Ok((
                ContextEventFieldsV1 {
                    kind: ContextLedgerEventKindV1::Retirement,
                    subject_id,
                    subject_version: *subject_version,
                    summary: reason,
                    value_digest: None,
                    result_id: None,
                    result_digest: None,
                    total_bytes: None,
                    duration_ms: None,
                },
                serde_json::to_vec(&(subject_id, subject_version, reason))?,
                &[],
            ))
        }
    }
}

fn duplicate_context_envelope_v1(
    transaction: &Transaction<'_>,
    envelope_digest: &str,
    canonical_digest: &str,
) -> Result<Option<ContextLedgerAppendOutcomeV1>> {
    let existing = transaction
        .query_row(
            "SELECT sequence, canonical_digest FROM context_ledger_events_v1 WHERE envelope_digest = ?1",
            [envelope_digest],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    match existing {
        Some((sequence, existing_digest)) if existing_digest == canonical_digest => {
            Ok(Some(ContextLedgerAppendOutcomeV1::Duplicate { sequence }))
        }
        Some(_) => bail!("context envelope digest conflicts with prior immutable event"),
        None => Ok(None),
    }
}

fn insert_context_event_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    envelope_digest: &str,
    canonical_digest: &str,
    fields: &ContextEventFieldsV1<'_>,
    now: i64,
) -> Result<u64> {
    reserve_task_context_bytes_v1(
        transaction,
        identity.repository_id(),
        identity.workspace_id(),
        context_event_logical_bytes_v1(fields.subject_id, fields.summary),
    )?;
    transaction.execute(
        "INSERT INTO context_ledger_events_v1 (
            envelope_digest, canonical_digest, schema_version, repository_id, workspace_id,
            task_id, authorization_scope_digest, agent_id, session_id, turn_id,
            connection_generation, compaction_generation, lifecycle_generation, kind,
            subject_id, subject_version, summary, value_digest, result_id, result_digest,
            total_bytes, duration_ms, created_ms
         ) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                   ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
        params![
            envelope_digest,
            canonical_digest,
            identity.repository_id(),
            identity.workspace_id(),
            identity.task_id(),
            identity.authorization_scope_digest(),
            identity.agent_id(),
            identity.session_id(),
            identity.turn_id(),
            identity.connection_generation(),
            identity.compaction_generation(),
            identity.lifecycle_generation(),
            fields.kind.code(),
            fields.subject_id,
            fields.subject_version,
            fields.summary,
            fields.value_digest,
            fields.result_id,
            fields.result_digest,
            fields.total_bytes,
            fields.duration_ms,
            now,
        ],
    )?;
    u64::try_from(transaction.last_insert_rowid()).context("context event sequence is negative")
}

fn verify_context_sources_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    sources: &[ContextVerifiedObservationV1],
    now: i64,
) -> Result<Vec<GatewayDependencyV1>> {
    if sources.len() > crate::agent_gateway::context::MAX_REASONING_SOURCES_PER_ITEM_V1
        || sources.windows(2).any(|pair| {
            (pair[0].source.result_id(), pair[0].source.locator())
                >= (pair[1].source.result_id(), pair[1].source.locator())
        })
    {
        bail!(ReasoningContextRefusalV1::SourceReferenceBound.code());
    }
    let mut dependencies = BTreeMap::<String, String>::new();
    for verified in sources {
        let source = &verified.source;
        if source.repository_id() != identity.repository_id()
            || source.workspace_id() != identity.workspace_id()
            || source.authorization_scope_digest() != identity.authorization_scope_digest()
            || source.result_id() != source.result_digest()
            || verified.freshness_valid_until_ms < now
            || gateway_dependency_digest_v1(&verified.dependencies) != source.dependency_digest()
        {
            bail!(GatewayRefusalReason::BindingMismatch.as_str());
        }
        let row = transaction
            .query_row(
                "SELECT binding_digest, state_digest, status, quarantine_reason
                 FROM gateway_results WHERE gateway_result_id = ?1",
                [source.result_id()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((binding_digest, state_digest, status, quarantine_reason)) = row else {
            bail!(GatewayRefusalReason::ResultNotFound.as_str());
        };
        if binding_digest != verified.binding_digest
            || state_digest != source.state_digest()
            || status != "ready"
            || quarantine_reason.is_some()
        {
            bail!(GatewayRefusalReason::ResultCorrupt.as_str());
        }
        let stored_dependencies = load_result_dependencies_v1(transaction, source.result_id())?;
        if stored_dependencies != verified.dependencies {
            bail!(GatewayRefusalReason::BindingMismatch.as_str());
        }
        for dependency in &verified.dependencies {
            match dependencies.entry(dependency.key_digest.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(dependency.value_digest.clone());
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get() == &dependency.value_digest => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    bail!("verified context sources contain contradictory dependencies");
                }
            }
        }
    }
    if dependencies.len() > MAX_CONTEXT_LEDGER_DEPENDENCIES_V1 {
        bail!(ReasoningContextRefusalV1::SourceReferenceBound.code());
    }
    Ok(dependencies
        .into_iter()
        .map(|(key_digest, value_digest)| GatewayDependencyV1 {
            key_digest,
            value_digest,
        })
        .collect())
}

fn insert_context_provenance_v1(
    transaction: &Transaction<'_>,
    sequence: u64,
    sources: &[ContextVerifiedObservationV1],
    dependencies: &[GatewayDependencyV1],
) -> Result<()> {
    for (ordinal, verified) in sources.iter().enumerate() {
        let source = &verified.source;
        transaction.execute(
            "INSERT INTO context_ledger_event_sources_v1 (
                event_sequence, ordinal, result_id, result_digest, repository_id,
                workspace_id, state_digest, dependency_digest, authorization_scope_digest,
                locator, binding_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                sequence,
                ordinal,
                source.result_id(),
                source.result_digest(),
                source.repository_id(),
                source.workspace_id(),
                source.state_digest(),
                source.dependency_digest(),
                source.authorization_scope_digest(),
                source.locator(),
                verified.binding_digest
            ],
        )?;
    }
    for (ordinal, dependency) in dependencies.iter().enumerate() {
        transaction.execute(
            "INSERT INTO context_ledger_event_dependencies_v1 (
                event_sequence, ordinal, dependency_key_digest, dependency_value_digest
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                sequence,
                ordinal,
                dependency.key_digest,
                dependency.value_digest
            ],
        )?;
    }
    Ok(())
}

fn enforce_context_quota_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<()> {
    let mut count = context_event_count_v1(transaction, identity)?;
    if count >= MAX_CONTEXT_LEDGER_EVENTS_PER_TASK_V1 as u64 {
        let target = MAX_CONTEXT_LEDGER_EVENTS_PER_TASK_V1.saturating_sub(1);
        gc_context_ledger_tx_v1(transaction, identity, target)?;
        reconcile_task_quota_scope_v1_tx(
            transaction,
            identity.repository_id(),
            identity.workspace_id(),
            now_ms(),
        )?;
        count = context_event_count_v1(transaction, identity)?;
    }
    if count >= MAX_CONTEXT_LEDGER_EVENTS_PER_TASK_V1 as u64 {
        bail!("context ledger task quota exceeded; required provenance is retained");
    }
    Ok(())
}

fn context_event_count_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<u64> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM context_ledger_events_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id()
            ],
            |row| row.get(0),
        )
        .context("count context task events")
}

fn context_latest_cursor_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<u64> {
    transaction
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM context_ledger_events_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3",
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id()
            ],
            |row| row.get(0),
        )
        .context("read context task cursor")
}

fn retire_context_facts_for_changes_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    sequence: u64,
    changes: &[ContextDependencyChangeV1],
) -> Result<u64> {
    let mut retired = 0_u64;
    for change in changes {
        retired = retired.saturating_add(transaction.execute(
            "UPDATE context_ledger_fact_versions_v1 AS fact
             SET retired_event_sequence = ?1, retirement_reason = 'dependency_invalidated'
             WHERE fact.repository_id = ?2 AND fact.workspace_id = ?3 AND fact.task_id = ?4
               AND fact.retired_event_sequence IS NULL
               AND EXISTS (
                   SELECT 1 FROM context_ledger_event_dependencies_v1 AS dependency
                   WHERE dependency.event_sequence = fact.admission_event_sequence
                     AND dependency.dependency_key_digest = ?5
                     AND dependency.dependency_value_digest != ?6
               )",
            params![
                sequence,
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                change.key_digest,
                change.current_value_digest
            ],
        )? as u64);
    }
    Ok(retired)
}

fn retire_context_results_for_changes_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    sequence: u64,
    changes: &[ContextDependencyChangeV1],
) -> Result<u64> {
    let mut retired = 0_u64;
    for change in changes {
        retired = retired.saturating_add(transaction.execute(
            "UPDATE context_ledger_result_references_v1 AS reference
             SET retired_event_sequence = ?1, retirement_reason = 'dependency_invalidated'
             WHERE reference.repository_id = ?2 AND reference.workspace_id = ?3
               AND reference.task_id = ?4 AND reference.retired_event_sequence IS NULL
               AND EXISTS (
                   SELECT 1 FROM context_ledger_event_dependencies_v1 AS dependency
                   WHERE dependency.event_sequence = reference.admission_event_sequence
                     AND dependency.dependency_key_digest = ?5
                     AND dependency.dependency_value_digest != ?6
               )",
            params![
                sequence,
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                change.key_digest,
                change.current_value_digest
            ],
        )? as u64);
    }
    Ok(retired)
}

fn context_invalidation_counts_v1(
    transaction: &Transaction<'_>,
    sequence: u64,
) -> Result<(u64, u64)> {
    transaction
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM context_ledger_fact_versions_v1 WHERE retired_event_sequence = ?1),
                (SELECT COUNT(*) FROM context_ledger_result_references_v1 WHERE retired_event_sequence = ?1)",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("read context invalidation counts")
}

fn retire_context_source_facts_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    sequence: u64,
    source_result_id: &str,
) -> Result<u64> {
    let count = transaction.execute(
        "UPDATE context_ledger_fact_versions_v1 AS fact
         SET retired_event_sequence = ?1, retirement_reason = 'source_observation_unavailable'
         WHERE fact.repository_id = ?2 AND fact.workspace_id = ?3 AND fact.task_id = ?4
           AND fact.retired_event_sequence IS NULL
           AND EXISTS(SELECT 1 FROM context_ledger_events_v1 AS event
                      WHERE event.sequence = fact.admission_event_sequence
                        AND event.authorization_scope_digest = ?5
                        AND (EXISTS(SELECT 1 FROM context_ledger_event_sources_v1 AS source
                                    WHERE source.event_sequence = event.sequence
                                      AND source.result_id = ?6)
                             OR EXISTS(SELECT 1 FROM context_ledger_event_dependencies_v1 AS dependency
                                       JOIN result_dependencies AS changed
                                         ON changed.gateway_result_id = ?6
                                        AND changed.dependency_key_digest = dependency.dependency_key_digest
                                        AND changed.dependency_value_digest = dependency.dependency_value_digest
                                       WHERE dependency.event_sequence = event.sequence)))",
        params![
            sequence,
            identity.repository_id(),
            identity.workspace_id(),
            identity.task_id(),
            identity.authorization_scope_digest(),
            source_result_id
        ],
    )?;
    Ok(count as u64)
}

fn retire_context_source_results_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    sequence: u64,
    source_result_id: &str,
) -> Result<u64> {
    let count = transaction.execute(
        "UPDATE context_ledger_result_references_v1 AS reference
         SET retired_event_sequence = ?1, retirement_reason = 'source_observation_unavailable'
         WHERE reference.repository_id = ?2 AND reference.workspace_id = ?3
           AND reference.task_id = ?4 AND reference.retired_event_sequence IS NULL
           AND EXISTS(SELECT 1 FROM context_ledger_events_v1 AS event
                      WHERE event.sequence = reference.admission_event_sequence
                        AND event.authorization_scope_digest = ?5
                        AND (EXISTS(SELECT 1 FROM context_ledger_event_sources_v1 AS source
                                    WHERE source.event_sequence = event.sequence
                                      AND source.result_id = ?6)
                             OR EXISTS(SELECT 1 FROM context_ledger_event_dependencies_v1 AS dependency
                                       JOIN result_dependencies AS changed
                                         ON changed.gateway_result_id = ?6
                                        AND changed.dependency_key_digest = dependency.dependency_key_digest
                                        AND changed.dependency_value_digest = dependency.dependency_value_digest
                                       WHERE dependency.event_sequence = event.sequence)))",
        params![
            sequence,
            identity.repository_id(),
            identity.workspace_id(),
            identity.task_id(),
            identity.authorization_scope_digest(),
            source_result_id
        ],
    )?;
    Ok(count as u64)
}

fn context_event_provenance_current_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    event_sequence: u64,
) -> Result<bool> {
    let source_count: u64 = transaction.query_row(
        "SELECT COUNT(*) FROM context_ledger_event_sources_v1 WHERE event_sequence = ?1",
        [event_sequence],
        |row| row.get(0),
    )?;
    if source_count == 0 {
        return Ok(false);
    }
    let invalid_source: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM context_ledger_event_sources_v1 AS source
            LEFT JOIN gateway_results AS result ON result.gateway_result_id = source.result_id
            WHERE source.event_sequence = ?1
              AND (
                  result.gateway_result_id IS NULL OR result.status != 'ready'
                  OR result.quarantine_reason IS NOT NULL
                  OR result.gateway_result_id != source.result_digest
                  OR result.binding_digest != source.binding_digest
                  OR result.state_digest != source.state_digest
                  OR source.repository_id != ?2 OR source.workspace_id != ?3
                  OR source.authorization_scope_digest != ?4
                  OR EXISTS(
                      SELECT 1 FROM result_dependencies AS actual
                      WHERE actual.gateway_result_id = source.result_id
                        AND NOT EXISTS(
                            SELECT 1 FROM context_ledger_event_dependencies_v1 AS admitted
                            WHERE admitted.event_sequence = source.event_sequence
                              AND admitted.dependency_key_digest = actual.dependency_key_digest
                              AND admitted.dependency_value_digest = actual.dependency_value_digest
                        )
                  )
              )
        )",
        params![
            event_sequence,
            identity.repository_id(),
            identity.workspace_id(),
            identity.authorization_scope_digest()
        ],
        |row| row.get(0),
    )?;
    Ok(!invalid_source)
}

fn load_context_sources_for_event_v1(
    transaction: &Transaction<'_>,
    event_sequence: u64,
) -> Result<Vec<ReasoningSourceReferenceV1>> {
    let mut statement = transaction.prepare(
        "SELECT result_id, result_digest, repository_id, workspace_id, state_digest,
                dependency_digest, authorization_scope_digest, locator
         FROM context_ledger_event_sources_v1
         WHERE event_sequence = ?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([event_sequence], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|row| {
            reasoning_item_v1(ReasoningSourceReferenceV1::new(
                &row.0, &row.1, &row.2, &row.3, &row.4, &row.5, &row.6, &row.7,
            ))
        })
        .collect()
}

fn load_current_context_facts_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<Vec<ReasoningFactV1>> {
    type FactRow = (
        u64,
        String,
        u64,
        String,
        String,
        String,
        String,
        Option<String>,
    );
    let rows: Vec<FactRow> = {
        let mut statement = transaction.prepare(
            "SELECT admission_event_sequence, fact_id, fact_version, topic, statement,
                    value_digest, fact_scope, fact_task_id
             FROM context_ledger_fact_versions_v1
             WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
               AND retired_event_sequence IS NULL
             ORDER BY fact_id, fact_version DESC LIMIT ?4",
        )?;
        statement
            .query_map(
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    MAX_CONTEXT_LEDGER_SNAPSHOT_ITEMS_V1
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut facts = Vec::new();
    for (event, fact_id, _, topic, statement, value_digest, scope, task_id) in rows {
        if !context_event_provenance_current_v1(transaction, identity, event)? {
            continue;
        }
        let sources = load_context_sources_for_event_v1(transaction, event)?;
        let scope = match scope.as_str() {
            "repository_wide" => ReasoningFactScopeV1::RepositoryWide,
            "task_specific" => ReasoningFactScopeV1::TaskSpecific,
            _ => bail!("context fact has invalid stored scope"),
        };
        facts.push(reasoning_item_v1(ReasoningFactV1::new(
            &fact_id,
            &topic,
            &statement,
            &value_digest,
            scope,
            task_id.as_deref(),
            sources,
        ))?);
    }
    Ok(facts)
}

fn load_context_suggestions_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<Vec<ContextLedgerSuggestionV1>> {
    let mut statement = transaction.prepare(
        "SELECT subject_id, summary, value_digest
         FROM context_ledger_events_v1
         WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
           AND kind = 'unverified_suggestion'
         ORDER BY sequence DESC LIMIT ?4",
    )?;
    let rows = statement
        .query_map(
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                MAX_CONTEXT_LEDGER_SNAPSHOT_ITEMS_V1
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(subject, statement, digest)| {
            reasoning_item_v1(ContextLedgerSuggestionV1::new(
                &subject, &statement, &digest,
            ))
        })
        .collect()
}

fn load_context_unknowns_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<Vec<ReasoningUnknownV1>> {
    let mut statement = transaction.prepare(
        "SELECT subject_id, summary FROM context_ledger_events_v1
         WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
           AND kind = 'explicit_unknown'
         ORDER BY sequence DESC LIMIT ?4",
    )?;
    let rows = statement
        .query_map(
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                MAX_CONTEXT_LEDGER_SNAPSHOT_ITEMS_V1
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(subject, explanation)| {
            reasoning_item_v1(ReasoningUnknownV1::new(&subject, &explanation))
        })
        .collect()
}

fn load_current_context_results_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
) -> Result<Vec<ReasoningRetrievalIdentityV1>> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT reference.admission_event_sequence, reference.result_id,
                    reference.result_digest, reference.total_bytes
             FROM context_ledger_result_references_v1 AS reference
                 JOIN gateway_results AS result
                   ON result.gateway_result_id = reference.result_id
                  AND result.status = 'ready' AND result.origin = 'leased'
             WHERE reference.repository_id = ?1 AND reference.workspace_id = ?2
               AND reference.task_id = ?3 AND reference.retired_event_sequence IS NULL
             ORDER BY reference.result_id, reference.reference_version DESC LIMIT ?4",
        )?;
        statement
            .query_map(
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    MAX_CONTEXT_LEDGER_SNAPSHOT_ITEMS_V1
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut references = Vec::new();
    for (event, result_id, result_digest, total_bytes) in rows {
        if context_event_provenance_current_v1(transaction, identity, event)? {
            references.push(reasoning_item_v1(ReasoningRetrievalIdentityV1::new(
                &result_id,
                &result_digest,
                total_bytes,
            ))?);
        }
    }
    Ok(references)
}

fn load_context_inflight_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    now: i64,
) -> Result<Vec<InflightReasoningWorkV1>> {
    let mut statement = transaction.prepare(
        "SELECT lease_id, leader_agent_id, generation, summary
         FROM context_ledger_leases_v1
         WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
           AND authorization_scope_digest = ?4 AND status = 'active' AND expires_ms > ?5
         ORDER BY work_key_digest LIMIT ?6",
    )?;
    let rows = statement
        .query_map(
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                now,
                MAX_CONTEXT_LEDGER_SNAPSHOT_ITEMS_V1
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(lease, agent, generation, summary)| {
            reasoning_item_v1(InflightReasoningWorkV1::new(
                &lease, &agent, generation, &summary,
            ))
        })
        .collect()
}

fn context_event_kind_from_str_v1(value: &str) -> Result<ContextLedgerEventKindV1> {
    Ok(match value {
        "verified_fact_admission" => ContextLedgerEventKindV1::VerifiedFactAdmission,
        "unverified_suggestion" => ContextLedgerEventKindV1::UnverifiedSuggestion,
        "completed_observation" => ContextLedgerEventKindV1::CompletedObservation,
        "inflight_work" => ContextLedgerEventKindV1::InflightWork,
        "failed_approach" => ContextLedgerEventKindV1::FailedApproach,
        "explicit_unknown" => ContextLedgerEventKindV1::ExplicitUnknown,
        "result_reference" => ContextLedgerEventKindV1::ResultReference,
        "invalidation" => ContextLedgerEventKindV1::Invalidation,
        "retirement" => ContextLedgerEventKindV1::Retirement,
        _ => bail!("context ledger contains an unknown event kind"),
    })
}

fn load_context_delta_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    after: u64,
    limit: usize,
) -> Result<Vec<ContextLedgerEventV1>> {
    type EventRow = (
        u64,
        String,
        String,
        String,
        u64,
        String,
        Option<String>,
        u64,
    );
    let mut statement = transaction.prepare(
        "SELECT sequence, envelope_digest, kind, subject_id, subject_version,
                summary, value_digest, created_ms
         FROM context_ledger_events_v1
         WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3 AND sequence > ?4
         ORDER BY sequence ASC LIMIT ?5",
    )?;
    let rows: Vec<EventRow> = statement
        .query_map(
            params![
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                after,
                limit
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|row| {
            Ok(ContextLedgerEventV1::from_store(
                row.0,
                row.1,
                context_event_kind_from_str_v1(&row.2)?,
                row.3,
                row.4,
                row.5,
                row.6,
                row.7,
            ))
        })
        .collect()
}

fn expire_context_leases_v1(transaction: &Transaction<'_>, now: i64) -> Result<u64> {
    Ok(transaction.execute(
        "UPDATE context_ledger_leases_v1
         SET status = 'expired', completed_ms = ?1
         WHERE status = 'active' AND (expires_ms <= ?1 OR deadline_ms <= ?1)",
        [now],
    )? as u64)
}

fn context_owned_lease_deadline_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    lease_id: &str,
) -> Result<i64> {
    let deadline = transaction
        .query_row(
            "SELECT deadline_ms FROM context_ledger_leases_v1
             WHERE lease_id = ?1 AND repository_id = ?2 AND workspace_id = ?3 AND task_id = ?4
               AND authorization_scope_digest = ?5 AND leader_agent_id = ?6
               AND leader_session_id = ?7 AND leader_lifecycle_generation = ?8
               AND status = 'active'",
            params![
                lease_id,
                identity.repository_id(),
                identity.workspace_id(),
                identity.task_id(),
                identity.authorization_scope_digest(),
                identity.agent_id(),
                identity.session_id(),
                identity.lifecycle_generation()
            ],
            |row| row.get(0),
        )
        .optional()?;
    deadline.ok_or_else(|| anyhow!(GatewayRefusalReason::OwnerMismatch.as_str()))
}

fn context_delivery_receipt_digest_v1(
    identity: &ContextLedgerIdentityV1,
    response_envelope_digest: &str,
    through: ContextLedgerCursorV1,
    delivered_bytes: u64,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.context-ledger.delivery.v1\0");
    for value in [
        response_envelope_digest,
        identity.repository_id(),
        identity.workspace_id(),
        identity.task_id(),
        identity.authorization_scope_digest(),
        identity.agent_id(),
        identity.session_id(),
        identity.turn_id(),
        identity.connection_generation(),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    for number in [
        identity.compaction_generation(),
        identity.lifecycle_generation(),
        through.sequence(),
        delivered_bytes,
    ] {
        hasher.update(&number.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn gc_context_ledger_tx_v1(
    transaction: &Transaction<'_>,
    identity: &ContextLedgerIdentityV1,
    maximum_events: usize,
) -> Result<ContextLedgerGcReportV1> {
    let fact_versions = transaction.execute(
        "DELETE FROM context_ledger_fact_versions_v1
         WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
           AND retired_event_sequence IS NOT NULL",
        params![
            identity.repository_id(),
            identity.workspace_id(),
            identity.task_id()
        ],
    )? as u64;
    let result_references = transaction.execute(
        "DELETE FROM context_ledger_result_references_v1
         WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3
           AND retired_event_sequence IS NOT NULL",
        params![
            identity.repository_id(),
            identity.workspace_id(),
            identity.task_id()
        ],
    )? as u64;
    let count = context_event_count_v1(transaction, identity)?;
    let remove = count.saturating_sub(maximum_events as u64);
    if remove == 0 {
        return Ok(ContextLedgerGcReportV1 {
            events: 0,
            fact_versions,
            result_references,
        });
    }
    // A delivery receipt conservatively retains the complete prefix it
    // authenticated. Live projections retain their admission events and
    // cascading source/dependency provenance through RESTRICT foreign keys.
    let retained_through: u64 = transaction.query_row(
        "SELECT COALESCE(MAX(through_sequence), 0)
         FROM context_ledger_delivery_receipts_v1
         WHERE repository_id = ?1 AND workspace_id = ?2 AND task_id = ?3",
        params![
            identity.repository_id(),
            identity.workspace_id(),
            identity.task_id()
        ],
        |row| row.get(0),
    )?;
    let candidates: Vec<u64> = {
        let mut statement = transaction.prepare(
            "SELECT event.sequence FROM context_ledger_events_v1 AS event
             WHERE event.repository_id = ?1 AND event.workspace_id = ?2 AND event.task_id = ?3
               AND event.sequence > ?4
               AND NOT EXISTS(
                   SELECT 1 FROM context_ledger_fact_versions_v1 AS fact
                   WHERE fact.admission_event_sequence = event.sequence
                      OR fact.retired_event_sequence = event.sequence
               )
               AND NOT EXISTS(
                   SELECT 1 FROM context_ledger_result_references_v1 AS reference
                   WHERE reference.admission_event_sequence = event.sequence
                      OR reference.retired_event_sequence = event.sequence
               )
               AND NOT EXISTS(
                   SELECT 1 FROM context_ledger_event_sources_v1 AS source
                   JOIN gateway_delivery_receipts_v2 AS receipt
                     ON receipt.gateway_result_id = source.result_id
                   WHERE source.event_sequence = event.sequence
               )
             ORDER BY event.sequence ASC LIMIT ?5",
        )?;
        statement
            .query_map(
                params![
                    identity.repository_id(),
                    identity.workspace_id(),
                    identity.task_id(),
                    retained_through,
                    remove
                ],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut removed = 0_u64;
    for sequence in candidates {
        removed = removed.saturating_add(transaction.execute(
            "DELETE FROM context_ledger_events_v1 WHERE sequence = ?1",
            [sequence],
        )? as u64);
    }
    Ok(ContextLedgerGcReportV1 {
        events: removed,
        fact_versions,
        result_references,
    })
}

fn reasoning_item_v1<T>(item: std::result::Result<T, ReasoningContextRefusalV1>) -> Result<T> {
    item.map_err(|reason| anyhow!(reason.code()))
}

fn reasoning_gateway_source_v1(
    scope: &ReasoningScopeV1,
    observation_id: &str,
    observation_digest: &str,
    locator: &str,
) -> Result<ReasoningSourceReferenceV1> {
    reasoning_item_v1(ReasoningSourceReferenceV1::new(
        observation_id,
        observation_digest,
        scope.repository_id(),
        scope.workspace_id(),
        scope.state_digest(),
        scope.dependency_digest(),
        scope.authorization_scope_digest(),
        locator,
    ))
}

fn add_reasoning_unknown_v1(
    brief: &mut ReasoningBriefInputV1,
    route: ReasoningRouteDecisionV1,
) -> Result<()> {
    brief
        .explicit_unknowns
        .push(reasoning_item_v1(ReasoningUnknownV1::new(
            "gateway-exact-observation",
            "no verified current result or matching active work is available",
        ))?);
    brief
        .suggested_next_tool_calls
        .push(reasoning_item_v1(SuggestedReasoningToolCallV1::new(
            "gateway",
            "execute-observation",
            "obtain the missing exact observation",
            route,
        ))?);
    brief.route_decisions.push(route);
    Ok(())
}

fn gateway_failure_explanation_v1(reason: GatewayFailureReason) -> &'static str {
    match reason {
        GatewayFailureReason::ProviderUnavailable => {
            "the provider was unavailable for the verified failed execution"
        }
        GatewayFailureReason::Transport => {
            "the verified execution failed at the provider transport boundary"
        }
        GatewayFailureReason::Deadline => {
            "the verified execution or freshness interval reached its deadline"
        }
        GatewayFailureReason::Cancelled => {
            "the verified execution was cancelled before a result committed"
        }
        GatewayFailureReason::Protocol => {
            "the provider response failed verified protocol validation"
        }
        GatewayFailureReason::Internal => {
            "the coordinator recorded a verified internal execution failure"
        }
    }
}

fn reasoning_store_row_digest_v1(
    kind: &str,
    binding_digest: &str,
    row_id: &str,
    reason: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.reasoning-store-row.v1\0");
    for value in [kind, binding_digest, row_id, reason] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn has_matching_reasoning_delivery_v1(
    connection: &Connection,
    authorization_scope_digest: &str,
    result: &GatewayFullResultV1,
) -> Result<bool> {
    let legacy: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM gateway_delivery_receipts
            WHERE authorization_scope_digest = ?1
              AND gateway_result_id = ?2
              AND result_digest = ?2
              AND exact_status = ?3
              AND stdout_digest = ?4 AND stdout_bytes = ?5
              AND stderr_digest = ?6 AND stderr_bytes = ?7
        )",
        params![
            authorization_scope_digest,
            result.gateway_result_id,
            result.result.exit_code,
            result.result.stdout_digest,
            result.result.stdout_bytes,
            result.result.stderr_digest,
            result.result.stderr_bytes,
        ],
        |row| row.get(0),
    )?;
    if legacy {
        return Ok(true);
    }
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM gateway_delivery_receipts_v2
                WHERE authorization_scope_digest = ?1
                  AND gateway_result_id = ?2
                  AND result_digest = ?2
                  AND exact_status = ?3
                  AND stdout_digest = ?4 AND stdout_bytes = ?5
                  AND stderr_digest = ?6 AND stderr_bytes = ?7
                  AND presentation = 'full'
            )",
            params![
                authorization_scope_digest,
                result.gateway_result_id,
                result.result.exit_code,
                result.result.stdout_digest,
                result.result.stdout_bytes,
                result.result.stderr_digest,
                result.result.stderr_bytes,
            ],
            |row| row.get(0),
        )
        .context("read authenticated reasoning delivery")
}

fn exact_store_record_digest_v1(
    binding: &ValidatedGatewayReadV1,
    lease: &GatewayLeaseRowV1,
    gateway_result_id: &str,
    dependency_digest: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.exact-store-record.v1\0");
    for value in [
        binding.request_digest(),
        binding.state_digest(),
        binding.policy_digest(),
        binding.binding_digest(),
        dependency_digest,
        lease.lease_id.as_str(),
        gateway_result_id,
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(&lease.lifecycle_generation.to_le_bytes());
    hasher.update(&lease.execution_started_ms.unwrap_or(-1).to_le_bytes());
    hasher.update(&lease.completed_ms.unwrap_or(-1).to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

fn inflight_store_record_digest_v1(
    binding: &ValidatedGatewayReadV1,
    lease: &GatewayLeaseRowV1,
    observed_at_ms: u64,
    dependency_digest: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.inflight-store-record.v1\0");
    for value in [
        binding.request_digest(),
        binding.state_digest(),
        binding.policy_digest(),
        binding.binding_digest(),
        dependency_digest,
        lease.lease_id.as_str(),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(&lease.lifecycle_generation.to_le_bytes());
    hasher.update(&lease.execution_started_ms.unwrap_or(-1).to_le_bytes());
    hasher.update(&observed_at_ms.to_le_bytes());
    hasher.update(&lease.expires_ms.to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

fn gateway_lease_row_v1(
    transaction: &Transaction<'_>,
    lease_id: &str,
) -> Result<Option<GatewayLeaseRowV1>> {
    transaction
        .query_row(
            "SELECT lease_id, call_id, request_digest, state_digest, policy_digest, binding_digest, freshness_valid_until_ms, owner, status, gateway_result_id, expires_ms, execution_started_ms, completed_ms, lifecycle_generation FROM inflight_leases WHERE lease_id = ?1",
            [lease_id],
            |row| {
                Ok(GatewayLeaseRowV1 {
                    lease_id: row.get(0)?,
                    call_id: row.get(1)?,
                    request_digest: row.get(2)?,
                    state_digest: row.get(3)?,
                    policy_digest: row.get(4)?,
                    binding_digest: row.get(5)?,
                    freshness_valid_until_ms: row.get(6)?,
                    owner: row.get(7)?,
                    status: row.get(8)?,
                    gateway_result_id: row.get(9)?,
                    expires_ms: row.get(10)?,
                    execution_started_ms: row.get(11)?,
                    completed_ms: row.get(12)?,
                    lifecycle_generation: row.get(13)?,
                })
            },
        )
        .optional()
        .context("read exact gateway lease")
}

#[allow(clippy::too_many_arguments)]
fn insert_gateway_request_v1(
    transaction: &Transaction<'_>,
    call_id: &str,
    binding: &ValidatedGatewayReadV1,
    owner: &str,
    role: &str,
    status: &str,
    lease_id: Option<&str>,
    gateway_result_id: Option<&str>,
    reason: Option<&str>,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO gateway_requests (call_id, request_digest, state_digest, policy_digest, binding_digest, freshness_valid_until_ms, owner, role, status, joined_lease_id, gateway_result_id, reason, created_ms, updated_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
        params![
            call_id,
            binding.request_digest(),
            binding.state_digest(),
            binding.policy_digest(),
            binding.binding_digest(),
            binding.input.freshness.valid_until_ms,
            owner,
            role,
            status,
            lease_id,
            gateway_result_id,
            reason,
            now
        ],
    )?;
    for (ordinal, dependency) in binding.input.dependencies.iter().enumerate() {
        transaction.execute(
            "INSERT INTO gateway_request_dependencies (call_id, ordinal, dependency_key_digest, dependency_value_digest) VALUES (?1, ?2, ?3, ?4)",
            params![
                call_id,
                i64::try_from(ordinal)?,
                dependency.key_digest,
                dependency.value_digest
            ],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_gateway_event_v1_tx(
    transaction: &Transaction<'_>,
    call_id: Option<&str>,
    lease_id: Option<&str>,
    gateway_result_id: Option<&str>,
    event_type: &str,
    reason: Option<&str>,
    estimated_tokens_avoided: u64,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO gateway_events (call_id, lease_id, gateway_result_id, event_type, reason, estimated_tokens_avoided, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            call_id,
            lease_id,
            gateway_result_id,
            event_type,
            reason,
            estimated_tokens_avoided,
            now
        ],
    )?;
    Ok(())
}

fn load_visible_result_tx(
    transaction: &Transaction<'_>,
    result_id: &str,
) -> Result<Option<StoredResult>> {
    transaction
        .query_row(
            "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE id = ?1 AND quarantined = 0",
            [result_id],
            row_to_result,
        )
        .optional()
        .context("load visible exact gateway result source")
}

fn load_request_dependencies_v1(
    transaction: &Transaction<'_>,
    call_id: &str,
) -> Result<Vec<GatewayDependencyV1>> {
    let mut statement = transaction.prepare(
        "SELECT dependency_key_digest, dependency_value_digest FROM gateway_request_dependencies WHERE call_id = ?1 ORDER BY ordinal",
    )?;
    statement
        .query_map([call_id], |row| {
            Ok(GatewayDependencyV1 {
                key_digest: row.get(0)?,
                value_digest: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("load exact gateway request dependencies")
}

fn load_result_dependencies_v1(
    transaction: &Transaction<'_>,
    gateway_result_id: &str,
) -> Result<Vec<GatewayDependencyV1>> {
    let mut statement = transaction.prepare(
        "SELECT dependency_key_digest, dependency_value_digest FROM result_dependencies WHERE gateway_result_id = ?1 ORDER BY ordinal",
    )?;
    statement
        .query_map([gateway_result_id], |row| {
            Ok(GatewayDependencyV1 {
                key_digest: row.get(0)?,
                value_digest: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("load exact gateway result dependencies")
}

fn gateway_result_content_digest(
    lease: &GatewayLeaseRowV1,
    result: &StoredResult,
    dependencies: &[GatewayDependencyV1],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.result.v1\0");
    for value in [
        lease.binding_digest.as_str(),
        lease.request_digest.as_str(),
        lease.state_digest.as_str(),
        lease.policy_digest.as_str(),
        result.stdout_digest.as_str(),
        result.stderr_digest.as_str(),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(&result.stdout_bytes.to_le_bytes());
    hasher.update(&result.stderr_bytes.to_le_bytes());
    hasher.update(&result.exit_code.to_le_bytes());
    hasher.update(&result.duration_ms.to_le_bytes());
    hash_field(&mut hasher, result.policy_version.as_bytes());
    hash_field(&mut hasher, result.proof_json.as_bytes());
    hasher.update(&(dependencies.len() as u64).to_le_bytes());
    for dependency in dependencies {
        hash_field(&mut hasher, dependency.key_digest.as_bytes());
        hash_field(&mut hasher, dependency.value_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn direct_observation_content_digest_v1(
    binding: &ValidatedGatewayReadV1,
    result: &StoredResult,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.direct-observation.v1\0");
    for value in [
        binding.binding_digest(),
        binding.request_digest(),
        binding.state_digest(),
        binding.policy_digest(),
        result.stdout_digest.as_str(),
        result.stderr_digest.as_str(),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(&result.stdout_bytes.to_le_bytes());
    hasher.update(&result.stderr_bytes.to_le_bytes());
    hasher.update(&result.exit_code.to_le_bytes());
    hasher.update(&result.duration_ms.to_le_bytes());
    hash_field(&mut hasher, result.policy_version.as_bytes());
    hash_field(&mut hasher, result.proof_json.as_bytes());
    hasher.update(&(binding.dependencies().len() as u64).to_le_bytes());
    for dependency in binding.dependencies() {
        hash_field(&mut hasher, dependency.key_digest.as_bytes());
        hash_field(&mut hasher, dependency.value_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn direct_observation_request_key_v1(binding: &ValidatedGatewayReadV1) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.direct-observation-request.v1\0");
    hash_field(&mut hasher, binding.binding_digest().as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn delivery_token_digest_v2(token: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.retrieval-token.v2\0");
    hasher.update(&(token.len() as u64).to_be_bytes());
    hasher.update(token.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn constant_time_digest_eq_v2(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Reconstruct a ready result from its complete publication chain without
/// treating its content address as authorization. Callers must already hold a
/// separate live recipient authority before reaching this helper.
fn load_gateway_result_unbound_snapshot_v2(
    transaction: &Transaction<'_>,
    gateway_result_id: &str,
) -> Result<(StoredResult, Vec<GatewayDependencyV1>)> {
    let snapshot = transaction
        .query_row(
            "SELECT result_id, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, result_policy_version, proof_digest, request_digest, state_digest, policy_digest, binding_digest, lease_id, status, quarantine_reason FROM gateway_results WHERE gateway_result_id = ?1",
            [gateway_result_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, u64>(3)?, row.get::<_, u64>(4)?, row.get::<_, i32>(5)?, row.get::<_, u64>(6)?, row.get::<_, String>(7)?, row.get::<_, String>(8)?, row.get::<_, String>(9)?, row.get::<_, String>(10)?, row.get::<_, String>(11)?, row.get::<_, String>(12)?, row.get::<_, String>(13)?, row.get::<_, String>(14)?, row.get::<_, Option<String>>(15)?)),
        )
        .optional()?;
    let Some((
        result_id,
        stdout_digest,
        stderr_digest,
        stdout_bytes,
        stderr_bytes,
        exit_code,
        duration_ms,
        policy_version,
        proof_digest,
        request_digest,
        state_digest,
        policy_digest,
        binding_digest,
        lease_id,
        status,
        quarantine_reason,
    )) = snapshot
    else {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    };
    if status != "ready" || quarantine_reason.is_some() {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    for digest in [
        gateway_result_id,
        &stdout_digest,
        &stderr_digest,
        &proof_digest,
        &request_digest,
        &state_digest,
        &policy_digest,
        &binding_digest,
    ] {
        validate_digest(digest, "gateway retrieval snapshot digest")?;
    }
    let divergent_rows: u64 = transaction.query_row(
        "SELECT COUNT(*) FROM gateway_results WHERE binding_digest = ?1 AND gateway_result_id != ?2",
        params![binding_digest, gateway_result_id],
        |row| row.get(0),
    )?;
    if divergent_rows != 0 {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    let Some(lease) = gateway_lease_row_v1(transaction, &lease_id)? else {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    };
    let current_generation: Option<u64> = transaction.query_row(
        "SELECT MAX(lifecycle_generation) FROM inflight_leases WHERE binding_digest = ?1",
        [&binding_digest],
        |row| row.get(0),
    )?;
    if lease.status != "completed"
        || lease.gateway_result_id.as_deref() != Some(gateway_result_id)
        || lease.request_digest != request_digest
        || lease.state_digest != state_digest
        || lease.policy_digest != policy_digest
        || lease.binding_digest != binding_digest
        || current_generation != Some(lease.lifecycle_generation)
    {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    let leader_request = transaction
        .query_row(
            "SELECT request_digest, state_digest, policy_digest, binding_digest, role, status, joined_lease_id, gateway_result_id FROM gateway_requests WHERE call_id = ?1",
            [&lease.call_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some(leader_request) = leader_request else {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    };
    if leader_request.0 != request_digest
        || leader_request.1 != state_digest
        || leader_request.2 != policy_digest
        || leader_request.3 != binding_digest
        || leader_request.4 != "leader"
        || leader_request.5 != "ready"
        || leader_request.6.as_deref() != Some(lease_id.as_str())
        || leader_request.7.as_deref() != Some(gateway_result_id)
    {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    let dependencies = load_result_dependencies_v1(transaction, gateway_result_id)?;
    validate_gateway_dependency_manifest_v1(&dependencies)?;
    let request_dependencies = load_request_dependencies_v1(transaction, &lease.call_id)?;
    validate_gateway_dependency_manifest_v1(&request_dependencies)?;
    if dependencies != request_dependencies
        || gateway_binding_content_digest(
            &request_digest,
            &state_digest,
            &policy_digest,
            &dependencies,
        ) != binding_digest
    {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    let source = transaction
        .query_row(
            "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, quarantined FROM results WHERE id = ?1",
            [&result_id],
            |row| Ok((row_to_result(row)?, row.get::<_, bool>(10)?)),
        )
        .optional()?;
    let Some((result, source_quarantined)) = source else {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    };
    if source_quarantined
        || result.request_key != request_digest
        || result.stdout_digest != stdout_digest
        || result.stderr_digest != stderr_digest
        || result.stdout_bytes != stdout_bytes
        || result.stderr_bytes != stderr_bytes
        || result.exit_code != exit_code
        || result.duration_ms != duration_ms
        || result.policy_version != policy_version
        || blake3::hash(result.proof_json.as_bytes()).to_hex().as_str() != proof_digest
        || gateway_policy_digest(&result.policy_version) != policy_digest
    {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    if gateway_result_content_digest(&lease, &result, &dependencies) != gateway_result_id {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    Ok((result, dependencies))
}

fn validate_gateway_dependency_manifest_v1(dependencies: &[GatewayDependencyV1]) -> Result<()> {
    if dependencies.len() > GATEWAY_MAX_DEPENDENCIES {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    for dependency in dependencies {
        validate_digest(
            &dependency.key_digest,
            "gateway result dependency key digest",
        )?;
        validate_digest(
            &dependency.value_digest,
            "gateway result dependency value digest",
        )?;
    }
    if dependencies
        .windows(2)
        .any(|pair| pair[0].key_digest >= pair[1].key_digest)
    {
        bail!(DeliveryAuthorityRefusalV1::InvalidBinding.code());
    }
    Ok(())
}

fn load_gateway_result_snapshot_v1(
    transaction: &Transaction<'_>,
    binding: &ValidatedGatewayReadV1,
    gateway_result_id: &str,
) -> Result<Option<StoredResult>> {
    let snapshot = transaction
        .query_row(
            "SELECT result_id, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, result_policy_version, proof_digest, request_digest, state_digest, policy_digest, binding_digest, origin FROM gateway_results WHERE gateway_result_id = ?1 AND status = 'ready'",
            [gateway_result_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, i32>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                ))
            },
        )
        .optional()?;
    let Some((
        result_id,
        stdout_digest,
        stderr_digest,
        stdout_bytes,
        stderr_bytes,
        exit_code,
        duration_ms,
        policy_version,
        proof_digest,
        request_digest,
        state_digest,
        policy_digest,
        binding_digest,
        origin,
    )) = snapshot
    else {
        return Ok(None);
    };
    if request_digest != binding.request_digest()
        || state_digest != binding.state_digest()
        || policy_digest != binding.policy_digest()
        || binding_digest != binding.binding_digest()
    {
        bail!("gateway result row is not bound to the admitted request");
    }
    let Some(result) = load_visible_result_tx(transaction, &result_id)? else {
        bail!("gateway result source is missing or quarantined");
    };
    if result.request_key
        != if origin == "direct_observation" {
            direct_observation_request_key_v1(binding)
        } else {
            request_digest.clone()
        }
        || result.stdout_digest != stdout_digest
        || result.stderr_digest != stderr_digest
        || result.stdout_bytes != stdout_bytes
        || result.stderr_bytes != stderr_bytes
        || result.exit_code != exit_code
        || result.duration_ms != duration_ms
        || result.policy_version != policy_version
        || blake3::hash(result.proof_json.as_bytes()).to_hex().as_str() != proof_digest
    {
        bail!("gateway result source metadata drifted after publication");
    }
    let dependencies = load_result_dependencies_v1(transaction, gateway_result_id)?;
    if origin == "direct_observation" {
        if direct_observation_content_digest_v1(binding, &result) != gateway_result_id {
            bail!("direct context observation content address mismatch");
        }
        return Ok(Some(result));
    }
    if origin != "leased" {
        bail!("gateway result origin is invalid");
    }
    let synthetic_lease = GatewayLeaseRowV1 {
        lease_id: String::new(),
        call_id: String::new(),
        request_digest,
        state_digest,
        policy_digest,
        binding_digest,
        freshness_valid_until_ms: 0,
        owner: String::new(),
        status: "completed".to_owned(),
        gateway_result_id: Some(gateway_result_id.to_owned()),
        expires_ms: 0,
        execution_started_ms: Some(0),
        completed_ms: Some(0),
        lifecycle_generation: 1,
    };
    if gateway_result_content_digest(&synthetic_lease, &result, &dependencies) != gateway_result_id
    {
        bail!("gateway result content address mismatch");
    }
    Ok(Some(result))
}

fn source_result_blobs_valid_v1(store: &Store, result: &StoredResult) -> bool {
    let Ok(stdout) = store.get_blob(&result.stdout_digest) else {
        return false;
    };
    let Ok(stderr) = store.get_blob(&result.stderr_digest) else {
        return false;
    };
    stdout.len() as u64 == result.stdout_bytes && stderr.len() as u64 == result.stderr_bytes
}

/// Quarantine the complete ready binding in the same transaction that detected
/// invalid durable authority. This prevents another process from observing a
/// transient hit between CAS/lease validation failure and quarantine.
fn quarantine_invalid_gateway_result_v1_tx(
    transaction: &Transaction<'_>,
    call_id: Option<&str>,
    gateway_result_id: &str,
    now: i64,
) -> Result<()> {
    let changed = transaction.execute(
        "UPDATE gateway_results SET status = 'quarantined', quarantine_reason = 'result_corrupt', updated_ms = ?2 WHERE gateway_result_id = ?1 AND status = 'ready'",
        params![gateway_result_id, now],
    )?;
    if changed == 0 {
        return Ok(());
    }
    transaction.execute(
        "UPDATE inflight_leases SET status = 'quarantined', reason = 'result_corrupt', completed_ms = ?2 WHERE gateway_result_id = ?1 AND status = 'completed'",
        params![gateway_result_id, now],
    )?;
    transaction.execute(
        "UPDATE gateway_requests SET status = 'quarantined', reason = 'result_corrupt', updated_ms = ?2 WHERE gateway_result_id = ?1 AND status = 'ready'",
        params![gateway_result_id, now],
    )?;
    record_gateway_event_v1_tx(
        transaction,
        call_id,
        None,
        Some(gateway_result_id),
        "binding_quarantined",
        Some(GatewayRefusalReason::ResultCorrupt.as_str()),
        0,
        now,
    )
}

fn expire_gateway_leases_v1_tx(
    transaction: &Transaction<'_>,
    now: i64,
    binding_digest: Option<&str>,
) -> Result<u64> {
    let expired: Vec<(String, String)> = if let Some(binding_digest) = binding_digest {
        let mut statement = transaction.prepare(
            "SELECT lease_id, call_id FROM inflight_leases WHERE status = 'active' AND expires_ms <= ?1 AND binding_digest = ?2",
        )?;
        statement
            .query_map(params![now, binding_digest], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?
    } else {
        let mut statement = transaction.prepare(
            "SELECT lease_id, call_id FROM inflight_leases WHERE status = 'active' AND expires_ms <= ?1",
        )?;
        statement
            .query_map([now], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (lease_id, call_id) in &expired {
        transaction.execute(
            "UPDATE inflight_leases SET status = 'expired', reason = 'deadline', completed_ms = ?2 WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, now],
        )?;
        transaction.execute(
            "UPDATE gateway_requests SET status = 'failed', reason = 'deadline', updated_ms = ?2 WHERE joined_lease_id = ?1 AND status IN ('inflight', 'waiting')",
            params![lease_id, now],
        )?;
        record_gateway_event_v1_tx(
            transaction,
            Some(call_id),
            Some(lease_id),
            None,
            "lease_expired",
            None,
            0,
            now,
        )?;
    }
    Ok(expired.len() as u64)
}

fn quarantine_gateway_divergence_v1_tx(
    transaction: &Transaction<'_>,
    lease: &GatewayLeaseRowV1,
    existing_gateway_result_id: &str,
    conflicting_gateway_result_id: &str,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "UPDATE gateway_results SET status = 'quarantined', quarantine_reason = 'divergent_result', updated_ms = ?2 WHERE binding_digest = ?1 AND status = 'ready'",
        params![lease.binding_digest, now],
    )?;
    transaction.execute(
        "UPDATE inflight_leases SET status = 'quarantined', reason = 'divergent_result', completed_ms = ?2 WHERE call_id = ?1",
        params![lease.call_id, now],
    )?;
    transaction.execute(
        "UPDATE gateway_requests SET status = 'quarantined', reason = 'divergent_result', updated_ms = ?2 WHERE joined_lease_id = (SELECT lease_id FROM inflight_leases WHERE call_id = ?1)",
        params![lease.call_id, now],
    )?;
    record_gateway_event_v1_tx(
        transaction,
        Some(&lease.call_id),
        None,
        Some(conflicting_gateway_result_id),
        "divergent_result",
        Some(existing_gateway_result_id),
        0,
        now,
    )
}

type ExpectedForeignKeyV1 = (&'static str, &'static str, &'static str, &'static str);
type ExpectedTableForeignKeysV1 = (&'static str, &'static [ExpectedForeignKeyV1]);

fn expected_gateway_column_shape(table: &str, column: &str) -> (&'static str, bool) {
    let integer = matches!(
        column,
        "freshness_valid_until_ms"
            | "ordinal"
            | "stdout_bytes"
            | "stderr_bytes"
            | "exit_code"
            | "exact_status"
            | "duration_ms"
            | "created_ms"
            | "updated_ms"
            | "acquired_ms"
            | "heartbeat_ms"
            | "expires_ms"
            | "execution_started_ms"
            | "completed_ms"
            | "lifecycle_generation"
            | "compaction_epoch"
            | "compaction_generation"
            | "estimated_tokens_avoided"
            | "bytes_omitted"
            | "issued_ms"
            | "recorded_ms"
            | "consumed_ms"
            | "retired_ms"
            | "delivered_ms"
            | "acknowledged_ms"
            | "schema_version"
            | "sequence"
            | "subject_version"
            | "event_sequence"
            | "fact_version"
            | "admission_event_sequence"
            | "retired_event_sequence"
            | "reference_version"
            | "total_bytes"
            | "generation"
            | "leader_lifecycle_generation"
            | "deadline_ms"
            | "through_sequence"
            | "delivered_bytes"
            | "active"
            | "revision"
            | "state_generation"
            | "task_context_bytes"
            | "workspace_state_bytes"
            | "maintenance_mode"
            | "reconciled_ms"
            | "observed_ms"
            | "started_ms"
            | "turn_completed"
            | "completed_commands"
            | "completed_source_reads"
            | "completed_edits"
            | "completed_mcp_calls"
            | "successful_tests"
            | "input_tokens"
            | "cached_input_tokens"
            | "output_tokens"
    ) || (table == "gateway_events" && column == "id");
    let nullable = matches!(
        (table, column),
        (
            "gateway_requests",
            "call_id" | "joined_lease_id" | "gateway_result_id" | "reason"
        ) | ("gateway_results", "gateway_result_id" | "quarantine_reason")
            | (
                "inflight_leases",
                "lease_id"
                    | "gateway_result_id"
                    | "reason"
                    | "execution_started_ms"
                    | "completed_ms"
            )
            | (
                "gateway_events",
                "id" | "call_id" | "lease_id" | "gateway_result_id" | "reason"
            )
            | ("gateway_delivery_receipts_v2", "source_receipt_id")
            | (
                "gateway_retrieval_grants_v2",
                "consumed_ms" | "retired_ms" | "retire_reason"
            )
            | (
                "context_ledger_events_v1",
                "sequence"
                    | "value_digest"
                    | "result_id"
                    | "result_digest"
                    | "total_bytes"
                    | "duration_ms"
            )
            | (
                "context_ledger_fact_versions_v1",
                "fact_task_id" | "retired_event_sequence" | "retirement_reason"
            )
            | (
                "context_ledger_result_references_v1",
                "retired_event_sequence" | "retirement_reason"
            )
            | ("context_ledger_leases_v1", "lease_id" | "completed_ms")
            | (
                "brain_events_v1",
                "source_digest"
                    | "command_digest"
                    | "command_hint"
                    | "exit_code"
                    | "authorization_scope_digest"
            )
            | ("brain_files_v1", "authorization_scope_digest")
            | ("brain_test_commands_v1", "authorization_scope_digest")
            | (
                "brain_runs_v1",
                "input_tokens" | "cached_input_tokens" | "output_tokens"
            )
            | ("context_tasks_v1", "definition_digest")
            | (
                "context_task_transitions_v1",
                "sequence"
                    | "from_state"
                    | "lease_id"
                    | "agent_id"
                    | "session_id"
                    | "lifecycle_generation"
            )
    );
    (if integer { "INTEGER" } else { "TEXT" }, !nullable)
}

fn verify_gateway_schema_current(connection: &Connection) -> Result<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        bail!("Again gateway schema verification requires version {SCHEMA_VERSION}, got {version}");
    }
    let tables: &[(&str, &[&str])] = &[
        (
            "gateway_requests",
            &[
                "call_id",
                "request_digest",
                "state_digest",
                "policy_digest",
                "binding_digest",
                "freshness_valid_until_ms",
                "owner",
                "role",
                "status",
                "joined_lease_id",
                "gateway_result_id",
                "reason",
                "created_ms",
                "updated_ms",
            ],
        ),
        (
            "gateway_request_dependencies",
            &[
                "call_id",
                "ordinal",
                "dependency_key_digest",
                "dependency_value_digest",
            ],
        ),
        (
            "gateway_results",
            &[
                "gateway_result_id",
                "request_digest",
                "state_digest",
                "policy_digest",
                "binding_digest",
                "result_id",
                "stdout_digest",
                "stderr_digest",
                "stdout_bytes",
                "stderr_bytes",
                "exit_code",
                "duration_ms",
                "result_policy_version",
                "proof_digest",
                "lease_id",
                "status",
                "quarantine_reason",
                "created_ms",
                "updated_ms",
                "origin",
            ],
        ),
        (
            "result_dependencies",
            &[
                "gateway_result_id",
                "ordinal",
                "dependency_key_digest",
                "dependency_value_digest",
            ],
        ),
        (
            "gateway_context_source_recipes_v1",
            &[
                "result_id",
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "repository_digest",
                "plan_json",
                "plan_digest",
                "created_ms",
            ],
        ),
        (
            "inflight_leases",
            &[
                "lease_id",
                "call_id",
                "request_digest",
                "state_digest",
                "policy_digest",
                "binding_digest",
                "freshness_valid_until_ms",
                "owner",
                "status",
                "gateway_result_id",
                "reason",
                "acquired_ms",
                "heartbeat_ms",
                "expires_ms",
                "execution_started_ms",
                "completed_ms",
                "lifecycle_generation",
            ],
        ),
        (
            "gateway_deliveries",
            &[
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_epoch",
                "gateway_result_id",
                "presentation",
                "estimated_tokens_avoided",
                "delivered_ms",
            ],
        ),
        (
            "gateway_delivery_receipts",
            &[
                "challenge_id",
                "authorization_scope_digest",
                "connection_digest",
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_generation",
                "call_digest",
                "gateway_result_id",
                "result_digest",
                "exact_status",
                "stdout_digest",
                "stdout_bytes",
                "stderr_digest",
                "stderr_bytes",
                "acknowledged_ms",
            ],
        ),
        (
            "gateway_delivery_receipts_v2",
            &[
                "receipt_id",
                "challenge_id",
                "authorization_scope_digest",
                "connection_digest",
                "connection_generation",
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_generation",
                "response_request_id_digest",
                "call_digest",
                "gateway_result_id",
                "result_digest",
                "exact_status",
                "stdout_digest",
                "stdout_bytes",
                "stderr_digest",
                "stderr_bytes",
                "response_envelope_digest",
                "presentation",
                "source_receipt_id",
                "acknowledged_ms",
            ],
        ),
        (
            "gateway_retrieval_grants_v2",
            &[
                "grant_id",
                "token_digest",
                "source_receipt_id",
                "authorization_scope_digest",
                "connection_digest",
                "connection_generation",
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_generation",
                "gateway_result_id",
                "issued_ms",
                "expires_ms",
                "consumed_ms",
                "retired_ms",
                "retire_reason",
            ],
        ),
        (
            "gateway_delivery_savings_v2",
            &[
                "receipt_id",
                "response_envelope_digest",
                "bytes_omitted",
                "estimated_tokens_avoided",
                "recorded_ms",
            ],
        ),
        (
            "gateway_events",
            &[
                "id",
                "call_id",
                "lease_id",
                "gateway_result_id",
                "event_type",
                "reason",
                "estimated_tokens_avoided",
                "created_ms",
            ],
        ),
        (
            "context_tasks_v1",
            &[
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "canonical_task_id",
                "prompt_digest",
                "prompt_text",
                "created_ms",
                "updated_ms",
                "definition_digest",
                "acceptance_criteria_json",
                "revision",
                "state",
                "state_generation",
            ],
        ),
        (
            "context_task_relations_v1",
            &[
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "source_task_id",
                "relation_kind",
                "target_task_id",
                "ordinal",
                "created_ms",
            ],
        ),
        (
            "context_task_transitions_v1",
            &[
                "sequence",
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "canonical_task_id",
                "from_state",
                "to_state",
                "state_generation",
                "lease_id",
                "agent_id",
                "session_id",
                "lifecycle_generation",
                "reason",
                "created_ms",
            ],
        ),
        (
            "context_workspace_quota_v1",
            &[
                "repository_id",
                "workspace_id",
                "task_context_bytes",
                "workspace_state_bytes",
                "maintenance_mode",
                "counter_checksum",
                "reconciled_ms",
            ],
        ),
        (
            "context_task_aliases_v1",
            &[
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "requested_task_id",
                "canonical_task_id",
                "created_ms",
            ],
        ),
        (
            "context_ledger_recipients_v1",
            &[
                "repository_id",
                "workspace_id",
                "task_id",
                "authorization_scope_digest",
                "agent_id",
                "session_id",
                "turn_id",
                "connection_generation",
                "compaction_generation",
                "lifecycle_generation",
                "active",
                "updated_ms",
            ],
        ),
        (
            "context_ledger_events_v1",
            &[
                "sequence",
                "envelope_digest",
                "canonical_digest",
                "schema_version",
                "repository_id",
                "workspace_id",
                "task_id",
                "authorization_scope_digest",
                "agent_id",
                "session_id",
                "turn_id",
                "connection_generation",
                "compaction_generation",
                "lifecycle_generation",
                "kind",
                "subject_id",
                "subject_version",
                "summary",
                "value_digest",
                "result_id",
                "result_digest",
                "total_bytes",
                "duration_ms",
                "created_ms",
            ],
        ),
        (
            "context_ledger_event_sources_v1",
            &[
                "event_sequence",
                "ordinal",
                "result_id",
                "result_digest",
                "repository_id",
                "workspace_id",
                "state_digest",
                "dependency_digest",
                "authorization_scope_digest",
                "locator",
                "binding_digest",
            ],
        ),
        (
            "context_ledger_event_dependencies_v1",
            &[
                "event_sequence",
                "ordinal",
                "dependency_key_digest",
                "dependency_value_digest",
            ],
        ),
        (
            "context_ledger_fact_versions_v1",
            &[
                "repository_id",
                "workspace_id",
                "task_id",
                "fact_id",
                "fact_version",
                "admission_event_sequence",
                "topic",
                "statement",
                "value_digest",
                "fact_scope",
                "fact_task_id",
                "retired_event_sequence",
                "retirement_reason",
            ],
        ),
        (
            "context_ledger_result_references_v1",
            &[
                "repository_id",
                "workspace_id",
                "task_id",
                "result_id",
                "reference_version",
                "admission_event_sequence",
                "result_digest",
                "total_bytes",
                "retired_event_sequence",
                "retirement_reason",
            ],
        ),
        (
            "context_ledger_leases_v1",
            &[
                "lease_id",
                "repository_id",
                "workspace_id",
                "task_id",
                "authorization_scope_digest",
                "work_key_digest",
                "generation",
                "leader_agent_id",
                "leader_session_id",
                "leader_lifecycle_generation",
                "summary",
                "status",
                "acquired_ms",
                "heartbeat_ms",
                "deadline_ms",
                "expires_ms",
                "completed_ms",
            ],
        ),
        (
            "context_ledger_delivery_receipts_v1",
            &[
                "receipt_digest",
                "response_envelope_digest",
                "repository_id",
                "workspace_id",
                "task_id",
                "authorization_scope_digest",
                "agent_id",
                "session_id",
                "turn_id",
                "connection_generation",
                "compaction_generation",
                "lifecycle_generation",
                "through_sequence",
                "delivered_bytes",
                "acknowledged_ms",
            ],
        ),
        (
            "context_ledger_delivery_savings_v1",
            &[
                "receipt_digest",
                "response_envelope_digest",
                "bytes_omitted",
                "recorded_ms",
            ],
        ),
        (
            "brain_events_v1",
            &[
                "session_id",
                "event_id",
                "task_id",
                "kind",
                "path",
                "source_digest",
                "command_digest",
                "command_hint",
                "exit_code",
                "created_ms",
                "authorization_scope_digest",
            ],
        ),
        (
            "brain_files_v1",
            &[
                "path",
                "source_digest",
                "task_id",
                "session_id",
                "event_id",
                "observed_ms",
                "authorization_scope_digest",
            ],
        ),
        (
            "brain_test_commands_v1",
            &[
                "command_hint",
                "command_digest",
                "task_id",
                "observed_ms",
                "authorization_scope_digest",
            ],
        ),
        (
            "brain_runs_v1",
            &[
                "session_id",
                "task_id",
                "authorization_scope_digest",
                "started_ms",
                "completed_ms",
                "exit_code",
                "turn_completed",
                "completed_commands",
                "completed_source_reads",
                "completed_edits",
                "completed_mcp_calls",
                "successful_tests",
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
            ],
        ),
    ];
    let mut table_info_statement = connection
        .prepare("SELECT name, type, \"notnull\" FROM pragma_table_info(?1) ORDER BY cid")?;
    for (table, expected) in tables {
        let actual: Vec<(String, String, bool)> = table_info_statement
            .query_map([table], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let expected = expected
            .iter()
            .map(|column| {
                let (column_type, not_null) = expected_gateway_column_shape(table, column);
                ((*column).to_owned(), column_type.to_owned(), not_null)
            })
            .collect::<Vec<_>>();
        if actual != expected {
            bail!("Again gateway schema table {table} has an unexpected column shape");
        }
    }
    let required_indexes: &[(&str, &str, &[&str], bool, bool)] = &[
        (
            "gateway_requests",
            "gateway_requests_binding_idx",
            &["binding_digest", "created_ms"],
            false,
            false,
        ),
        (
            "gateway_requests",
            "gateway_requests_lease_idx",
            &["joined_lease_id", "status"],
            false,
            false,
        ),
        (
            "gateway_results",
            "gateway_results_ready_idx",
            &["binding_digest"],
            true,
            true,
        ),
        (
            "gateway_results",
            "gateway_results_direct_idx",
            &["binding_digest"],
            true,
            true,
        ),
        (
            "gateway_results",
            "gateway_results_result_idx",
            &["result_id"],
            false,
            false,
        ),
        (
            "result_dependencies",
            "result_dependencies_digest_idx",
            &["dependency_key_digest", "dependency_value_digest"],
            false,
            false,
        ),
        (
            "inflight_leases",
            "inflight_leases_active_idx",
            &["binding_digest"],
            true,
            true,
        ),
        (
            "inflight_leases",
            "inflight_leases_expiry_idx",
            &["status", "expires_ms"],
            false,
            false,
        ),
        (
            "inflight_leases",
            "inflight_leases_generation_idx",
            &["binding_digest", "lifecycle_generation"],
            true,
            false,
        ),
        (
            "gateway_delivery_receipts",
            "gateway_delivery_receipts_context_idx",
            &[
                "authorization_scope_digest",
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_generation",
                "gateway_result_id",
            ],
            false,
            false,
        ),
        (
            "gateway_delivery_receipts_v2",
            "gateway_delivery_receipts_v2_context_idx",
            &[
                "authorization_scope_digest",
                "connection_digest",
                "connection_generation",
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_generation",
                "gateway_result_id",
                "presentation",
            ],
            false,
            false,
        ),
        (
            "gateway_retrieval_grants_v2",
            "gateway_retrieval_grants_v2_context_idx",
            &[
                "authorization_scope_digest",
                "connection_digest",
                "connection_generation",
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_generation",
                "gateway_result_id",
                "expires_ms",
            ],
            false,
            false,
        ),
        (
            "gateway_events",
            "gateway_events_created_idx",
            &["created_ms"],
            false,
            false,
        ),
        (
            "gateway_events",
            "gateway_events_type_idx",
            &["event_type"],
            false,
            false,
        ),
        (
            "context_tasks_v1",
            "context_tasks_definition_idx",
            &[
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "definition_digest",
            ],
            true,
            false,
        ),
        (
            "context_tasks_v1",
            "context_tasks_state_idx",
            &["repository_id", "workspace_id", "state", "created_ms"],
            false,
            false,
        ),
        (
            "context_task_relations_v1",
            "context_task_relations_target_idx",
            &[
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "target_task_id",
                "relation_kind",
            ],
            false,
            false,
        ),
        (
            "context_task_transitions_v1",
            "context_task_transitions_task_idx",
            &[
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "canonical_task_id",
                "sequence",
            ],
            false,
            false,
        ),
        (
            "context_task_aliases_v1",
            "context_task_aliases_canonical_idx",
            &[
                "repository_id",
                "workspace_id",
                "authorization_scope_digest",
                "canonical_task_id",
            ],
            false,
            false,
        ),
        (
            "context_ledger_events_v1",
            "context_ledger_events_task_idx",
            &["repository_id", "workspace_id", "task_id", "sequence"],
            false,
            false,
        ),
        (
            "context_ledger_events_v1",
            "context_ledger_events_result_idx",
            &["result_id", "sequence"],
            false,
            false,
        ),
        (
            "context_ledger_event_sources_v1",
            "context_ledger_sources_result_idx",
            &["result_id", "event_sequence"],
            false,
            false,
        ),
        (
            "context_ledger_event_dependencies_v1",
            "context_ledger_dependency_reverse_idx",
            &[
                "dependency_key_digest",
                "dependency_value_digest",
                "event_sequence",
            ],
            false,
            false,
        ),
        (
            "context_ledger_fact_versions_v1",
            "context_ledger_facts_current_idx",
            &["repository_id", "workspace_id", "task_id", "fact_id"],
            false,
            true,
        ),
        (
            "context_ledger_result_references_v1",
            "context_ledger_results_current_idx",
            &["repository_id", "workspace_id", "task_id", "result_id"],
            false,
            true,
        ),
        (
            "context_ledger_leases_v1",
            "context_ledger_leases_active_idx",
            &[
                "repository_id",
                "workspace_id",
                "task_id",
                "authorization_scope_digest",
                "work_key_digest",
            ],
            true,
            true,
        ),
        (
            "context_ledger_leases_v1",
            "context_ledger_leases_expiry_idx",
            &["status", "expires_ms"],
            false,
            false,
        ),
        (
            "context_ledger_delivery_receipts_v1",
            "context_ledger_receipts_task_idx",
            &[
                "repository_id",
                "workspace_id",
                "task_id",
                "through_sequence",
            ],
            false,
            false,
        ),
        (
            "brain_events_v1",
            "brain_events_recent_idx",
            &["created_ms"],
            false,
            false,
        ),
        (
            "brain_events_v1",
            "brain_events_task_idx",
            &["task_id", "created_ms"],
            false,
            false,
        ),
        (
            "brain_files_v1",
            "brain_files_recent_idx",
            &["observed_ms"],
            false,
            false,
        ),
        (
            "brain_files_v1",
            "brain_files_scope_recent_idx",
            &["authorization_scope_digest", "observed_ms"],
            false,
            false,
        ),
        (
            "brain_test_commands_v1",
            "brain_test_commands_recent_idx",
            &["observed_ms"],
            false,
            false,
        ),
        (
            "brain_test_commands_v1",
            "brain_test_commands_scope_recent_idx",
            &["authorization_scope_digest", "observed_ms"],
            false,
            false,
        ),
        (
            "brain_runs_v1",
            "brain_runs_scope_recent_idx",
            &["authorization_scope_digest", "completed_ms"],
            false,
            false,
        ),
    ];
    let mut index_signature_statement = connection.prepare(
        "SELECT \"unique\", partial FROM pragma_index_list(?1) WHERE name = ?2 AND origin = 'c'",
    )?;
    let mut index_columns_statement =
        connection.prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")?;
    for (table, index, expected_columns, expected_unique, expected_partial) in required_indexes {
        let signature = index_signature_statement
            .query_row(params![table, index], |row| {
                Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?))
            })
            .optional()?;
        if signature != Some((*expected_unique, *expected_partial)) {
            bail!("Again gateway schema is missing required index {index}");
        }
        let actual_columns: Vec<String> = index_columns_statement
            .query_map([index], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if actual_columns
            != expected_columns
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        {
            bail!("Again gateway schema index {index} has an unexpected key shape");
        }
    }
    for (index, predicate) in [
        (
            "gateway_results_ready_idx",
            "WHERE status = 'ready' AND origin = 'leased'",
        ),
        (
            "gateway_results_direct_idx",
            "WHERE status = 'ready' AND origin = 'direct_observation'",
        ),
    ] {
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?1",
            [index],
            |row| row.get(0),
        )?;
        if !sql.contains(predicate) {
            bail!("Again gateway schema index {index} has an unexpected admission predicate");
        }
    }
    let required_checks = [
        ("brain_runs_v1", "CHECK(completed_ms >= started_ms)"),
        ("brain_runs_v1", "CHECK(turn_completed IN (0, 1))"),
        (
            "brain_runs_v1",
            "CHECK(cached_input_tokens IS NULL OR cached_input_tokens <= input_tokens)",
        ),
        (
            "gateway_context_source_recipes_v1",
            "CHECK(json_valid(plan_json)",
        ),
        (
            "gateway_context_source_recipes_v1",
            "length(CAST(plan_json AS BLOB)) BETWEEN 1 AND 65536",
        ),
        (
            "gateway_context_source_recipes_v1",
            "CHECK(length(plan_digest) = 64)",
        ),
        ("gateway_requests", "CHECK(length(request_digest) = 64)"),
        ("gateway_requests", "CHECK(length(state_digest) = 64)"),
        ("gateway_requests", "CHECK(length(policy_digest) = 64)"),
        ("gateway_requests", "CHECK(length(binding_digest) = 64)"),
        ("gateway_requests", "CHECK(length(owner) BETWEEN 1 AND 128)"),
        (
            "gateway_requests",
            "CHECK(role IN ('leader', 'follower', 'ready', 'refused'))",
        ),
        (
            "gateway_request_dependencies",
            "CHECK(ordinal >= 0 AND ordinal < 64)",
        ),
        (
            "gateway_request_dependencies",
            "UNIQUE (call_id, dependency_key_digest)",
        ),
        ("gateway_results", "CHECK(length(gateway_result_id) = 64)"),
        ("gateway_results", "CHECK(stdout_bytes >= 0)"),
        ("gateway_results", "CHECK(stderr_bytes >= 0)"),
        ("gateway_results", "CHECK(duration_ms >= 0)"),
        (
            "gateway_results",
            "CHECK(origin IN ('leased', 'direct_observation'))",
        ),
        (
            "gateway_results",
            "CHECK(status IN ('ready', 'quarantined'))",
        ),
        (
            "result_dependencies",
            "UNIQUE (gateway_result_id, dependency_key_digest)",
        ),
        ("inflight_leases", "CHECK(length(request_digest) = 64)"),
        ("inflight_leases", "CHECK(length(owner) BETWEEN 1 AND 128)"),
        (
            "inflight_leases",
            "CHECK(status IN ('active', 'completed', 'failed', 'expired', 'quarantined'))",
        ),
        ("gateway_deliveries", "CHECK(compaction_epoch >= 0)"),
        (
            "gateway_delivery_receipts",
            "CHECK(length(authorization_scope_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(connection_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(challenge_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(session_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(turn_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(agent_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(compaction_generation >= 0)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(call_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(gateway_result_id) = 64)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(result_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts",
            "CHECK(length(stdout_digest) = 64)",
        ),
        ("gateway_delivery_receipts", "CHECK(stdout_bytes >= 0)"),
        (
            "gateway_delivery_receipts",
            "CHECK(length(stderr_digest) = 64)",
        ),
        ("gateway_delivery_receipts", "CHECK(stderr_bytes >= 0)"),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(receipt_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "UNIQUE CHECK(length(challenge_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(authorization_scope_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(connection_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(response_request_id_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(response_envelope_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(connection_generation) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(session_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(turn_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(agent_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(compaction_generation >= 0)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(call_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(gateway_result_id) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(result_digest) = 64)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(stdout_digest) = 64)",
        ),
        ("gateway_delivery_receipts_v2", "CHECK(stdout_bytes >= 0)"),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(length(stderr_digest) = 64)",
        ),
        ("gateway_delivery_receipts_v2", "CHECK(stderr_bytes >= 0)"),
        (
            "gateway_delivery_receipts_v2",
            "CHECK(presentation IN ('full', 'compact'))",
        ),
        (
            "gateway_delivery_receipts_v2",
            "(presentation = 'full' AND source_receipt_id IS NULL)",
        ),
        (
            "gateway_delivery_receipts_v2",
            "(presentation = 'compact' AND source_receipt_id IS NOT NULL)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(grant_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "UNIQUE CHECK(length(token_digest) = 64)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(authorization_scope_digest) = 64)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(connection_digest) = 64)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(connection_generation) = 64)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(session_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(turn_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(agent_id) BETWEEN 1 AND 128)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(compaction_generation >= 0)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(length(gateway_result_id) = 64)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(expires_ms > issued_ms)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(consumed_ms IS NULL OR consumed_ms >= issued_ms)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(retired_ms IS NULL OR retired_ms >= issued_ms)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK(consumed_ms IS NULL OR retired_ms IS NULL)",
        ),
        (
            "gateway_retrieval_grants_v2",
            "CHECK((retired_ms IS NULL) = (retire_reason IS NULL))",
        ),
        (
            "gateway_delivery_savings_v2",
            "CHECK(length(response_envelope_digest) = 64)",
        ),
        ("gateway_delivery_savings_v2", "CHECK(bytes_omitted > 0)"),
        (
            "gateway_delivery_savings_v2",
            "CHECK(estimated_tokens_avoided >= 0)",
        ),
        (
            "gateway_delivery_receipts",
            "FOREIGN KEY (gateway_result_id) REFERENCES gateway_results",
        ),
        (
            "gateway_deliveries",
            "FOREIGN KEY (gateway_result_id) REFERENCES gateway_results",
        ),
        (
            "gateway_events",
            "CHECK(length(event_type) BETWEEN 1 AND 64)",
        ),
        (
            "context_tasks_v1",
            "CHECK(length(authorization_scope_digest) = 64)",
        ),
        (
            "context_tasks_v1",
            "CHECK(length(CAST(prompt_text AS BLOB)) BETWEEN 1 AND 8192)",
        ),
        (
            "context_tasks_v1",
            "CHECK(definition_digest IS NULL OR length(definition_digest) = 64)",
        ),
        (
            "context_tasks_v1",
            "CHECK(json_valid(acceptance_criteria_json))",
        ),
        ("context_tasks_v1", "CHECK(state IN ("),
        (
            "context_task_relations_v1",
            "CHECK(relation_kind IN ('parent', 'dependency', 'supersedes'))",
        ),
        (
            "context_task_relations_v1",
            "CHECK(source_task_id != target_task_id)",
        ),
        (
            "context_task_transitions_v1",
            "CHECK(length(CAST(reason AS BLOB)) BETWEEN 1 AND 512)",
        ),
        (
            "context_task_transitions_v1",
            "CHECK((agent_id IS NULL) = (session_id IS NULL))",
        ),
        (
            "context_workspace_quota_v1",
            "CHECK(maintenance_mode IN (0, 1))",
        ),
        (
            "context_task_aliases_v1",
            "CHECK(length(authorization_scope_digest) = 64)",
        ),
        ("context_ledger_events_v1", "CHECK(schema_version = 1)"),
        ("context_ledger_events_v1", "CHECK(kind IN ("),
        (
            "context_ledger_event_sources_v1",
            "UNIQUE(event_sequence, result_id, locator)",
        ),
        (
            "context_ledger_event_dependencies_v1",
            "UNIQUE(event_sequence, dependency_key_digest)",
        ),
        (
            "context_ledger_fact_versions_v1",
            "CHECK((retired_event_sequence IS NULL) = (retirement_reason IS NULL))",
        ),
        (
            "context_ledger_result_references_v1",
            "CHECK((retired_event_sequence IS NULL) = (retirement_reason IS NULL))",
        ),
        (
            "context_ledger_leases_v1",
            "CHECK(status IN ('active', 'completed', 'failed', 'cancelled', 'expired'))",
        ),
        (
            "context_ledger_leases_v1",
            "CHECK((status = 'active') = (completed_ms IS NULL))",
        ),
        (
            "context_ledger_delivery_savings_v1",
            "CHECK(bytes_omitted > 0)",
        ),
    ];
    let mut table_sql_statement =
        connection.prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1")?;
    let mut current_table = None;
    let mut current_sql = String::new();
    for (table, fragment) in required_checks {
        if current_table != Some(table) {
            current_sql = table_sql_statement.query_row([table], |row| row.get(0))?;
            current_table = Some(table);
        }
        if !current_sql.contains(fragment) {
            bail!("Again gateway schema table {table} is missing a required constraint");
        }
    }
    let expected_foreign_keys: &[ExpectedTableForeignKeysV1] = &[
        (
            "gateway_context_source_recipes_v1",
            &[(
                "gateway_results",
                "result_id",
                "gateway_result_id",
                "CASCADE",
            )],
        ),
        (
            "context_task_aliases_v1",
            &[
                (
                    "context_tasks_v1",
                    "repository_id",
                    "repository_id",
                    "RESTRICT",
                ),
                (
                    "context_tasks_v1",
                    "workspace_id",
                    "workspace_id",
                    "RESTRICT",
                ),
                (
                    "context_tasks_v1",
                    "authorization_scope_digest",
                    "authorization_scope_digest",
                    "RESTRICT",
                ),
                (
                    "context_tasks_v1",
                    "canonical_task_id",
                    "canonical_task_id",
                    "RESTRICT",
                ),
            ],
        ),
        (
            "context_ledger_event_sources_v1",
            &[
                (
                    "gateway_results",
                    "result_id",
                    "gateway_result_id",
                    "RESTRICT",
                ),
                (
                    "context_ledger_events_v1",
                    "event_sequence",
                    "sequence",
                    "CASCADE",
                ),
            ],
        ),
        (
            "context_ledger_event_dependencies_v1",
            &[(
                "context_ledger_events_v1",
                "event_sequence",
                "sequence",
                "CASCADE",
            )],
        ),
        (
            "context_ledger_fact_versions_v1",
            &[
                (
                    "context_ledger_events_v1",
                    "retired_event_sequence",
                    "sequence",
                    "RESTRICT",
                ),
                (
                    "context_ledger_events_v1",
                    "admission_event_sequence",
                    "sequence",
                    "RESTRICT",
                ),
            ],
        ),
        (
            "context_ledger_result_references_v1",
            &[
                (
                    "context_ledger_events_v1",
                    "retired_event_sequence",
                    "sequence",
                    "RESTRICT",
                ),
                (
                    "context_ledger_events_v1",
                    "admission_event_sequence",
                    "sequence",
                    "RESTRICT",
                ),
            ],
        ),
        (
            "context_ledger_delivery_savings_v1",
            &[(
                "context_ledger_delivery_receipts_v1",
                "receipt_digest",
                "receipt_digest",
                "CASCADE",
            )],
        ),
        (
            "gateway_delivery_receipts_v2",
            &[
                (
                    "gateway_delivery_receipts_v2",
                    "source_receipt_id",
                    "receipt_id",
                    "RESTRICT",
                ),
                (
                    "gateway_results",
                    "gateway_result_id",
                    "gateway_result_id",
                    "CASCADE",
                ),
            ],
        ),
        (
            "gateway_retrieval_grants_v2",
            &[
                (
                    "gateway_results",
                    "gateway_result_id",
                    "gateway_result_id",
                    "CASCADE",
                ),
                (
                    "gateway_delivery_receipts_v2",
                    "source_receipt_id",
                    "receipt_id",
                    "CASCADE",
                ),
            ],
        ),
        (
            "gateway_delivery_savings_v2",
            &[(
                "gateway_delivery_receipts_v2",
                "receipt_id",
                "receipt_id",
                "CASCADE",
            )],
        ),
        (
            "gateway_request_dependencies",
            &[("gateway_requests", "call_id", "call_id", "CASCADE")],
        ),
        (
            "gateway_results",
            &[("results", "result_id", "id", "RESTRICT")],
        ),
        (
            "result_dependencies",
            &[(
                "gateway_results",
                "gateway_result_id",
                "gateway_result_id",
                "CASCADE",
            )],
        ),
        (
            "gateway_delivery_receipts",
            &[(
                "gateway_results",
                "gateway_result_id",
                "gateway_result_id",
                "CASCADE",
            )],
        ),
        (
            "inflight_leases",
            &[("gateway_requests", "call_id", "call_id", "RESTRICT")],
        ),
        (
            "gateway_deliveries",
            &[(
                "gateway_results",
                "gateway_result_id",
                "gateway_result_id",
                "CASCADE",
            )],
        ),
    ];
    let mut foreign_key_statement = connection.prepare(
        "SELECT \"table\", \"from\", \"to\", on_delete FROM pragma_foreign_key_list(?1) ORDER BY id",
    )?;
    for (table, expected) in expected_foreign_keys {
        let actual: Vec<(String, String, String, String)> = foreign_key_statement
            .query_map([table], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let expected = expected
            .iter()
            .map(|(target, from, to, delete)| {
                (
                    (*target).to_owned(),
                    (*from).to_owned(),
                    (*to).to_owned(),
                    (*delete).to_owned(),
                )
            })
            .collect::<Vec<_>>();
        if actual != expected {
            bail!("Again gateway schema table {table} has unexpected foreign keys");
        }
    }
    let foreign_key_failure: Option<String> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()?;
    if let Some(table) = foreign_key_failure {
        bail!("Again gateway schema foreign-key violation in {table}");
    }
    let missing_canonical_alias: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM context_tasks_v1 AS task
             LEFT JOIN context_task_aliases_v1 AS alias
               ON alias.repository_id = task.repository_id
              AND alias.workspace_id = task.workspace_id
              AND alias.authorization_scope_digest = task.authorization_scope_digest
              AND alias.requested_task_id = task.canonical_task_id
              AND alias.canonical_task_id = task.canonical_task_id
             WHERE alias.requested_task_id IS NULL
         )",
        [],
        |row| row.get(0),
    )?;
    if missing_canonical_alias {
        bail!("Again context task registry is missing a canonical alias");
    }
    let task_capacity_exceeded: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM context_tasks_v1
             GROUP BY repository_id, workspace_id
             HAVING COUNT(*) > ?1
         )",
        [MAX_CONTEXT_TASKS_PER_WORKSPACE_V1],
        |row| row.get(0),
    )?;
    if task_capacity_exceeded {
        bail!("Again context task registry exceeds its task capacity");
    }
    let alias_capacity_exceeded: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM context_task_aliases_v1
             GROUP BY repository_id, workspace_id
             HAVING COUNT(*) > ?1
         )",
        [MAX_CONTEXT_TASK_ALIASES_PER_WORKSPACE_V1],
        |row| row.get(0),
    )?;
    if alias_capacity_exceeded {
        bail!("Again context task registry exceeds its alias capacity");
    }
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Deferred)?;
    let task_keys = {
        let mut statement = transaction.prepare(
            "SELECT repository_id, workspace_id, authorization_scope_digest, canonical_task_id
             FROM context_tasks_v1
             ORDER BY repository_id, workspace_id, authorization_scope_digest, canonical_task_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (repository, workspace, authorization, task_id) in &task_keys {
        let task = load_task_record_tx_v1(
            &transaction,
            repository,
            workspace,
            authorization,
            task_id,
            task_id,
        )
        .context("Again context task registry contains a corrupt definition")?;
        let transitions = load_task_transitions_tx_v1(
            &transaction,
            repository,
            workspace,
            authorization,
            task_id,
        )?;
        let Some(last) = transitions.last() else {
            bail!("Again context task registry is missing transition history");
        };
        if last.to_state != task.state
            || last.state_generation != task.state_generation
            || transitions.len() as u64 != task.state_generation
            || transitions.first().is_some_and(|transition| {
                transition.from_state.is_some() || transition.state_generation != 1
            })
            || transitions.windows(2).any(|pair| {
                pair[1].state_generation != pair[0].state_generation.saturating_add(1)
                    || pair[1].from_state != Some(pair[0].to_state)
            })
        {
            bail!("Again context task transition history is inconsistent");
        }
    }
    let graph_edges = {
        let mut statement = transaction.prepare(
            "SELECT repository_id, workspace_id, authorization_scope_digest,
                    source_task_id, target_task_id
             FROM context_task_relations_v1
             ORDER BY repository_id, workspace_id, authorization_scope_digest,
                      source_task_id, relation_kind, ordinal",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (repository, workspace, authorization, source, target) in graph_edges {
        ensure_task_graph_edge_v1(
            &transaction,
            &repository,
            &workspace,
            &authorization,
            &source,
            &target,
        )
        .context("Again context task graph is corrupt")?;
    }
    let quotas = {
        let mut statement = transaction.prepare(
            "SELECT repository_id, workspace_id, task_context_bytes,
                    workspace_state_bytes, maintenance_mode, counter_checksum
             FROM context_workspace_quota_v1
             ORDER BY repository_id, workspace_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (repository, workspace, task_bytes, workspace_bytes, maintenance, checksum) in quotas {
        if checksum
            != task_quota_checksum_v1(
                &repository,
                &workspace,
                task_bytes,
                workspace_bytes,
                maintenance,
            )
            || (!maintenance
                && (task_bytes > MAX_TASK_CONTEXT_LOGICAL_BYTES_V1
                    || workspace_bytes > MAX_WORKSPACE_STATE_LOGICAL_BYTES_V1))
        {
            bail!("Again context workspace quota accounting is corrupt");
        }
    }
    let missing_quota: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM context_tasks_v1 AS task
             LEFT JOIN context_workspace_quota_v1 AS quota
               ON quota.repository_id = task.repository_id
              AND quota.workspace_id = task.workspace_id
             WHERE quota.repository_id IS NULL
         )",
        [],
        |row| row.get(0),
    )?;
    if missing_quota {
        bail!("Again context workspace quota accounting is incomplete");
    }
    transaction.commit()?;
    Ok(())
}

fn verify_reasoning_metrics_accounting_v1(connection: &Connection) -> Result<()> {
    let mut result_columns = connection.prepare("SELECT name FROM pragma_table_info('results')")?;
    let result_columns = result_columns
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_complete_result_shape = [
        "id",
        "exit_code",
        "stdout_digest",
        "stdout_bytes",
        "stderr_digest",
        "stderr_bytes",
        "quarantined",
    ]
    .iter()
    .all(|required| result_columns.iter().any(|actual| actual == required));
    if !has_complete_result_shape {
        // Early legacy test/fixture databases may have the historical minimal
        // results table. Migration creates the gateway tables empty, so there
        // is no reasoning accounting to authenticate. Never waive the shape
        // requirement once any gateway result exists.
        let has_gateway_result: bool =
            connection.query_row("SELECT EXISTS(SELECT 1 FROM gateway_results)", [], |row| {
                row.get(0)
            })?;
        if has_gateway_result {
            bail!("Again reasoning delivery accounting requires the complete result schema");
        }
        return Ok(());
    }

    // Receipts are evidence, not authority by identifier. Every counted row
    // must still bind to the exact ready, unquarantined result bytes.
    let invalid_exact_receipt: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM gateway_delivery_receipts AS receipt
             LEFT JOIN gateway_results AS gateway_result
               ON gateway_result.gateway_result_id = receipt.gateway_result_id
             LEFT JOIN results AS stored_result
               ON stored_result.id = gateway_result.result_id
             WHERE gateway_result.gateway_result_id IS NULL
                OR stored_result.id IS NULL
                OR gateway_result.status != 'ready'
                OR gateway_result.quarantine_reason IS NOT NULL
                OR stored_result.quarantined != 0
                OR receipt.result_digest != receipt.gateway_result_id
                OR receipt.exact_status != gateway_result.exit_code
                OR receipt.stdout_digest != gateway_result.stdout_digest
                OR receipt.stdout_bytes != gateway_result.stdout_bytes
                OR receipt.stderr_digest != gateway_result.stderr_digest
                OR receipt.stderr_bytes != gateway_result.stderr_bytes
                OR receipt.exact_status != stored_result.exit_code
                OR receipt.stdout_digest != stored_result.stdout_digest
                OR receipt.stdout_bytes != stored_result.stdout_bytes
                OR receipt.stderr_digest != stored_result.stderr_digest
                OR receipt.stderr_bytes != stored_result.stderr_bytes
             UNION ALL
             SELECT 1
             FROM gateway_delivery_receipts_v2 AS receipt
             LEFT JOIN gateway_results AS gateway_result
               ON gateway_result.gateway_result_id = receipt.gateway_result_id
             LEFT JOIN results AS stored_result
               ON stored_result.id = gateway_result.result_id
             WHERE gateway_result.gateway_result_id IS NULL
                OR stored_result.id IS NULL
                OR gateway_result.status != 'ready'
                OR gateway_result.quarantine_reason IS NOT NULL
                OR stored_result.quarantined != 0
                OR receipt.result_digest != receipt.gateway_result_id
                OR receipt.exact_status != gateway_result.exit_code
                OR receipt.stdout_digest != gateway_result.stdout_digest
                OR receipt.stdout_bytes != gateway_result.stdout_bytes
                OR receipt.stderr_digest != gateway_result.stderr_digest
                OR receipt.stderr_bytes != gateway_result.stderr_bytes
                OR receipt.exact_status != stored_result.exit_code
                OR receipt.stdout_digest != stored_result.stdout_digest
                OR receipt.stdout_bytes != stored_result.stdout_bytes
                OR receipt.stderr_digest != stored_result.stderr_digest
                OR receipt.stderr_bytes != stored_result.stderr_bytes
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_exact_receipt {
        bail!("Again reasoning delivery accounting has an invalid exact-result receipt");
    }

    // A compact receipt may cite only a prior full receipt for the exact same
    // authenticated recipient generation and exact result. Restart, turn,
    // compaction, or generation changes therefore cannot inherit savings.
    let invalid_compact_source: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM gateway_delivery_receipts_v2 AS compact
             LEFT JOIN gateway_delivery_receipts_v2 AS source
               ON source.receipt_id = compact.source_receipt_id
             WHERE compact.presentation = 'compact'
               AND (
                    source.receipt_id IS NULL
                    OR source.presentation != 'full'
                    OR source.authorization_scope_digest != compact.authorization_scope_digest
                    OR source.connection_digest != compact.connection_digest
                    OR source.connection_generation != compact.connection_generation
                    OR source.session_id != compact.session_id
                    OR source.turn_id != compact.turn_id
                    OR source.agent_id != compact.agent_id
                    OR source.compaction_generation != compact.compaction_generation
                    OR source.gateway_result_id != compact.gateway_result_id
                    OR source.result_digest != compact.result_digest
                    OR source.exact_status != compact.exact_status
                    OR source.stdout_digest != compact.stdout_digest
                    OR source.stdout_bytes != compact.stdout_bytes
                    OR source.stderr_digest != compact.stderr_digest
                    OR source.stderr_bytes != compact.stderr_bytes
                    OR source.acknowledged_ms > compact.acknowledged_ms
               )
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_compact_source {
        bail!("Again reasoning delivery accounting has an invalid compact source");
    }

    let invalid_savings: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM gateway_delivery_savings_v2 AS savings
             LEFT JOIN gateway_delivery_receipts_v2 AS receipt
               ON receipt.receipt_id = savings.receipt_id
             WHERE receipt.receipt_id IS NULL
                OR receipt.presentation != 'compact'
                OR receipt.response_envelope_digest != savings.response_envelope_digest
                OR savings.estimated_tokens_avoided != savings.bytes_omitted / 4
                OR savings.recorded_ms < receipt.acknowledged_ms
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_savings {
        bail!("Again reasoning delivery accounting has invalid confirmed savings");
    }

    // Duplicate database receipts can arise from a retried durable write. They
    // are harmless only when the immutable response envelope and every binding
    // dimension agree. Aggregation below then counts that envelope once.
    let inconsistent_duplicate: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM (
                 SELECT receipt.response_envelope_digest
                 FROM gateway_delivery_receipts_v2 AS receipt
                 LEFT JOIN gateway_delivery_receipts_v2 AS source
                   ON source.receipt_id = receipt.source_receipt_id
                 GROUP BY receipt.response_envelope_digest
                 HAVING COUNT(*) > 1
                    AND (
                         MIN(receipt.presentation) != MAX(receipt.presentation)
                         OR MIN(receipt.authorization_scope_digest) != MAX(receipt.authorization_scope_digest)
                         OR MIN(receipt.connection_digest) != MAX(receipt.connection_digest)
                         OR MIN(receipt.connection_generation) != MAX(receipt.connection_generation)
                         OR MIN(receipt.session_id) != MAX(receipt.session_id)
                         OR MIN(receipt.turn_id) != MAX(receipt.turn_id)
                         OR MIN(receipt.agent_id) != MAX(receipt.agent_id)
                         OR MIN(receipt.compaction_generation) != MAX(receipt.compaction_generation)
                         OR MIN(receipt.response_request_id_digest) != MAX(receipt.response_request_id_digest)
                         OR MIN(receipt.call_digest) != MAX(receipt.call_digest)
                         OR MIN(receipt.gateway_result_id) != MAX(receipt.gateway_result_id)
                         OR MIN(receipt.result_digest) != MAX(receipt.result_digest)
                         OR MIN(receipt.exact_status) != MAX(receipt.exact_status)
                         OR MIN(receipt.stdout_digest) != MAX(receipt.stdout_digest)
                         OR MIN(receipt.stdout_bytes) != MAX(receipt.stdout_bytes)
                         OR MIN(receipt.stderr_digest) != MAX(receipt.stderr_digest)
                         OR MIN(receipt.stderr_bytes) != MAX(receipt.stderr_bytes)
                         OR MIN(COALESCE(source.response_envelope_digest, ''))
                            != MAX(COALESCE(source.response_envelope_digest, ''))
                    )
             )
             UNION ALL
             SELECT 1
             FROM (
                 SELECT receipt.response_envelope_digest
                 FROM gateway_delivery_receipts_v2 AS receipt
                 JOIN gateway_delivery_savings_v2 AS savings
                   ON savings.receipt_id = receipt.receipt_id
                 GROUP BY receipt.response_envelope_digest
                 HAVING COUNT(*) > 1
                    AND (
                         MIN(savings.bytes_omitted) != MAX(savings.bytes_omitted)
                         OR MIN(savings.estimated_tokens_avoided)
                            != MAX(savings.estimated_tokens_avoided)
                    )
             )
         )",
        [],
        |row| row.get(0),
    )?;
    if inconsistent_duplicate {
        bail!("Again reasoning delivery accounting has inconsistent duplicate receipts");
    }
    Ok(())
}

fn lease_refusal_for_status(status: &str) -> GatewayRefusalReason {
    match status {
        "expired" => GatewayRefusalReason::LeaseExpired,
        "quarantined" => GatewayRefusalReason::Quarantined,
        "completed" | "failed" => GatewayRefusalReason::AlreadyTerminal,
        _ => GatewayRefusalReason::LeaseNotCurrent,
    }
}

impl FileDigestCache for Store {
    fn lookup(&mut self, identity: &FileIdentity) -> Option<[u8; 32]> {
        if !identity.is_valid() {
            return None;
        }
        let device = u64_blob(identity.device);
        let inode = u64_blob(identity.inode);
        let row = self
            .conn
            .query_row(
                r#"
                SELECT digest, row_checksum
                FROM file_digests
                WHERE device = ?1 AND inode = ?2 AND mode = ?3 AND uid = ?4
                  AND gid = ?5 AND size = ?6 AND mtime_sec = ?7 AND mtime_nsec = ?8
                  AND ctime_sec = ?9 AND ctime_nsec = ?10
                "#,
                params![
                    device,
                    inode,
                    i64::from(identity.mode),
                    i64::from(identity.uid),
                    i64::from(identity.gid),
                    u64_blob(identity.size),
                    identity.mtime_sec,
                    identity.mtime_nsec,
                    identity.ctime_sec,
                    identity.ctime_nsec,
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional();

        let (digest_bytes, checksum_bytes) = match row {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(_) => return None,
        };
        let Ok(digest) = <[u8; 32]>::try_from(digest_bytes.as_slice()) else {
            self.delete_file_digest(identity);
            return None;
        };
        let Ok(checksum) = <[u8; 32]>::try_from(checksum_bytes.as_slice()) else {
            self.delete_file_digest(identity);
            return None;
        };
        if checksum != file_digest_row_checksum(identity, &digest) {
            self.delete_file_digest(identity);
            return None;
        }
        // Keep warm fingerprinting read-only. Updating LRU state for every file in
        // a recursive tree turns a cache hit into thousands of SQLite writes.
        // `last_used_ms` therefore means last validated/recorded time in v0; an
        // evicted hot digest is merely recomputed, never a correctness failure.
        Some(digest)
    }

    fn record(&mut self, identity: &FileIdentity, digest: [u8; 32]) {
        if !identity.is_valid() {
            return;
        }
        let checksum = file_digest_row_checksum(identity, &digest);
        let insert_result = self.conn.execute(
            r#"
                INSERT INTO file_digests (
                    device, inode, mode, uid, gid, size, mtime_sec, mtime_nsec,
                    ctime_sec, ctime_nsec, digest, row_checksum, last_used_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                ON CONFLICT(device, inode) DO UPDATE SET
                    mode = excluded.mode, uid = excluded.uid, gid = excluded.gid,
                    size = excluded.size, mtime_sec = excluded.mtime_sec,
                    mtime_nsec = excluded.mtime_nsec, ctime_sec = excluded.ctime_sec,
                    ctime_nsec = excluded.ctime_nsec, digest = excluded.digest,
                    row_checksum = excluded.row_checksum, last_used_ms = excluded.last_used_ms
                "#,
            params![
                u64_blob(identity.device),
                u64_blob(identity.inode),
                i64::from(identity.mode),
                i64::from(identity.uid),
                i64::from(identity.gid),
                u64_blob(identity.size),
                identity.mtime_sec,
                identity.mtime_nsec,
                identity.ctime_sec,
                identity.ctime_nsec,
                digest.as_slice(),
                checksum.as_slice(),
                now_ms(),
            ],
        );
        if insert_result.is_err() {
            return;
        }

        self.file_digest_writes_since_prune = self.file_digest_writes_since_prune.saturating_add(1);
        if self.file_digest_writes_since_prune >= FILE_DIGEST_PRUNE_INTERVAL {
            self.prune_file_digests();
            self.file_digest_writes_since_prune = 0;
        }
    }
}

impl Store {
    fn delete_file_digest(&self, identity: &FileIdentity) {
        let _ = self.conn.execute(
            "DELETE FROM file_digests WHERE device = ?1 AND inode = ?2",
            params![u64_blob(identity.device), u64_blob(identity.inode)],
        );
    }

    fn prune_file_digests(&self) {
        let Ok(count) = self
            .conn
            .query_row("SELECT COUNT(*) FROM file_digests", [], |row| {
                row.get::<_, i64>(0)
            })
        else {
            return;
        };
        let excess = (count - MAX_FILE_DIGEST_ROWS).max(0);
        if excess == 0 {
            return;
        }
        let _ = self.conn.execute(
            r#"
            DELETE FROM file_digests
            WHERE (device, inode) IN (
                SELECT device, inode FROM file_digests
                ORDER BY last_used_ms ASC, device ASC, inode ASC LIMIT ?1
            )
            "#,
            [excess],
        );
    }
}

fn u64_blob(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn file_digest_row_checksum(identity: &FileIdentity, digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("again.file-digest-row.v1");
    hasher.update(&identity.device.to_be_bytes());
    hasher.update(&identity.inode.to_be_bytes());
    hasher.update(&identity.mode.to_be_bytes());
    hasher.update(&identity.uid.to_be_bytes());
    hasher.update(&identity.gid.to_be_bytes());
    hasher.update(&identity.size.to_be_bytes());
    hasher.update(&identity.mtime_sec.to_be_bytes());
    hasher.update(&identity.mtime_nsec.to_be_bytes());
    hasher.update(&identity.ctime_sec.to_be_bytes());
    hasher.update(&identity.ctime_nsec.to_be_bytes());
    hasher.update(digest);
    *hasher.finalize().as_bytes()
}

fn default_workspace_state_root(workspace: &Path, temporary_directory: &Path) -> Result<PathBuf> {
    let temporary_directory = fs::canonicalize(temporary_directory).with_context(|| {
        format!(
            "resolve operating-system temporary directory {}",
            temporary_directory.display()
        )
    })?;
    let base = temporary_directory.join(format!("again-{}", user_namespace()));
    validate_external_state_root(workspace, &base)?;
    let base = prepare_store_root(&base)?;
    let workspaces = prepare_private_child_dir(&base, "workspaces")?;
    let root = workspaces.join(workspace_state_id(workspace));
    validate_external_state_root(workspace, &root)?;
    Ok(root)
}

fn workspace_state_id(workspace: &Path) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("again.workspace-state-path.v1");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(workspace.as_os_str().as_bytes());
    }
    #[cfg(not(unix))]
    hasher.update(workspace.to_string_lossy().as_bytes());
    hasher.finalize().to_hex().to_string()
}

#[cfg(unix)]
fn user_namespace() -> String {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }.to_string()
}

#[cfg(not(unix))]
fn user_namespace() -> String {
    let identity = std::env::var_os("USERNAME")
        .or_else(|| std::env::var_os("USER"))
        .unwrap_or_else(|| std::ffi::OsString::from("unknown"));
    blake3::hash(identity.to_string_lossy().as_bytes())
        .to_hex()
        .to_string()
}

fn prepare_store_root(requested: &Path) -> Result<PathBuf> {
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()?.join(requested)
    };
    match fs::symlink_metadata(&requested) {
        Ok(metadata) => {
            // Never chmod an arbitrary existing AGAIN_HOME or caller-supplied
            // path: a typo such as AGAIN_HOME=$HOME must fail without changing
            // broad directory permissions. Existing roots opt in with 0700.
            validate_private_directory(&requested, &metadata, "Again state root")?;
            fs::canonicalize(&requested)
                .with_context(|| format!("canonicalize Again state root {}", requested.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = requested.parent().ok_or_else(|| {
                anyhow!("Again state root has no parent: {}", requested.display())
            })?;
            let name = requested
                .file_name()
                .ok_or_else(|| anyhow!("Again state root has no final component"))?;
            let parent = fs::canonicalize(parent).with_context(|| {
                format!(
                    "resolve parent of Again state root {}; create its parent directories first",
                    requested.display()
                )
            })?;
            let root = parent.join(name);
            match create_private_directory(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create Again state root {}", root.display()));
                }
            }
            let metadata = fs::symlink_metadata(&root)
                .with_context(|| format!("inspect Again state root {}", root.display()))?;
            validate_private_directory(&root, &metadata, "Again state root")?;
            fs::canonicalize(&root)
                .with_context(|| format!("canonicalize Again state root {}", root.display()))
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspect Again state root {}", requested.display()))
        }
    }
}

fn prospective_store_root(requested: &Path) -> Result<PathBuf> {
    let requested = requested.to_path_buf();
    match fs::symlink_metadata(&requested) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!("AGAIN_HOME must not be a symlink: {}", requested.display());
            }
            fs::canonicalize(&requested).with_context(|| {
                format!(
                    "resolve configured Again state root {}",
                    requested.display()
                )
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = requested.parent().ok_or_else(|| {
                anyhow!("Again state root has no parent: {}", requested.display())
            })?;
            let name = requested
                .file_name()
                .ok_or_else(|| anyhow!("Again state root has no final component"))?;
            Ok(fs::canonicalize(parent)
                .with_context(|| {
                    format!(
                        "resolve parent of Again state root {}; create its parent directories first",
                        requested.display()
                    )
                })?
                .join(name))
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspect Again state root {}", requested.display()))
        }
    }
}

fn validate_external_state_root(workspace: &Path, root: &Path) -> Result<()> {
    if root.starts_with(workspace) {
        bail!(
            "Again state must be outside the active workspace {}; set AGAIN_HOME to an absolute external directory",
            workspace.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_state_ancestors(root: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    let parent = root
        .parent()
        .ok_or_else(|| anyhow!("configured Again state root has no parent"))?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).with_context(|| {
            format!(
                "inspect configured Again state ancestor {}",
                ancestor.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "configured Again state ancestor must be a real directory: {}",
                ancestor.display()
            );
        }
        if metadata.uid() != effective_uid && metadata.uid() != 0 {
            bail!(
                "configured Again state ancestor has an untrusted owner: {}",
                ancestor.display()
            );
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            bail!(
                "configured Again state ancestor is writable by other users without sticky protection: {}",
                ancestor.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_state_ancestors(_root: &Path) -> Result<()> {
    Ok(())
}

fn prepare_private_child_dir(parent: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || matches!(name, "." | "..") {
        bail!("invalid Again state directory component");
    }
    let path = parent.join(name);
    let created = match create_private_directory(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("create Again state directory {}", path.display()));
        }
    };
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect Again state directory {}", path.display()))?;
    let label = if created {
        "new Again state directory"
    } else {
        "Again state directory"
    };
    validate_private_directory(&path, &metadata, label)?;
    Ok(path)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

fn validate_owned_directory(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "{label} must be a real directory, not a symlink: {}",
            path.display()
        );
    }
    validate_current_owner(path, metadata, label)
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    validate_owned_directory(path, metadata, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            bail!("{label} must already have mode 0700: {}", path.display());
        }
    }
    Ok(())
}

fn reject_unsafe_existing_file(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_owned_regular_file(path, &metadata, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {label} {}", path.display())),
    }
}

fn ensure_private_database_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => {
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_unsafe_existing_file(path, "Again database")?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("create Again database {}", path.display()));
        }
    }
    set_private_file(path)
}

fn validate_owned_regular_file(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    validate_owned_regular_file_identity(path, metadata, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("{label} must already have mode 0600: {}", path.display());
        }
    }
    Ok(())
}

fn validate_owned_regular_file_identity(
    path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{label} must be a regular file, not a symlink: {}",
            path.display()
        );
    }
    validate_current_owner(path, metadata, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!("{label} must not be hard-linked: {}", path.display());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_current_owner(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!(
            "{label} is not owned by the current user: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_current_owner(_path: &Path, _metadata: &fs::Metadata, _label: &str) -> Result<()> {
    Ok(())
}

fn blob_path_under(blobs: &Path, digest: &str) -> Result<PathBuf> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid BLAKE3 digest");
    }
    Ok(blobs.join(&digest[..2]).join(&digest[2..]))
}

fn ensure_blob_file(target: &Path, digest: &str, expected: &[u8]) -> Result<()> {
    match fs::symlink_metadata(target) {
        Ok(metadata) => {
            validate_owned_regular_file(target, &metadata, "Again blob")?;
            return verify_blob_file(target, digest, expected);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect Again blob {digest}"));
        }
    }

    let parent = target.parent().context("blob target has no parent")?;
    let blobs = parent.parent().context("blob shard has no CAS parent")?;
    let shard = parent
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("blob shard is not valid UTF-8"))?;
    let parent = prepare_private_child_dir(blobs, shard)?;
    let staged = parent.join(format!(".{digest}.{}.tmp", Uuid::new_v4().simple()));
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(expected)?;
        file.sync_all()?;
        set_private_file(&staged)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    match fs::rename(&staged, target) {
        Ok(()) => Ok(()),
        Err(error) if fs::symlink_metadata(target).is_ok() => {
            let _ = fs::remove_file(&staged);
            let metadata = fs::symlink_metadata(target)
                .with_context(|| format!("inspect raced Again blob {digest}"))?;
            validate_owned_regular_file(target, &metadata, "Again blob")?;
            verify_blob_file(target, digest, expected).context(error)
        }
        Err(error) => {
            let _ = fs::remove_file(&staged);
            Err(error).context("commit CAS blob")
        }
    }
}

fn verify_blob_file(path: &Path, digest: &str, expected: &[u8]) -> Result<()> {
    let existing = read_blob_bounded(path, digest)?;
    let actual = blake3::hash(&existing).to_hex().to_string();
    if actual != digest {
        bail!("CAS corruption: blob {digest} hashes to {actual}");
    }
    if existing != expected {
        bail!("CAS collision or corruption for blob {digest}");
    }
    Ok(())
}

fn read_blob_bounded(path: &Path, digest: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect blob {digest} before bounded read"))?;
    if metadata.len() > MAX_LOCAL_BLOB_BYTES as u64 {
        bail!("Again blob {digest} exceeds the local 16 MiB limit");
    }
    let file = File::open(path).with_context(|| format!("open blob {digest}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_LOCAL_BLOB_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read blob {digest}"))?;
    if bytes.len() > MAX_LOCAL_BLOB_BYTES {
        bail!("Again blob {digest} grew beyond the local 16 MiB limit");
    }
    Ok(bytes)
}

fn system_time_ms(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
}

fn create_self_ignoring_gitignore(root: &Path) -> Result<()> {
    if root.file_name().and_then(|name| name.to_str()) != Some(".again") {
        return Ok(());
    }
    let path = root.join(".gitignore");
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(b"*\n")?;
            file.sync_all()?;
            set_private_file(&path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_unsafe_existing_file(&path, "Again .gitignore")
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

fn row_to_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredResult> {
    Ok(StoredResult {
        id: row.get(0)?,
        request_key: row.get(1)?,
        stdout_digest: row.get(2)?,
        stderr_digest: row.get(3)?,
        stdout_bytes: row.get(4)?,
        stderr_bytes: row.get(5)?,
        exit_code: row.get(6)?,
        duration_ms: row.get(7)?,
        policy_version: row.get(8)?,
        proof_json: row.get(9)?,
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(all(test, unix))]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    validate_owned_directory(path, &metadata, "Again private directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(all(test, not(unix)))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_owned_regular_file_identity(path, &metadata, "Again private file")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{File, FileTimes};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use tempfile::TempDir;

    fn restore_pre_v15_gateway_result_shape(store: &Store) {
        store
            .conn
            .execute_batch(
                "DROP INDEX gateway_results_direct_idx;
             DROP INDEX gateway_results_ready_idx;
             ALTER TABLE gateway_results DROP COLUMN origin;
             CREATE UNIQUE INDEX gateway_results_ready_idx
               ON gateway_results(binding_digest) WHERE status = 'ready';",
            )
            .unwrap();
    }

    fn context_test_identity(
        agent: &str,
        authorization: char,
        connection: char,
        lifecycle_generation: u64,
    ) -> ContextLedgerIdentityV1 {
        ContextLedgerIdentityV1::new(
            "repository",
            "workspace",
            "task",
            &authorization.to_string().repeat(64),
            agent,
            &format!("session-{agent}"),
            "turn",
            &connection.to_string().repeat(64),
            0,
            lifecycle_generation,
        )
        .unwrap()
    }

    fn context_test_gateway_result(
        store: &mut Store,
        label: &str,
        dependency_key: &str,
        dependency_value: &str,
    ) -> (ValidatedGatewayReadV1, String) {
        let state_digest = blake3::hash(format!("state-{label}").as_bytes())
            .to_hex()
            .to_string();
        let binding = ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
            request_digest: blake3::hash(format!("request-{label}").as_bytes())
                .to_hex()
                .to_string(),
            state_digest: state_digest.clone(),
            policy_digest: gateway_policy_digest("context-ledger-test-v1"),
            operation: GatewayOperationDispositionV1::ReplayEligibleRead,
            freshness: GatewayFreshnessEvidenceV1 {
                snapshot_digest: state_digest,
                observed_at_ms: now_ms(),
                valid_until_ms: now_ms() + 60_000,
            },
            dependencies: vec![GatewayDependencyV1 {
                key_digest: dependency_key.to_owned(),
                value_digest: dependency_value.to_owned(),
            }],
        })
        .unwrap();
        let owner = format!("context-owner-{label}");
        let lease_id = match store.acquire_gateway_call(&binding, &owner).unwrap() {
            GatewayCallAcquisition::Leader { lease_id, .. } => lease_id,
            other => panic!("expected context test leader, got {other:?}"),
        };
        assert_eq!(
            store.start_gateway_execution(&lease_id, &owner).unwrap(),
            GatewayExecutionStart::Started
        );
        let result = store
            .insert_result(
                binding.request_digest(),
                format!("result-{label}").as_bytes(),
                b"",
                0,
                5,
                "context-ledger-test-v1",
                "{}",
            )
            .unwrap();
        let gateway_result_id = match store.complete_gateway_call(&lease_id, &result.id).unwrap() {
            GatewayCompletion::Completed {
                gateway_result_id, ..
            } => gateway_result_id,
            other => panic!("expected context test completion, got {other:?}"),
        };
        (binding, gateway_result_id)
    }

    #[test]
    fn direct_observation_backs_context_but_never_becomes_a_cache_candidate() {
        let temp = TempDir::new().unwrap();
        let mut store = Store::open(temp.path().join("state")).unwrap();
        let identity = context_test_identity("agent-a", 'a', '1', 1);
        store.activate_context_recipient_v1(&identity).unwrap();
        let state_digest = blake3::hash(b"direct-state").to_hex().to_string();
        let binding = ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
            request_digest: blake3::hash(b"direct-request").to_hex().to_string(),
            state_digest: state_digest.clone(),
            policy_digest: gateway_policy_digest("context-ledger-test-v1"),
            operation: GatewayOperationDispositionV1::ReplayEligibleRead,
            freshness: GatewayFreshnessEvidenceV1 {
                snapshot_digest: state_digest,
                observed_at_ms: now_ms(),
                valid_until_ms: now_ms() + 60_000,
            },
            dependencies: vec![GatewayDependencyV1 {
                key_digest: "b".repeat(64),
                value_digest: "c".repeat(64),
            }],
        })
        .unwrap();
        let result = store
            .insert_result(
                &direct_observation_request_key_v1(&binding),
                b"direct bytes",
                b"",
                0,
                1,
                "context-ledger-test-v1",
                "{}",
            )
            .unwrap();
        let direct_id = store
            .publish_gateway_direct_observation_v1(&binding, &result.id)
            .unwrap();
        assert_eq!(
            store
                .publish_gateway_direct_observation_v1(&binding, &result.id)
                .unwrap(),
            direct_id,
        );
        let stats = store.gateway_stats().unwrap();
        assert_eq!(stats.direct_observations_published, 1);
        assert_eq!(stats.provider_calls_avoided, 0);
        assert_eq!(stats.exact_hits, 0);
        assert_eq!(store.stats().unwrap().direct_observations_published, 1);
        let source = store
            .context_verified_observation_v1(&identity, &binding, &direct_id, "repo.read:input.txt")
            .unwrap();
        let fact = context_test_fact(&store, &identity, "fact:direct", &source);
        store
            .admit_context_fact_v1(
                &identity,
                &"d".repeat(64),
                1,
                &fact,
                std::slice::from_ref(&source),
            )
            .unwrap();
        let forged_reference =
            ReasoningRetrievalIdentityV1::new(&direct_id, &direct_id, b"direct bytes".len() as u64)
                .unwrap();
        assert!(
            store
                .append_context_event_v1(
                    &identity,
                    &"e".repeat(64),
                    &ContextLedgerEventInputV1::ResultReference {
                        reference: forged_reference,
                        reference_version: 1,
                        verified_sources: vec![source.clone()],
                    },
                )
                .is_err()
        );
        assert_eq!(
            store
                .context_task_snapshot_v1(&identity)
                .unwrap()
                .current_facts()
                .len(),
            1
        );
        assert_eq!(
            store
                .get_gateway_result(&binding, &direct_id)
                .unwrap()
                .unwrap()
                .stdout,
            b"direct bytes"
        );
        assert!(matches!(
            store
                .acquire_gateway_call(&binding, "direct-test-owner")
                .unwrap(),
            GatewayCallAcquisition::Leader { .. }
        ));
        store.conn.execute(
            "UPDATE gateway_results SET stdout_bytes = stdout_bytes + 1 WHERE gateway_result_id = ?1",
            [&direct_id],
        ).unwrap();
        assert!(store.get_gateway_result(&binding, &direct_id).is_err());
    }

    fn context_test_fact(
        store: &Store,
        identity: &ContextLedgerIdentityV1,
        fact_id: &str,
        source: &ContextVerifiedObservationV1,
    ) -> ReasoningFactV1 {
        store
            .context_fact_from_verified_observations_v1(
                identity,
                fact_id,
                true,
                std::slice::from_ref(source),
            )
            .unwrap()
    }

    fn context_test_admit_result(
        store: &Store,
        identity: &ContextLedgerIdentityV1,
        binding: &ValidatedGatewayReadV1,
        result_id: &str,
        label: &str,
    ) {
        let source = store
            .context_verified_observation_v1(identity, binding, result_id, "repo.read:input.txt")
            .unwrap();
        let fact = context_test_fact(store, identity, &format!("fact:{label}"), &source);
        let fact_envelope = blake3::hash(format!("fact:{label}").as_bytes())
            .to_hex()
            .to_string();
        store
            .admit_context_fact_v1(
                identity,
                &fact_envelope,
                1,
                &fact,
                std::slice::from_ref(&source),
            )
            .unwrap();
        let full = store
            .get_gateway_result(binding, result_id)
            .unwrap()
            .unwrap();
        let retrieval = ReasoningRetrievalIdentityV1::new(
            result_id,
            result_id,
            full.result.stdout_bytes + full.result.stderr_bytes,
        )
        .unwrap();
        let reference_envelope = blake3::hash(format!("reference:{label}").as_bytes())
            .to_hex()
            .to_string();
        store
            .append_context_event_v1(
                identity,
                &reference_envelope,
                &ContextLedgerEventInputV1::ResultReference {
                    reference: retrieval,
                    reference_version: 1,
                    verified_sources: vec![source],
                },
            )
            .unwrap();
    }

    #[test]
    fn source_recipe_is_scope_bound_idempotent_and_counted_once() {
        let temp = TempDir::new().unwrap();
        let mut store = Store::open(temp.path().join("state")).unwrap();
        let identity = context_test_identity("agent-a", 'a', '1', 1);
        store.activate_context_recipient_v1(&identity).unwrap();
        let (binding, result_id) = context_test_gateway_result(
            &mut store,
            "source-recipe",
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let before = store
            .task_quota_status_v1(identity.repository_id(), identity.workspace_id())
            .unwrap();
        let plan = br#"{"content_paths":["input.txt"],"recursive_trees":[],"source_trees":[],"directory_listings":[],"negative_dependencies":[]}"#;
        store
            .admit_context_source_recipe_v1(&identity, &binding, &result_id, &"d".repeat(64), plan)
            .unwrap();
        let after_first = store
            .task_quota_status_v1(identity.repository_id(), identity.workspace_id())
            .unwrap();
        store
            .admit_context_source_recipe_v1(&identity, &binding, &result_id, &"d".repeat(64), plan)
            .unwrap();
        let after = store
            .task_quota_status_v1(identity.repository_id(), identity.workspace_id())
            .unwrap();
        assert_eq!(
            after.workspace_state_bytes,
            after_first.workspace_state_bytes
        );
        let result = store
            .get_gateway_result(&binding, &result_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.workspace_state_bytes,
            before.workspace_state_bytes
                + result.result.stdout_bytes
                + result.result.stderr_bytes
                + plan.len() as u64
                + 256
        );
        assert_eq!(
            store
                .context_source_recipe_v1(&identity, &result_id)
                .unwrap(),
            Some(("d".repeat(64), plan.to_vec()))
        );
        let other_scope = context_test_identity("agent-b", 'e', '2', 1);
        store.activate_context_recipient_v1(&other_scope).unwrap();
        assert!(
            store
                .context_source_recipe_v1(&other_scope, &result_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unavailable_source_retires_matching_dependencies_across_tasks_only() {
        let temp = TempDir::new().unwrap();
        let mut store = Store::open(temp.path().join("state")).unwrap();
        let first = context_test_identity("agent-a", 'a', '1', 1);
        let second = ContextLedgerIdentityV1::new(
            "repository",
            "workspace",
            "second-task",
            &"a".repeat(64),
            "agent-b",
            "session-b",
            "turn",
            &"2".repeat(64),
            0,
            1,
        )
        .unwrap();
        let unrelated = ContextLedgerIdentityV1::new(
            "repository",
            "workspace",
            "unrelated-task",
            &"a".repeat(64),
            "agent-c",
            "session-c",
            "turn",
            &"3".repeat(64),
            0,
            1,
        )
        .unwrap();
        let other_scope = context_test_identity("agent-d", 'd', '4', 1);
        for identity in [&first, &second, &unrelated, &other_scope] {
            store.activate_context_recipient_v1(identity).unwrap();
        }
        let (first_binding, first_id) = context_test_gateway_result(
            &mut store,
            "source-first",
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let (second_binding, second_id) = context_test_gateway_result(
            &mut store,
            "source-second",
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let (unrelated_binding, unrelated_id) = context_test_gateway_result(
            &mut store,
            "source-unrelated",
            &"e".repeat(64),
            &"f".repeat(64),
        );
        let (scope_binding, scope_id) = context_test_gateway_result(
            &mut store,
            "source-other-scope",
            &"b".repeat(64),
            &"c".repeat(64),
        );
        context_test_admit_result(&store, &first, &first_binding, &first_id, "first");
        context_test_admit_result(&store, &second, &second_binding, &second_id, "second");
        context_test_admit_result(
            &store,
            &unrelated,
            &unrelated_binding,
            &unrelated_id,
            "unrelated",
        );
        context_test_admit_result(
            &store,
            &other_scope,
            &scope_binding,
            &scope_id,
            "other-scope",
        );
        let cursor = store.context_task_snapshot_v1(&second).unwrap().cursor();
        let retired = store
            .invalidate_context_source_observation_v1(&first, &"9".repeat(64), &first_id)
            .unwrap();
        assert_eq!(retired.retired_facts, 2);
        assert_eq!(retired.retired_result_references, 2);
        assert!(store.retrieve_context_result_v1(&first, &first_id).is_err());
        assert!(
            store
                .retrieve_context_result_v1(&second, &second_id)
                .is_err()
        );
        assert!(
            store
                .retrieve_context_result_v1(&unrelated, &unrelated_id)
                .is_ok()
        );
        assert!(
            store
                .retrieve_context_result_v1(&other_scope, &scope_id)
                .is_ok()
        );
        let delta = store.context_delta_after_v1(&second, cursor, 64).unwrap();
        assert!(
            delta
                .events()
                .iter()
                .any(|event| event.kind() == ContextLedgerEventKindV1::Invalidation)
        );
    }

    #[test]
    fn unavailable_source_retirement_is_atomic_and_same_result_can_be_readmitted() {
        let temp = TempDir::new().unwrap();
        let mut store = Store::open(temp.path().join("state")).unwrap();
        let identity = context_test_identity("agent-a", 'a', '1', 1);
        store.activate_context_recipient_v1(&identity).unwrap();
        let (binding, result_id) = context_test_gateway_result(
            &mut store,
            "recoverable",
            &"b".repeat(64),
            &"c".repeat(64),
        );
        let source = store
            .context_verified_observation_v1(&identity, &binding, &result_id, "repo.read:input.txt")
            .unwrap();
        let full = store
            .get_gateway_result(&binding, &result_id)
            .unwrap()
            .unwrap();
        let retrieval = ReasoningRetrievalIdentityV1::new(
            &result_id,
            &result_id,
            full.result.stdout_bytes + full.result.stderr_bytes,
        )
        .unwrap();
        let fact = context_test_fact(&store, &identity, "fact:recoverable", &source);
        store
            .admit_context_fact_v1(
                &identity,
                &"d".repeat(64),
                1,
                &fact,
                std::slice::from_ref(&source),
            )
            .unwrap();
        store
            .append_context_event_v1(
                &identity,
                &"e".repeat(64),
                &ContextLedgerEventInputV1::ResultReference {
                    reference: retrieval.clone(),
                    reference_version: 1,
                    verified_sources: vec![source.clone()],
                },
            )
            .unwrap();
        assert_eq!(
            store
                .context_result_admission_version_v1(&identity, &result_id)
                .unwrap(),
            1
        );
        assert!(
            store
                .context_result_reference_current_v1(&identity, &result_id)
                .unwrap()
        );
        let retired = store
            .invalidate_context_source_observation_v1(&identity, &"f".repeat(64), &result_id)
            .unwrap();
        assert_eq!(retired.retired_facts, 1);
        assert_eq!(retired.retired_result_references, 1);
        assert!(
            store
                .retrieve_context_result_v1(&identity, &result_id)
                .is_err()
        );
        assert!(
            !store
                .context_result_reference_current_v1(&identity, &result_id)
                .unwrap()
        );
        assert_eq!(
            store
                .context_result_admission_version_v1(&identity, &result_id)
                .unwrap(),
            2
        );
        let restored_fact = context_test_fact(&store, &identity, "fact:recoverable:2", &source);
        store
            .admit_context_fact_v1(
                &identity,
                &"1".repeat(64),
                1,
                &restored_fact,
                std::slice::from_ref(&source),
            )
            .unwrap();
        store
            .append_context_event_v1(
                &identity,
                &"2".repeat(64),
                &ContextLedgerEventInputV1::ResultReference {
                    reference: retrieval,
                    reference_version: 2,
                    verified_sources: vec![source],
                },
            )
            .unwrap();
        assert!(
            store
                .retrieve_context_result_v1(&identity, &result_id)
                .is_ok()
        );
        assert!(
            store
                .context_result_reference_current_v1(&identity, &result_id)
                .unwrap()
        );
    }

    #[test]
    fn shared_context_ledger_converges_across_handles_and_invalidates_exact_reverse_edges() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("state");
        let mut first = Store::open(&root).unwrap();
        let first_identity = context_test_identity("agent-a", 'a', '1', 1);
        let second_identity = context_test_identity("agent-b", 'a', '2', 1);
        first
            .activate_context_recipient_v1(&first_identity)
            .unwrap();

        let affected_key = "b".repeat(64);
        let unaffected_key = "c".repeat(64);
        let (affected_binding, affected_result) =
            context_test_gateway_result(&mut first, "affected", &affected_key, &"d".repeat(64));
        let (unaffected_binding, unaffected_result) =
            context_test_gateway_result(&mut first, "unaffected", &unaffected_key, &"e".repeat(64));
        let affected_source = first
            .context_verified_observation_v1(
                &first_identity,
                &affected_binding,
                &affected_result,
                "src/affected.rs:1",
            )
            .unwrap();
        let unaffected_source = first
            .context_verified_observation_v1(
                &first_identity,
                &unaffected_binding,
                &unaffected_result,
                "src/unaffected.rs:1",
            )
            .unwrap();
        let affected_fact =
            context_test_fact(&first, &first_identity, "affected-fact", &affected_source);
        let unaffected_fact = context_test_fact(
            &first,
            &first_identity,
            "unaffected-fact",
            &unaffected_source,
        );
        let agent_prose = ReasoningFactV1::new(
            "agent-prose",
            CONTEXT_VERIFIED_FACT_TOPIC_V1,
            "an agent asserted this without a typed adapter",
            &context_verified_fact_value_digest_v1(std::slice::from_ref(&affected_source)),
            ReasoningFactScopeV1::TaskSpecific,
            Some("task"),
            vec![affected_source.source().clone()],
        )
        .unwrap();
        assert!(
            first
                .admit_context_fact_v1(
                    &first_identity,
                    &"2".repeat(64),
                    1,
                    &agent_prose,
                    std::slice::from_ref(&affected_source),
                )
                .is_err(),
            "agent prose was admitted as a verified fact"
        );
        first
            .admit_context_fact_v1(
                &first_identity,
                &"5".repeat(64),
                1,
                &affected_fact,
                std::slice::from_ref(&affected_source),
            )
            .unwrap();
        first
            .admit_context_fact_v1(
                &first_identity,
                &"6".repeat(64),
                1,
                &unaffected_fact,
                std::slice::from_ref(&unaffected_source),
            )
            .unwrap();
        let reference = ReasoningRetrievalIdentityV1::new(
            &affected_result,
            &affected_result,
            u64::try_from("result-affected".len()).unwrap(),
        )
        .unwrap();
        first
            .append_context_event_v1(
                &first_identity,
                &"0".repeat(64),
                &ContextLedgerEventInputV1::ResultReference {
                    reference,
                    reference_version: 1,
                    verified_sources: vec![affected_source.clone()],
                },
            )
            .unwrap();

        let second = Store::open(&root).unwrap();
        second
            .activate_context_recipient_v1(&second_identity)
            .unwrap();
        assert_eq!(
            second
                .context_task_snapshot_v1(&second_identity)
                .unwrap()
                .current_facts()
                .len(),
            2
        );
        assert_eq!(
            second
                .context_task_snapshot_v1(&second_identity)
                .unwrap()
                .result_references()
                .len(),
            1
        );

        let concurrent_fact =
            context_test_fact(&first, &first_identity, "affected-fact", &affected_source);
        let barrier = Arc::new(Barrier::new(2));
        let outcomes = (0..2)
            .map(|_| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                let identity = first_identity.clone();
                let fact = concurrent_fact.clone();
                let source = affected_source.clone();
                thread::spawn(move || {
                    let store = Store::open(root).unwrap();
                    barrier.wait();
                    store
                        .admit_context_fact_v1(&identity, &"8".repeat(64), 2, &fact, &[source])
                        .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ContextLedgerAppendOutcomeV1::Appended { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ContextLedgerAppendOutcomeV1::Duplicate { .. }))
                .count(),
            1
        );

        let changes = [ContextDependencyChangeV1::new(&affected_key, &"f".repeat(64)).unwrap()];
        let report = second
            .invalidate_context_dependencies_v1(&second_identity, &"9".repeat(64), &changes)
            .unwrap();
        assert_eq!(report.retired_facts, 1);
        assert_eq!(report.retired_result_references, 1);
        let snapshot = second.context_task_snapshot_v1(&second_identity).unwrap();
        assert_eq!(snapshot.current_facts().len(), 1);
        assert_eq!(snapshot.current_facts()[0].fact_id(), "unaffected-fact");
        assert!(snapshot.result_references().is_empty());
        let repeated = second
            .invalidate_context_dependencies_v1(&second_identity, &"9".repeat(64), &changes)
            .unwrap();
        assert_eq!(
            repeated, report,
            "duplicate invalidation must be idempotent"
        );
    }

    #[test]
    fn context_ledger_rejects_stale_recipients_and_scopes_lease_joining() {
        let temp = TempDir::new().unwrap();
        let store = Store::open(temp.path().join("state")).unwrap();
        let leader = context_test_identity("leader", 'a', '1', 1);
        let follower = context_test_identity("follower", 'a', '2', 1);
        let other_user = context_test_identity("other", 'b', '3', 1);
        for identity in [&leader, &follower, &other_user] {
            store.activate_context_recipient_v1(identity).unwrap();
        }
        let work_key = "a".repeat(64);
        let deadline = now_ms() + 60_000;
        let first = store
            .acquire_context_lease_v1(&leader, &work_key, "inspect exact work", 30_000, deadline)
            .unwrap();
        assert!(matches!(
            first,
            ContextLeaseAcquisitionV1::Leader { generation: 1, .. }
        ));
        assert!(matches!(
            store
                .acquire_context_lease_v1(
                    &follower,
                    &work_key,
                    "inspect exact work",
                    30_000,
                    deadline
                )
                .unwrap(),
            ContextLeaseAcquisitionV1::Join { generation: 1, .. }
        ));
        assert!(matches!(
            store
                .acquire_context_lease_v1(
                    &other_user,
                    &work_key,
                    "inspect exact work",
                    30_000,
                    deadline
                )
                .unwrap(),
            ContextLeaseAcquisitionV1::Leader { generation: 1, .. }
        ));

        let renewed_follower = follower.after_lifecycle_change(&"4".repeat(64)).unwrap();
        store
            .activate_context_recipient_v1(&renewed_follower)
            .unwrap();
        assert!(
            store
                .context_delta_after_v1(&follower, ContextLedgerCursorV1::default(), 16)
                .is_err(),
            "stale lifecycle identity received a delta"
        );
        assert!(
            store
                .context_delta_after_v1(&renewed_follower, ContextLedgerCursorV1::default(), 16)
                .is_ok()
        );

        let lease_id = match first {
            ContextLeaseAcquisitionV1::Leader { lease_id, .. } => lease_id,
            _ => unreachable!(),
        };
        store.cancel_context_lease_v1(&leader, &lease_id).unwrap();
        assert!(store.retire_context_recipient_v1(&leader).unwrap());
        assert!(
            store.activate_context_recipient_v1(&leader).is_err(),
            "an explicitly retired lifecycle generation was resurrected"
        );
        let renewed_leader = leader.after_lifecycle_change(&"5".repeat(64)).unwrap();
        store
            .activate_context_recipient_v1(&renewed_leader)
            .unwrap();
        assert!(matches!(
            store
                .acquire_context_lease_v1(
                    &renewed_follower,
                    &work_key,
                    "recover exact work",
                    30_000,
                    deadline,
                )
                .unwrap(),
            ContextLeaseAcquisitionV1::Leader { generation: 2, .. }
        ));
    }

    #[test]
    fn context_delivery_is_idempotent_and_partial_schema_fails_closed() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("state");
        let store = Store::open(&root).unwrap();
        let identity = context_test_identity("agent", 'a', '1', 1);
        store.activate_context_recipient_v1(&identity).unwrap();
        let suggestion = ContextLedgerSuggestionV1::new(
            "candidate",
            "model-ranked prose remains an unverified suggestion",
            &"b".repeat(64),
        )
        .unwrap();
        let event = store
            .append_context_event_v1(
                &identity,
                &"c".repeat(64),
                &ContextLedgerEventInputV1::UnverifiedSuggestion(suggestion),
            )
            .unwrap();
        let cursor = ContextLedgerCursorV1::new(event.sequence());
        assert!(
            store
                .acknowledge_context_delivery_v1(&identity, &"d".repeat(64), cursor, 200, 80)
                .unwrap()
        );
        assert!(
            !store
                .acknowledge_context_delivery_v1(&identity, &"d".repeat(64), cursor, 200, 80)
                .unwrap()
        );
        let savings: u64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM context_ledger_delivery_savings_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(savings, 1);
        drop(store);

        let database = root.join("again.sqlite");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute("DROP INDEX context_ledger_dependency_reverse_idx", [])
            .unwrap();
        drop(connection);
        assert!(Store::open(&root).is_err());
    }

    #[test]
    fn store_configures_exact_sqlite_busy_timeout() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let configured_ms: u64 = store
            .conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(
            configured_ms,
            u64::try_from(SQLITE_BUSY_TIMEOUT.as_millis()).unwrap()
        );
    }

    #[test]
    fn state_root_and_fixed_children_reject_symlinks() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();

        let untrusted_root = temp.path().join("untrusted-root");
        fs::create_dir(&untrusted_root).unwrap();
        fs::set_permissions(&untrusted_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::open_with_policy(&untrusted_root).is_err());
        assert_eq!(
            fs::symlink_metadata(&untrusted_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        let root_link = temp.path().join("root-link");
        symlink(&outside, &root_link).unwrap();
        assert!(Store::open(&root_link).is_err());
        assert!(!outside.join("blobs").exists());

        let blobs_root = temp.path().join("blobs-root");
        fs::create_dir(&blobs_root).unwrap();
        set_private_dir(&blobs_root).unwrap();
        symlink(&outside, blobs_root.join("blobs")).unwrap();
        assert!(Store::open(&blobs_root).is_err());

        let database_root = temp.path().join("database-root");
        fs::create_dir(&database_root).unwrap();
        set_private_dir(&database_root).unwrap();
        let outside_file = outside.join("victim");
        fs::write(&outside_file, b"unchanged").unwrap();
        symlink(&outside_file, database_root.join("again.sqlite")).unwrap();
        assert!(Store::open(&database_root).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(), b"unchanged");

        let ignore_root = temp.path().join(".again");
        fs::create_dir(&ignore_root).unwrap();
        set_private_dir(&ignore_root).unwrap();
        symlink(&outside_file, ignore_root.join(".gitignore")).unwrap();
        assert!(Store::open(&ignore_root).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(), b"unchanged");
    }

    #[test]
    fn default_state_is_external_stable_and_workspace_scoped() {
        let temp = TempDir::new().unwrap();
        let workspace = temp.path().join("workspace");
        let other_workspace = temp.path().join("other-workspace");
        let temporary_directory = temp.path().join("system-temp");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&other_workspace).unwrap();
        fs::create_dir(&temporary_directory).unwrap();

        let root = default_workspace_state_root(&workspace, &temporary_directory).unwrap();
        let repeated = default_workspace_state_root(&workspace, &temporary_directory).unwrap();
        let other = default_workspace_state_root(&other_workspace, &temporary_directory).unwrap();

        assert_eq!(root, repeated);
        assert_ne!(root, other);
        assert!(root.starts_with(temporary_directory.canonicalize().unwrap()));
        assert!(!root.starts_with(workspace.canonicalize().unwrap()));
        assert!(!workspace.join(".again").exists());
        let store = Store::open(&root).unwrap();
        assert_eq!(store.root(), root.canonicalize().unwrap());
    }

    #[test]
    fn configured_state_must_be_external_and_final_symlinks_are_rejected() {
        let temp = TempDir::new().unwrap();
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&outside).unwrap();

        assert!(validate_external_state_root(&workspace, &workspace.join(".again")).is_err());
        assert!(validate_external_state_root(&workspace, &outside).is_ok());

        let link = temp.path().join("configured-link");
        symlink(&outside, &link).unwrap();
        assert!(prospective_store_root(&link).is_err());
    }

    #[test]
    fn configured_state_rejects_an_unprotected_writable_parent_namespace() {
        let temp = TempDir::new().unwrap();
        let parent = temp.path().join("shared-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let root = prospective_store_root(&parent.join("state")).unwrap();
        assert!(validate_trusted_state_ancestors(&root).is_err());

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(validate_trusted_state_ancestors(&root).is_ok());
    }

    #[test]
    fn blob_shards_and_reads_reject_symlinks() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let store = Store::open(temp.path().join("state")).unwrap();
        let bytes = b"immutable blob";
        let digest = blake3::hash(bytes).to_hex().to_string();
        symlink(&outside, store.blobs.join(&digest[..2])).unwrap();
        assert!(store.put_blob(bytes).is_err());

        fs::remove_file(store.blobs.join(&digest[..2])).unwrap();
        let stored = store.put_blob(bytes).unwrap();
        let path = store.blob_path(&stored).unwrap();
        fs::remove_file(&path).unwrap();
        let outside_file = outside.join("blob-victim");
        fs::write(&outside_file, bytes).unwrap();
        symlink(&outside_file, &path).unwrap();
        assert!(store.get_blob(&stored).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(), bytes);
    }

    #[test]
    fn blob_reads_are_bounded_even_if_state_is_tampered() {
        let temp = TempDir::new().unwrap();
        let store = Store::open(temp.path().join("state")).unwrap();
        let digest = store.put_blob(b"small").unwrap();
        let path = store.blob_path(&digest).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_LOCAL_BLOB_BYTES as u64 + 1)
            .unwrap();
        assert!(store.get_blob(&digest).is_err());
    }

    fn test_file_identity() -> FileIdentity {
        FileIdentity {
            device: 17,
            inode: 29,
            mode: 0o100644,
            uid: 501,
            gid: 20,
            size: 4096,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 123,
            ctime_sec: 1_700_000_001,
            ctime_nsec: 456,
        }
    }

    #[test]
    fn blobs_round_trip_and_detect_invalid_digest() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let digest = store.put_blob(b"hello").unwrap();
        assert_eq!(store.get_blob(&digest).unwrap(), b"hello");
        assert!(store.get_blob("../escape").is_err());
    }

    #[test]
    fn file_digest_memo_survives_reopen_without_persisting_paths() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let identity = test_file_identity();
        let digest = [0x5a; 32];
        {
            let mut store = Store::open(temp.path()).unwrap();
            store.record(&identity, digest);
            assert_eq!(store.lookup(&identity), Some(digest));
        }

        let mut reopened = Store::open(temp.path()).unwrap();
        assert_eq!(reopened.lookup(&identity), Some(digest));
        let columns: Vec<String> = reopened
            .conn
            .prepare("PRAGMA table_info(file_digests)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!columns.iter().any(|column| column.contains("path")));
    }

    #[test]
    fn corrupted_file_digest_row_is_a_miss_and_can_be_recomputed() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let identity = test_file_identity();
        let digest = [0x71; 32];
        let mut store = Store::open(temp.path()).unwrap();
        store.record(&identity, digest);
        store
            .conn
            .execute("UPDATE file_digests SET digest = zeroblob(32)", [])
            .unwrap();

        assert_eq!(store.lookup(&identity), None, "checksum failure is a miss");
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM file_digests", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "corrupt row is discarded");

        store.record(&identity, digest);
        assert_eq!(store.lookup(&identity), Some(digest));
    }

    #[test]
    fn version_one_database_migrates_file_digest_table() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let database = temp.path().join("again.sqlite");
        Connection::open(&database)
            .unwrap()
            .execute_batch(
                r#"
                CREATE TABLE pending_calls (id TEXT PRIMARY KEY, created_ms INTEGER NOT NULL);
                CREATE TABLE results (
                    id TEXT PRIMARY KEY,
                    stdout_digest TEXT NOT NULL,
                    stderr_digest TEXT NOT NULL
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY,
                    disposition TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL
                );
                PRAGMA user_version = 1;
                "#,
            )
            .unwrap();
        set_private_file(&database).unwrap();

        let store = Store::open(temp.path()).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let exists: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'file_digests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
        assert_eq!(store.gateway_stats().unwrap(), GatewayStats::default());
    }

    #[test]
    fn version_four_replay_metrics_are_reset_before_net_savings_are_reported() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        {
            let store = Store::open(temp.path()).unwrap();
            store
                .record_event(
                    None,
                    None,
                    EventDisposition::ReplayedFull,
                    "LEGACY_GROSS_DURATION",
                    9_999,
                    0,
                )
                .unwrap();
            store
                .conn
                .execute_batch(
                    "DROP TABLE gateway_context_source_recipes_v1;
                     DROP TABLE brain_test_commands_v1;
                     DROP TABLE brain_files_v1;
                     DROP TABLE brain_events_v1;
                     DROP TABLE context_workspace_quota_v1;
                     DROP TABLE context_task_transitions_v1;
                     DROP TABLE context_task_relations_v1;
                     DROP TABLE context_task_aliases_v1;
                     DROP TABLE context_tasks_v1;
                     DROP TABLE context_ledger_delivery_savings_v1;
                     DROP TABLE context_ledger_delivery_receipts_v1;
                     DROP TABLE context_ledger_fact_versions_v1;
                     DROP TABLE context_ledger_result_references_v1;
                     DROP TABLE context_ledger_event_dependencies_v1;
                     DROP TABLE context_ledger_event_sources_v1;
                     DROP TABLE context_ledger_events_v1;
                     DROP TABLE context_ledger_recipients_v1;
                     DROP TABLE context_ledger_leases_v1;
                     DROP TABLE gateway_delivery_savings_v2;
                     DROP TABLE gateway_retrieval_grants_v2;
                     DROP TABLE gateway_delivery_receipts_v2;
                     DROP TABLE gateway_deliveries;
                     DROP TABLE gateway_delivery_receipts;
                     DROP TABLE result_dependencies;
                     DROP TABLE gateway_results;
                     DROP TABLE gateway_request_dependencies;
                     DROP TABLE inflight_leases;
                     DROP TABLE gateway_requests;
                     DROP TABLE gateway_events;",
                )
                .unwrap();
            store.conn.pragma_update(None, "user_version", 4).unwrap();
        }

        let reopened = Store::open(temp.path()).unwrap();
        let version: i64 = reopened
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let stats = reopened.stats().unwrap();
        assert_eq!(stats.full_replays, 1);
        assert_eq!(stats.estimated_execution_ms_saved, 0);
    }

    #[test]
    fn version_seventeen_brain_history_migrates_without_granting_unknown_scope() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let scope = "a".repeat(64);
        {
            let store = Store::open(temp.path()).unwrap();
            store
                .record_brain_event_v1(&BrainEventV1 {
                    session_id: "session".to_owned(),
                    event_id: "old".to_owned(),
                    task_id: "task".to_owned(),
                    kind: "file_change".to_owned(),
                    path: Some("src/file.py".to_owned()),
                    source_digest: Some("b".repeat(64)),
                    command_digest: None,
                    command_hint: None,
                    exit_code: None,
                    created_ms: now_ms(),
                    authorization_scope_digest: Some(scope.clone()),
                })
                .unwrap();
            store
                .conn
                .execute_batch(
                    "DROP INDEX brain_files_scope_recent_idx;
                 DROP INDEX brain_test_commands_scope_recent_idx;
                 ALTER TABLE brain_events_v1 DROP COLUMN authorization_scope_digest;
                 ALTER TABLE brain_files_v1 DROP COLUMN authorization_scope_digest;
                 ALTER TABLE brain_test_commands_v1 DROP COLUMN authorization_scope_digest;
                 PRAGMA user_version = 17;",
                )
                .unwrap();
        }
        let store = Store::open(temp.path()).unwrap();
        assert_eq!(store.recent_brain_files_v1(8).unwrap().len(), 1);
        assert!(
            store
                .brain_file_v1("src/file.py", &scope)
                .unwrap()
                .is_none()
        );
        store
            .record_brain_event_v1(&BrainEventV1 {
                session_id: "session".to_owned(),
                event_id: "new".to_owned(),
                task_id: "task".to_owned(),
                kind: "file_change".to_owned(),
                path: Some("src/file.py".to_owned()),
                source_digest: Some("c".repeat(64)),
                command_digest: None,
                command_hint: None,
                exit_code: None,
                created_ms: now_ms() + 1,
                authorization_scope_digest: Some(scope.clone()),
            })
            .unwrap();
        assert_eq!(
            store
                .brain_file_v1("src/file.py", &scope)
                .unwrap()
                .unwrap()
                .source_digest,
            "c".repeat(64)
        );
    }

    #[test]
    fn brain_run_summary_is_idempotent_bounded_and_clearable() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let run = BrainRunV1 {
            session_id: "session".to_owned(),
            task_id: "task".to_owned(),
            authorization_scope_digest: "a".repeat(64),
            started_ms: now_ms() - 100,
            completed_ms: now_ms(),
            exit_code: 0,
            turn_completed: true,
            completed_commands: 2,
            completed_source_reads: 1,
            completed_edits: 1,
            completed_mcp_calls: 0,
            successful_tests: 1,
            input_tokens: Some(100),
            cached_input_tokens: Some(40),
            output_tokens: Some(12),
        };
        store.record_brain_run_v1(&run).unwrap();
        store.record_brain_run_v1(&run).unwrap();
        assert_eq!(store.recent_brain_runs_v1(8).unwrap(), vec![run.clone()]);
        let mut collision = run.clone();
        collision.output_tokens = Some(13);
        assert!(store.record_brain_run_v1(&collision).is_err());
        let mut invalid = run.clone();
        invalid.cached_input_tokens = Some(101);
        assert!(store.record_brain_run_v1(&invalid).is_err());
        assert_eq!(store.clear_brain_events_v1().unwrap(), 1);
        assert!(store.recent_brain_runs_v1(8).unwrap().is_empty());
    }

    #[test]
    fn version_eighteen_brain_store_migrates_to_run_summaries() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        {
            let store = Store::open(temp.path()).unwrap();
            store
                .conn
                .execute_batch("DROP TABLE brain_runs_v1; PRAGMA user_version = 18;")
                .unwrap();
        }
        let store = Store::open(temp.path()).unwrap();
        assert!(store.recent_brain_runs_v1(8).unwrap().is_empty());
        assert_eq!(
            store
                .conn
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn current_schema_verifier_requires_every_delivery_receipt_constraint() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let original: String = store
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'gateway_delivery_receipts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let weakened = original.replace("CHECK(length(call_digest) = 64)", "");
        assert_ne!(weakened, original);
        store
            .conn
            .execute_batch("PRAGMA writable_schema=ON;")
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'gateway_delivery_receipts'",
                [&weakened],
            )
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA writable_schema=OFF;")
            .unwrap();
        assert!(verify_gateway_schema_current(&store.conn).is_err());
    }

    #[test]
    fn current_schema_verifier_requires_v10_retrieval_token_uniqueness() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let original: String = store
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'gateway_retrieval_grants_v2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let weakened = original.replace(
            "token_digest TEXT NOT NULL UNIQUE CHECK(length(token_digest) = 64)",
            "token_digest TEXT NOT NULL CHECK(length(token_digest) = 64)",
        );
        assert_ne!(weakened, original);
        store
            .conn
            .execute_batch("PRAGMA writable_schema=ON;")
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'gateway_retrieval_grants_v2'",
                [&weakened],
            )
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA writable_schema=OFF;")
            .unwrap();
        assert!(verify_gateway_schema_current(&store.conn).is_err());
    }

    #[test]
    fn current_schema_verifier_rechecks_catalog_after_reopen() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let original: String = store
            .conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'gateway_delivery_receipts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let weakened = original.replace("CHECK(stderr_bytes >= 0)", "");
        assert_ne!(weakened, original);
        store
            .conn
            .execute_batch("PRAGMA writable_schema=ON;")
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'gateway_delivery_receipts'",
                [&weakened],
            )
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA writable_schema=OFF;")
            .unwrap();
        drop(store);

        assert!(Store::open(temp.path()).is_err());
    }

    #[test]
    fn source_recipe_schema_migrates_from_thirteen_and_is_required_at_fourteen() {
        let temp = TempDir::new().unwrap();
        let store = Store::open(temp.path().join("state")).unwrap();
        restore_pre_v15_gateway_result_shape(&store);
        store
            .conn
            .execute_batch(
                "DROP TABLE gateway_context_source_recipes_v1;
                 DROP TABLE brain_test_commands_v1;
                 DROP TABLE brain_files_v1;
                 DROP TABLE brain_events_v1;
                 PRAGMA user_version = 13;",
            )
            .unwrap();
        drop(store);
        let reopened = Store::open(temp.path().join("state")).unwrap();
        let version: i64 = reopened
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        reopened
            .conn
            .execute_batch("DROP TABLE gateway_context_source_recipes_v1;")
            .unwrap();
        assert!(verify_gateway_schema_current(&reopened.conn).is_err());
    }

    #[test]
    fn version_eight_compact_savings_are_neutralized_without_a_receipt() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        {
            let store = Store::open(temp.path()).unwrap();
            restore_pre_v15_gateway_result_shape(&store);
            store
                .conn
                .execute(
                    "INSERT INTO gateway_events (event_type, estimated_tokens_avoided, created_ms) VALUES ('compact_delivery', 777, 1)",
                    [],
                )
                .unwrap();
            store
                .conn
                .execute_batch(
                    "DROP TABLE gateway_context_source_recipes_v1;
                     DROP TABLE brain_test_commands_v1;
                     DROP TABLE brain_files_v1;
                     DROP TABLE brain_events_v1;
                     DROP TABLE context_workspace_quota_v1;
                     DROP TABLE context_task_transitions_v1;
                     DROP TABLE context_task_relations_v1;
                     DROP TABLE context_task_aliases_v1;
                     DROP TABLE context_tasks_v1;
                     DROP TABLE context_ledger_delivery_savings_v1;
                     DROP TABLE context_ledger_delivery_receipts_v1;
                     DROP TABLE context_ledger_fact_versions_v1;
                     DROP TABLE context_ledger_result_references_v1;
                     DROP TABLE context_ledger_event_dependencies_v1;
                     DROP TABLE context_ledger_event_sources_v1;
                     DROP TABLE context_ledger_events_v1;
                     DROP TABLE context_ledger_recipients_v1;
                     DROP TABLE context_ledger_leases_v1;
                     DROP TABLE gateway_delivery_savings_v2;
                     DROP TABLE gateway_retrieval_grants_v2;
                     DROP TABLE gateway_delivery_receipts_v2;
                     PRAGMA user_version = 8;",
                )
                .unwrap();
        }

        let reopened = Store::open(temp.path()).unwrap();
        let version: i64 = reopened
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let legacy_tokens: i64 = reopened
            .conn
            .query_row(
                "SELECT estimated_tokens_avoided FROM gateway_events WHERE event_type = 'compact_delivery'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_tokens, 0);
        let stats = reopened.gateway_stats().unwrap();
        assert_eq!(stats.compact_deliveries, 0);
        assert_eq!(stats.estimated_tokens_avoided, 0);
    }

    #[test]
    fn version_nine_migrates_additively_without_reinterpreting_legacy_receipts() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        {
            let store = Store::open(temp.path()).unwrap();
            restore_pre_v15_gateway_result_shape(&store);
            store
                .conn
                .execute_batch(
                    "PRAGMA foreign_keys = OFF;
                     DROP TABLE gateway_context_source_recipes_v1;
                     DROP TABLE brain_test_commands_v1;
                     DROP TABLE brain_files_v1;
                     DROP TABLE brain_events_v1;
                     DROP TABLE context_workspace_quota_v1;
                     DROP TABLE context_task_transitions_v1;
                     DROP TABLE context_task_relations_v1;
                     DROP TABLE context_task_aliases_v1;
                     DROP TABLE context_tasks_v1;
                     DROP TABLE context_ledger_delivery_savings_v1;
                     DROP TABLE context_ledger_delivery_receipts_v1;
                     DROP TABLE context_ledger_fact_versions_v1;
                     DROP TABLE context_ledger_result_references_v1;
                     DROP TABLE context_ledger_event_dependencies_v1;
                     DROP TABLE context_ledger_event_sources_v1;
                     DROP TABLE context_ledger_events_v1;
                     DROP TABLE context_ledger_recipients_v1;
                     DROP TABLE context_ledger_leases_v1;
                     DROP TABLE gateway_delivery_savings_v2;
                     DROP TABLE gateway_retrieval_grants_v2;
                     DROP TABLE gateway_delivery_receipts_v2;
                     PRAGMA user_version = 9;
                     PRAGMA foreign_keys = ON;",
                )
                .unwrap();
        }

        let reopened = Store::open(temp.path()).unwrap();
        let version: i64 = reopened
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        for table in [
            "gateway_delivery_receipts",
            "gateway_delivery_receipts_v2",
            "gateway_retrieval_grants_v2",
            "gateway_delivery_savings_v2",
        ] {
            let exists: bool = reopened
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing additive migration table {table}");
        }
    }

    #[test]
    fn repository_scoped_store_is_self_ignored_without_overwriting_user_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join(".again");
        let store = Store::open(&root).unwrap();
        assert_eq!(fs::read_to_string(root.join(".gitignore")).unwrap(), "*\n");
        drop(store);

        fs::write(root.join(".gitignore"), "user-owned\n").unwrap();
        drop(Store::open(&root).unwrap());
        assert_eq!(
            fs::read_to_string(root.join(".gitignore")).unwrap(),
            "user-owned\n"
        );
    }

    #[test]
    fn pending_calls_round_trip_without_shell_interpolation() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let call = store
            .create_call(
                "session",
                Some("turn"),
                Some("root-turn"),
                temp.path(),
                "rg needle src",
                &["rg".into(), "needle".into(), "src".into()],
            )
            .unwrap();
        assert_eq!(store.get_call(&call.id).unwrap(), Some(call.clone()));
        store.delete_call(&call.id).unwrap();
        assert_eq!(store.get_call(&call.id).unwrap(), None);
    }

    #[test]
    fn cleanup_expires_only_stale_unreferenced_state() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let current = now_ms();
        let stale_pending = current - PENDING_CALL_TTL_MS - 1;
        let stale_event = current - EVENT_TTL_MS - 1;
        let stale_artifact = current - ORPHAN_ARTIFACT_TTL_MS - 1;

        store
            .conn
            .execute(
                "INSERT INTO pending_calls (id, session_id, cwd, raw_command, argv_json, created_ms) VALUES ('stale', 's', '/tmp', 'cat x', '[]', ?1)",
                [stale_pending],
            )
            .unwrap();
        let recent = store
            .create_call("session", None, None, temp.path(), "cat x", &["cat".into()])
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO events (disposition, reason_code, elapsed_ms, bytes_omitted, created_ms) VALUES ('passed_through', 'old', 0, 0, ?1)",
                [stale_event],
            )
            .unwrap();
        store
            .record_event(None, None, EventDisposition::Executed, "recent", 0, 0)
            .unwrap();

        let orphan_digest = store.put_blob(b"orphan").unwrap();
        let retained = store
            .insert_result("retained", b"referenced", b"", 0, 1, "v0", "{}")
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE artifacts SET created_ms = ?1 WHERE digest = ?2",
                params![stale_artifact, orphan_digest],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE artifacts SET created_ms = ?1 WHERE digest = ?2 OR digest = ?3",
                params![
                    stale_artifact,
                    retained.stdout_digest,
                    retained.stderr_digest
                ],
            )
            .unwrap();
        let old_time = UNIX_EPOCH + Duration::from_millis(stale_artifact as u64);
        for digest in [
            orphan_digest.as_str(),
            retained.stdout_digest.as_str(),
            retained.stderr_digest.as_str(),
        ] {
            File::open(store.blob_path(digest).unwrap())
                .unwrap()
                .set_times(FileTimes::new().set_modified(old_time))
                .unwrap();
        }

        let report = store.cleanup_at(current, true).unwrap();
        assert_eq!(
            report,
            CleanupReport {
                pending_calls: 1,
                events: 1,
                gateway_events: 0,
                artifacts: 1,
            }
        );
        assert!(store.get_call("stale").unwrap().is_none());
        assert_eq!(store.get_call(&recent.id).unwrap(), Some(recent));
        assert!(store.get_blob(&orphan_digest).is_err());
        assert_eq!(
            store.get_blob(&retained.stdout_digest).unwrap(),
            b"referenced"
        );
        assert_eq!(store.get_result("retained").unwrap(), Some(retained));
        assert_eq!(store.stats().unwrap().executions, 1);
    }

    #[test]
    fn cleanup_batches_are_strictly_bounded() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let current = now_ms();
        let stale = current - PENDING_CALL_TTL_MS - 1;
        let transaction = store.conn.transaction().unwrap();
        for index in 0..(CLEANUP_ROW_LIMIT + 1) {
            transaction
                .execute(
                    "INSERT INTO pending_calls (id, session_id, cwd, raw_command, argv_json, created_ms) VALUES (?1, 's', '/tmp', 'cat', '[]', ?2)",
                    params![format!("stale-{index}"), stale],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        assert_eq!(
            store.cleanup_at(current, true).unwrap().pending_calls,
            CLEANUP_ROW_LIMIT as u64
        );
        let remaining: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM pending_calls", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
        assert_eq!(store.cleanup_at(current, true).unwrap().pending_calls, 1);
    }

    #[test]
    fn results_and_delivery_state_round_trip() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let result = store
            .insert_result("key", b"out", b"", 0, 50, "v0", "{}")
            .unwrap();
        assert_eq!(store.get_result("key").unwrap(), Some(result.clone()));
        assert!(!store.was_delivered("s", "root-turn", &result.id).unwrap());
        store.mark_delivered("s", "root-turn", &result.id).unwrap();
        assert!(store.was_delivered("s", "root-turn", &result.id).unwrap());
    }

    struct RetrievalAuthorityFixtureV2 {
        _temp: TempDir,
        root: PathBuf,
        store: Store,
        result: StoredResult,
        gateway_result_id: String,
    }

    impl RetrievalAuthorityFixtureV2 {
        fn new(label: &str) -> Self {
            let temp = TempDir::new().unwrap();
            let root = temp.path().join("state");
            let mut store = Store::open(&root).unwrap();
            let state_digest = blake3::hash(format!("state-{label}").as_bytes())
                .to_hex()
                .to_string();
            let binding = ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
                request_digest: blake3::hash(format!("request-{label}").as_bytes())
                    .to_hex()
                    .to_string(),
                state_digest: state_digest.clone(),
                policy_digest: gateway_policy_digest("retrieval-authority-v2"),
                operation: GatewayOperationDispositionV1::ReplayEligibleRead,
                freshness: GatewayFreshnessEvidenceV1 {
                    snapshot_digest: state_digest,
                    observed_at_ms: now_ms(),
                    valid_until_ms: now_ms() + 60_000,
                },
                dependencies: vec![GatewayDependencyV1 {
                    key_digest: blake3::hash(b"retrieval-dependency-key")
                        .to_hex()
                        .to_string(),
                    value_digest: blake3::hash(format!("dependency-{label}").as_bytes())
                        .to_hex()
                        .to_string(),
                }],
            })
            .unwrap();
            let lease_id = match store
                .acquire_gateway_call(&binding, "retrieval-authority-owner")
                .unwrap()
            {
                GatewayCallAcquisition::Leader { lease_id, .. } => lease_id,
                other => panic!("expected retrieval authority leader, got {other:?}"),
            };
            assert_eq!(
                store
                    .start_gateway_execution(&lease_id, "retrieval-authority-owner")
                    .unwrap(),
                GatewayExecutionStart::Started
            );
            let result = store
                .insert_result(
                    binding.request_digest(),
                    br#"{"retrieved":true}"#,
                    b"",
                    0,
                    7,
                    "retrieval-authority-v2",
                    r#"{"proof":"retrieval-authority-v2"}"#,
                )
                .unwrap();
            let gateway_result_id =
                match store.complete_gateway_call(&lease_id, &result.id).unwrap() {
                    GatewayCompletion::Completed {
                        gateway_result_id, ..
                    } => gateway_result_id,
                    other => panic!("expected retrieval authority completion, got {other:?}"),
                };
            Self {
                _temp: temp,
                root,
                store,
                result,
                gateway_result_id,
            }
        }

        fn issue(&self, suffix: &str) -> (String, String, String, i64) {
            let confirmation = crate::mcp_gateway::confirmed_delivery_for_test_v1(
                &format!("retrieval_authority_{suffix}"),
                &self.gateway_result_id,
                self.result.exit_code,
                &self.result.stdout_digest,
                self.result.stdout_bytes,
                &self.result.stderr_digest,
                self.result.stderr_bytes,
            );
            self.store
                .confirm_gateway_delivery_and_issue_retrieval_v2(&confirmation)
                .unwrap()
                .into_wire_parts()
        }

        fn assert_zero_confirmed_savings(&self) {
            let (compact_receipts, savings): (u64, u64) = self
                .store
                .conn
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM gateway_delivery_receipts_v2 WHERE presentation = 'compact'), (SELECT COUNT(*) FROM gateway_delivery_savings_v2)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!((compact_receipts, savings), (0, 0));
        }
    }

    struct RetrievalRecipientBindingV2 {
        scope: String,
        connection: String,
        connection_generation: String,
        agent: String,
        session: String,
        turn: String,
        compaction_generation: u64,
    }

    impl RetrievalRecipientBindingV2 {
        fn authentic() -> Self {
            Self {
                scope: "1".repeat(64),
                connection: "2".repeat(64),
                connection_generation: "3".repeat(64),
                agent: "test-agent".to_owned(),
                session: "test-session".to_owned(),
                turn: "test-turn".to_owned(),
                compaction_generation: 0,
            }
        }
    }

    fn retrieval_authority_v2(
        wire: &(String, String, String, i64),
        binding: &RetrievalRecipientBindingV2,
    ) -> crate::mcp_gateway::RecipientRetrievalAuthorityV2 {
        crate::mcp_gateway::recipient_retrieval_authority_for_test_v2(
            wire.0.clone(),
            wire.1.clone(),
            wire.2.clone(),
            wire.3,
            binding.scope.clone(),
            binding.connection.clone(),
            binding.connection_generation.clone(),
            binding.agent.clone(),
            binding.session.clone(),
            binding.turn.clone(),
            binding.compaction_generation,
        )
    }

    #[test]
    fn acknowledged_delivery_persists_once_and_legacy_clear_cannot_erase_receipt() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let state_digest = "a".repeat(64);
        let binding = ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
            request_digest: "b".repeat(64),
            state_digest: state_digest.clone(),
            policy_digest: gateway_policy_digest("delivery-test-v1"),
            operation: GatewayOperationDispositionV1::ReplayEligibleRead,
            freshness: GatewayFreshnessEvidenceV1 {
                snapshot_digest: state_digest,
                observed_at_ms: now_ms(),
                valid_until_ms: now_ms() + 60_000,
            },
            dependencies: Vec::new(),
        })
        .unwrap();
        let acquisition = store.acquire_gateway_call(&binding, "test-owner").unwrap();
        let lease_id = match acquisition {
            GatewayCallAcquisition::Leader { lease_id, .. } => lease_id,
            other => panic!("expected delivery test leader, got {other:?}"),
        };
        assert_eq!(
            store
                .start_gateway_execution(&lease_id, "test-owner")
                .unwrap(),
            GatewayExecutionStart::Started
        );
        let result = store
            .insert_result(
                binding.request_digest(),
                b"delivered bytes",
                b"delivery diagnostic",
                0,
                1,
                "delivery-test-v1",
                "{}",
            )
            .unwrap();
        let gateway_result_id = match store.complete_gateway_call(&lease_id, &result.id).unwrap() {
            GatewayCompletion::Completed {
                gateway_result_id, ..
            } => gateway_result_id,
            other => panic!("expected delivery test completion, got {other:?}"),
        };
        let confirmation = crate::mcp_gateway::confirmed_delivery_for_test_v1(
            "delivery_test_challenge",
            &gateway_result_id,
            result.exit_code,
            &result.stdout_digest,
            result.stdout_bytes,
            &result.stderr_digest,
            result.stderr_bytes,
        );
        assert!(store.confirm_gateway_delivery_v1(&confirmation).unwrap());
        assert!(!store.confirm_gateway_delivery_v1(&confirmation).unwrap());

        let context = GatewayAgentContext::new("test-session", "test-turn", "test-agent", 0);
        assert_eq!(store.clear_gateway_deliveries(&context).unwrap(), 1);
        let receipts: u64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM gateway_delivery_receipts WHERE challenge_id = 'delivery_test_challenge'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let legacy: u64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM gateway_deliveries WHERE session_id = 'test-session'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            receipts, 1,
            "legacy context must not delete receipt authority"
        );
        assert_eq!(legacy, 0);

        let grant = store
            .confirm_gateway_delivery_and_issue_retrieval_v2(&confirmation)
            .unwrap();
        assert!(
            store
                .confirm_gateway_delivery_and_issue_retrieval_v2(&confirmation)
                .is_err(),
            "the same response-bound receipt is one use"
        );
        let (grant_id, token, granted_result_id, grant_expires_at_ms) = grant.into_wire_parts();
        let wrong_connection = crate::mcp_gateway::recipient_retrieval_authority_for_test_v2(
            grant_id.clone(),
            token.clone(),
            granted_result_id.clone(),
            grant_expires_at_ms,
            "1".repeat(64),
            "f".repeat(64),
            "3".repeat(64),
            "test-agent".to_owned(),
            "test-session".to_owned(),
            "test-turn".to_owned(),
            0,
        );
        assert!(
            store
                .consume_gateway_retrieval_grant_v2(&wrong_connection)
                .is_err(),
            "a grant token cannot cross the live connection boundary"
        );
        let authority = crate::mcp_gateway::recipient_retrieval_authority_for_test_v2(
            grant_id,
            token,
            granted_result_id,
            grant_expires_at_ms,
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "test-agent".to_owned(),
            "test-session".to_owned(),
            "test-turn".to_owned(),
            0,
        );
        let retrieved = store
            .consume_gateway_retrieval_grant_v2(&authority)
            .unwrap();
        assert_eq!(retrieved.stdout, b"delivered bytes");
        assert_eq!(retrieved.stderr, b"delivery diagnostic");
        assert!(
            store
                .consume_gateway_retrieval_grant_v2(&authority)
                .is_err(),
            "retrieval grants are one use"
        );
    }

    #[test]
    fn retrieval_authority_v2_refuses_forged_bindings_without_consuming_the_grant() {
        let fixture = RetrievalAuthorityFixtureV2::new("forged-bindings");
        let authentic_binding = RetrievalRecipientBindingV2::authentic();
        let cases = vec![
            (
                "f".repeat(64),
                authentic_binding.connection.clone(),
                authentic_binding.connection_generation.clone(),
                "test-agent".to_owned(),
                "test-session".to_owned(),
                "test-turn".to_owned(),
                0,
            ),
            (
                authentic_binding.scope.clone(),
                "f".repeat(64),
                authentic_binding.connection_generation.clone(),
                "test-agent".to_owned(),
                "test-session".to_owned(),
                "test-turn".to_owned(),
                0,
            ),
            (
                authentic_binding.scope.clone(),
                authentic_binding.connection.clone(),
                "f".repeat(64),
                "test-agent".to_owned(),
                "test-session".to_owned(),
                "test-turn".to_owned(),
                0,
            ),
            (
                authentic_binding.scope.clone(),
                authentic_binding.connection.clone(),
                authentic_binding.connection_generation.clone(),
                "forged-agent".to_owned(),
                "test-session".to_owned(),
                "test-turn".to_owned(),
                0,
            ),
            (
                authentic_binding.scope.clone(),
                authentic_binding.connection.clone(),
                authentic_binding.connection_generation.clone(),
                "test-agent".to_owned(),
                "forged-session".to_owned(),
                "test-turn".to_owned(),
                0,
            ),
            (
                authentic_binding.scope.clone(),
                authentic_binding.connection.clone(),
                authentic_binding.connection_generation.clone(),
                "test-agent".to_owned(),
                "test-session".to_owned(),
                "forged-turn".to_owned(),
                0,
            ),
            (
                authentic_binding.scope.clone(),
                authentic_binding.connection.clone(),
                authentic_binding.connection_generation.clone(),
                "test-agent".to_owned(),
                "test-session".to_owned(),
                "test-turn".to_owned(),
                1,
            ),
        ];
        for (
            index,
            (
                wrong_scope,
                wrong_connection,
                wrong_generation,
                wrong_agent,
                wrong_session,
                wrong_turn,
                wrong_compaction,
            ),
        ) in cases.into_iter().enumerate()
        {
            let wire = fixture.issue(&format!("forged_binding_{index}"));
            let forged_binding = RetrievalRecipientBindingV2 {
                scope: wrong_scope,
                connection: wrong_connection,
                connection_generation: wrong_generation,
                agent: wrong_agent,
                session: wrong_session,
                turn: wrong_turn,
                compaction_generation: wrong_compaction,
            };
            let forged = retrieval_authority_v2(&wire, &forged_binding);
            assert!(
                fixture
                    .store
                    .consume_gateway_retrieval_grant_v2(&forged)
                    .is_err()
            );
            let authentic = retrieval_authority_v2(&wire, &authentic_binding);
            assert!(
                fixture
                    .store
                    .consume_gateway_retrieval_grant_v2(&authentic)
                    .is_ok(),
                "forged case {index} consumed authentic one-use authority"
            );
            fixture.assert_zero_confirmed_savings();
        }

        for (suffix, mutate) in [
            ("stolen_token", 0_u8),
            ("stolen_result_id", 1_u8),
            ("forged_expiry", 2_u8),
        ] {
            let wire = fixture.issue(suffix);
            let mut forged_wire = wire.clone();
            match mutate {
                0 => forged_wire.1 = "stolen-token".to_owned(),
                1 => forged_wire.2 = "f".repeat(64),
                2 => forged_wire.3 = forged_wire.3.saturating_add(1),
                _ => unreachable!(),
            }
            let forged = retrieval_authority_v2(&forged_wire, &authentic_binding);
            assert!(
                fixture
                    .store
                    .consume_gateway_retrieval_grant_v2(&forged)
                    .is_err()
            );
            let authentic = retrieval_authority_v2(&wire, &authentic_binding);
            assert!(
                fixture
                    .store
                    .consume_gateway_retrieval_grant_v2(&authentic)
                    .is_ok()
            );
            fixture.assert_zero_confirmed_savings();
        }
    }

    #[test]
    fn retrieval_authority_v2_revalidates_every_store_binding_and_retires_on_refusal() {
        type MutationV2 = Box<dyn FnOnce(&RetrievalAuthorityFixtureV2)>;
        let mutations: Vec<(&str, MutationV2)> = vec![
            (
                "leader-request",
                Box::new(|fixture| {
                    fixture.store.conn.execute(
                    "UPDATE gateway_requests SET state_digest = ?2 WHERE gateway_result_id = ?1 AND role = 'leader'",
                    params![fixture.gateway_result_id, "f".repeat(64)],
                ).unwrap();
                }),
            ),
            (
                "request-dependency",
                Box::new(|fixture| {
                    fixture
                        .store
                        .conn
                        .execute(
                            "UPDATE gateway_request_dependencies SET dependency_value_digest = ?1",
                            ["f".repeat(64)],
                        )
                        .unwrap();
                }),
            ),
            (
                "result-dependency",
                Box::new(|fixture| {
                    fixture
                        .store
                        .conn
                        .execute(
                            "UPDATE result_dependencies SET dependency_value_digest = ?1",
                            ["f".repeat(64)],
                        )
                        .unwrap();
                }),
            ),
            (
                "repository-state",
                Box::new(|fixture| {
                    fixture.store.conn.execute(
                    "UPDATE inflight_leases SET state_digest = ?2 WHERE gateway_result_id = ?1",
                    params![fixture.gateway_result_id, "f".repeat(64)],
                ).unwrap();
                }),
            ),
            (
                "policy",
                Box::new(|fixture| {
                    fixture
                        .store
                        .conn
                        .execute(
                            "UPDATE results SET policy_version = 'forged-policy' WHERE id = ?1",
                            [&fixture.result.id],
                        )
                        .unwrap();
                }),
            ),
            (
                "quarantined-result",
                Box::new(|fixture| {
                    fixture.store.conn.execute(
                    "UPDATE gateway_results SET status = 'quarantined', quarantine_reason = 'test' WHERE gateway_result_id = ?1",
                    [&fixture.gateway_result_id],
                ).unwrap();
                }),
            ),
            (
                "incomplete-source",
                Box::new(|fixture| {
                    fixture.store.conn.execute(
                    "UPDATE results SET quarantined = 1, quarantine_reason = 'test' WHERE id = ?1",
                    [&fixture.result.id],
                ).unwrap();
                }),
            ),
        ];

        for (label, mutation) in mutations {
            let fixture = RetrievalAuthorityFixtureV2::new(label);
            let wire = fixture.issue(label);
            mutation(&fixture);
            let authority =
                retrieval_authority_v2(&wire, &RetrievalRecipientBindingV2::authentic());
            assert!(
                fixture
                    .store
                    .consume_gateway_retrieval_grant_v2(&authority)
                    .is_err(),
                "mutation {label} unexpectedly retained retrieval authority"
            );
            let outstanding: u64 = fixture.store.conn.query_row(
                "SELECT COUNT(*) FROM gateway_retrieval_grants_v2 WHERE consumed_ms IS NULL AND retired_ms IS NULL",
                [],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(outstanding, 0, "mutation {label} left authority live");
            fixture.assert_zero_confirmed_savings();
        }
    }

    #[test]
    fn retrieval_authority_v2_refuses_deleted_replaced_and_same_length_corrupt_cas() {
        for mode in ["deleted", "replaced", "same-length-corrupt"] {
            let fixture = RetrievalAuthorityFixtureV2::new(mode);
            let wire = fixture.issue(mode);
            let path = fixture
                .store
                .blob_path(&fixture.result.stdout_digest)
                .unwrap();
            match mode {
                "deleted" => fs::remove_file(path).unwrap(),
                "replaced" => fs::write(path, b"replacement").unwrap(),
                "same-length-corrupt" => {
                    fs::write(path, vec![b'x'; fixture.result.stdout_bytes as usize]).unwrap()
                }
                _ => unreachable!(),
            }
            let authority =
                retrieval_authority_v2(&wire, &RetrievalRecipientBindingV2::authentic());
            assert!(
                fixture
                    .store
                    .consume_gateway_retrieval_grant_v2(&authority)
                    .is_err(),
                "CAS mode {mode} unexpectedly retained retrieval authority"
            );
            let outstanding: u64 = fixture.store.conn.query_row(
                "SELECT COUNT(*) FROM gateway_retrieval_grants_v2 WHERE consumed_ms IS NULL AND retired_ms IS NULL",
                [],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(outstanding, 0);
            fixture.assert_zero_confirmed_savings();
        }
    }

    #[test]
    fn retrieval_authority_v2_is_expiring_and_concurrently_one_use() {
        let expired = RetrievalAuthorityFixtureV2::new("expired");
        let expired_wire = expired.issue("expired");
        expired
            .store
            .conn
            .execute(
                "UPDATE gateway_retrieval_grants_v2 SET issued_ms = 0, expires_ms = 1 WHERE grant_id = ?1",
                [&expired_wire.0],
            )
            .unwrap();
        let expired_authority =
            retrieval_authority_v2(&expired_wire, &RetrievalRecipientBindingV2::authentic());
        assert!(
            expired
                .store
                .consume_gateway_retrieval_grant_v2(&expired_authority)
                .is_err()
        );
        let retired: bool = expired.store.conn.query_row(
            "SELECT retired_ms IS NOT NULL FROM gateway_retrieval_grants_v2 WHERE grant_id = ?1",
            [&expired_wire.0],
            |row| row.get(0),
        ).unwrap();
        assert!(retired);
        expired.assert_zero_confirmed_savings();

        let concurrent = RetrievalAuthorityFixtureV2::new("concurrent");
        let wire = concurrent.issue("concurrent");
        let barrier = Arc::new(Barrier::new(2));
        let workers = (0..2)
            .map(|_| {
                let root = concurrent.root.clone();
                let wire = wire.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let store = Store::open(root).unwrap();
                    let authority =
                        retrieval_authority_v2(&wire, &RetrievalRecipientBindingV2::authentic());
                    barrier.wait();
                    store.consume_gateway_retrieval_grant_v2(&authority)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(workers.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(workers.iter().filter(|result| result.is_err()).count(), 1);
        concurrent.assert_zero_confirmed_savings();
    }

    #[test]
    fn same_key_with_different_output_is_quarantined() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        store
            .insert_result("key", b"first", b"", 0, 1, "v0", "{}")
            .unwrap();
        assert!(
            store
                .insert_result("key", b"second", b"", 0, 1, "v0", "{}")
                .is_err()
        );
        assert!(store.get_result("key").unwrap().is_none());
    }

    #[test]
    fn concurrent_identical_writes_converge_on_one_result() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        drop(Store::open(temp.path()).unwrap());
        let root = temp.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = Store::open(root).unwrap();
                    barrier.wait();
                    store
                        .insert_result("shared", b"same", b"", 0, 1, "v0", "{}")
                        .unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert!(results.iter().all(|result| result.id == results[0].id));
        let store = Store::open(temp.path()).unwrap();
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM results", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.get_blob(&results[0].stdout_digest).unwrap(), b"same");
    }

    #[test]
    fn concurrent_same_key_divergence_is_atomically_quarantined() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        drop(Store::open(temp.path()).unwrap());
        let root = temp.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|output| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = Store::open(root).unwrap();
                    barrier.wait();
                    store.insert_result("shared", output, b"", 0, 1, "v0", "{}")
                })
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);

        let store = Store::open(temp.path()).unwrap();
        assert!(store.get_result("shared").unwrap().is_none());
        let quarantined: i64 = store
            .conn
            .query_row(
                "SELECT quarantined FROM results WHERE request_key = 'shared'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(quarantined, 1);
        let quarantine_events: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE reason_code = 'same_key_different_result'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(quarantine_events, 1);
    }

    #[test]
    fn product_diagnostics_cover_context_and_both_decision_paths() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();

        assert_eq!(
            store.context_ledger_stats_v1().unwrap(),
            ContextLedgerStatsV1::default()
        );
        store
            .record_event(
                None,
                None,
                EventDisposition::PassedThrough,
                "unsafe_effect",
                0,
                0,
            )
            .unwrap();
        let explicit = store.latest_decision_explanation_v1().unwrap().unwrap();
        assert_eq!(explicit.source, "explicit");
        assert_eq!(explicit.decision, "bypassed");
        assert_eq!(explicit.reason, "unsafe_effect");

        store
            .conn
            .execute(
                "INSERT INTO gateway_events (event_type, reason, estimated_tokens_avoided, created_ms)
                 VALUES ('inflight_join', 'joined_current_leader', 0, ?1)",
                [i64::MAX - 1],
            )
            .unwrap();
        let joined = store.latest_decision_explanation_v1().unwrap().unwrap();
        assert_eq!(joined.source, "gateway");
        assert_eq!(joined.decision, "joined");
        assert_eq!(joined.raw_event, "inflight_join");

        store
            .conn
            .execute(
                "INSERT INTO gateway_events (event_type, reason, estimated_tokens_avoided, created_ms)
                 VALUES ('executed', 'direct', 0, ?1)",
                [i64::MAX],
            )
            .unwrap();
        let direct = store.latest_decision_explanation_v1().unwrap().unwrap();
        assert_eq!(direct.decision, "bypassed");
        assert_eq!(direct.reason, "direct");

        let stats = store.stats().unwrap();
        assert_eq!(stats.context_events, 0);
        assert_eq!(stats.current_verified_facts, 0);
        assert_eq!(stats.context_delivery_receipts, 0);
    }

    #[test]
    fn context_task_registry_converges_aliases_refuses_conflicts_and_rechecks_bytes() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let authorization = "a".repeat(64);
        let first = store
            .resolve_context_task_v1(
                "repository",
                "workspace",
                &authorization,
                "external-a",
                Some("repair the shared parser"),
            )
            .unwrap();
        assert_eq!(first.matched_by, ContextTaskMatchV1::Created);
        let by_prompt = store
            .resolve_context_task_v1(
                "repository",
                "workspace",
                &authorization,
                "external-b",
                Some("repair the shared parser"),
            )
            .unwrap();
        assert_eq!(by_prompt.canonical_task_id, "external-a");
        assert_eq!(by_prompt.matched_by, ContextTaskMatchV1::JoinedByPrompt);
        let by_alias = store
            .resolve_context_task_v1(
                "repository",
                "workspace",
                &authorization,
                "external-b",
                None,
            )
            .unwrap();
        assert_eq!(by_alias.prompt, "repair the shared parser");
        assert_eq!(by_alias.matched_by, ContextTaskMatchV1::JoinedByTaskId);
        assert_eq!(
            store
                .resolve_context_task_v1(
                    "repository",
                    "workspace",
                    &authorization,
                    "external-b",
                    Some("replace the public API"),
                )
                .unwrap_err()
                .to_string(),
            "task_definition_conflict"
        );

        store
            .conn
            .execute(
                "UPDATE context_tasks_v1 SET prompt_text = 'tampered' WHERE canonical_task_id = 'external-a'",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .context_task_by_alias_v1("repository", "workspace", &authorization, "external-a")
                .unwrap_err()
                .to_string(),
            "context_task_corrupt"
        );
        drop(store);
        assert!(Store::open(temp.path()).is_err());
    }

    #[test]
    fn concurrent_exact_prompts_create_one_task_and_every_alias() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        drop(Store::open(temp.path()).unwrap());
        let root = temp.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(8));
        let handles = (0..8)
            .map(|index| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let store = Store::open(root).unwrap();
                    barrier.wait();
                    store
                        .resolve_context_task_v1(
                            "repository",
                            "workspace",
                            &"b".repeat(64),
                            &format!("external-{index}"),
                            Some("one exact concurrent task"),
                        )
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let resolutions = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(
            resolutions
                .iter()
                .all(|resolution| resolution.canonical_task_id == resolutions[0].canonical_task_id)
        );
        assert_eq!(
            resolutions
                .iter()
                .filter(|resolution| resolution.matched_by == ContextTaskMatchV1::Created)
                .count(),
            1
        );
        let store = Store::open(temp.path()).unwrap();
        let tasks: u64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM context_tasks_v1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let aliases: u64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM context_task_aliases_v1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(tasks, 1);
        assert_eq!(aliases, 8);
    }

    #[test]
    fn quota_maintenance_refuses_writes_but_keeps_inspect_export_and_delete_available() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let authorization = "c".repeat(64);
        let task = TaskDefinitionV1::new(
            "terminal maintenance task",
            Vec::new(),
            None,
            Vec::new(),
            None,
        )
        .unwrap();
        store
            .start_task_v1(
                "repository",
                "workspace",
                &authorization,
                "maintenance-task",
                &task,
            )
            .unwrap();
        let identity = ContextLedgerIdentityV1::new(
            "repository",
            "workspace",
            "maintenance-task",
            &authorization,
            "agent",
            "session",
            "turn",
            &"d".repeat(64),
            0,
            1,
        )
        .unwrap();
        store.activate_context_recipient_v1(&identity).unwrap();
        let lease = match store
            .claim_task_v1(&identity, 1, 30_000, now_ms().saturating_add(60_000))
            .unwrap()
        {
            TaskClaimOutcomeV1::Leader { lease_id, .. } => lease_id,
            other => panic!("unexpected claim: {other:?}"),
        };
        store
            .transition_task_v1(
                &identity,
                &lease,
                1,
                TaskStateV1::Completed,
                "complete before maintenance",
            )
            .unwrap();
        let workspace_bytes = MAX_TASK_CONTEXT_LOGICAL_BYTES_V1.saturating_add(1);
        let checksum = task_quota_checksum_v1(
            "repository",
            "workspace",
            workspace_bytes,
            workspace_bytes,
            true,
        );
        store
            .conn
            .execute(
                "UPDATE context_workspace_quota_v1
                 SET task_context_bytes = ?1, workspace_state_bytes = ?1,
                     maintenance_mode = 1, counter_checksum = ?2
                 WHERE repository_id = 'repository' AND workspace_id = 'workspace'",
                params![workspace_bytes, checksum],
            )
            .unwrap();
        drop(store);

        let mut reopened = Store::open(temp.path()).unwrap();
        assert!(
            reopened
                .task_quota_status_v1("repository", "workspace")
                .unwrap()
                .maintenance_mode
        );
        assert!(
            reopened
                .start_task_v1(
                    "repository",
                    "workspace",
                    &authorization,
                    "refused-write",
                    &TaskDefinitionV1::new(
                        "this write must be refused",
                        Vec::new(),
                        None,
                        Vec::new(),
                        None,
                    )
                    .unwrap(),
                )
                .is_err()
        );
        let artifacts_before: u64 = reopened
            .conn
            .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
            .unwrap();
        assert!(
            reopened
                .insert_result(
                    "maintenance-result",
                    b"stdout",
                    b"stderr",
                    0,
                    1,
                    "policy-v1",
                    "{}",
                )
                .is_err()
        );
        let artifacts_after: u64 = reopened
            .conn
            .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(artifacts_after, artifacts_before);
        assert!(
            reopened
                .inspect_task_v1(
                    "repository",
                    "workspace",
                    &authorization,
                    "maintenance-task",
                )
                .unwrap()
                .is_some()
        );
        assert!(
            reopened
                .export_task_v1(
                    "repository",
                    "workspace",
                    &authorization,
                    "maintenance-task",
                )
                .unwrap()
                .is_some()
        );
        assert!(
            reopened
                .delete_task_v1(
                    "repository",
                    "workspace",
                    &authorization,
                    "maintenance-task",
                )
                .unwrap()
        );
        assert!(
            !reopened
                .task_quota_status_v1("repository", "workspace")
                .unwrap()
                .maintenance_mode
        );
    }
}
