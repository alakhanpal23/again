//! Experimental repository-aware MCP execution memory.
//!
//! The runtime composes the protocol, descriptor-bound workspace authority,
//! exact store coordinator, and MCP provider boundary. Only the closed,
//! built-in repository provider is eligible for reuse. Every other provider or
//! incomplete observation executes normally.

#[path = "agent_gateway_runtime/context_compiler.rs"]
pub mod context_compiler;
#[path = "agent_gateway_runtime/context_coordinator.rs"]
mod context_coordinator;
#[path = "agent_gateway_runtime/repository_tools.rs"]
mod repository_tools;

use std::any::Any;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::agent_gateway::context::{
    ReasoningBriefInputV1, ReasoningRecipientV1, ReasoningScopeV1,
};
use crate::agent_gateway::protocol::{
    AgentCallIdentityV1, CanonicalArguments, DeliveryAuthorityRefusalV1, DeliveryStreamsV1,
    DigestReferenceV1, EffectClass as CoreEffectClass, FreshnessRequirementV1,
    GatewayToolCallInputV1, GatewayToolCallV1, ModelIdentityV1, PermissionClass, PresentationMode,
    ProviderIdentityV1, RepositoryEnvironmentStateV1, StateDigestReferenceV1, TaskIdentityV1,
    ToolIdentityV1, WorkspaceIdentityV1,
};
use crate::agent_gateway::router::{GatewayDecision, RoutingCandidatesV1, route};
use crate::agent_gateway_runtime::context_compiler::{
    CompiledReasoningBriefV1, ReasoningBriefPresentationRequestV1, ReasoningBriefPresentationV1,
    ReasoningDeliveryAcknowledgmentV1, compile_reasoning_brief_v1,
    complete_reasoning_brief_delivery_v1,
};
use crate::agent_gateway_runtime::context_coordinator::{
    ContextProviderKindV1, LocalContextCoordinatorV1, LocalContextProviderV1,
};
use crate::mcp_gateway::{
    AuthorizationScopeId, CapturedToolResult, ConfirmedDeliveryV1, DeliveryConfirmationSink,
    EffectClass, EphemeralSecrets, Freshness, FreshnessMetadata, GatewayLimits, McpError,
    McpErrorCode, McpGateway, OpaqueReasoningAcknowledgmentV1, PreparedReasoningContextV1,
    ProviderCall, ProviderCancellation, ProviderDescriptor, ProviderError, ProviderRegistration,
    ProviderTool, ReasoningContextCandidateV1, ReasoningDeliveryCompletionV1,
    ReasoningTransportPresentationV1, ReasoningTransportRecipientV1, ReasoningTransportScopeV1,
    RecipientConnectionRetirementV2, RecipientRetrievalAuthorityV2, RetrievalGrantV2,
    SideEffectClassification, StructuredResultCapture, ToolCancellation, ToolDiscovery,
    ToolExecution, UpstreamProvider, authorization_scope_digest_v1,
};
use crate::store::{
    GatewayCallAcquisition, GatewayCallObservation, GatewayCompletion, GatewayCoordinatorInputV1,
    GatewayDependencyV1, GatewayExecutionStart, GatewayFailureReason, GatewayFreshnessEvidenceV1,
    GatewayFullResultV1, GatewayHeartbeat, GatewayOperationDispositionV1,
    GatewayReasoningContextQueryV1, GatewayRouteProofObservationV1, GatewayServedRouteV1,
    GatewayStats, Store, ValidatedGatewayReadV1, gateway_policy_digest,
};
use crate::workspace_authority::{
    CompleteToolStateV1, EnvironmentObservationPlanV1, EnvironmentRelevanceProofV1,
    ExecutableObservationRequestV1, ExternalFreshnessV1, ManifestDependentKindV1,
    ManifestDependentV1, McpIdentityV1, ObservedManifestV1, RepositoryGitStateV1,
    RepositoryObservationKindV1, RepositoryObservationPlanV1, StateDigestV1, StateDimensionV1,
    TaskStateInputV1, TaskStateV1, WorkspaceAuthorityLimitsV1, WorkspaceExecutionEpochV1,
    issue_no_external_dependencies_v1, observe_environment_v1,
};

const POLICY_VERSION_V1: &str = "agent-gateway-exact-v1";
const REPOSITORY_PROVIDER_ID_V1: &str = "repo";
const REPOSITORY_PROVIDER_IMPLEMENTATION_V1: &str = "again.repository-provider-v1";
const GIT_PROVIDER_ID_V1: &str = "git";
const GIT_PROVIDER_IMPLEMENTATION_V1: &str = "again.git-provider-v1";
const MAX_REPOSITORY_FILE_BYTES_V1: u64 = 4 * 1024 * 1024;
const MAX_REPOSITORY_SCAN_BYTES_V1: u64 = 16 * 1024 * 1024;
const MAX_REPOSITORY_ENTRIES_V1: usize = 20_000;
const FOLLOWER_WAIT_V1: Duration = Duration::from_secs(30);
// Under a 100-client cold start the elected leader may not be scheduled
// immediately after durable acquisition. Preserve conservative bounded
// waiting long enough for that leader to publish its execution-start proof,
// rather than duplicating the provider read during transient scheduler load.
const FOLLOWER_PROOF_WAIT_V1: Duration = Duration::from_secs(2);
const LEADER_HEARTBEAT_INTERVAL_V1: Duration = Duration::from_secs(5);
const MAX_PENDING_REASONING_CONTEXTS_V1: usize = 128;
const MAX_RECENT_GATEWAY_CANDIDATES_V1: usize = 64;
const INTERNAL_REASONING_CONTEXT_TOKEN_V1: &str = "__again_internal_reasoning_context_v1";

struct RuntimeReasoningContextV1 {
    input: ReasoningBriefInputV1,
}

impl ReasoningContextCandidateV1 for RuntimeReasoningContextV1 {
    fn scope(&self) -> ReasoningTransportScopeV1 {
        ReasoningTransportScopeV1 {
            task_id: self.input.scope.task_id().to_owned(),
            repository_id: self.input.scope.repository_id().to_owned(),
            workspace_id: self.input.scope.workspace_id().to_owned(),
            state_digest: self.input.scope.state_digest().to_owned(),
            dependency_digest: self.input.scope.dependency_digest().to_owned(),
            authorization_scope_digest: self.input.scope.authorization_scope_digest().to_owned(),
        }
    }

    fn compile(
        mut self: Box<Self>,
        recipient: &ReasoningTransportRecipientV1,
        acknowledgment: Option<&(dyn Any + Send + Sync)>,
    ) -> Result<PreparedReasoningContextV1, ()> {
        let recipient = ReasoningRecipientV1::new(
            &recipient.agent_id,
            &recipient.session_id,
            &recipient.turn_id,
            &recipient.connection_generation,
            recipient.compaction_generation,
            recipient.lifecycle_generation,
        )
        .map_err(|_| ())?;
        self.input.recipient = recipient.clone();
        let acknowledgment = acknowledgment
            .and_then(|value| value.downcast_ref::<ReasoningDeliveryAcknowledgmentV1>());
        let compiled = compile_reasoning_brief_v1(
            &self.input,
            ReasoningBriefPresentationRequestV1::PreferCompact { acknowledgment },
        )
        .map_err(|_| ())?;
        let brief = serde_json::from_slice(compiled.bytes()).map_err(|_| ())?;
        let metrics = serde_json::to_value(compiled.metrics()).map_err(|_| ())?;
        let (presentation, completion) = match compiled.presentation() {
            ReasoningBriefPresentationV1::Full => (
                ReasoningTransportPresentationV1::Full,
                Some(Box::new(RuntimeReasoningDeliveryCompletionV1 {
                    recipient,
                    compiled,
                }) as Box<dyn ReasoningDeliveryCompletionV1>),
            ),
            ReasoningBriefPresentationV1::CompactReference => {
                (ReasoningTransportPresentationV1::CompactReference, None)
            }
        };
        Ok(PreparedReasoningContextV1 {
            presentation,
            brief,
            metrics,
            completion,
        })
    }
}

struct RuntimeReasoningDeliveryCompletionV1 {
    recipient: ReasoningRecipientV1,
    compiled: CompiledReasoningBriefV1,
}

impl ReasoningDeliveryCompletionV1 for RuntimeReasoningDeliveryCompletionV1 {
    fn complete(self: Box<Self>) -> Result<OpaqueReasoningAcknowledgmentV1, ()> {
        let acknowledgment = complete_reasoning_brief_delivery_v1(
            &self.recipient,
            &self.compiled,
            self.compiled.bytes(),
            true,
            true,
            true,
        )
        .map_err(|_| ())?;
        Ok(Arc::new(acknowledgment))
    }
}

fn gateway_workspace_limits_v1() -> WorkspaceAuthorityLimitsV1 {
    WorkspaceAuthorityLimitsV1 {
        max_file_bytes: MAX_REPOSITORY_FILE_BYTES_V1,
        max_total_bytes: MAX_REPOSITORY_SCAN_BYTES_V1,
        max_tree_entries: MAX_REPOSITORY_ENTRIES_V1 as u64,
        max_tree_depth: 128,
        max_directory_entries: MAX_REPOSITORY_ENTRIES_V1 as u64,
        max_total_path_bytes: 16 * 1024 * 1024,
        ..WorkspaceAuthorityLimitsV1::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepositoryOperationV1 {
    Read,
    Search,
    List,
    Tree,
    Stat,
    Glob,
    References,
    Manifest,
    GitStatus,
    GitDiff,
    GitLog,
    GitShow,
    GitBlame,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GatewayReuseModeV1 {
    Automatic,
    #[cfg(test)]
    ForceReuse,
    ExecuteOnly,
}

// A 250-file authenticated probe measured git.status warm reuse at 53.65 ms
// versus 14.89 ms direct. The index crossed 16 KiB at that scale. A standalone
// probe confirmed that the default bypass is near direct latency, while the
// one-file index retains a measured reuse win. This check can only disable
// reuse, never authorize a cache hit.
const STANDALONE_GIT_STATUS_DIRECT_INDEX_BYTES_V1: u64 = 16 * 1024;
// Bound retained provider values by serialized size (64 entries, 16 MiB total
// serialized budget); larger results use digest comparison.
const MAX_RECENT_PROVIDER_VALUE_BYTES_V1: u64 = 256 * 1024;

impl RepositoryOperationV1 {
    fn from_call(call: &ProviderCall) -> Option<Self> {
        if call.provider_identity.is_empty()
            || call.translation.disposition()
                != crate::mcp_gateway::ReuseDispositionV1::EligibleForStateEvaluation
        {
            return None;
        }
        match call.translation.namespaced_tool_name() {
            "repo.read" => Some(Self::Read),
            "repo.search" => Some(Self::Search),
            "repo.list" => Some(Self::List),
            "repo.tree" => Some(Self::Tree),
            "repo.stat" => Some(Self::Stat),
            "repo.glob" => Some(Self::Glob),
            "repo.references" => Some(Self::References),
            "repo.manifest" => Some(Self::Manifest),
            "git.status" => Some(Self::GitStatus),
            "git.diff" => Some(Self::GitDiff),
            "git.log" => Some(Self::GitLog),
            "git.show" => Some(Self::GitShow),
            "git.blame" => Some(Self::GitBlame),
            _ => None,
        }
    }

    fn provider_boundary(self) -> (&'static str, &'static str) {
        match self {
            Self::GitStatus | Self::GitDiff | Self::GitLog | Self::GitShow | Self::GitBlame => {
                (GIT_PROVIDER_ID_V1, GIT_PROVIDER_IMPLEMENTATION_V1)
            }
            _ => (
                REPOSITORY_PROVIDER_ID_V1,
                REPOSITORY_PROVIDER_IMPLEMENTATION_V1,
            ),
        }
    }

    fn is_git(self) -> bool {
        self.provider_boundary().0 == GIT_PROVIDER_ID_V1
    }
}

#[derive(Debug)]
struct ResolvedRequestV1 {
    core_call: GatewayToolCallV1,
    binding: ValidatedGatewayReadV1,
    observation_plan: RepositoryObservationPlanV1,
}

#[derive(Clone)]
enum ActiveCoordinatorV1 {
    Leader {
        lease_id: String,
        owner: String,
        cancelled: Arc<AtomicBool>,
    },
    Follower {
        call_id: String,
        cancelled: Arc<AtomicBool>,
    },
}

trait RepositoryEpochProviderV1: UpstreamProvider {
    fn execute_with_epoch(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError>;
}

/// Provider wrapper used by the experimental MCP server. Its constructor is
/// crate-private so an SDK caller cannot spoof the built-in provider identity
/// and obtain reuse authority.
pub(crate) struct GatewayControlledProviderV1 {
    inner: Arc<dyn RepositoryEpochProviderV1>,
    workspace: PathBuf,
    observed_workspace: SharedObservedWorkspaceV1,
    store: Arc<Mutex<Store>>,
    context_coordinator: Option<Arc<LocalContextCoordinatorV1>>,
    active: Mutex<BTreeMap<(String, u64), ActiveCoordinatorV1>>,
    pending_reasoning: Mutex<BTreeMap<String, ReasoningBriefInputV1>>,
    recent_candidates: Mutex<BTreeMap<String, RecentGatewayCandidateV1>>,
    reuse_mode: GatewayReuseModeV1,
}

#[derive(Clone)]
struct SharedObservedWorkspaceV1 {
    execution_epoch: Arc<WorkspaceExecutionEpochV1>,
    manifest: Arc<Mutex<ObservedManifestV1>>,
}

impl SharedObservedWorkspaceV1 {
    fn begin(workspace: &Path) -> Result<Self> {
        let limits = gateway_workspace_limits_v1();
        let execution_epoch = Arc::new(
            WorkspaceExecutionEpochV1::begin(workspace, &limits)
                .map_err(|_| anyhow!("descriptor-retained workspace issuance failed"))?,
        );
        let manifest = execution_epoch
            .begin_observed_manifest(&limits)
            .map_err(|_| anyhow!("sealed observed manifest issuance failed"))?;
        Ok(Self {
            execution_epoch,
            manifest: Arc::new(Mutex::new(manifest)),
        })
    }
}

#[derive(Clone)]
struct SharedObservedWorkspaceV1 {
    execution_epoch: Arc<WorkspaceExecutionEpochV1>,
    manifest: Arc<Mutex<ObservedManifestV1>>,
}

impl SharedObservedWorkspaceV1 {
    fn begin(workspace: &Path) -> Result<Self> {
        let limits = gateway_workspace_limits_v1();
        let execution_epoch = Arc::new(
            WorkspaceExecutionEpochV1::begin(workspace, &limits)
                .map_err(|_| anyhow!("descriptor-retained workspace issuance failed"))?,
        );
        let manifest = execution_epoch
            .begin_observed_manifest(&limits)
            .map_err(|_| anyhow!("sealed observed manifest issuance failed"))?;
        Ok(Self {
            execution_epoch,
            manifest: Arc::new(Mutex::new(manifest)),
        })
    }
}

#[derive(Clone)]
struct RecentGatewayCandidateV1 {
    binding: ValidatedGatewayReadV1,
    gateway_result_id: String,
    task_id: Option<String>,
    stdout_digest: String,
    provider_value: Option<Arc<Value>>,
}

impl RecentGatewayCandidateV1 {
    fn matches_fresh_provider_result(&self, value: &Value) -> bool {
        if let Some(prior) = self.provider_value.as_deref() {
            return prior == value;
        }
        let bytes = serde_json::to_vec(value).expect("JSON values are serializable");
        blake3::hash(&bytes).to_hex().as_str() == self.stdout_digest
    }
}

struct LoadedGatewayResultV1 {
    value: Value,
    full: GatewayFullResultV1,
}

struct ActiveRegistrationV1<'a> {
    provider: &'a GatewayControlledProviderV1,
    key: (String, u64),
}

impl Drop for ActiveRegistrationV1<'_> {
    fn drop(&mut self) {
        self.provider
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.key);
    }
}

impl GatewayControlledProviderV1 {
    #[cfg(test)]
    fn new(
        inner: Arc<dyn RepositoryEpochProviderV1>,
        workspace: PathBuf,
        store: Arc<Mutex<Store>>,
    ) -> Result<Self> {
        let observed_workspace = SharedObservedWorkspaceV1::begin(&workspace)?;
        Ok(Self::new_with_observed_workspace(
            inner,
            workspace,
            observed_workspace,
            store,
            None,
            GatewayReuseModeV1::ForceReuse,
        ))
    }

    fn new_with_observed_workspace(
        inner: Arc<dyn RepositoryEpochProviderV1>,
        workspace: PathBuf,
        observed_workspace: SharedObservedWorkspaceV1,
        store: Arc<Mutex<Store>>,
        context_coordinator: Option<Arc<LocalContextCoordinatorV1>>,
        reuse_mode: GatewayReuseModeV1,
    ) -> Self {
        Self {
            inner,
            workspace,
            observed_workspace,
            store,
            context_coordinator,
            active: Mutex::new(BTreeMap::new()),
            pending_reasoning: Mutex::new(BTreeMap::new()),
            recent_candidates: Mutex::new(BTreeMap::new()),
            reuse_mode,
        }
    }

    fn execute_direct(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
        record_request: bool,
    ) -> Result<Value, ProviderError> {
        let _ = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .record_gateway_direct_execution(record_request);
        self.inner.execute_with_epoch(epoch, call, secrets)
    }

    fn large_git_status_index(&self) -> bool {
        fs::symlink_metadata(self.workspace.join(".git/index"))
            .ok()
            .is_some_and(|metadata| {
                metadata.is_file() && metadata.len() >= STANDALONE_GIT_STATUS_DIRECT_INDEX_BYTES_V1
            })
    }

    fn resolve(&self, call: &ProviderCall) -> Option<ResolvedRequestV1> {
        let operation = RepositoryOperationV1::from_call(call)?;
        let descriptor = self.inner.descriptor();
        let (provider_id, implementation) = operation.provider_boundary();
        if descriptor.id != provider_id || descriptor.implementation != implementation {
            return None;
        }
        let mut manifest = self
            .observed_workspace
            .manifest
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let resolved = resolve_repository_request_v1(
            &self.observed_workspace.execution_epoch,
            &mut manifest,
            call,
            operation,
        )
        .ok()?;
        drop(manifest);
        if let Some(coordinator) = self.context_coordinator.as_ref() {
            coordinator
                .observe_dependencies(call, &resolved.binding)
                .ok()?;
        }
        Some(resolved)
    }

    fn owner(call: &ProviderCall) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"again.gateway.owner.v1\0");
        hasher.update(call.logical_call_id.as_str().as_bytes());
        hasher.update(&call.physical_attempt_id.get().to_le_bytes());
        format!("mcp:{}", &hasher.finalize().to_hex()[..32])
    }

    fn recent_candidate_key(call: &ProviderCall) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"again.gateway.recent-candidate.v1\0");
        hasher.update(call.translation.canonical_digest());
        hasher.update(call.authorization_scope.as_str().as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    fn recent_candidate(&self, key: &str) -> Option<RecentGatewayCandidateV1> {
        self.recent_candidates
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(key)
            .cloned()
    }

    fn remember_candidate(
        &self,
        call: &ProviderCall,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
    ) {
        let key = Self::recent_candidate_key(call);
        {
            let recent = self
                .recent_candidates
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if recent.get(&key).is_some_and(|candidate| {
                candidate.binding.binding_digest() == binding.binding_digest()
                    && candidate.gateway_result_id == gateway_result_id
            }) {
                return;
            }
        }
        let Some(loaded) = self
            .load_stored_exact(binding, gateway_result_id)
            .ok()
            .flatten()
        else {
            return;
        };
        let mut recent = self
            .recent_candidates
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !recent.contains_key(&key)
            && recent.len() >= MAX_RECENT_GATEWAY_CANDIDATES_V1
            && let Some(oldest_key) = recent.keys().next().cloned()
        {
            recent.remove(&oldest_key);
        }
        let provider_value = (loaded.full.result.stdout_bytes
            <= MAX_RECENT_PROVIDER_VALUE_BYTES_V1)
            .then(|| Arc::new(loaded.value));
        recent.insert(
            key,
            RecentGatewayCandidateV1 {
                binding: binding.clone(),
                gateway_result_id: gateway_result_id.to_owned(),
                task_id: self
                    .context_coordinator
                    .as_ref()
                    .and_then(|coordinator| coordinator.active_identity_for_call(call))
                    .map(|identity| identity.task_id().to_owned()),
                stdout_digest: loaded.full.result.stdout_digest,
                provider_value,
            },
        );
    }

    fn register_result_dependency(
        &self,
        resolved: &ResolvedRequestV1,
        gateway_result_id: &str,
    ) -> bool {
        let dependent = ManifestDependentV1::new(
            ManifestDependentKindV1::Result,
            StateDigestV1::from_domain_and_bytes(
                b"again.gateway-result-dependent.v1",
                gateway_result_id.as_bytes(),
            ),
        );
        self.observed_workspace
            .manifest
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .register_dependent(&resolved.observation_plan, dependent)
            .is_ok()
    }

    fn remember_active(
        &self,
        logical_call_id: &str,
        physical_attempt_id: u64,
        active: ActiveCoordinatorV1,
    ) -> ActiveRegistrationV1<'_> {
        let key = (logical_call_id.to_owned(), physical_attempt_id);
        self.active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(key.clone(), active);
        ActiveRegistrationV1 {
            provider: self,
            key,
        }
    }

    fn load_stored_exact(
        &self,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
    ) -> Result<Option<LoadedGatewayResultV1>> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(full) = store.get_gateway_result(binding, gateway_result_id)? else {
            return Ok(None);
        };
        let value: Value =
            serde_json::from_slice(&full.stdout).context("decode exact gateway provider result")?;
        Ok(Some(LoadedGatewayResultV1 { value, full }))
    }

    fn attach_loaded_exact(
        &self,
        resolved: &ResolvedRequestV1,
        call: &ProviderCall,
        loaded: LoadedGatewayResultV1,
    ) -> Value {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let reasoning = reasoning_context_for_result_v1(&store, &self.workspace, resolved, call)
            .ok()
            .flatten();
        drop(store);
        if let Some(coordinator) = self.context_coordinator.as_ref() {
            let _ = coordinator.admit_verified_result(
                call,
                &resolved.binding,
                &loaded.full.gateway_result_id,
                loaded.full.result.duration_ms,
            );
        }
        let reasoning_token = reasoning.and_then(|reasoning| {
            let mut pending = self
                .pending_reasoning
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if pending.len() >= MAX_PENDING_REASONING_CONTEXTS_V1 {
                return None;
            }
            let token = format!("rc_{}", uuid::Uuid::new_v4().simple());
            pending.insert(token.clone(), reasoning);
            Some(token)
        });
        attach_result_reference_v1(
            loaded.value,
            &loaded.full.gateway_result_id,
            &loaded.full.result,
            reasoning_token.as_deref(),
        )
    }

    fn load_exact(
        &self,
        resolved: &ResolvedRequestV1,
        gateway_result_id: &str,
        call: &ProviderCall,
    ) -> Result<Option<Value>> {
        Ok(self
            .load_stored_exact(&resolved.binding, gateway_result_id)?
            .map(|loaded| self.attach_loaded_exact(resolved, call, loaded)))
    }

    fn execute_as_leader(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
        resolved: &ResolvedRequestV1,
        lease_id: String,
        owner: String,
    ) -> Result<Value, ProviderError> {
        let logical_call_id = call.logical_call_id.as_str().to_owned();
        let physical_attempt_id = call.physical_attempt_id.get();
        let cancelled = Arc::new(AtomicBool::new(false));
        let _active = self.remember_active(
            &logical_call_id,
            physical_attempt_id,
            ActiveCoordinatorV1::Leader {
                lease_id: lease_id.clone(),
                owner: owner.clone(),
                cancelled: Arc::clone(&cancelled),
            },
        );
        let verification_call = call.clone();
        let started = Instant::now();
        let heartbeat_failed = Arc::new(AtomicBool::new(false));
        let provider_result = thread::scope(|scope| {
            let (stop_sender, stop_receiver) = mpsc::channel::<()>();
            let store = Arc::clone(&self.store);
            let heartbeat_lease = lease_id.clone();
            let heartbeat_owner = owner.clone();
            let heartbeat_failed = Arc::clone(&heartbeat_failed);
            scope.spawn(move || {
                loop {
                    match stop_receiver.recv_timeout(LEADER_HEARTBEAT_INTERVAL_V1) {
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {
                            let heartbeat = store
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .heartbeat_gateway_call(&heartbeat_lease, &heartbeat_owner);
                            if !matches!(heartbeat, Ok(GatewayHeartbeat::Extended { .. })) {
                                heartbeat_failed.store(true, Ordering::Release);
                                break;
                            }
                        }
                    }
                }
            });
            let result = self.inner.execute_with_epoch(epoch, call, secrets);
            drop(stop_sender);
            result
        });

        match provider_result {
            Ok(value) if !cancelled.load(Ordering::Acquire) => {
                if heartbeat_failed.load(Ordering::Acquire) {
                    let _ = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .fail_gateway_call(&lease_id, GatewayFailureReason::Protocol);
                    return Ok(value);
                }
                let revalidated = self.resolve(&verification_call);
                if revalidated
                    .as_ref()
                    .map(|request| request.binding.binding_digest())
                    != Some(resolved.binding.binding_digest())
                {
                    let _ = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .fail_gateway_call(&lease_id, GatewayFailureReason::Protocol);
                    return Ok(value);
                }
                if cancelled.load(Ordering::Acquire) {
                    let _ = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .fail_gateway_call(&lease_id, GatewayFailureReason::Cancelled);
                    return Err(cancelled_provider_error_v1());
                }
                let bytes = canonical_json_bytes_v1(&value);
                let duration_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                let proof = json!({
                    "schema": "again.gateway-provider-result-proof.v1",
                    "requestDigest": resolved.binding.request_digest(),
                    "stateDigest": resolved.binding.state_digest(),
                    "policyDigest": resolved.binding.policy_digest(),
                    "authority": {
                        "semantic": false,
                        "mutationReplay": false,
                        "externalWriteReplay": false
                    }
                });
                let completion = (|| {
                    let mut store = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner());
                    let stored = store.insert_result(
                        resolved.binding.request_digest(),
                        &bytes,
                        b"",
                        0,
                        duration_ms,
                        POLICY_VERSION_V1,
                        &serde_json::to_string(&proof)?,
                    )?;
                    let outcome = store.complete_gateway_call(&lease_id, &stored.id)?;
                    Ok::<_, anyhow::Error>((outcome, stored))
                })();
                match completion {
                    Ok((
                        GatewayCompletion::Completed {
                            gateway_result_id, ..
                        },
                        stored,
                    ))
                    | Ok((
                        GatewayCompletion::AlreadyCompleted {
                            gateway_result_id, ..
                        },
                        stored,
                    )) => match self.load_exact(resolved, &gateway_result_id, &verification_call) {
                        Ok(Some(exact)) => {
                            // Dependency-proof registration controls only
                            // future reuse authority. The just-executed,
                            // durably loaded result remains valid for this
                            // exact current call even if registration briefly
                            // contends under high client concurrency.
                            if self.register_result_dependency(resolved, &gateway_result_id) {
                                self.remember_candidate(
                                    &verification_call,
                                    &resolved.binding,
                                    &gateway_result_id,
                                );
                            }
                            Ok(exact)
                        }
                        Ok(None) | Err(_) => {
                            // Completion already proved and committed this
                            // exact stored result. If a contended immediate
                            // reload is unavailable, preserve the durable
                            // reference on the validated provider value instead
                            // of returning one unreferenced duplicate response.
                            if let Some(coordinator) = self.context_coordinator.as_ref() {
                                let _ = coordinator.admit_verified_result(
                                    &verification_call,
                                    &resolved.binding,
                                    &gateway_result_id,
                                    stored.duration_ms,
                                );
                            }
                            if self.register_result_dependency(resolved, &gateway_result_id) {
                                self.remember_candidate(
                                    &verification_call,
                                    &resolved.binding,
                                    &gateway_result_id,
                                );
                            }
                            Ok(attach_result_reference_v1(
                                value,
                                &gateway_result_id,
                                &stored,
                                None,
                            ))
                        }
                    },
                    Ok(_) | Err(_) => Ok(value),
                }
            }
            Ok(_value) => {
                let _ = self
                    .store
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .fail_gateway_call(&lease_id, GatewayFailureReason::Cancelled);
                Err(cancelled_provider_error_v1())
            }
            Err(error) => {
                let _ = self
                    .store
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .fail_gateway_call(&lease_id, GatewayFailureReason::ProviderUnavailable);
                Err(error)
            }
        }
    }

    fn wait_as_follower(
        &self,
        call: &ProviderCall,
        resolved: &ResolvedRequestV1,
        call_id: &str,
        cancelled: &AtomicBool,
    ) -> Result<Option<Value>, ProviderError> {
        let deadline = Instant::now() + FOLLOWER_WAIT_V1;
        let answer = loop {
            if cancelled.load(Ordering::Acquire) {
                break Err(cancelled_provider_error_v1());
            }
            let observation = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .observe_gateway_call(&resolved.binding);
            match observation {
                Ok(GatewayCallObservation::Ready { gateway_result_id }) => {
                    if self
                        .resolve(call)
                        .as_ref()
                        .map(|request| request.binding.binding_digest())
                        != Some(resolved.binding.binding_digest())
                    {
                        break Ok(None);
                    }
                    let dependency_registered =
                        self.register_result_dependency(resolved, &gateway_result_id);
                    let loaded =
                        self.load_exact(resolved, &gateway_result_id, call)
                            .map_err(|_| {
                                ProviderError::gateway_authored(
                                    McpError::typed(
                                        McpErrorCode::InternalError,
                                        "verified gateway result became unavailable",
                                    )
                                    .with_data(json!({ "reason": "verified_result_unavailable" })),
                                )
                            });
                    if matches!(loaded, Ok(Some(_))) && dependency_registered {
                        self.remember_candidate(call, &resolved.binding, &gateway_result_id);
                        let _ = self
                            .store
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .record_gateway_route_served(
                                call_id,
                                &gateway_result_id,
                                GatewayServedRouteV1::Inflight,
                            );
                    }
                    break loaded;
                }
                Ok(GatewayCallObservation::Inflight { .. }) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                Ok(GatewayCallObservation::Failed { .. })
                | Ok(GatewayCallObservation::Quarantined { .. })
                | Ok(GatewayCallObservation::Missing)
                | Err(_) => break Ok(None),
                Ok(GatewayCallObservation::Inflight { .. }) => break Ok(None),
            }
        };
        if !matches!(answer, Ok(Some(_))) {
            let _ = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .cancel_gateway_follower(call_id);
        }
        answer
    }
}

impl ToolDiscovery for GatewayControlledProviderV1 {
    fn descriptor(&self) -> ProviderDescriptor {
        self.inner.descriptor()
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        self.inner.discover_tools()
    }
}

impl FreshnessMetadata for GatewayControlledProviderV1 {
    fn freshness(&self) -> Freshness {
        self.inner.freshness()
    }
}

impl SideEffectClassification for GatewayControlledProviderV1 {
    fn classify_effect(&self, upstream_tool_name: &str) -> EffectClass {
        self.inner.classify_effect(upstream_tool_name)
    }
}

impl StructuredResultCapture for GatewayControlledProviderV1 {
    fn capture_result(&self, mut result: Value) -> Result<CapturedToolResult, ProviderError> {
        let delivery = delivery_capture_v1(&result);
        let reasoning = take_reasoning_context_v1(&mut result).and_then(|token| {
            self.pending_reasoning
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&token)
        });
        let exact = self.inner.capture_result(result)?.into_exact();
        match delivery {
            Some((gateway_result_id, result_digest, streams)) => {
                Ok(CapturedToolResult::exact_with_delivery_and_reasoning(
                    exact,
                    gateway_result_id,
                    result_digest,
                    streams,
                    reasoning.map(|input| {
                        Box::new(RuntimeReasoningContextV1 { input })
                            as Box<dyn ReasoningContextCandidateV1>
                    }),
                ))
            }
            None => Ok(CapturedToolResult::exact(exact)),
        }
    }
}

impl ToolCancellation for GatewayControlledProviderV1 {
    fn cancel(&self, cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        let active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&(
                cancellation.logical_call_id.as_str().to_owned(),
                cancellation.physical_attempt_id.get(),
            ))
            .cloned();
        if let Some(active) = active {
            match active {
                ActiveCoordinatorV1::Leader {
                    lease_id,
                    owner,
                    cancelled,
                } => {
                    cancelled.store(true, Ordering::Release);
                    let _ = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .fail_gateway_call(&lease_id, GatewayFailureReason::Cancelled);
                    let _ = owner;
                }
                ActiveCoordinatorV1::Follower { call_id, cancelled } => {
                    cancelled.store(true, Ordering::Release);
                    let _ = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .cancel_gateway_follower(&call_id);
                }
            }
        }
        self.inner.cancel(cancellation)
    }
}

impl ToolExecution for GatewayControlledProviderV1 {
    fn execute(
        &self,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        let epoch = Arc::clone(&self.observed_workspace.execution_epoch);
        if call.effect != EffectClass::ReadOnly
            || self.reuse_mode == GatewayReuseModeV1::ExecuteOnly
        {
            return self.execute_direct(&epoch, call, secrets, true);
        }
        // Exact proof for built-in repository tools inspects the same source
        // or listing state as the provider. With no active task to receive a
        // durable fact or result reference, lookup and storage add work. The
        // task-bound path still stores proof and source-backed shared context.
        if self.reuse_mode == GatewayReuseModeV1::Automatic
            && self
                .context_coordinator
                .as_ref()
                .and_then(|coordinator| coordinator.active_identity_for_call(&call))
                .is_none()
        {
            match RepositoryOperationV1::from_call(&call) {
                Some(operation) if !operation.is_git() => {
                    return self.execute_direct(&epoch, call, secrets, true);
                }
                Some(RepositoryOperationV1::GitStatus) if self.large_git_status_index() => {
                    return self.execute_direct(&epoch, call, secrets, true);
                }
                _ => {}
            }
        }
        let candidate_key = Self::recent_candidate_key(&call);
        let mut candidate = self.recent_candidate(&candidate_key);
        let active_task_id = self
            .context_coordinator
            .as_ref()
            .and_then(|coordinator| coordinator.active_identity_for_call(&call))
            .map(|identity| identity.task_id().to_owned());
        if let Some(remembered) = candidate.as_ref()
            && remembered.task_id == active_task_id
            && remembered.task_id.is_some()
            && let Some(coordinator) = self.context_coordinator.as_ref()
        {
            match coordinator.result_reference_current(&call, &remembered.gateway_result_id) {
                Ok(true) => {}
                Ok(false) => {
                    self.recent_candidates
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .remove(&candidate_key);
                    candidate = None;
                }
                Err(_) => return Err(context_authority_failed_v1()),
            }
        }
        // After a task has received one source-backed built-in result, a
        // repeated repository call or large-index Git status can execute
        // through the trusted provider directly.
        // Returning its freshly executed value is cheaper than proving a
        // cache hit, and an identical result leaves the admitted fact truthful.
        // Divergence falls back to the full proof path to retire the old fact
        // and publish the changed result. This path never serves cached bytes.
        if self.reuse_mode == GatewayReuseModeV1::Automatic
            && RepositoryOperationV1::from_call(&call).is_some_and(|operation| {
                !operation.is_git()
                    || (operation == RepositoryOperationV1::GitStatus
                        && self.large_git_status_index())
            })
            && let Some(candidate) = candidate.as_ref()
            && candidate.task_id == active_task_id
            && candidate.task_id.is_some()
        {
            let observed = self.inner.execute_with_epoch(&epoch, call.clone(), secrets);
            // A bounded in-memory value makes the common comparison cheap.
            // Larger values use the stored blob digest; neither branch serves
            // cached bytes as a hit.
            if matches!(&observed, Ok(value) if candidate.matches_fresh_provider_result(value)) {
                let _ = self
                    .store
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .record_gateway_direct_execution(true);
                return observed;
            }
            if let Some(coordinator) = self.context_coordinator.as_ref() {
                if coordinator
                    .invalidate_source_observation(&call, &candidate.gateway_result_id)
                    .is_err()
                {
                    return Err(context_authority_failed_v1());
                }
            }
            // A source change can retire references in other tasks too. Their
            // in-memory shortcuts must re-enter admission on the next call.
            self.recent_candidates
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clear();
            let _ = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .record_gateway_direct_execution(observed.is_err());
            if let Err(error) = observed {
                let _ = self.resolve(&call);
                return Err(error);
            }
        }
        // Preload only a previously verified candidate for the actual cache
        // route. The direct path above compares a fresh provider result with
        // an in-memory digest and never serves cached bytes.
        let preloaded = self.recent_candidate(&candidate_key).and_then(|candidate| {
            self.load_stored_exact(&candidate.binding, &candidate.gateway_result_id)
                .ok()
                .flatten()
                .map(|loaded| (candidate, loaded))
        });
        let Some(resolved) = self.resolve(&call) else {
            return self.execute_direct(&epoch, call, secrets, true);
        };
        let owner = Self::owner(&call);
        let acquisition = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .acquire_gateway_call(&resolved.binding, &owner);
        let Ok(acquisition) = acquisition else {
            return self.execute_direct(&epoch, call, secrets, true);
        };
        match acquisition {
            GatewayCallAcquisition::Ready {
                call_id,
                gateway_result_id,
            } => {
                let proof = self
                    .store
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .observe_gateway_route_proof_v1(&resolved.binding, &resolved.core_call);
                let decision = match proof {
                    Ok(GatewayRouteProofObservationV1::Exact(proof))
                        if proof.gateway_result_id() == gateway_result_id =>
                    {
                        route(
                            &resolved.core_call,
                            &RoutingCandidatesV1::default().with_store_exact_proof(proof),
                        )
                    }
                    _ => GatewayDecision::Execute,
                };
                if decision == GatewayDecision::ServeExact {
                    if let Some((candidate, loaded)) = preloaded
                        && candidate.binding.binding_digest() == resolved.binding.binding_digest()
                        && candidate.gateway_result_id == gateway_result_id
                    {
                        let value = self.attach_loaded_exact(&resolved, &call, loaded);
                        if self.register_result_dependency(&resolved, &gateway_result_id) {
                            self.remember_candidate(&call, &resolved.binding, &gateway_result_id);
                            let _ = self
                                .store
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .record_gateway_route_served(
                                    &call_id,
                                    &gateway_result_id,
                                    GatewayServedRouteV1::Exact,
                                );
                        }
                        return Ok(value);
                    }
                    let value = self.load_exact(&resolved, &gateway_result_id, &call);
                    let revalidated = self.resolve(&call);
                    if revalidated
                        .as_ref()
                        .map(|request| request.binding.binding_digest())
                        == Some(resolved.binding.binding_digest())
                        && let Ok(Some(value)) = value
                    {
                        if self.register_result_dependency(&resolved, &gateway_result_id) {
                            self.remember_candidate(&call, &resolved.binding, &gateway_result_id);
                            let _ = self
                                .store
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .record_gateway_route_served(
                                    &call_id,
                                    &gateway_result_id,
                                    GatewayServedRouteV1::Exact,
                                );
                        }
                        return Ok(value);
                    }
                }
                self.execute_direct(&epoch, call, secrets, false)
            }
            GatewayCallAcquisition::Follower {
                call_id, lease_id, ..
            } => {
                let cancelled = Arc::new(AtomicBool::new(false));
                let _active = self.remember_active(
                    call.logical_call_id.as_str(),
                    call.physical_attempt_id.get(),
                    ActiveCoordinatorV1::Follower {
                        call_id: call_id.clone(),
                        cancelled: Arc::clone(&cancelled),
                    },
                );
                let proof_deadline = Instant::now() + FOLLOWER_PROOF_WAIT_V1;
                let decision = loop {
                    if cancelled.load(Ordering::Acquire) {
                        return Err(cancelled_provider_error_v1());
                    }
                    let proof = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .observe_gateway_route_proof_v1(&resolved.binding, &resolved.core_call);
                    match proof {
                        Ok(GatewayRouteProofObservationV1::Inflight(proof))
                            if proof.lease_id() == lease_id =>
                        {
                            break route(
                                &resolved.core_call,
                                &RoutingCandidatesV1::default().with_store_inflight_proof(proof),
                            );
                        }
                        Ok(GatewayRouteProofObservationV1::Exact(proof)) => {
                            // The leader can complete between follower
                            // acquisition and proof observation. Exact is a
                            // monotonic strengthening of that same authority;
                            // let the follower's normal wait/load path consume
                            // it instead of duplicating provider execution.
                            let exact = route(
                                &resolved.core_call,
                                &RoutingCandidatesV1::default().with_store_exact_proof(proof),
                            );
                            break if exact == GatewayDecision::ServeExact {
                                GatewayDecision::JoinInflight
                            } else {
                                GatewayDecision::Execute
                            };
                        }
                        Ok(GatewayRouteProofObservationV1::Unavailable(
                            crate::store::GatewayRouteProofUnavailableV1::ExecutionNotStarted,
                        )) if Instant::now() < proof_deadline => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        _ => break GatewayDecision::Execute,
                    }
                };
                if decision == GatewayDecision::JoinInflight
                    && let Some(value) =
                        self.wait_as_follower(&call, &resolved, &call_id, &cancelled)?
                {
                    return Ok(value);
                }
                let _ = self
                    .store
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .cancel_gateway_follower(&call_id);
                self.execute_direct(&epoch, call, secrets, false)
            }
            GatewayCallAcquisition::Leader {
                lease_id,
                expires_at_ms: _,
                ..
            } => {
                let started = self
                    .store
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .start_gateway_execution(&lease_id, &owner);
                if !matches!(started, Ok(GatewayExecutionStart::Started)) {
                    let _ = self
                        .store
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .fail_gateway_call(&lease_id, GatewayFailureReason::Protocol);
                    return self.execute_direct(&epoch, call, secrets, false);
                }
                self.execute_as_leader(&epoch, call, secrets, &resolved, lease_id, owner)
            }
            GatewayCallAcquisition::Refused { .. } => {
                self.execute_direct(&epoch, call, secrets, true)
            }
        }
    }
}

struct RepositoryProviderV1 {
    workspace: PathBuf,
}

impl RepositoryProviderV1 {
    fn new(workspace: &Path) -> Result<Self> {
        let workspace = fs::canonicalize(workspace).context("resolve MCP workspace")?;
        if !workspace.is_dir() {
            bail!("MCP workspace is not a directory");
        }
        Ok(Self { workspace })
    }

    fn execute_with_epoch(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        call: ProviderCall,
        _secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        repository_tools::execute_repository_tool_v1(
            epoch,
            &call.upstream_tool_name,
            &call.arguments,
        )
    }
}

impl RepositoryEpochProviderV1 for RepositoryProviderV1 {
    fn execute_with_epoch(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        RepositoryProviderV1::execute_with_epoch(self, epoch, call, secrets)
    }
}

impl ToolDiscovery for RepositoryProviderV1 {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: REPOSITORY_PROVIDER_ID_V1.to_owned(),
            implementation: REPOSITORY_PROVIDER_IMPLEMENTATION_V1.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint_identity: "local-workspace-descriptor-bound".to_owned(),
        }
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        Ok(repository_tools::repository_tool_definitions_v1())
    }
}

impl FreshnessMetadata for RepositoryProviderV1 {
    fn freshness(&self) -> Freshness {
        Freshness {
            revision: "descriptor-state-v1".to_owned(),
            observed_at_unix_ms: None,
        }
    }
}

impl SideEffectClassification for RepositoryProviderV1 {
    fn classify_effect(&self, upstream_tool_name: &str) -> EffectClass {
        match upstream_tool_name {
            "read" | "search" | "list" | "tree" | "stat" | "glob" | "references" | "manifest" => {
                EffectClass::ReadOnly
            }
            _ => EffectClass::Unknown,
        }
    }
}

impl StructuredResultCapture for RepositoryProviderV1 {
    fn capture_result(&self, result: Value) -> Result<CapturedToolResult, ProviderError> {
        Ok(CapturedToolResult::exact(result))
    }
}

impl ToolCancellation for RepositoryProviderV1 {
    fn cancel(&self, _cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl ToolExecution for RepositoryProviderV1 {
    fn execute(
        &self,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        let limits = gateway_workspace_limits_v1();
        let epoch = WorkspaceExecutionEpochV1::begin(&self.workspace, &limits).map_err(|_| {
            provider_io_v1(anyhow!("descriptor-retained workspace issuance failed"))
        })?;
        self.execute_with_epoch(&epoch, call, secrets)
    }
}

struct GitProviderV1 {
    workspace: PathBuf,
}

impl GitProviderV1 {
    fn new(workspace: &Path) -> Result<Self> {
        let workspace = fs::canonicalize(workspace).context("resolve Git MCP workspace")?;
        if !workspace.is_dir() {
            bail!("Git MCP workspace is not a directory");
        }
        Ok(Self { workspace })
    }
}

impl RepositoryEpochProviderV1 for GitProviderV1 {
    fn execute_with_epoch(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        call: ProviderCall,
        _secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        repository_tools::execute_git_tool_v1(epoch, &call.upstream_tool_name, &call.arguments)
    }
}

impl ToolDiscovery for GitProviderV1 {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: GIT_PROVIDER_ID_V1.to_owned(),
            implementation: GIT_PROVIDER_IMPLEMENTATION_V1.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint_identity: "local-git-descriptor-bound".to_owned(),
        }
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        Ok(repository_tools::git_tool_definitions_v1())
    }
}

impl FreshnessMetadata for GitProviderV1 {
    fn freshness(&self) -> Freshness {
        Freshness {
            revision: "descriptor-git-state-v1".to_owned(),
            observed_at_unix_ms: None,
        }
    }
}

impl SideEffectClassification for GitProviderV1 {
    fn classify_effect(&self, upstream_tool_name: &str) -> EffectClass {
        match upstream_tool_name {
            "status" | "diff" | "log" | "show" | "blame" => EffectClass::ReadOnly,
            _ => EffectClass::Unknown,
        }
    }
}

impl StructuredResultCapture for GitProviderV1 {
    fn capture_result(&self, result: Value) -> Result<CapturedToolResult, ProviderError> {
        Ok(CapturedToolResult::exact(result))
    }
}

impl ToolCancellation for GitProviderV1 {
    fn cancel(&self, _cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl ToolExecution for GitProviderV1 {
    fn execute(
        &self,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        let limits = gateway_workspace_limits_v1();
        let epoch = WorkspaceExecutionEpochV1::begin(&self.workspace, &limits).map_err(|_| {
            provider_io_v1(anyhow!("descriptor-retained Git workspace issuance failed"))
        })?;
        self.execute_with_epoch(&epoch, call, secrets)
    }
}

/// Fully composed experimental MCP server. The returned gateway owns an exact
/// repository provider and a coordinator-backed execution memory.
pub struct ExperimentalMcpGatewayV1 {
    gateway: McpGateway,
    store: Arc<Mutex<Store>>,
}

struct StoreDeliveryConfirmationSinkV1 {
    store: Arc<Mutex<Store>>,
}

fn delivery_store_refusal_v2(error: anyhow::Error) -> DeliveryAuthorityRefusalV1 {
    match error.to_string().as_str() {
        "acknowledgement_replayed" => DeliveryAuthorityRefusalV1::AcknowledgementReplayed,
        "delivery_authority_retired" => DeliveryAuthorityRefusalV1::Retired,
        _ => DeliveryAuthorityRefusalV1::InvalidBinding,
    }
}

impl DeliveryConfirmationSink for StoreDeliveryConfirmationSinkV1 {
    fn confirm_delivery_and_issue_retrieval(
        &self,
        delivery: &ConfirmedDeliveryV1,
    ) -> Result<RetrievalGrantV2, DeliveryAuthorityRefusalV1> {
        let grant = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .confirm_gateway_delivery_and_issue_retrieval_v2(delivery)
            .map_err(delivery_store_refusal_v2)?;
        let (grant_id, token, result_id, expires_at_ms) = grant.into_wire_parts();
        Ok(RetrievalGrantV2::from_store(
            grant_id,
            token,
            result_id,
            expires_at_ms,
        ))
    }

    fn retrieve_result(
        &self,
        authority: &RecipientRetrievalAuthorityV2,
    ) -> Result<Value, DeliveryAuthorityRefusalV1> {
        let full = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .consume_gateway_retrieval_grant_v2(authority)
            .map_err(delivery_store_refusal_v2)?;
        if !full.stderr.is_empty() || full.result.exit_code != 0 {
            return Err(DeliveryAuthorityRefusalV1::InvalidBinding);
        }
        serde_json::from_slice(&full.stdout).map_err(|_| DeliveryAuthorityRefusalV1::InvalidBinding)
    }

    fn retire_retrievals(
        &self,
        retirement: &RecipientConnectionRetirementV2,
        reason: &'static str,
    ) -> Result<(), DeliveryAuthorityRefusalV1> {
        self.store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retire_gateway_retrieval_grants_v2(retirement, reason)
            .map(|_| ())
            .map_err(delivery_store_refusal_v2)
    }
}

impl ExperimentalMcpGatewayV1 {
    pub fn build(workspace: &Path) -> Result<Self> {
        let workspace = fs::canonicalize(workspace).context("resolve experimental workspace")?;
        let store = Arc::new(Mutex::new(Store::open_for_workspace(&workspace)?));
        Self::build_with_shared_store_mode_v1(&workspace, store, GatewayReuseModeV1::Automatic)
    }

    /// Diagnostic control for measuring the exact same MCP and provider path
    /// with cache lookup and storage bypassed. Stdio has no authenticated task
    /// recipient, so this mode cannot silently weaken shared-context claims.
    pub(crate) fn build_execute_only_v1(workspace: &Path) -> Result<Self> {
        let workspace = fs::canonicalize(workspace).context("resolve experimental workspace")?;
        let store = Arc::new(Mutex::new(Store::open_for_workspace(&workspace)?));
        Self::build_with_shared_store_mode_v1(&workspace, store, GatewayReuseModeV1::ExecuteOnly)
    }

    #[cfg(test)]
    fn build_force_reuse_v1(workspace: &Path) -> Result<Self> {
        let workspace = fs::canonicalize(workspace).context("resolve experimental workspace")?;
        let store = Arc::new(Mutex::new(Store::open_for_workspace(&workspace)?));
        Self::build_with_shared_store_mode_v1(&workspace, store, GatewayReuseModeV1::ForceReuse)
    }

    /// Construct isolated MCP protocol state over one daemon-owned durable
    /// store. Each connection still receives its own gateway and lifecycle,
    /// while cold connection storms avoid concurrently reopening/migrating the
    /// same SQLite authority.
    pub(crate) fn build_with_shared_store_v1(
        workspace: &Path,
        store: Arc<Mutex<Store>>,
    ) -> Result<Self> {
        Self::build_with_shared_store_mode_v1(workspace, store, GatewayReuseModeV1::Automatic)
    }

    pub(crate) fn build_with_shared_store_execute_only_v1(
        workspace: &Path,
        store: Arc<Mutex<Store>>,
    ) -> Result<Self> {
        Self::build_with_shared_store_mode_v1(workspace, store, GatewayReuseModeV1::ExecuteOnly)
    }

    fn build_with_shared_store_mode_v1(
        workspace: &Path,
        store: Arc<Mutex<Store>>,
        reuse_mode: GatewayReuseModeV1,
    ) -> Result<Self> {
        let workspace = fs::canonicalize(workspace).context("resolve experimental workspace")?;
        let observed_workspace = SharedObservedWorkspaceV1::begin(&workspace)?;
        let context_coordinator = Arc::new(LocalContextCoordinatorV1::new(
            &workspace,
            Arc::clone(&store),
            observed_workspace.clone(),
        ));
        let repository = Arc::new(RepositoryProviderV1::new(&workspace)?);
        let repository_controlled: Arc<dyn UpstreamProvider> =
            Arc::new(GatewayControlledProviderV1::new_with_observed_workspace(
                repository,
                workspace.clone(),
                observed_workspace.clone(),
                Arc::clone(&store),
                Some(Arc::clone(&context_coordinator)),
                reuse_mode,
            ));
        let git = Arc::new(GitProviderV1::new(&workspace)?);
        let git_controlled: Arc<dyn UpstreamProvider> =
            Arc::new(GatewayControlledProviderV1::new_with_observed_workspace(
                git,
                workspace.clone(),
                observed_workspace.clone(),
                Arc::clone(&store),
                Some(Arc::clone(&context_coordinator)),
                reuse_mode,
            ));
        let task_context: Arc<dyn UpstreamProvider> = Arc::new(LocalContextProviderV1::new(
            ContextProviderKindV1::Task,
            Arc::clone(&context_coordinator),
        ));
        let shared_context: Arc<dyn UpstreamProvider> = Arc::new(LocalContextProviderV1::new(
            ContextProviderKindV1::Context,
            Arc::clone(&context_coordinator),
        ));
        let gateway = McpGateway::new(
            vec![
                ProviderRegistration::trusted_annotations(repository_controlled),
                ProviderRegistration::trusted_annotations(git_controlled),
                ProviderRegistration::trusted_annotations(task_context),
                ProviderRegistration::trusted_annotations(shared_context),
            ],
            GatewayLimits::default(),
        )?
        .with_delivery_confirmation_sink(Arc::new(StoreDeliveryConfirmationSinkV1 {
            store: Arc::clone(&store),
        }))
        .with_recipient_lifecycle_sink_v1(context_coordinator);
        Ok(Self { gateway, store })
    }

    pub fn gateway(&self) -> &McpGateway {
        &self.gateway
    }

    pub fn stats(&self) -> Result<GatewayStats> {
        self.store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .gateway_stats()
    }

    pub fn serve_stdio(&self, authorization_scope: &AuthorizationScopeId) -> io::Result<()> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut writer = io::stdout();
        self.serve_io(&mut reader, &mut writer, authorization_scope)
    }

    /// Serve one already-authenticated byte transport. This is crate-private
    /// because transport peer authentication and workspace binding must happen
    /// before MCP can observe or mutate gateway-owned connection state.
    pub(crate) fn serve_io<R: std::io::BufRead, W: std::io::Write + Send>(
        &self,
        reader: &mut R,
        writer: &mut W,
        authorization_scope: &AuthorizationScopeId,
    ) -> io::Result<()> {
        self.gateway.serve_stdio(
            reader,
            writer,
            authorization_scope,
            EphemeralSecrets::default(),
        )
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn serve_authenticated_io<R: std::io::BufRead, W: std::io::Write + Send>(
        &self,
        reader: &mut R,
        writer: &mut W,
        authorization_scope: &AuthorizationScopeId,
        recipient: crate::mcp_gateway::AuthenticatedStdioRecipientV1,
    ) -> io::Result<()> {
        self.gateway.serve_stdio_for_local_recipient_v1(
            reader,
            writer,
            authorization_scope,
            EphemeralSecrets::default(),
            recipient,
        )
    }
}

fn resolve_repository_request_v1(
    execution_epoch: &WorkspaceExecutionEpochV1,
    observed_manifest: &mut ObservedManifestV1,
    call: &ProviderCall,
    operation: RepositoryOperationV1,
) -> Result<ResolvedRequestV1> {
    let limits = gateway_workspace_limits_v1();
    let workspace = execution_epoch.canonical_workspace();
    let observation_plan =
        repository_tools::observation_plan_v1(execution_epoch, &call.arguments, operation)?;
    let repository = observed_manifest
        .observe_repository(&observation_plan)
        .map_err(|_| anyhow!("repository state is incomplete"))?;
    if operation.is_git()
        && !matches!(
            repository.git_state(),
            RepositoryGitStateV1::Git { worktree_root, .. }
                if worktree_root == repository.canonical_workspace()
        )
    {
        bail!("Git tools require the exact workspace to be a Git worktree root");
    }

    let mut exclusions = vec![
        (
            StateDimensionV1::Kernel,
            b"closed repository tools make no kernel-version-dependent query".to_vec(),
        ),
        (
            StateDimensionV1::EnvironmentValues,
            b"closed repository tools read no ambient environment value".to_vec(),
        ),
    ];
    if !operation.is_git() {
        exclusions.push((
            StateDimensionV1::Executables,
            b"closed in-process repository tools execute no child binary".to_vec(),
        ));
    }
    let relevance = EnvironmentRelevanceProofV1::from_exclusions(exclusions, &limits)
        .map_err(|_| anyhow!("environment relevance is incomplete"))?;
    let mut environment_plan = EnvironmentObservationPlanV1::new()
        .with_operating_system()
        .with_architecture()
        .with_cwd(workspace)
        .with_resource_profile_id("bounded-repository-observation-v1")
        .with_sandbox_backend_id("host-read-only-provider-v1")
        .with_mcp_identity(McpIdentityV1::new(
            call.translation.provider_identity(),
            call.translation.tool_schema_identity(),
        ))
        .with_authorization_scope_identifier(
            call.translation.authorization_scope_identity().as_bytes(),
            &limits,
        )
        .map_err(|_| anyhow!("authorization scope is incomplete"))?
        .with_relevance_proof(relevance);
    if operation.is_git() {
        let executable = ExecutableObservationRequestV1::new(
            "git",
            "/usr/bin/git",
            b"again.read-only-git-provider.v1",
            &limits,
        )
        .map_err(|_| anyhow!("Git executable identity is incomplete"))?;
        environment_plan = environment_plan.with_executable(executable);
    }
    let environment = observe_environment_v1(&environment_plan, &limits)
        .map_err(|_| anyhow!("environment state is incomplete"))?;

    let task = TaskStateV1::from_input(
        TaskStateInputV1 {
            task_id: "task-independent-repository-observation-v1".to_owned(),
            task_revision: 1,
            user_goal_digest: StateDigestV1::from_domain_and_bytes(
                b"again.gateway.task-goal.v1",
                b"return the exact repository observation requested by the MCP call",
            ),
            accepted_constraints_digest: StateDigestV1::from_domain_and_bytes(
                b"again.gateway.task-constraints.v1",
                b"read-only, root-confined, bounded, deterministic",
            ),
            branch_identity: "repository-state-bound".to_owned(),
            worktree_identity: repository.workspace_identity_digest().to_hex(),
            patch_digest: repository.digest(),
            plan_revision: 1,
            compaction_epoch: 0,
        },
        &limits,
    )
    .map_err(|_| anyhow!("task state is incomplete"))?;
    let no_external = issue_no_external_dependencies_v1(
        b"again.repository-provider.v1 schemas have no external dependency",
        &limits,
    )
    .map_err(|_| anyhow!("external state is incomplete"))?;
    let complete = CompleteToolStateV1::new(
        repository.clone(),
        environment.clone(),
        task,
        ExternalFreshnessV1::no_external_dependencies(no_external),
    );
    let complete_digest = complete.digest().to_hex();
    let repository_digest = repository.digest().to_hex();
    let environment_digest = environment.digest().to_hex();
    let translation_digest = call
        .translation
        .canonical_digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let core_call = GatewayToolCallV1::from_input(GatewayToolCallInputV1 {
        schema_version: 1,
        provider: ProviderIdentityV1 {
            id: call.translation.provider_identity().to_owned(),
            version: call.freshness.revision.clone(),
        },
        model: ModelIdentityV1 {
            id: "mcp-agent".to_owned(),
            version: "task-independent-read-v1".to_owned(),
        },
        tool: ToolIdentityV1 {
            id: call.translation.namespaced_tool_name().to_owned(),
            version: call.translation.tool_schema_identity().to_owned(),
        },
        arguments: CanonicalArguments::from_json_slice(call.translation.canonical_arguments())?,
        workspace: WorkspaceIdentityV1 {
            workspace_id: repository.workspace_identity_digest().to_hex(),
            cwd: repository
                .canonical_workspace()
                .to_string_lossy()
                .into_owned(),
        },
        call: AgentCallIdentityV1 {
            agent_id: "shared-exact-repository-read".to_owned(),
            session_id: "state-bound".to_owned(),
            turn_id: "task-independent".to_owned(),
            call_id: translation_digest,
        },
        task: Some(TaskIdentityV1 {
            task_id: "repository-observation".to_owned(),
            version: complete_digest.clone(),
        }),
        state: RepositoryEnvironmentStateV1::Known {
            reference: StateDigestReferenceV1 {
                schema_version: 1,
                repository: DigestReferenceV1::new("blake3", repository_digest)?,
                environment: DigestReferenceV1::new("blake3", environment_digest)?,
            },
        },
        permission_class: PermissionClass::Preapproved,
        effect_class: CoreEffectClass::SnapshotRead,
        freshness: FreshnessRequirementV1::Snapshot,
        presentation: PresentationMode::Exact,
    })?;
    let mut dependencies = repository
        .observations()
        .iter()
        .map(|observation| {
            let kind = match observation.kind() {
                RepositoryObservationKindV1::ContentPath => b"content".as_slice(),
                RepositoryObservationKindV1::RecursiveTree => b"tree".as_slice(),
                RepositoryObservationKindV1::SourceTree => b"source-tree".as_slice(),
                RepositoryObservationKindV1::DirectoryListing => b"listing".as_slice(),
                RepositoryObservationKindV1::NegativeDependency => b"negative".as_slice(),
            };
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"again.gateway.dependency-key.v1\0");
            hasher.update(kind);
            hasher.update(observation.path().as_os_str().as_encoded_bytes());
            GatewayDependencyV1 {
                key_digest: hasher.finalize().to_hex().to_string(),
                value_digest: observation.digest().to_hex(),
            }
        })
        .collect::<Vec<_>>();
    dependencies.sort_by(|left, right| left.key_digest.cmp(&right.key_digest));
    let now = now_millis_i64_v1();
    let binding = ValidatedGatewayReadV1::validate(GatewayCoordinatorInputV1 {
        request_digest: core_call.request_digest().as_str().to_owned(),
        state_digest: complete_digest,
        policy_digest: gateway_policy_digest(POLICY_VERSION_V1),
        operation: GatewayOperationDispositionV1::ReplayEligibleRead,
        freshness: GatewayFreshnessEvidenceV1 {
            snapshot_digest: complete.digest().to_hex(),
            observed_at_ms: now,
            valid_until_ms: now.saturating_add(60_000),
        },
        dependencies,
    })?;
    Ok(ResolvedRequestV1 {
        core_call,
        binding,
        observation_plan,
    })
}

fn attach_result_reference_v1(
    mut value: Value,
    gateway_result_id: &str,
    result: &crate::store::StoredResult,
    reasoning_token: Option<&str>,
) -> Value {
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    if let Some(reasoning_token) = reasoning_token {
        object.insert(
            INTERNAL_REASONING_CONTEXT_TOKEN_V1.to_owned(),
            Value::String(reasoning_token.to_owned()),
        );
    }
    let metadata = object
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(metadata) = metadata.as_object_mut() else {
        return value;
    };
    metadata.insert(
        "again".to_owned(),
        json!({
            "experimental": true,
            "resultId": gateway_result_id,
            "fullRetrievalAvailable": false,
            "delivery": {
                "resultDigest": gateway_result_id,
                "exactStatus": result.exit_code,
                "stdoutDigest": result.stdout_digest,
                "stdoutBytes": result.stdout_bytes,
                "stderrDigest": result.stderr_digest,
                "stderrBytes": result.stderr_bytes
            }
        }),
    );
    value
}

fn take_reasoning_context_v1(value: &mut Value) -> Option<String> {
    value
        .as_object_mut()?
        .remove(INTERNAL_REASONING_CONTEXT_TOKEN_V1)?
        .as_str()
        .map(str::to_owned)
}

fn reasoning_context_for_result_v1(
    store: &Store,
    workspace: &Path,
    resolved: &ResolvedRequestV1,
    call: &ProviderCall,
) -> Result<Option<ReasoningBriefInputV1>> {
    let mut identity_hasher = blake3::Hasher::new();
    identity_hasher.update(b"again.reasoning.workspace-identity.v1\0");
    identity_hasher.update(workspace.as_os_str().as_encoded_bytes());
    let workspace_identity = identity_hasher.finalize().to_hex().to_string();
    let scope = ReasoningScopeV1::new(
        resolved.binding.request_digest(),
        &format!("repository:{}", &workspace_identity[..24]),
        &format!("workspace:{}", &workspace_identity[..24]),
        resolved.binding.state_digest(),
        &resolved.binding.dependency_digest(),
        &authorization_scope_digest_v1(&call.authorization_scope),
    )
    .map_err(|reason| anyhow!(reason.code()))?;
    // This placeholder is never delivered. The authenticated transport
    // replaces it before compilation, keeping recipient identity outside the
    // provider and out of repository result metadata.
    let placeholder_recipient = ReasoningRecipientV1::new(
        "pending-agent",
        "pending-session",
        "pending-turn",
        &delivery_context_digest_v1(call),
        0,
        1,
    )
    .map_err(|reason| anyhow!(reason.code()))?;
    let query = GatewayReasoningContextQueryV1::new(
        scope,
        placeholder_recipient,
        resolved.binding.clone(),
    )?;
    store.reasoning_context_v1(&query).map(Some)
}

fn delivery_context_digest_v1(call: &ProviderCall) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.reasoning.pending-delivery.v1\0");
    hasher.update(call.logical_call_id.as_str().as_bytes());
    hasher.update(&call.physical_attempt_id.get().to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

fn delivery_capture_v1(value: &Value) -> Option<(String, String, DeliveryStreamsV1)> {
    let again = value.get("_meta")?.get("again")?.as_object()?;
    let gateway_result_id = again.get("resultId")?.as_str()?.to_owned();
    let delivery = again.get("delivery")?.as_object()?;
    let result_digest = delivery.get("resultDigest")?.as_str()?.to_owned();
    let exact_status = i32::try_from(delivery.get("exactStatus")?.as_i64()?).ok()?;
    let stdout_digest = delivery.get("stdoutDigest")?.as_str()?;
    let stdout_bytes = delivery.get("stdoutBytes")?.as_u64()?;
    let stderr_digest = delivery.get("stderrDigest")?.as_str()?;
    let stderr_bytes = delivery.get("stderrBytes")?.as_u64()?;
    let streams = DeliveryStreamsV1::new(
        exact_status,
        stdout_digest,
        stdout_bytes,
        stderr_digest,
        stderr_bytes,
    )
    .ok()?;
    Some((gateway_result_id, result_digest, streams))
}

fn canonical_json_bytes_v1(value: &Value) -> Vec<u8> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            Value::Object(values) => {
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                let mut object = Map::new();
                for key in keys {
                    object.insert(key.clone(), sorted(&values[key]));
                }
                Value::Object(object)
            }
            value => value.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).expect("JSON values are serializable")
}

fn path_text_v1(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        path.to_string_lossy().replace('\\', "/")
    }
}

fn now_millis_i64_v1() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn invalid_arguments_v1(error: impl std::fmt::Display) -> ProviderError {
    let _ = error;
    ProviderError::gateway_authored(
        McpError::typed(
            McpErrorCode::InvalidParams,
            "invalid repository tool arguments",
        )
        .with_data(json!({
            "reason": "invalid_repository_arguments",
            "hint": "Check this tool's inputSchema from tools/list"
        })),
    )
}

fn provider_io_v1(error: impl std::fmt::Display) -> ProviderError {
    let _ = error;
    ProviderError::gateway_authored(
        McpError::typed(McpErrorCode::InternalError, "repository observation failed").with_data(
            json!({
                "reason": "repository_observation_failed",
                "retryable": true
            }),
        ),
    )
}

fn context_authority_failed_v1() -> ProviderError {
    ProviderError::gateway_authored(
        McpError::typed(
            McpErrorCode::InternalError,
            "verified context authority check failed",
        )
        .with_data(json!({
            "reason": "context_authority_failed",
            "retryable": true
        })),
    )
}

fn cancelled_provider_error_v1() -> ProviderError {
    ProviderError::gateway_authored(
        McpError::typed(McpErrorCode::RequestCancelled, "gateway call cancelled")
            .with_data(json!({ "reason": "gateway_call_cancelled" })),
    )
}

#[cfg(test)]
mod product_tests {
    use std::process::Command;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;

    use super::*;
    use crate::mcp_gateway::{GatewayRequestContext, LogicalCallId};

    struct SlowRepositoryProviderV1 {
        executions: AtomicUsize,
    }

    impl ToolDiscovery for SlowRepositoryProviderV1 {
        fn descriptor(&self) -> ProviderDescriptor {
            ProviderDescriptor {
                id: REPOSITORY_PROVIDER_ID_V1.to_owned(),
                implementation: REPOSITORY_PROVIDER_IMPLEMENTATION_V1.to_owned(),
                version: "test-v1".to_owned(),
                endpoint_identity: "test://repository".to_owned(),
            }
        }

        fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
            Ok(vec![ProviderTool::new(
                "read",
                json!({
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"],
                    "additionalProperties": false
                }),
            )])
        }
    }

    impl FreshnessMetadata for SlowRepositoryProviderV1 {
        fn freshness(&self) -> Freshness {
            Freshness {
                revision: "test-state-v1".to_owned(),
                observed_at_unix_ms: None,
            }
        }
    }

    impl SideEffectClassification for SlowRepositoryProviderV1 {
        fn classify_effect(&self, _upstream_tool_name: &str) -> EffectClass {
            EffectClass::ReadOnly
        }
    }

    impl StructuredResultCapture for SlowRepositoryProviderV1 {
        fn capture_result(&self, result: Value) -> Result<CapturedToolResult, ProviderError> {
            Ok(CapturedToolResult::exact(result))
        }
    }

    impl ToolCancellation for SlowRepositoryProviderV1 {
        fn cancel(&self, _cancellation: ProviderCancellation) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    impl ToolExecution for SlowRepositoryProviderV1 {
        fn execute(
            &self,
            _call: ProviderCall,
            _secrets: EphemeralSecrets<'_>,
        ) -> Result<Value, ProviderError> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(100));
            Ok(json!({
                "content": [{ "type": "text", "text": "same" }],
                "structuredContent": { "value": "same" }
            }))
        }
    }

    impl RepositoryEpochProviderV1 for SlowRepositoryProviderV1 {
        fn execute_with_epoch(
            &self,
            _epoch: &WorkspaceExecutionEpochV1,
            call: ProviderCall,
            secrets: EphemeralSecrets<'_>,
        ) -> Result<Value, ProviderError> {
            self.execute(call, secrets)
        }
    }

    fn context(id: &str) -> GatewayRequestContext {
        context_with_scope(id, "shared-repository-scope")
    }

    fn context_with_scope(id: &str, scope: &str) -> GatewayRequestContext {
        GatewayRequestContext::new(
            AuthorizationScopeId::new(scope).unwrap(),
            LogicalCallId::new(id).unwrap(),
        )
    }

    fn process(gateway: &McpGateway, id: &str, frame: &[u8]) -> Value {
        serde_json::from_slice(
            &gateway
                .process_bytes(frame, &context(id), EphemeralSecrets::default())
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn diagnostic_execute_only_mode_preserves_results_without_reuse() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"same\n").unwrap();
        let gateway = ExperimentalMcpGatewayV1::build_execute_only_v1(workspace.path()).unwrap();
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        let initialized = process(gateway.gateway(), "init", initialize);
        assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
        let read = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#;
        let first = process(gateway.gateway(), "first", read);
        let second = process(gateway.gateway(), "second", read);
        assert_eq!(first["result"]["content"][0]["text"], "same\n");
        assert_eq!(first["result"], second["result"]);
        let stats = gateway.stats().unwrap();
        assert_eq!(stats.requested, 2);
        assert_eq!(stats.executed, 2);
        assert_eq!(stats.exact_hits, 0);
    }

    #[test]
    fn automatic_mode_executes_repository_reads_without_a_shared_task() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"same\n").unwrap();
        let gateway = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        process(gateway.gateway(), "init", initialize);
        let read = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#;
        let first = process(gateway.gateway(), "first", read);
        let second = process(gateway.gateway(), "second", read);
        assert_eq!(first["result"], second["result"]);
        assert_eq!(first["result"]["content"][0]["text"], "same\n");
        let search = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"repo.search","arguments":{"path":".","pattern":"same"}}}"#;
        let first_search = process(gateway.gateway(), "first-search", search);
        let second_search = process(gateway.gateway(), "second-search", search);
        assert_eq!(first_search["result"], second_search["result"]);
        let stats = gateway.stats().unwrap();
        assert_eq!(stats.requested, 4);
        assert_eq!(stats.executed, 4);
        assert_eq!(stats.exact_hits, 0);
    }

    #[test]
    fn automatic_mode_executes_large_standalone_git_status_directly() {
        let workspace = TempDir::new().unwrap();
        let git = |arguments: &[&str]| {
            assert!(
                Command::new("git")
                    .args(arguments)
                    .current_dir(workspace.path())
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .status()
                    .unwrap()
                    .success()
            );
        };
        git(&["init", "--quiet"]);
        for index in 0..250 {
            fs::write(
                workspace.path().join(format!("file_{index:04}.txt")),
                b"x\n",
            )
            .unwrap();
        }
        git(&["add", "."]);
        assert!(
            fs::metadata(workspace.path().join(".git/index"))
                .unwrap()
                .len()
                >= STANDALONE_GIT_STATUS_DIRECT_INDEX_BYTES_V1
        );
        git(&[
            "-c",
            "user.name=Again Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ]);
        let gateway = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        process(gateway.gateway(), "init", initialize);
        let status = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"git.status","arguments":{}}}"#;
        let first = process(gateway.gateway(), "first", status);
        let second = process(gateway.gateway(), "second", status);
        assert_eq!(first["result"], second["result"]);
        let stats = gateway.stats().unwrap();
        assert_eq!(stats.requested, 2);
        assert_eq!(stats.executed, 2);
        assert_eq!(stats.exact_hits, 0);
    }

    #[test]
    fn concurrent_sessions_execute_once_and_join_exact_inflight_call() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"same").unwrap();
        let state = TempDir::new().unwrap();
        let store = Arc::new(Mutex::new(Store::open(state.path().join("store")).unwrap()));
        let upstream = Arc::new(SlowRepositoryProviderV1 {
            executions: AtomicUsize::new(0),
        });
        let controlled: Arc<dyn UpstreamProvider> = Arc::new(
            GatewayControlledProviderV1::new(
                upstream.clone(),
                fs::canonicalize(workspace.path()).unwrap(),
                Arc::clone(&store),
            )
            .unwrap(),
        );
        let gateway = Arc::new(
            McpGateway::new(
                vec![ProviderRegistration::trusted_annotations(controlled)],
                GatewayLimits::default(),
            )
            .unwrap(),
        );
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        assert!(
            gateway
                .process_bytes(initialize, &context("init"), EphemeralSecrets::default())
                .is_some()
        );
        let calls: [&'static [u8]; 2] = [
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#,
            br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#,
        ];
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for (id, call) in ["agent-a", "agent-b"].into_iter().zip(calls) {
            let gateway = Arc::clone(&gateway);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                gateway
                    .process_bytes(call, &context(id), EphemeralSecrets::default())
                    .unwrap()
            }));
        }
        barrier.wait();
        let first: Value = serde_json::from_slice(&workers.remove(0).join().unwrap()).unwrap();
        let second: Value = serde_json::from_slice(&workers.remove(0).join().unwrap()).unwrap();
        assert_eq!(first["result"], second["result"]);
        assert_eq!(upstream.executions.load(Ordering::SeqCst), 1);
        let stats = store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .gateway_stats()
            .unwrap();
        assert_eq!(stats.requested, 2);
        assert_eq!(stats.executed, 1);
        assert_eq!(stats.inflight_joins, 1);
    }

    #[test]
    fn exact_dependency_proof_invalidates_only_relevant_repository_mutations() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"first").unwrap();
        fs::write(workspace.path().join("other.txt"), b"unrelated").unwrap();
        let gateway = ExperimentalMcpGatewayV1::build_force_reuse_v1(workspace.path()).unwrap();
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        process(gateway.gateway(), "init", initialize);
        let call = |id: u8| {
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"repo.read\",\"arguments\":{{\"path\":\"input.txt\"}}}}}}"
            )
        };
        let first = process(gateway.gateway(), "first", call(2).as_bytes());
        let exact = process(gateway.gateway(), "second", call(3).as_bytes());
        assert_eq!(first["result"], exact["result"]);
        assert_eq!(gateway.stats().unwrap().executed, 1);
        assert_eq!(gateway.stats().unwrap().exact_hits, 1);

        fs::write(workspace.path().join("other.txt"), b"changed elsewhere").unwrap();
        let irrelevant = process(gateway.gateway(), "third", call(4).as_bytes());
        assert_eq!(first["result"], irrelevant["result"]);
        assert_eq!(gateway.stats().unwrap().executed, 1);
        assert_eq!(gateway.stats().unwrap().exact_hits, 2);

        fs::write(workspace.path().join("input.txt"), b"second").unwrap();
        let relevant = process(gateway.gateway(), "fourth", call(5).as_bytes());
        assert_ne!(first["result"], relevant["result"]);
        assert_eq!(relevant["result"]["content"][0]["text"], "second");
        assert_eq!(gateway.stats().unwrap().executed, 2);
    }

    #[test]
    fn one_gateway_manifest_shares_nodes_and_invalidates_cross_tool_results() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"needle one").unwrap();
        let state = TempDir::new().unwrap();
        let store = Arc::new(Mutex::new(Store::open(state.path().join("store")).unwrap()));
        let repository = Arc::new(RepositoryProviderV1::new(workspace.path()).unwrap());
        let controlled = Arc::new(
            GatewayControlledProviderV1::new(
                repository,
                fs::canonicalize(workspace.path()).unwrap(),
                Arc::clone(&store),
            )
            .unwrap(),
        );
        let registered: Arc<dyn UpstreamProvider> = controlled.clone();
        let gateway = McpGateway::new(
            vec![ProviderRegistration::trusted_annotations(registered)],
            GatewayLimits::default(),
        )
        .unwrap();
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        process(&gateway, "init-shared-manifest", initialize);
        let read = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#;
        let search = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"repo.search","arguments":{"pattern":"needle"}}}"#;
        process(&gateway, "manifest-read", read);
        process(&gateway, "manifest-search", search);

        let before = controlled
            .observed_workspace
            .manifest
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .accounting();
        assert_eq!(before.physical_content_hashes(), 1);
        assert!(before.node_reuse_hits() >= 1);
        assert!(before.dependent_count() >= 4);

        fs::write(workspace.path().join("input.txt"), b"needle two").unwrap();
        process(&gateway, "manifest-search-after-mutation", search);
        let after = controlled
            .observed_workspace
            .manifest
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .accounting();
        assert_eq!(after.physical_content_hashes(), 2);
        assert_eq!(after.epoch_advancements(), 1);
        assert_eq!(after.invalidation_events(), 1);
        assert!(after.invalidated_dependents() >= 4);
    }

    #[test]
    fn task_start_requires_transport_authenticated_recipient_authority() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"same").unwrap();
        let gateway = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        process(gateway.gateway(), "context-init", initialize);
        let start = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"task.start","arguments":{"taskId":"task"}}}"#;
        let response = process(gateway.gateway(), "context-start", start);
        assert_eq!(
            response["error"]["data"]["reason"],
            "recipient_authority_required"
        );
    }

    #[test]
    fn warm_preload_is_partitioned_by_authorization_scope() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"same").unwrap();
        let state = TempDir::new().unwrap();
        let store = Arc::new(Mutex::new(Store::open(state.path().join("store")).unwrap()));
        let repository = Arc::new(RepositoryProviderV1::new(workspace.path()).unwrap());
        let controlled = Arc::new(
            GatewayControlledProviderV1::new(
                repository,
                fs::canonicalize(workspace.path()).unwrap(),
                Arc::clone(&store),
            )
            .unwrap(),
        );
        let registered: Arc<dyn UpstreamProvider> = controlled.clone();
        let gateway = McpGateway::new(
            vec![ProviderRegistration::trusted_annotations(registered)],
            GatewayLimits::default(),
        )
        .unwrap();
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        assert!(
            gateway
                .process_bytes(
                    initialize,
                    &context_with_scope("init", "scope-a"),
                    EphemeralSecrets::default(),
                )
                .is_some()
        );
        let call = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#;
        for (id, scope) in [
            ("a-cold", "scope-a"),
            ("b-cold", "scope-b"),
            ("a-warm", "scope-a"),
        ] {
            assert!(
                gateway
                    .process_bytes(
                        call,
                        &context_with_scope(id, scope),
                        EphemeralSecrets::default(),
                    )
                    .is_some()
            );
        }
        let stats = store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .gateway_stats()
            .unwrap();
        assert_eq!(stats.executed, 2);
        assert_eq!(stats.exact_hits, 1);
        assert_eq!(
            controlled
                .recent_candidates
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .len(),
            2
        );
    }

    #[test]
    fn cancellation_releases_the_coordinator_lease_for_a_fresh_attempt() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("input.txt"), b"same").unwrap();
        let state = TempDir::new().unwrap();
        let store = Arc::new(Mutex::new(Store::open(state.path().join("store")).unwrap()));
        let upstream = Arc::new(SlowRepositoryProviderV1 {
            executions: AtomicUsize::new(0),
        });
        let controlled: Arc<dyn UpstreamProvider> = Arc::new(
            GatewayControlledProviderV1::new(
                upstream.clone(),
                fs::canonicalize(workspace.path()).unwrap(),
                Arc::clone(&store),
            )
            .unwrap(),
        );
        let gateway = Arc::new(
            McpGateway::new(
                vec![ProviderRegistration::trusted_annotations(controlled)],
                GatewayLimits::default(),
            )
            .unwrap(),
        );
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        process(&gateway, "init", initialize);
        let worker_gateway = Arc::clone(&gateway);
        let worker = thread::spawn(move || {
            process(
                &worker_gateway,
                "cancelled-leader",
                br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#,
            )
        });
        while upstream.executions.load(Ordering::SeqCst) == 0 {
            thread::yield_now();
        }
        assert!(
            gateway
                .process_bytes(
                    br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}"#,
                    &context("cancel-request"),
                    EphemeralSecrets::default(),
                )
                .is_none()
        );
        let cancelled = worker.join().unwrap();
        assert_eq!(
            cancelled["error"]["code"],
            McpErrorCode::RequestCancelled as i64
        );
        let retry = process(
            &gateway,
            "retry",
            br#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"repo.read","arguments":{"path":"input.txt"}}}"#,
        );
        assert!(retry.get("result").is_some());
        assert_eq!(upstream.executions.load(Ordering::SeqCst), 2);
        let stats = store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .gateway_stats()
            .unwrap();
        assert_eq!(stats.executed, 2);
        assert_eq!(stats.inflight_joins, 0);
    }
}
