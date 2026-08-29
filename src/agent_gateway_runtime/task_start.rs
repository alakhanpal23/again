//! Workspace-bound deterministic task-start provider and edit-brief assembly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use super::context_compiler::{compile_edit_brief_v1, contains_sensitive_reasoning_content_v1};
use super::{
    LoadedGatewayResultV1, RepositoryEpochProviderV1, ResolvedRequestV1, TASK_START_PROVIDER_ID_V1,
    TASK_START_PROVIDER_IMPLEMENTATION_V1, delivery_context_digest_v1, gateway_workspace_limits_v1,
    path_text_v1, provider_io_v1, repository_tools,
};
use crate::agent_gateway::context::{
    EditBriefInputV1, EditValidationDispositionV1, EditValidationPreviewV1,
    InvalidatedReasoningFactV1, ReasoningContextRefusalV1, ReasoningFactScopeV1, ReasoningFactV1,
    ReasoningInvalidationV1, ReasoningRecipientV1, ReasoningRouteDecisionV1, ReasoningScopeV1,
    ReasoningSourceReferenceV1, ReasoningUnknownV1, SuggestedReasoningToolCallV1,
};
use crate::mcp_gateway::{
    CapturedToolResult, EffectClass, EphemeralSecrets, Freshness, FreshnessMetadata, McpError,
    McpErrorCode, OpaqueReasoningAcknowledgmentV1, PreparedReasoningContextV1, ProviderCall,
    ProviderCancellation, ProviderDescriptor, ProviderError, ProviderTool,
    ReasoningContextCandidateV1, ReasoningDeliveryCompletionV1, ReasoningTransportPresentationV1,
    ReasoningTransportRecipientV1, ReasoningTransportScopeV1, SideEffectClassification,
    StructuredResultCapture, ToolCancellation, ToolDiscovery, ToolExecution,
    authorization_scope_digest_v1,
};
use crate::store::{
    DependencyChangeReportV1, DependencyChangeStateV1, GatewayReasoningContextQueryV1, Store,
};
use crate::workspace_authority::{
    RepositoryNodeKindV1, RepositoryObservationPlanV1, WorkspaceExecutionEpochV1,
};

const INTERNAL_SNAPSHOT_FIELD_V1: &str = "__again_internal_task_start_snapshot_v1";
const INTERNAL_ERROR_FIELD_V1: &str = "__again_internal_task_start_error_v1";
const MAX_TASK_BYTES_V1: usize = 2 * 1024;
const MAX_CONSTRAINTS_V1: usize = 16;
const MAX_CONSTRAINT_BYTES_V1: usize = 512;
const MAX_CHANGED_PATHS_V1: usize = 32;
const MAX_CHANGED_PATH_BYTES_V1: usize = 512;
const MAX_VALIDATION_INTENT_BYTES_V1: usize = 512;
const MAX_ENTRY_POINTS_V1: usize = 8;
pub(super) const MAX_DEPENDENCY_REPORT_RESULTS_V1: usize = 16;
const MAX_DEPENDENCY_INVALIDATIONS_V1: usize = 8;
const REPOSITORY_TOOL_CALLS_DISPLACED_V1: u64 = 2;

const MANIFEST_PATHS_V1: [&str; 6] = [
    "Cargo.toml",
    "go.mod",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "tsconfig.json",
];

const CONVENTIONAL_ENTRY_PATHS_V1: [&str; 10] = [
    "src/lib.rs",
    "src/main.rs",
    "src/index.ts",
    "src/index.js",
    "src/app.py",
    "lib.rs",
    "main.rs",
    "main.go",
    "app.py",
    "index.js",
];

#[derive(Clone)]
struct TaskStartInputV1 {
    task: String,
    constraints: Vec<String>,
    changed_paths: Vec<PathBuf>,
    validation_intent: Option<String>,
}

#[derive(Clone, Copy)]
pub(super) struct TaskStartFailureV1 {
    code: &'static str,
}

impl TaskStartFailureV1 {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
}

pub(super) fn unavailable_v1(reason: &'static str) -> ProviderError {
    ProviderError::gateway_authored(
        McpError::typed(
            McpErrorCode::InternalError,
            "deterministic task-start context is unavailable",
        )
        .with_data(json!({ "reason": reason })),
    )
}

fn invalid_input_v1(reason: &'static str) -> ProviderError {
    ProviderError::gateway_authored(
        McpError::typed(McpErrorCode::InvalidParams, "task-start input was refused")
            .with_data(json!({ "reason": reason })),
    )
}

fn limit_input_v1(reason: &'static str) -> ProviderError {
    ProviderError::gateway_authored(
        McpError::typed(
            McpErrorCode::LimitExceeded,
            "task-start input exceeded a hard bound",
        )
        .with_data(json!({ "reason": reason })),
    )
}

pub(super) struct TaskStartProviderV1 {
    workspace: PathBuf,
}

impl TaskStartProviderV1 {
    pub(super) fn new(workspace: &Path) -> Result<Self> {
        let workspace = std::fs::canonicalize(workspace)?;
        if !workspace.is_dir() {
            return Err(anyhow!("task-start workspace is not a directory"));
        }
        Ok(Self { workspace })
    }

    fn execute_with_epoch_v1(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        arguments: &Value,
    ) -> Result<Value, ProviderError> {
        let input = parse_input_v1(arguments)?;
        let snapshot = repository_snapshot_v1(epoch, &input)?;
        Ok(json!({
            "content": [{
                "type": "text",
                "text": "A deterministic, full-delivery edit brief is attached in _meta.again.reasoningContext."
            }],
            "structuredContent": {
                "schemaVersion": 1,
                "mode": "deterministic_local",
                "repositoryToolCallsDisplaced": REPOSITORY_TOOL_CALLS_DISPLACED_V1,
                "externalModelCalls": 0,
                "authority": {
                    "editCorrect": false,
                    "testReusable": false,
                    "compactDelivery": false,
                    "toolReuse": false,
                    "executionReuse": false
                }
            },
            INTERNAL_SNAPSHOT_FIELD_V1: snapshot
        }))
    }
}

impl RepositoryEpochProviderV1 for TaskStartProviderV1 {
    fn execute_with_epoch(
        &self,
        epoch: &WorkspaceExecutionEpochV1,
        call: ProviderCall,
        _secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        self.execute_with_epoch_v1(epoch, &call.arguments)
    }
}

impl ToolDiscovery for TaskStartProviderV1 {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: TASK_START_PROVIDER_ID_V1.to_owned(),
            implementation: TASK_START_PROVIDER_IMPLEMENTATION_V1.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint_identity: "local-workspace-task-start-v1".to_owned(),
        }
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        let mut tool = ProviderTool::new(
            "task_start",
            json!({
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_TASK_BYTES_V1
                    },
                    "constraints": {
                        "type": "array",
                        "maxItems": MAX_CONSTRAINTS_V1,
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_CONSTRAINT_BYTES_V1
                        }
                    },
                    "changedPaths": {
                        "type": "array",
                        "maxItems": MAX_CHANGED_PATHS_V1,
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_CHANGED_PATH_BYTES_V1
                        }
                    },
                    "validationIntent": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_VALIDATION_INTENT_BYTES_V1
                    }
                },
                "required": ["task"],
                "additionalProperties": false
            }),
        );
        tool.title = Some("Start a repository-bound coding task".to_owned());
        tool.description = Some(
            "Call once when beginning or resuming a coding task, before broad repository reads. Returns one bounded deterministic edit brief from the current verified workspace epoch. Use source-backed facts directly, inspect explicit unknowns, and treat suggestions as advisory; the brief never authorizes an edit or skipped validation."
                .to_owned(),
        );
        tool.annotations = Some(json!({
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }));
        Ok(vec![tool])
    }
}

impl FreshnessMetadata for TaskStartProviderV1 {
    fn freshness(&self) -> Freshness {
        Freshness {
            revision: "workspace-task-start-v1".to_owned(),
            observed_at_unix_ms: None,
        }
    }
}

impl SideEffectClassification for TaskStartProviderV1 {
    fn classify_effect(&self, upstream_tool_name: &str) -> EffectClass {
        if upstream_tool_name == "task_start" {
            EffectClass::ReadOnly
        } else {
            EffectClass::Unknown
        }
    }
}

impl StructuredResultCapture for TaskStartProviderV1 {
    fn capture_result(&self, mut result: Value) -> Result<CapturedToolResult, ProviderError> {
        if let Some(reason) = result
            .as_object_mut()
            .and_then(|object| object.remove(INTERNAL_ERROR_FIELD_V1))
            .and_then(|value| value.as_str().map(str::to_owned))
        {
            return Err(unavailable_v1(match reason.as_str() {
                "dependency_evidence_contradictory" => "dependency_evidence_contradictory",
                "dependency_report_truncated" => "dependency_report_truncated",
                "dependency_evidence_malformed" => "dependency_evidence_malformed",
                "task_start_snapshot_malformed" => "task_start_snapshot_malformed",
                _ => "edit_brief_assembly_failed",
            }));
        }
        Ok(CapturedToolResult::exact(result))
    }
}

impl ToolCancellation for TaskStartProviderV1 {
    fn cancel(&self, _cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl ToolExecution for TaskStartProviderV1 {
    fn execute(
        &self,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        let epoch =
            WorkspaceExecutionEpochV1::begin(&self.workspace, &gateway_workspace_limits_v1())
                .map_err(|_| provider_io_v1("descriptor-retained task-start epoch failed"))?;
        <Self as RepositoryEpochProviderV1>::execute_with_epoch(self, &epoch, call, secrets)
    }
}

fn parse_input_v1(arguments: &Value) -> Result<TaskStartInputV1, ProviderError> {
    let object = arguments
        .as_object()
        .ok_or_else(|| invalid_input_v1("task_start_object_required"))?;
    let allowed = BTreeSet::from(["task", "constraints", "changedPaths", "validationIntent"]);
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(invalid_input_v1("task_start_unknown_field"));
    }
    let task = bounded_text_v1(object.get("task"), MAX_TASK_BYTES_V1, "task_text_invalid")?;
    let constraints = bounded_text_list_v1(
        object.get("constraints"),
        MAX_CONSTRAINTS_V1,
        MAX_CONSTRAINT_BYTES_V1,
        "task_constraints_invalid",
    )?;
    let raw_paths = bounded_text_list_v1(
        object.get("changedPaths"),
        MAX_CHANGED_PATHS_V1,
        MAX_CHANGED_PATH_BYTES_V1,
        "task_changed_paths_invalid",
    )?;
    let mut changed_paths = raw_paths
        .iter()
        .map(|path| {
            repository_tools::argument_path_v1(&json!({ "path": path }), false)
                .map_err(|_| invalid_input_v1("task_changed_path_unsafe"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    changed_paths.sort();
    changed_paths.dedup();
    let validation_intent = object
        .get("validationIntent")
        .map(|value| {
            bounded_text_v1(
                Some(value),
                MAX_VALIDATION_INTENT_BYTES_V1,
                "task_validation_intent_invalid",
            )
        })
        .transpose()?;
    let serialized = serde_json::to_vec(arguments)
        .map_err(|_| invalid_input_v1("task_start_canonicalization_failed"))?;
    if contains_sensitive_reasoning_content_v1(&serialized) {
        return Err(invalid_input_v1("task_start_sensitive_content"));
    }
    Ok(TaskStartInputV1 {
        task,
        constraints,
        changed_paths,
        validation_intent,
    })
}

pub(super) fn validate_arguments_v1(arguments: &Value) -> Result<(), ProviderError> {
    parse_input_v1(arguments).map(|_| ())
}

fn bounded_text_v1(
    value: Option<&Value>,
    maximum: usize,
    reason: &'static str,
) -> Result<String, ProviderError> {
    let Some(text) = value.and_then(Value::as_str) else {
        return Err(invalid_input_v1(reason));
    };
    if text.is_empty()
        || text.len() > maximum
        || text
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(if text.len() > maximum {
            limit_input_v1(reason)
        } else {
            invalid_input_v1(reason)
        });
    }
    Ok(text.to_owned())
}

fn bounded_text_list_v1(
    value: Option<&Value>,
    maximum_items: usize,
    maximum_bytes: usize,
    reason: &'static str,
) -> Result<Vec<String>, ProviderError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| invalid_input_v1(reason))?;
    if values.len() > maximum_items {
        return Err(limit_input_v1(reason));
    }
    values
        .iter()
        .map(|value| bounded_text_v1(Some(value), maximum_bytes, reason))
        .collect()
}

pub(super) fn observation_plan_v1(
    epoch: &WorkspaceExecutionEpochV1,
    arguments: &Value,
) -> Result<RepositoryObservationPlanV1> {
    let input = parse_input_v1(arguments).map_err(|_| anyhow!("task-start arguments refused"))?;
    let mut content = Vec::new();
    let mut listings = vec![PathBuf::new()];
    let mut negative = Vec::new();
    let mut source_trees = Vec::new();

    for path in MANIFEST_PATHS_V1
        .iter()
        .chain(CONVENTIONAL_ENTRY_PATHS_V1.iter())
        .map(PathBuf::from)
        .chain(input.changed_paths.iter().cloned())
    {
        match epoch
            .classify_relative(&path)
            .map_err(|_| anyhow!("task-start path classification failed"))?
        {
            RepositoryNodeKindV1::Regular => content.push(path),
            RepositoryNodeKindV1::Directory => listings.push(path),
            RepositoryNodeKindV1::Missing => negative.push(path),
        }
    }
    if epoch
        .classify_relative(Path::new("src"))
        .map_err(|_| anyhow!("task-start source root classification failed"))?
        == RepositoryNodeKindV1::Directory
    {
        source_trees.push(PathBuf::from("src"));
        content.retain(|path| !path.starts_with("src"));
        listings.retain(|path| !path.starts_with("src"));
        negative.retain(|path| !path.starts_with("src"));
    }
    content.sort();
    content.dedup();
    listings.sort();
    listings.dedup();
    negative.sort();
    negative.dedup();
    source_trees.sort();
    source_trees.dedup();
    Ok(
        RepositoryObservationPlanV1::new(content, Vec::new(), listings, negative)
            .with_source_trees(source_trees),
    )
}

fn repository_snapshot_v1(
    epoch: &WorkspaceExecutionEpochV1,
    input: &TaskStartInputV1,
) -> Result<Value, ProviderError> {
    let task_tokens = task_tokens_v1(&input.task);
    let mut candidates: BTreeMap<PathBuf, (u64, &'static str)> = BTreeMap::new();
    let mut changed = Vec::new();
    for path in &input.changed_paths {
        let kind = epoch
            .classify_relative(path)
            .map_err(|_| invalid_input_v1("task_changed_path_unverifiable"))?;
        changed.push(json!({
            "path": path_text_v1(path),
            "state": node_kind_v1(kind),
            "hintOnly": true
        }));
        if kind == RepositoryNodeKindV1::Regular {
            candidates.insert(path.clone(), (u64::MAX, "changed_path"));
        }
    }

    for path in CONVENTIONAL_ENTRY_PATHS_V1.map(PathBuf::from) {
        if epoch
            .classify_relative(&path)
            .map_err(|_| provider_io_v1("task-start entry classification failed"))?
            == RepositoryNodeKindV1::Regular
        {
            candidates.entry(path).or_insert((10_000, "conventional"));
        }
    }

    if epoch
        .classify_relative(Path::new("src"))
        .map_err(|_| provider_io_v1("task-start source root classification failed"))?
        == RepositoryNodeKindV1::Directory
    {
        for file in repository_tools::source_files_v1(epoch, Path::new("src"))? {
            let path = file.relative_path().to_path_buf();
            let path_lower = path_text_v1(&path).to_ascii_lowercase();
            let score = task_tokens
                .iter()
                .filter(|token| path_lower.contains(token.as_str()))
                .count() as u64;
            candidates.entry(path).or_insert((score, "lexical_path"));
        }
    }

    let mut ranked = candidates
        .into_iter()
        .map(|(path, (score, basis))| (std::cmp::Reverse(score), path, basis))
        .collect::<Vec<_>>();
    ranked.sort();
    let entry_points = ranked
        .into_iter()
        .take(MAX_ENTRY_POINTS_V1)
        .map(|(_, path, basis)| {
            json!({
                "path": path_text_v1(&path),
                "locator": format!("{}:1", path_text_v1(&path)),
                "basis": basis
            })
        })
        .collect::<Vec<_>>();

    let mut manifests = Vec::new();
    for path in MANIFEST_PATHS_V1.map(PathBuf::from) {
        if epoch
            .classify_relative(&path)
            .map_err(|_| provider_io_v1("task-start manifest classification failed"))?
            == RepositoryNodeKindV1::Regular
        {
            let bytes = repository_tools::read_file_v1(epoch, &path)?;
            manifests.push(json!({
                "path": path_text_v1(&path),
                "locator": format!("{}:1", path_text_v1(&path)),
                "digest": blake3::hash(&bytes).to_hex().to_string()
            }));
        }
    }
    Ok(json!({
        "schemaVersion": 1,
        "entryPoints": entry_points,
        "manifests": manifests,
        "changedPathObservations": changed,
        "constraintsPresent": !input.constraints.is_empty(),
        "validationIntentPresent": input.validation_intent.is_some(),
        "repositoryToolCallsDisplaced": REPOSITORY_TOOL_CALLS_DISPLACED_V1,
        "externalModelCalls": 0
    }))
}

fn task_tokens_v1(task: &str) -> Vec<String> {
    let mut tokens = task
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| token.len() >= 3)
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    tokens.sort();
    tokens.dedup();
    tokens.truncate(32);
    tokens
}

fn node_kind_v1(kind: RepositoryNodeKindV1) -> &'static str {
    match kind {
        RepositoryNodeKindV1::Regular => "file",
        RepositoryNodeKindV1::Directory => "directory",
        RepositoryNodeKindV1::Missing => "missing",
    }
}

pub(super) fn take_context_for_result_v1(
    store: &Store,
    workspace: &Path,
    resolved: &ResolvedRequestV1,
    call: &ProviderCall,
    loaded: &mut LoadedGatewayResultV1,
    provider_call_avoided: bool,
) -> std::result::Result<Option<Box<dyn ReasoningContextCandidateV1>>, TaskStartFailureV1> {
    let snapshot = loaded
        .value
        .as_object_mut()
        .and_then(|object| object.remove(INTERNAL_SNAPSHOT_FIELD_V1))
        .ok_or_else(|| TaskStartFailureV1::new("task_start_snapshot_malformed"))?;
    let candidate = assemble_context_v1(
        store,
        workspace,
        resolved,
        call,
        &loaded.full,
        &snapshot,
        provider_call_avoided,
    )?;
    Ok(Some(Box::new(candidate)))
}

pub(super) fn attach_failure_v1(value: &mut Value, failure: TaskStartFailureV1) {
    if let Some(object) = value.as_object_mut() {
        object.insert(
            INTERNAL_ERROR_FIELD_V1.to_owned(),
            Value::String(failure.code.to_owned()),
        );
        object.remove(INTERNAL_SNAPSHOT_FIELD_V1);
    }
}

pub(super) struct DirectTaskStartContextV1 {
    brief: Value,
    metrics: Value,
}

pub(super) fn compile_full_context_for_call_v1(
    candidate: Box<dyn ReasoningContextCandidateV1>,
    call: &ProviderCall,
) -> std::result::Result<DirectTaskStartContextV1, TaskStartFailureV1> {
    let authorization_digest = authorization_scope_digest_v1(&call.authorization_scope);
    let scope = candidate.scope();
    if scope.authorization_scope_digest != authorization_digest {
        return Err(TaskStartFailureV1::new(
            "task_start_recipient_binding_failed",
        ));
    }
    let delivery_context = delivery_context_digest_v1(call);
    let recipient = ReasoningTransportRecipientV1 {
        agent_id: format!("task-start-agent-{}", &authorization_digest[..16]),
        session_id: format!("task-start-session-{}", &delivery_context[..16]),
        turn_id: format!("task-start-turn-{}", &delivery_context[16..32]),
        connection_generation: delivery_context,
        compaction_generation: 0,
        lifecycle_generation: call.physical_attempt_id.get(),
    };
    let prepared = candidate
        .compile(&recipient, None)
        .map_err(|_| TaskStartFailureV1::new("edit_brief_assembly_failed"))?;
    if prepared.presentation != ReasoningTransportPresentationV1::Full {
        return Err(TaskStartFailureV1::new(
            "task_start_compact_delivery_refused",
        ));
    }
    Ok(DirectTaskStartContextV1 {
        brief: prepared.brief,
        metrics: prepared.metrics,
    })
}

pub(super) fn attach_full_context_v1(value: &mut Value, context: DirectTaskStartContextV1) {
    let Some(again) = value
        .get_mut("_meta")
        .and_then(|metadata| metadata.get_mut("again"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    again.insert(
        "maturity".to_owned(),
        Value::String("local_alpha".to_owned()),
    );
    again.insert(
        "reasoningContext".to_owned(),
        json!({
            "schemaVersion": 1,
            "presentation": "full",
            "brief": context.brief,
            "metrics": context.metrics
        }),
    );
}

fn assemble_context_v1(
    store: &Store,
    workspace: &Path,
    resolved: &ResolvedRequestV1,
    call: &ProviderCall,
    full: &crate::store::GatewayFullResultV1,
    snapshot: &Value,
    provider_call_avoided: bool,
) -> std::result::Result<RuntimeEditBriefContextV1, TaskStartFailureV1> {
    let mut identity_hasher = blake3::Hasher::new();
    identity_hasher.update(b"again.reasoning.workspace-identity.v1\0");
    identity_hasher.update(workspace.as_os_str().as_encoded_bytes());
    let workspace_identity = identity_hasher.finalize().to_hex().to_string();
    let authorization_digest = authorization_scope_digest_v1(&call.authorization_scope);
    let scope = ReasoningScopeV1::new(
        resolved.binding.request_digest(),
        &format!("repository:{}", &workspace_identity[..24]),
        &format!("workspace:{}", &workspace_identity[..24]),
        resolved.binding.state_digest(),
        &resolved.binding.dependency_digest(),
        &authorization_digest,
    )
    .map_err(context_failure_v1)?;
    let placeholder_recipient = ReasoningRecipientV1::new(
        "pending-agent",
        "pending-session",
        "pending-turn",
        &delivery_context_digest_v1(call),
        0,
        1,
    )
    .map_err(context_failure_v1)?;
    let query = GatewayReasoningContextQueryV1::new(
        scope.clone(),
        placeholder_recipient.clone(),
        resolved.binding.clone(),
    )
    .map_err(|_| TaskStartFailureV1::new("task_start_store_binding_invalid"))?;
    let reasoning = store
        .reasoning_context_v1(&query)
        .map_err(|_| TaskStartFailureV1::new("task_start_store_query_failed"))?;

    let source = ReasoningSourceReferenceV1::new(
        &full.gateway_result_id,
        &full.result.stdout_digest,
        scope.repository_id(),
        scope.workspace_id(),
        scope.state_digest(),
        scope.dependency_digest(),
        scope.authorization_scope_digest(),
        "task-start-snapshot",
    )
    .map_err(context_failure_v1)?;
    let mut known_facts = reasoning.known_facts().to_vec();
    let mut invalidated = reasoning.invalidated_facts().to_vec();
    let mut unknowns = reasoning.explicit_unknowns().to_vec();
    let mut validation = Vec::new();
    let mut suggestions = reasoning.suggested_next_tool_calls().to_vec();

    let entry_points = snapshot
        .get("entryPoints")
        .and_then(Value::as_array)
        .ok_or_else(|| TaskStartFailureV1::new("task_start_snapshot_malformed"))?;
    for entry in entry_points {
        let path = snapshot_string_v1(entry, "path")?;
        let locator = snapshot_string_v1(entry, "locator")?;
        let value_digest = labeled_digest_v1("entry-point", path);
        known_facts.push(
            ReasoningFactV1::new(
                &format!("entry-{}", &value_digest[..16]),
                &format!("repository-entry-point-{}", &value_digest[..16]),
                &format!("verified task entry point: {path}"),
                &value_digest,
                ReasoningFactScopeV1::TaskSpecific,
                Some(scope.task_id()),
                vec![
                    ReasoningSourceReferenceV1::new(
                        source.result_id(),
                        source.result_digest(),
                        source.repository_id(),
                        source.workspace_id(),
                        source.state_digest(),
                        source.dependency_digest(),
                        source.authorization_scope_digest(),
                        locator,
                    )
                    .map_err(context_failure_v1)?,
                ],
            )
            .map_err(context_failure_v1)?,
        );
    }
    let manifests = snapshot
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| TaskStartFailureV1::new("task_start_snapshot_malformed"))?;
    for manifest in manifests {
        let path = snapshot_string_v1(manifest, "path")?;
        let locator = snapshot_string_v1(manifest, "locator")?;
        let digest = snapshot_string_v1(manifest, "digest")?;
        known_facts.push(
            ReasoningFactV1::new(
                &format!("manifest-{}", &digest[..16]),
                &format!("repository-manifest-{}", &digest[..16]),
                &format!("verified repository manifest: {path}"),
                digest,
                ReasoningFactScopeV1::RepositoryWide,
                None,
                vec![
                    ReasoningSourceReferenceV1::new(
                        source.result_id(),
                        source.result_digest(),
                        source.repository_id(),
                        source.workspace_id(),
                        source.state_digest(),
                        source.dependency_digest(),
                        source.authorization_scope_digest(),
                        locator,
                    )
                    .map_err(context_failure_v1)?,
                ],
            )
            .map_err(context_failure_v1)?,
        );
    }

    let changed = snapshot
        .get("changedPathObservations")
        .and_then(Value::as_array)
        .ok_or_else(|| TaskStartFailureV1::new("task_start_snapshot_malformed"))?;
    if changed
        .iter()
        .any(|entry| entry.get("state") == Some(&Value::String("missing".into())))
    {
        unknowns.push(
            ReasoningUnknownV1::new(
                "changed-path-missing",
                "a caller-supplied changed-path hint is absent in the verified workspace epoch",
            )
            .map_err(context_failure_v1)?,
        );
    }
    if entry_points.is_empty() {
        unknowns.push(
            ReasoningUnknownV1::new(
                "task-entry-point",
                "no verified task entry point was selected from the bounded repository observation",
            )
            .map_err(context_failure_v1)?,
        );
        suggestions.push(
            SuggestedReasoningToolCallV1::new(
                "repo",
                "search",
                "inspect only the unresolved task-specific symbol or path",
                ReasoningRouteDecisionV1::ExecuteForUnknown,
            )
            .map_err(context_failure_v1)?,
        );
    }
    if snapshot
        .get("constraintsPresent")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        unknowns.push(
            ReasoningUnknownV1::new(
                "caller-constraints",
                "caller constraints are task input and remain non-authoritative until verified",
            )
            .map_err(context_failure_v1)?,
        );
    }
    validation.push(
        EditValidationPreviewV1::new(
            "task-validation",
            EditValidationDispositionV1::ExecuteRequired,
        )
        .map_err(context_failure_v1)?,
    );
    if snapshot
        .get("validationIntentPresent")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        validation.push(
            EditValidationPreviewV1::new(
                "caller-validation-intent",
                EditValidationDispositionV1::CandidateUnproven,
            )
            .map_err(context_failure_v1)?,
        );
    }

    let mut unknown_dependency_evidence = false;
    let mut dependency_invalidations = 0usize;
    for dependency in resolved.binding.dependencies() {
        let report = store
            .dependency_change_report_v1(
                &authorization_digest,
                resolved.binding.state_digest(),
                &dependency.key_digest,
                MAX_DEPENDENCY_REPORT_RESULTS_V1,
            )
            .map_err(|_| TaskStartFailureV1::new("dependency_evidence_malformed"))?;
        apply_dependency_report_v1(
            &scope,
            dependency,
            report,
            &mut dependency_invalidations,
            &mut invalidated,
            &mut unknown_dependency_evidence,
        )?;
    }
    if unknown_dependency_evidence {
        unknowns.push(
            ReasoningUnknownV1::new(
                "dependency-change-evidence",
                "one or more exact result dependency edges have no immutable change evidence for this epoch",
            )
            .map_err(context_failure_v1)?,
        );
    }

    let current_result = full.gateway_result_id.as_str();
    let before = known_facts.len();
    known_facts.retain(|fact| {
        !fact.sources().is_empty()
            && fact
                .sources()
                .iter()
                .all(|source| source.result_id() == current_result)
    });
    if known_facts.len() != before {
        unknowns.push(
            ReasoningUnknownV1::new(
                "fact-source-resolution",
                "a candidate current fact lacked a resolvable live source and was not presented as current",
            )
            .map_err(context_failure_v1)?,
        );
    }

    let input = EditBriefInputV1::new(
        scope,
        placeholder_recipient,
        known_facts,
        invalidated,
        unknowns,
        reasoning.failed_approaches().to_vec(),
        validation,
        reasoning.completed_observations().to_vec(),
        reasoning.inflight_work().to_vec(),
        suggestions,
        reasoning.route_decisions().to_vec(),
        reasoning.evidence_metrics().clone(),
    );
    Ok(RuntimeEditBriefContextV1 {
        input,
        repository_tool_calls_displaced: snapshot
            .get("repositoryToolCallsDisplaced")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        provider_call_avoided,
    })
}

fn apply_dependency_report_v1(
    scope: &ReasoningScopeV1,
    dependency: &crate::store::GatewayDependencyV1,
    report: DependencyChangeReportV1,
    included: &mut usize,
    invalidated: &mut Vec<InvalidatedReasoningFactV1>,
    unknown: &mut bool,
) -> std::result::Result<(), TaskStartFailureV1> {
    if report.affected_results_truncated {
        return Err(TaskStartFailureV1::new("dependency_report_truncated"));
    }
    match report.state {
        DependencyChangeStateV1::Contradictory => {
            Err(TaskStartFailureV1::new("dependency_evidence_contradictory"))
        }
        DependencyChangeStateV1::Unknown => {
            *unknown = true;
            Ok(())
        }
        DependencyChangeStateV1::Unchanged => Ok(()),
        DependencyChangeStateV1::Changed => {
            if *included >= MAX_DEPENDENCY_INVALIDATIONS_V1 {
                *unknown = true;
                return Ok(());
            }
            let evidence = report
                .evidence
                .first()
                .ok_or_else(|| TaskStartFailureV1::new("dependency_evidence_malformed"))?;
            if evidence.dependency_key_digest != dependency.key_digest
                || evidence.current_dependency_value_digest != dependency.value_digest
            {
                return Err(TaskStartFailureV1::new("dependency_evidence_malformed"));
            }
            let source = ReasoningSourceReferenceV1::new(
                &evidence.record_id,
                &evidence.record_id,
                scope.repository_id(),
                scope.workspace_id(),
                scope.state_digest(),
                scope.dependency_digest(),
                scope.authorization_scope_digest(),
                &format!("dependency-evidence:{}", evidence.record_id),
            )
            .map_err(context_failure_v1)?;
            let affected = report.affected_gateway_result_ids.len();
            let fact = ReasoningFactV1::new(
                &format!("dependency-{}", &dependency.key_digest[..16]),
                "dependency-change",
                &format!("prior dependency evidence affects {affected} exact result(s)"),
                &dependency.value_digest,
                ReasoningFactScopeV1::RepositoryWide,
                None,
                vec![source],
            )
            .map_err(context_failure_v1)?;
            invalidated.push(
                InvalidatedReasoningFactV1::new(
                    fact,
                    ReasoningInvalidationV1::DependencyChanged,
                    Vec::new(),
                )
                .map_err(context_failure_v1)?,
            );
            *included += 1;
            Ok(())
        }
    }
}

fn snapshot_string_v1<'a>(
    value: &'a Value,
    field: &str,
) -> std::result::Result<&'a str, TaskStartFailureV1> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= MAX_CHANGED_PATH_BYTES_V1)
        .ok_or_else(|| TaskStartFailureV1::new("task_start_snapshot_malformed"))
}

fn context_failure_v1(_reason: ReasoningContextRefusalV1) -> TaskStartFailureV1 {
    TaskStartFailureV1::new("edit_brief_assembly_failed")
}

fn labeled_digest_v1(label: &str, value: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.task-start-fact.v1\0");
    for field in [label, value] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

struct RuntimeEditBriefContextV1 {
    input: EditBriefInputV1,
    repository_tool_calls_displaced: u64,
    provider_call_avoided: bool,
}

impl ReasoningContextCandidateV1 for RuntimeEditBriefContextV1 {
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
        _acknowledgment: Option<&(dyn std::any::Any + Send + Sync)>,
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
        self.input.recipient = recipient;
        let provider_calls_avoided = self
            .input
            .evidence_metrics
            .provider_calls_avoided
            .max(u64::from(self.provider_call_avoided));
        let false_hit_count = self.input.evidence_metrics.false_hit_quarantines;
        let compiled = compile_edit_brief_v1(&self.input).map_err(|_| ())?;
        let brief = serde_json::from_slice(compiled.bytes()).map_err(|_| ())?;
        let mut metrics = serde_json::to_value(compiled.metrics()).map_err(|_| ())?;
        let metrics_object = metrics.as_object_mut().ok_or(())?;
        metrics_object.insert(
            "repository_tool_calls_displaced".to_owned(),
            Value::from(self.repository_tool_calls_displaced),
        );
        metrics_object.insert(
            "provider_calls_avoided".to_owned(),
            Value::from(provider_calls_avoided),
        );
        metrics_object.insert("false_hit_count".to_owned(), Value::from(false_hit_count));
        metrics_object.insert("external_model_calls".to_owned(), Value::from(0));
        Ok(PreparedReasoningContextV1 {
            presentation: ReasoningTransportPresentationV1::Full,
            brief,
            metrics,
            completion: Some(Box::new(EditBriefDeliveryCompletionV1)),
        })
    }
}

struct EditBriefDeliveryCompletionV1;
struct EditBriefFullDeliveryMarkerV1;

impl ReasoningDeliveryCompletionV1 for EditBriefDeliveryCompletionV1 {
    fn complete(self: Box<Self>) -> Result<OpaqueReasoningAcknowledgmentV1, ()> {
        Ok(Arc::new(EditBriefFullDeliveryMarkerV1))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufReader, Cursor, Read};
    use std::thread;
    use std::time::Duration;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::agent_gateway_runtime::ExperimentalMcpGatewayV1;
    use crate::mcp_gateway::{
        AuthorizationScopeId, EphemeralSecrets, GatewayRequestContext, LogicalCallId,
    };

    fn fixture_v1() -> TempDir {
        let workspace = TempDir::new().unwrap();
        fs::create_dir_all(workspace.path().join("src/nested")).unwrap();
        fs::create_dir_all(workspace.path().join("docs")).unwrap();
        fs::write(
            workspace.path().join("src/lib.rs"),
            "pub fn target() -> usize { 7 }\n",
        )
        .unwrap();
        fs::write(
            workspace.path().join("src/nested/irrelevant.rs"),
            "pub fn unrelated() {}\n",
        )
        .unwrap();
        fs::write(
            workspace.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(
            workspace.path().join("docs/notes.md"),
            "outside the declared source dependency\n",
        )
        .unwrap();
        workspace
    }

    fn process_v1(server: &ExperimentalMcpGatewayV1, logical: &str, request: Value) -> Value {
        let context = GatewayRequestContext::new(
            AuthorizationScopeId::new("task-start-test").unwrap(),
            LogicalCallId::new(logical).unwrap(),
        );
        serde_json::from_slice(
            &server
                .gateway()
                .process_bytes(
                    &serde_json::to_vec(&request).unwrap(),
                    &context,
                    EphemeralSecrets::default(),
                )
                .unwrap(),
        )
        .unwrap()
    }

    fn initialize_v1(server: &ExperimentalMcpGatewayV1) {
        let response = process_v1(
            server,
            "initialize",
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "task-start-test", "version": "1" }
                }
            }),
        );
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    }

    fn call_v1(server: &ExperimentalMcpGatewayV1, arguments: Value) -> Value {
        process_v1(
            server,
            "task-start-call",
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "again.task_start", "arguments": arguments }
            }),
        )
    }

    #[test]
    fn task_start_input_is_strict_bounded_and_sensitive_safe() {
        let workspace = fixture_v1();
        let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
        initialize_v1(&server);

        for (arguments, reason) in [
            (
                json!({"task": "edit target", "extra": true}),
                "task_start_unknown_field",
            ),
            (
                json!({"task": "edit target", "changedPaths": ["../escape"]}),
                "task_changed_path_unsafe",
            ),
            (
                json!({"task": "x".repeat(MAX_TASK_BYTES_V1 + 1)}),
                "task_text_invalid",
            ),
            (
                json!({"task": "use authorization: bearer secret"}),
                "task_start_sensitive_content",
            ),
        ] {
            let response = call_v1(&server, arguments);
            assert_eq!(response["error"]["data"]["reason"], reason);
            assert!(matches!(
                response["error"]["code"].as_i64(),
                Some(-32602) | Some(-32021)
            ));
        }
    }

    #[test]
    fn task_start_dependency_evidence_fails_closed() {
        let scope = ReasoningScopeV1::new(
            &"a".repeat(64),
            "repository",
            "workspace",
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
        )
        .unwrap();
        let dependency = crate::store::GatewayDependencyV1 {
            key_digest: "e".repeat(64),
            value_digest: "f".repeat(64),
        };
        let mut included = 0;
        let mut invalidated = Vec::new();
        let mut unknown = false;
        for report in [
            DependencyChangeReportV1 {
                state: DependencyChangeStateV1::Contradictory,
                evidence: Vec::new(),
                affected_gateway_result_ids: Vec::new(),
                affected_results_truncated: false,
            },
            DependencyChangeReportV1 {
                state: DependencyChangeStateV1::Unknown,
                evidence: Vec::new(),
                affected_gateway_result_ids: Vec::new(),
                affected_results_truncated: true,
            },
        ] {
            assert!(
                apply_dependency_report_v1(
                    &scope,
                    &dependency,
                    report,
                    &mut included,
                    &mut invalidated,
                    &mut unknown,
                )
                .is_err()
            );
        }
        assert!(invalidated.is_empty());
    }

    struct DelayedEofV1 {
        bytes: Cursor<Vec<u8>>,
        delayed: bool,
    }

    impl Read for DelayedEofV1 {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.bytes.read(buffer)?;
            if count == 0 && !self.delayed {
                self.delayed = true;
                thread::sleep(Duration::from_millis(250));
            }
            Ok(count)
        }
    }

    fn stdio_task_start_v1(
        server: &ExperimentalMcpGatewayV1,
        authorization_scope: &str,
        arguments: Value,
    ) -> Value {
        let requests = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "stdio-task-start", "version": "1" }
                }
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "again.task_start", "arguments": arguments }
            }),
        ]
        .into_iter()
        .map(|request| serde_json::to_string(&request).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
            + "\n";
        let mut reader = BufReader::new(DelayedEofV1 {
            bytes: Cursor::new(requests.into_bytes()),
            delayed: false,
        });
        let mut output = Vec::new();
        server
            .serve_io(
                &mut reader,
                &mut output,
                &AuthorizationScopeId::new(authorization_scope).unwrap(),
            )
            .unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|response| response["id"] == 2)
            .expect("task-start response")
    }

    #[test]
    fn task_start_real_stdio_is_full_bound_and_zero_authority() {
        let workspace = fixture_v1();
        let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
        let requests = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "stdio-task-start", "version": "1" }
                }
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "again.task_start",
                    "arguments": {
                        "task": "edit target",
                        "constraints": ["preserve exact output"],
                        "changedPaths": ["src/lib.rs"],
                        "validationIntent": "run unit tests"
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {
                    "name": "again.task_start",
                    "arguments": {
                        "validationIntent": "run unit tests",
                        "changedPaths": ["src/lib.rs"],
                        "constraints": ["preserve exact output"],
                        "task": "edit target"
                    }
                }
            }),
        ]
        .into_iter()
        .map(|request| serde_json::to_string(&request).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
            + "\n";
        let mut reader = BufReader::new(DelayedEofV1 {
            bytes: Cursor::new(requests.into_bytes()),
            delayed: false,
        });
        let mut output = Vec::new();
        server
            .serve_io(
                &mut reader,
                &mut output,
                &AuthorizationScopeId::new("stdio-task-start").unwrap(),
            )
            .unwrap();
        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        for id in [2, 3] {
            let response = responses
                .iter()
                .find(|response| response["id"] == id)
                .expect("task-start response");
            let context = &response["result"]["_meta"]["again"]["reasoningContext"];
            let again = &response["result"]["_meta"]["again"];
            assert_eq!(again["experimental"], true);
            assert_eq!(again["maturity"], "local_alpha");
            assert_eq!(again["fullRetrievalAvailable"], false);
            assert_eq!(context["presentation"], "full");
            assert_eq!(context["brief"]["format"], "again.edit-brief");
            assert_eq!(context["brief"]["compiler"], "deterministic_local");
            assert_eq!(context["brief"]["authority"]["edit_correct"], false);
            assert_eq!(context["brief"]["authority"]["test_reusable"], false);
            assert_eq!(context["brief"]["authority"]["compact_delivery"], false);
            assert_eq!(context["brief"]["authority"]["tool_reuse"], false);
            assert_eq!(context["brief"]["authority"]["execution_reuse"], false);
            assert_eq!(context["brief"]["authority"]["llm_ran"], false);
            assert_eq!(context["metrics"]["external_model_calls"], 0);
            let identity = context["brief"]["identity"].as_object().unwrap();
            for field in [
                "workspace_id",
                "session_id",
                "authorization_scope_digest",
                "state_digest",
                "dependency_digest",
                "connection_generation",
                "task_id",
            ] {
                assert!(
                    identity
                        .get(field)
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty()),
                    "missing task-start identity field: {field}"
                );
            }
            assert!(context["metrics"]["delivered_bytes"].as_u64().unwrap() <= 16_384);
            assert!(
                context["brief"]["truncation"]["included_items"]
                    .as_u64()
                    .unwrap()
                    <= 24
            );
            assert!(
                context["brief"]["truncation"]["included_source_references"]
                    .as_u64()
                    .unwrap()
                    <= 32
            );
        }
        let first = responses
            .iter()
            .find(|response| response["id"] == 2)
            .unwrap();
        let warm = responses
            .iter()
            .find(|response| response["id"] == 3)
            .unwrap();
        assert_eq!(
            first["result"]["_meta"]["again"]["resultId"],
            warm["result"]["_meta"]["again"]["resultId"]
        );
        assert_ne!(
            first["result"]["_meta"]["again"]["reasoningContext"]["brief"]["identity"]["session_id"],
            warm["result"]["_meta"]["again"]["reasoningContext"]["brief"]["identity"]["session_id"]
        );
        let stats = server.stats().unwrap();
        assert!(stats.exact_hits.saturating_add(stats.inflight_joins) >= 1);
    }

    #[test]
    fn task_start_irrelevant_content_preserves_exact_reuse() {
        let workspace = fixture_v1();
        let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
        let arguments = json!({
            "task": "edit target",
            "changedPaths": ["src/lib.rs"]
        });
        let first = stdio_task_start_v1(&server, "irrelevant-scope", arguments.clone());
        fs::write(
            workspace.path().join("docs/notes.md"),
            "changed but still outside the declared source dependency\n",
        )
        .unwrap();
        let warm = stdio_task_start_v1(&server, "irrelevant-scope", arguments);
        assert_eq!(
            first["result"]["_meta"]["again"]["resultId"],
            warm["result"]["_meta"]["again"]["resultId"]
        );
        assert_eq!(
            warm["result"]["_meta"]["again"]["reasoningContext"]["metrics"]["provider_calls_avoided"],
            1
        );
        assert_eq!(
            warm["result"]["_meta"]["again"]["reasoningContext"]["brief"]["truncation"]["complete_within_budget"],
            true
        );
    }

    #[test]
    fn task_start_source_mutation_invalidates_prior_material() {
        let workspace = fixture_v1();
        let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
        let arguments = json!({
            "task": "edit target",
            "changedPaths": ["src/lib.rs"]
        });
        let first = stdio_task_start_v1(&server, "mutation-scope", arguments.clone());
        assert!(
            first["result"]["_meta"]["again"]["reasoningContext"]["brief"]
                ["invalidated_or_quarantined_facts"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        fs::write(
            workspace.path().join("src/lib.rs"),
            "pub fn target() -> usize { 8 }\n",
        )
        .unwrap();
        let changed = stdio_task_start_v1(&server, "mutation-scope", arguments);
        let brief = &changed["result"]["_meta"]["again"]["reasoningContext"]["brief"];
        assert!(
            !brief["invalidated_or_quarantined_facts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(brief["authority"]["execution_reuse"], false);
        assert_eq!(brief["authority"]["test_reusable"], false);
    }
}
