//! Same-user local task context provider.
//!
//! Recipient identity comes only from the authenticated MCP transport. Task
//! and result identifiers remain bounded selectors inside that live scope;
//! neither a socket path nor a serialized identifier grants retrieval.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::agent_gateway::context::{
    CompletedReasoningObservationV1, ContextLedgerCursorV1, ContextLedgerIdentityV1,
    ContextLedgerSuggestionV1, ReasoningRetrievalIdentityV1, ReasoningUnknownV1,
};
use crate::agent_gateway_runtime::SharedObservedWorkspaceV1;
use crate::code_intelligence::{
    CodeIntelligenceIndexV1, CodeIntelligenceLimitsV1, CodeIntelligenceProviderV1,
    EditBriefRequestV1,
};
use crate::mcp_gateway::{
    CapturedToolResult, EffectClass, EphemeralSecrets, Freshness, FreshnessMetadata, McpError,
    McpErrorCode, ProviderCall, ProviderCancellation, ProviderDescriptor, ProviderError,
    ProviderTool, ReasoningTransportRecipientV1, RecipientLifecycleSinkV1,
    ResponseWriteCompletionV1, SideEffectClassification, StructuredResultCapture, ToolCancellation,
    ToolDiscovery, ToolExecution,
};
use crate::store::{ContextLeaseAcquisitionV1, ContextLedgerEventInputV1, Store};

const INTERNAL_COMPLETION_FIELD_V1: &str = "__again_context_completion_v1";
const MAX_CONTEXT_DELTA_ITEMS_V1: usize = 64;
const MAX_CONTEXT_TEXT_BYTES_V1: usize = 1024;
const MAX_ACTIVE_CONTEXT_TASKS_V1: usize = 64;
const DEFAULT_CONTEXT_LEASE_TTL_MS_V1: u64 = 30_000;

#[derive(Clone, Copy)]
pub(super) enum ContextProviderKindV1 {
    Task,
    Context,
}

#[derive(Clone)]
struct ActiveContextV1 {
    identity: ContextLedgerIdentityV1,
    recipient_key: String,
}

pub(super) struct LocalContextCoordinatorV1 {
    store: Arc<Mutex<Store>>,
    repository_id: String,
    workspace_id: String,
    observed_workspace: SharedObservedWorkspaceV1,
    code_index: Mutex<CodeIntelligenceIndexV1>,
    active: Mutex<BTreeMap<String, ActiveContextV1>>,
    current: Mutex<BTreeMap<String, String>>,
    acknowledged: Mutex<BTreeMap<String, u64>>,
}

impl LocalContextCoordinatorV1 {
    pub(super) fn new(
        workspace: &Path,
        store: Arc<Mutex<Store>>,
        observed_workspace: SharedObservedWorkspaceV1,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"again.local-context.workspace.v1\0");
        hasher.update(workspace.as_os_str().as_encoded_bytes());
        let digest = hasher.finalize().to_hex().to_string();
        Self {
            store,
            repository_id: format!("repository:{}", &digest[..24]),
            workspace_id: format!("workspace:{}", &digest[..24]),
            observed_workspace,
            code_index: Mutex::new(
                CodeIntelligenceIndexV1::new(CodeIntelligenceLimitsV1::default())
                    .expect("default code-intelligence limits are valid"),
            ),
            active: Mutex::new(BTreeMap::new()),
            current: Mutex::new(BTreeMap::new()),
            acknowledged: Mutex::new(BTreeMap::new()),
        }
    }

    fn recipient_key(recipient: &ReasoningTransportRecipientV1) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            recipient.agent_id,
            recipient.session_id,
            recipient.turn_id,
            recipient.connection_generation,
            recipient.compaction_generation,
            recipient.lifecycle_generation
        )
    }

    fn delivery_key(identity: &ContextLedgerIdentityV1) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            identity.repository_id(),
            identity.workspace_id(),
            identity.task_id(),
            identity.authorization_scope_digest(),
            identity.agent_id(),
            identity.session_id(),
            identity.turn_id(),
            identity.connection_generation(),
            identity.compaction_generation(),
            identity.lifecycle_generation()
        )
    }

    fn activate(
        &self,
        recipient: &ReasoningTransportRecipientV1,
        task_id: &str,
        authorization_scope_digest: &str,
    ) -> Result<ContextLedgerIdentityV1> {
        let identity = ContextLedgerIdentityV1::new(
            &self.repository_id,
            &self.workspace_id,
            task_id,
            authorization_scope_digest,
            &recipient.agent_id,
            &recipient.session_id,
            &recipient.turn_id,
            &recipient.connection_generation,
            recipient.compaction_generation,
            recipient.lifecycle_generation,
        )
        .map_err(|refusal| anyhow!(refusal.code()))?;
        let recipient_key = Self::recipient_key(recipient);
        let identity_key = Self::delivery_key(&identity);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !active.contains_key(&identity_key) && active.len() >= MAX_ACTIVE_CONTEXT_TASKS_V1 {
            bail!("context_capacity_exceeded");
        }
        self.store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .activate_context_recipient_v1(&identity)?;
        active.insert(
            identity_key.clone(),
            ActiveContextV1 {
                identity: identity.clone(),
                recipient_key: recipient_key.clone(),
            },
        );
        drop(active);
        self.current
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(recipient_key, identity_key);
        Ok(identity)
    }

    pub(super) fn active_identity_for_call(
        &self,
        call: &ProviderCall,
    ) -> Option<ContextLedgerIdentityV1> {
        let recipient = call.transport_recipient_v1()?;
        let recipient_key = Self::recipient_key(recipient);
        let identity_key = self
            .current
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&recipient_key)
            .cloned()?;
        self.active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&identity_key)
            .map(|active| active.identity.clone())
    }

    pub(super) fn admit_verified_result(
        &self,
        call: &ProviderCall,
        binding: &crate::store::ValidatedGatewayReadV1,
        gateway_result_id: &str,
        duration_ms: u64,
    ) -> Result<()> {
        let Some(identity) = self.active_identity_for_call(call) else {
            return Ok(());
        };
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let source = store.context_verified_observation_v1(
            &identity,
            binding,
            gateway_result_id,
            &source_locator_v1(call),
        )?;
        let fact_id = bounded_digest_id_v1("fact", binding.request_digest());
        let fact = store.context_fact_from_verified_observations_v1(
            &identity,
            &fact_id,
            true,
            std::slice::from_ref(&source),
        )?;
        let fact_envelope = event_digest_v1(
            b"again.context.verified-fact-envelope.v1\0",
            &identity,
            gateway_result_id.as_bytes(),
        );
        let _ = store.admit_context_fact_v1(
            &identity,
            &fact_envelope,
            version_from_digest_v1(gateway_result_id),
            &fact,
            std::slice::from_ref(&source),
        )?;

        let full = store
            .get_gateway_result(binding, gateway_result_id)?
            .ok_or_else(|| anyhow!("verified context result disappeared"))?;
        let total_bytes = full
            .result
            .stdout_bytes
            .checked_add(full.result.stderr_bytes)
            .ok_or_else(|| anyhow!("context result byte count overflow"))?;
        let retrieval =
            ReasoningRetrievalIdentityV1::new(gateway_result_id, gateway_result_id, total_bytes)
                .map_err(|refusal| anyhow!(refusal.code()))?;
        let observation_id = bounded_digest_id_v1("observation", binding.request_digest());
        let observation = CompletedReasoningObservationV1::new(
            &observation_id,
            "verified repository tool observation",
            duration_ms,
            retrieval.clone(),
            vec![source.source().clone()],
        )
        .map_err(|refusal| anyhow!(refusal.code()))?;
        let observation_envelope = event_digest_v1(
            b"again.context.completed-observation-envelope.v1\0",
            &identity,
            gateway_result_id.as_bytes(),
        );
        let _ = store.append_context_event_v1(
            &identity,
            &observation_envelope,
            &ContextLedgerEventInputV1::CompletedObservation {
                observation,
                verified_sources: vec![source.clone()],
            },
        )?;
        let reference_envelope = event_digest_v1(
            b"again.context.result-reference-envelope.v1\0",
            &identity,
            gateway_result_id.as_bytes(),
        );
        let _ = store.append_context_event_v1(
            &identity,
            &reference_envelope,
            &ContextLedgerEventInputV1::ResultReference {
                reference: retrieval,
                reference_version: 1,
                verified_sources: vec![source],
            },
        )?;
        Ok(())
    }

    pub(super) fn observe_dependencies(
        &self,
        call: &ProviderCall,
        binding: &crate::store::ValidatedGatewayReadV1,
    ) -> Result<()> {
        let Some(identity) = self.active_identity_for_call(call) else {
            return Ok(());
        };
        let changes = binding
            .dependencies()
            .iter()
            .map(|dependency| {
                crate::store::ContextDependencyChangeV1::new(
                    &dependency.key_digest,
                    &dependency.value_digest,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        if changes.is_empty() {
            return Ok(());
        }
        let envelope = event_digest_v1(
            b"again.context.dependency-observation-envelope.v1\0",
            &identity,
            binding.binding_digest().as_bytes(),
        );
        let _ = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .invalidate_context_dependencies_v1(&identity, &envelope, &changes)?;
        Ok(())
    }

    fn task_start(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(&call.arguments, &["taskId", "task"])?;
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let task = call
            .arguments
            .get("task")
            .and_then(Value::as_str)
            .unwrap_or(task_id);
        if task.is_empty() || task.len() > 8 * 1024 {
            bail!("invalid_task_description");
        }
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let identity = self.activate(
            recipient,
            task_id,
            &crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope),
        )?;
        let snapshot = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .context_task_snapshot_v1(&identity)?;
        let cursor = snapshot.cursor();
        let code_brief = {
            let mut index = self
                .code_index
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let mut manifest = self
                .observed_workspace
                .manifest
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let limits = crate::agent_gateway_runtime::gateway_workspace_limits_v1();
            let status = index.refresh_from_manifest(
                &self.observed_workspace.execution_epoch,
                &mut manifest,
                &limits,
            );
            let request = EditBriefRequestV1::new(task)
                .and_then(|request| request.with_maximum_candidates(24));
            match (status, request) {
                (Ok(_), Some(request)) => {
                    serde_json::to_value(index.compile_edit_brief_v1(&request, None))?
                }
                _ => json!({
                    "schemaVersion": 1,
                    "candidates": [],
                    "incomplete": true,
                    "unknowns": [{ "kind": "index_unavailable" }]
                }),
            }
        };
        let delivery_key = Self::delivery_key(&identity);
        let acknowledged = self
            .acknowledged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&delivery_key)
            .copied();
        let (presentation, context, omitted_bytes) = if let Some(after) = acknowledged {
            let delta = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .context_delta_after_v1(
                    &identity,
                    ContextLedgerCursorV1::new(after),
                    MAX_CONTEXT_DELTA_ITEMS_V1,
                )?;
            let context = if delta.events().is_empty() {
                json!({
                    "reference": format!("again-context-v1:{}:{}", identity.task_id(), cursor.sequence()),
                    "unchangedThroughCursor": cursor.sequence()
                })
            } else {
                serde_json::to_value(delta)?
            };
            (
                "compact",
                context,
                serde_json::to_vec(&snapshot)?.len() as u64,
            )
        } else {
            ("full", serde_json::to_value(&snapshot)?, 0)
        };
        let structured = json!({
            "schemaVersion": 1,
            "operation": "task.start",
            "presentation": presentation,
            "taskId": identity.task_id(),
            "cursor": cursor.sequence(),
            "context": context,
            "relevantCode": code_brief,
            "validationPreview": {
                "status": "execute_required",
                "selectors": [],
                "reason": "no qualified validation profile supplied a proven selector"
            },
            "compulsoryPlan": false
        });
        Ok(ContextOperationResultV1::delivered(
            tool_result_v1(structured),
            Box::new(ContextDeliveryCompletionV1 {
                coordinator: Arc::clone(self),
                identity,
                through: cursor,
                omitted_bytes,
            }),
        ))
    }

    fn delta(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(&call.arguments, &["taskId", "afterCursor", "limit"])?;
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let after = call
            .arguments
            .get("afterCursor")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("invalid_after_cursor"))?;
        let limit = call
            .arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(MAX_CONTEXT_DELTA_ITEMS_V1 as u64);
        let limit = usize::try_from(limit).context("invalid_delta_limit")?;
        if !(1..=MAX_CONTEXT_DELTA_ITEMS_V1).contains(&limit) {
            bail!("invalid_delta_limit");
        }
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let identity = self.activate(
            recipient,
            task_id,
            &crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope),
        )?;
        let delivery_key = Self::delivery_key(&identity);
        let allowed = self
            .acknowledged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&delivery_key)
            .is_some_and(|cursor| *cursor >= after);
        if !allowed {
            bail!("full_delivery_required");
        }
        let delta = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .context_delta_after_v1(&identity, ContextLedgerCursorV1::new(after), limit)?;
        let through = delta.cursor();
        let structured = json!({
            "schemaVersion": 1,
            "operation": "context.delta",
            "presentation": "delta",
            "delta": delta
        });
        Ok(ContextOperationResultV1::delivered(
            tool_result_v1(structured),
            Box::new(ContextDeliveryCompletionV1 {
                coordinator: Arc::clone(self),
                identity,
                through,
                omitted_bytes: 0,
            }),
        ))
    }

    fn publish(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let kind = bounded_string_v1(&call.arguments, "kind", 64)?;
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let identity = self.activate(
            recipient,
            task_id,
            &crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope),
        )?;
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let outcome = match kind {
            "suggestion" => {
                require_keys_v1(&call.arguments, &["taskId", "kind", "subject", "statement"])?;
                let subject = bounded_string_v1(&call.arguments, "subject", 128)?;
                let statement =
                    bounded_text_v1(&call.arguments, "statement", MAX_CONTEXT_TEXT_BYTES_V1)?;
                let relevance = blake3::hash(statement.as_bytes()).to_hex().to_string();
                let suggestion = ContextLedgerSuggestionV1::new(subject, statement, &relevance)
                    .map_err(|refusal| anyhow!(refusal.code()))?;
                let envelope = event_digest_v1(
                    b"again.context.suggestion-envelope.v1\0",
                    &identity,
                    serde_json::to_string(&call.arguments)?.as_bytes(),
                );
                let event = store.append_context_event_v1(
                    &identity,
                    &envelope,
                    &ContextLedgerEventInputV1::UnverifiedSuggestion(suggestion),
                )?;
                json!({ "status": "suggestion_recorded", "cursor": event.sequence(), "verified": false })
            }
            "unknown" => {
                require_keys_v1(
                    &call.arguments,
                    &["taskId", "kind", "subject", "explanation"],
                )?;
                let unknown = ReasoningUnknownV1::new(
                    bounded_string_v1(&call.arguments, "subject", 128)?,
                    bounded_text_v1(&call.arguments, "explanation", MAX_CONTEXT_TEXT_BYTES_V1)?,
                )
                .map_err(|refusal| anyhow!(refusal.code()))?;
                let envelope = event_digest_v1(
                    b"again.context.unknown-envelope.v1\0",
                    &identity,
                    serde_json::to_string(&call.arguments)?.as_bytes(),
                );
                let event = store.append_context_event_v1(
                    &identity,
                    &envelope,
                    &ContextLedgerEventInputV1::ExplicitUnknown(unknown),
                )?;
                json!({ "status": "unknown_recorded", "cursor": event.sequence(), "verified": false })
            }
            "work_start" => {
                require_keys_v1(
                    &call.arguments,
                    &["taskId", "kind", "workKey", "summary", "ttlMs"],
                )?;
                let work_key = bounded_string_v1(&call.arguments, "workKey", 512)?;
                let summary =
                    bounded_text_v1(&call.arguments, "summary", MAX_CONTEXT_TEXT_BYTES_V1)?;
                let ttl_ms = call
                    .arguments
                    .get("ttlMs")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_CONTEXT_LEASE_TTL_MS_V1);
                let work_digest = blake3::hash(work_key.as_bytes()).to_hex().to_string();
                let deadline =
                    now_ms_v1().saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX));
                match store.acquire_context_lease_v1(
                    &identity,
                    &work_digest,
                    summary,
                    ttl_ms,
                    deadline,
                )? {
                    ContextLeaseAcquisitionV1::Leader {
                        lease_id,
                        generation,
                        expires_at_ms,
                    } => json!({
                        "status": "leader",
                        "leaseId": lease_id,
                        "generation": generation,
                        "expiresAtMs": expires_at_ms
                    }),
                    ContextLeaseAcquisitionV1::Join {
                        lease_id,
                        generation,
                        leader_agent_id,
                        expires_at_ms,
                    } => json!({
                        "status": "join",
                        "leaseId": lease_id,
                        "generation": generation,
                        "leaderAgentId": leader_agent_id,
                        "expiresAtMs": expires_at_ms
                    }),
                }
            }
            "work_finish" => {
                require_keys_v1(&call.arguments, &["taskId", "kind", "leaseId", "succeeded"])?;
                let lease_id = bounded_string_v1(&call.arguments, "leaseId", 128)?;
                let succeeded = call
                    .arguments
                    .get("succeeded")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("invalid_succeeded"))?;
                store.finish_context_lease_v1(&identity, lease_id, succeeded)?;
                json!({ "status": if succeeded { "completed" } else { "failed" } })
            }
            "work_cancel" => {
                require_keys_v1(&call.arguments, &["taskId", "kind", "leaseId"])?;
                let lease_id = bounded_string_v1(&call.arguments, "leaseId", 128)?;
                store.cancel_context_lease_v1(&identity, lease_id)?;
                json!({ "status": "cancelled" })
            }
            _ => bail!("unsupported_publish_kind"),
        };
        drop(store);
        Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
            "schemaVersion": 1,
            "operation": "context.publish",
            "outcome": outcome
        }))))
    }

    fn retrieve(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(&call.arguments, &["taskId", "resultId"])?;
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let result_id = bounded_string_v1(&call.arguments, "resultId", 128)?;
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let identity = self.activate(
            recipient,
            task_id,
            &crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope),
        )?;
        let full = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retrieve_context_result_v1(&identity, result_id)
            .map_err(|_| anyhow!("retrieval_refused"))?;
        if full.result.exit_code != 0 || !full.stderr.is_empty() {
            bail!("context_result_is_not_a_structured_tool_result");
        }
        let exact: Value =
            serde_json::from_slice(&full.stdout).context("context result is not canonical JSON")?;
        Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
            "schemaVersion": 1,
            "operation": "context.retrieve",
            "resultId": full.gateway_result_id,
            "presentation": "full",
            "toolResult": exact
        }))))
    }

    fn cancel(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(&call.arguments, &["taskId", "leaseId"])?;
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let identity = self.activate(
            recipient,
            task_id,
            &crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope),
        )?;
        if let Some(lease_id) = call.arguments.get("leaseId").and_then(Value::as_str) {
            if lease_id.len() > 128 {
                bail!("invalid_lease_id");
            }
            self.store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .cancel_context_lease_v1(&identity, lease_id)?;
        }
        let retired = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retire_context_recipient_v1(&identity)?;
        let recipient_key = Self::recipient_key(recipient);
        let identity_key = Self::delivery_key(&identity);
        self.active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&identity_key);
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if current.get(&recipient_key) == Some(&identity_key) {
            current.remove(&recipient_key);
        }
        self.acknowledged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&Self::delivery_key(&identity));
        Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
            "schemaVersion": 1,
            "operation": "context.cancel",
            "status": if retired { "retired" } else { "already_retired" }
        }))))
    }

    fn retire_recipient(&self, recipient: &ReasoningTransportRecipientV1) {
        let key = Self::recipient_key(recipient);
        self.current
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&key);
        let active = {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let identities = active
                .iter()
                .filter(|(_, active)| active.recipient_key == key)
                .map(|(identity_key, _)| identity_key.clone())
                .collect::<Vec<_>>();
            identities
                .into_iter()
                .filter_map(|identity_key| active.remove(&identity_key))
                .collect::<Vec<_>>()
        };
        for active in active {
            let _ = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .retire_context_recipient_v1(&active.identity);
            self.acknowledged
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&Self::delivery_key(&active.identity));
        }
    }
}

impl RecipientLifecycleSinkV1 for LocalContextCoordinatorV1 {
    fn retire(&self, recipient: &ReasoningTransportRecipientV1, _reason: &'static str) {
        self.retire_recipient(recipient);
    }
}

struct ContextDeliveryCompletionV1 {
    coordinator: Arc<LocalContextCoordinatorV1>,
    identity: ContextLedgerIdentityV1,
    through: ContextLedgerCursorV1,
    omitted_bytes: u64,
}

impl ResponseWriteCompletionV1 for ContextDeliveryCompletionV1 {
    fn complete(self: Box<Self>, delivered_response: &[u8]) {
        let envelope = event_digest_v1(
            b"again.context.response-envelope.v1\0",
            &self.identity,
            delivered_response,
        );
        let acknowledged = self
            .coordinator
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .acknowledge_context_delivery_v1(
                &self.identity,
                &envelope,
                self.through,
                delivered_response.len() as u64,
                self.omitted_bytes,
            );
        if acknowledged.is_ok() {
            let key = LocalContextCoordinatorV1::delivery_key(&self.identity);
            let mut delivered = self
                .coordinator
                .acknowledged
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            delivered
                .entry(key)
                .and_modify(|cursor| *cursor = (*cursor).max(self.through.sequence()))
                .or_insert(self.through.sequence());
        }
    }
}

struct ContextOperationResultV1 {
    value: Value,
    completion: Option<Box<dyn ResponseWriteCompletionV1>>,
}

impl ContextOperationResultV1 {
    fn exact(value: Value) -> Self {
        Self {
            value,
            completion: None,
        }
    }

    fn delivered(value: Value, completion: Box<dyn ResponseWriteCompletionV1>) -> Self {
        Self {
            value,
            completion: Some(completion),
        }
    }
}

pub(super) struct LocalContextProviderV1 {
    kind: ContextProviderKindV1,
    coordinator: Arc<LocalContextCoordinatorV1>,
    pending: Mutex<BTreeMap<String, Box<dyn ResponseWriteCompletionV1>>>,
}

impl LocalContextProviderV1 {
    pub(super) fn new(
        kind: ContextProviderKindV1,
        coordinator: Arc<LocalContextCoordinatorV1>,
    ) -> Self {
        Self {
            kind,
            coordinator,
            pending: Mutex::new(BTreeMap::new()),
        }
    }
}

impl ToolDiscovery for LocalContextProviderV1 {
    fn descriptor(&self) -> ProviderDescriptor {
        let id = match self.kind {
            ContextProviderKindV1::Task => "task",
            ContextProviderKindV1::Context => "context",
        };
        ProviderDescriptor {
            id: id.to_owned(),
            implementation: "again.local-context.v1".to_owned(),
            version: "1".to_owned(),
            endpoint_identity: "same-user-local-store".to_owned(),
        }
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        let output = || json!({ "type": "object" });
        let tools = match self.kind {
            ContextProviderKindV1::Task => vec![ProviderTool {
                name: "start".to_owned(),
                title: Some("Start task with shared context".to_owned()),
                description: Some(
                    "Return one bounded verified edit brief for the active local task.".to_owned(),
                ),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "taskId": { "type": "string", "maxLength": 128 },
                        "task": { "type": "string", "maxLength": 8192 }
                    },
                    "required": ["taskId"],
                    "additionalProperties": false
                }),
                output_schema: Some(output()),
                annotations: Some(json!({ "readOnlyHint": false })),
                meta: None,
            }],
            ContextProviderKindV1::Context => [
                (
                    "delta",
                    json!({
                        "type": "object",
                        "properties": {
                            "taskId": { "type": "string", "maxLength": 128 },
                            "afterCursor": { "type": "integer", "minimum": 0 },
                            "limit": { "type": "integer", "minimum": 1, "maximum": MAX_CONTEXT_DELTA_ITEMS_V1 }
                        },
                        "required": ["taskId", "afterCursor"],
                        "additionalProperties": false
                    }),
                ),
                (
                    "publish",
                    json!({
                        "type": "object",
                        "properties": {
                            "taskId": { "type": "string", "maxLength": 128 },
                            "kind": { "type": "string", "enum": ["suggestion", "unknown", "work_start", "work_finish", "work_cancel"] },
                            "subject": { "type": "string", "maxLength": 128 },
                            "statement": { "type": "string", "maxLength": MAX_CONTEXT_TEXT_BYTES_V1 },
                            "explanation": { "type": "string", "maxLength": MAX_CONTEXT_TEXT_BYTES_V1 },
                            "workKey": { "type": "string", "maxLength": 512 },
                            "summary": { "type": "string", "maxLength": MAX_CONTEXT_TEXT_BYTES_V1 },
                            "ttlMs": { "type": "integer", "minimum": 1 },
                            "leaseId": { "type": "string", "maxLength": 128 },
                            "succeeded": { "type": "boolean" }
                        },
                        "required": ["taskId", "kind"],
                        "additionalProperties": false
                    }),
                ),
                (
                    "retrieve",
                    json!({
                        "type": "object",
                        "properties": {
                            "taskId": { "type": "string", "maxLength": 128 },
                            "resultId": { "type": "string", "maxLength": 128 }
                        },
                        "required": ["taskId", "resultId"],
                        "additionalProperties": false
                    }),
                ),
                (
                    "cancel",
                    json!({
                        "type": "object",
                        "properties": {
                            "taskId": { "type": "string", "maxLength": 128 },
                            "leaseId": { "type": "string", "maxLength": 128 }
                        },
                        "required": ["taskId"],
                        "additionalProperties": false
                    }),
                ),
            ]
                .into_iter()
                .map(|(name, input_schema)| ProviderTool {
                    name: name.to_owned(),
                    title: Some(format!("Shared context {name}")),
                    description: Some(format!(
                        "Bounded recipient-scoped context {name} operation."
                    )),
                    input_schema,
                    output_schema: Some(output()),
                    annotations: Some(
                        json!({ "readOnlyHint": matches!(name, "delta" | "retrieve") }),
                    ),
                    meta: None,
                })
                .collect(),
        };
        Ok(tools)
    }
}

impl FreshnessMetadata for LocalContextProviderV1 {
    fn freshness(&self) -> Freshness {
        Freshness {
            revision: "local-context-v1".to_owned(),
            observed_at_unix_ms: None,
        }
    }
}

impl SideEffectClassification for LocalContextProviderV1 {
    fn classify_effect(&self, upstream_tool_name: &str) -> EffectClass {
        if matches!(upstream_tool_name, "delta" | "retrieve") {
            EffectClass::ReadOnly
        } else {
            EffectClass::Mutating
        }
    }
}

impl ToolExecution for LocalContextProviderV1 {
    fn execute(
        &self,
        call: ProviderCall,
        _secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        if call.transport_recipient_v1().is_none() {
            return Err(context_refusal_v1("recipient_authority_required"));
        }
        let result = match (self.kind, call.upstream_tool_name.as_str()) {
            (ContextProviderKindV1::Task, "start") => self.coordinator.task_start(&call),
            (ContextProviderKindV1::Context, "delta") => self.coordinator.delta(&call),
            (ContextProviderKindV1::Context, "publish") => self.coordinator.publish(&call),
            (ContextProviderKindV1::Context, "retrieve") => self.coordinator.retrieve(&call),
            (ContextProviderKindV1::Context, "cancel") => self.coordinator.cancel(&call),
            _ => Err(anyhow!("unsupported_context_operation")),
        }
        .map_err(|error| context_refusal_v1(context_error_code_v1(&error)))?;
        let mut value = result.value;
        if let Some(completion) = result.completion {
            let token = format!("cc_{}", uuid::Uuid::new_v4().simple());
            self.pending
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .insert(token.clone(), completion);
            value
                .as_object_mut()
                .expect("context tool results are objects")
                .insert(
                    INTERNAL_COMPLETION_FIELD_V1.to_owned(),
                    Value::String(token),
                );
        }
        Ok(value)
    }
}

impl StructuredResultCapture for LocalContextProviderV1 {
    fn capture_result(&self, mut result: Value) -> Result<CapturedToolResult, ProviderError> {
        let completion = result
            .as_object_mut()
            .and_then(|object| object.remove(INTERNAL_COMPLETION_FIELD_V1))
            .and_then(|value| value.as_str().map(str::to_owned))
            .and_then(|token| {
                self.pending
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .remove(&token)
            });
        Ok(match completion {
            Some(completion) => CapturedToolResult::exact_with_write_completion(result, completion),
            None => CapturedToolResult::exact(result),
        })
    }
}

impl ToolCancellation for LocalContextProviderV1 {
    fn cancel(&self, _cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn tool_result_v1(structured: Value) -> Value {
    let text = serde_json::to_string(&structured).expect("context values serialize");
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured
    })
}

fn require_keys_v1(arguments: &Value, allowed: &[&str]) -> Result<()> {
    let object = arguments
        .as_object()
        .ok_or_else(|| anyhow!("arguments_must_be_object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("unknown_argument");
    }
    Ok(())
}

fn bounded_string_v1<'a>(arguments: &'a Value, name: &str, maximum: usize) -> Result<&'a str> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= maximum
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b' ')
                })
        })
        .ok_or_else(|| anyhow!("invalid_argument"))
}

fn bounded_text_v1<'a>(arguments: &'a Value, name: &str, maximum: usize) -> Result<&'a str> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= maximum
                && value.chars().all(|character| {
                    character == '\n' || character == '\t' || !character.is_control()
                })
        })
        .ok_or_else(|| anyhow!("invalid_argument"))
}

fn source_locator_v1(call: &ProviderCall) -> String {
    let tool = call.namespaced_tool_name.as_str();
    let Some(path) = call.arguments.get("path").and_then(Value::as_str) else {
        return tool.to_owned();
    };
    let locator = format!("{tool}:{path}");
    if locator.len() <= 512 && locator.chars().all(|character| !character.is_control()) {
        locator
    } else {
        tool.to_owned()
    }
}

fn context_refusal_v1(reason: &str) -> ProviderError {
    ProviderError::gateway_authored(
        McpError::typed(McpErrorCode::InvalidParams, "context operation refused")
            .with_data(json!({ "reason": reason })),
    )
}

fn context_error_code_v1(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "recipient_authority_required" => "recipient_authority_required",
        "full_delivery_required" => "full_delivery_required",
        "invalid_after_cursor" => "invalid_after_cursor",
        "invalid_delta_limit" => "invalid_delta_limit",
        "unsupported_publish_kind" => "unsupported_publish_kind",
        "invalid_agent_context" => "invalid_agent_context",
        "context_capacity_exceeded" => "context_capacity_exceeded",
        "invalid_binding" => "retrieval_refused",
        "retrieval_refused" => "retrieval_refused",
        _ => "invalid_context_request",
    }
}

fn event_digest_v1(domain: &[u8], identity: &ContextLedgerIdentityV1, payload: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for value in [
        identity.repository_id(),
        identity.workspace_id(),
        identity.task_id(),
        identity.authorization_scope_digest(),
        identity.agent_id(),
        identity.session_id(),
        identity.turn_id(),
        identity.connection_generation(),
    ] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(&identity.compaction_generation().to_le_bytes());
    hasher.update(&identity.lifecycle_generation().to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    hasher.finalize().to_hex().to_string()
}

fn bounded_digest_id_v1(prefix: &str, digest: &str) -> String {
    format!("{prefix}:{}", &digest[..digest.len().min(64)])
}

fn version_from_digest_v1(digest: &str) -> u64 {
    let mut bytes = [0_u8; 8];
    for (index, pair) in digest.as_bytes().chunks_exact(2).take(8).enumerate() {
        bytes[index] = std::str::from_utf8(pair)
            .ok()
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .unwrap_or(0);
    }
    u64::from_be_bytes(bytes).max(1).min(i64::MAX as u64)
}

fn now_ms_v1() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}
