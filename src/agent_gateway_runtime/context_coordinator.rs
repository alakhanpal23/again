//! Same-user local task context provider.
//!
//! Recipient identity comes only from the authenticated MCP transport. Task
//! and result identifiers remain bounded selectors inside that live scope;
//! neither a socket path nor a serialized identifier grants retrieval.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::agent_gateway::context::{
    CompletedReasoningObservationV1, ContextLedgerCursorV1, ContextLedgerIdentityV1,
    ContextLedgerSuggestionV1, ReasoningRetrievalIdentityV1, ReasoningUnknownV1,
};
use crate::agent_gateway_runtime::SharedObservedWorkspaceV1;
use crate::code_intelligence::{
    CodeIntelligenceIndexV1, CodeIntelligenceLimitsV1, CodeIntelligenceProviderV1,
    EditBriefCandidateKindV1, EditBriefRequestV1, index_preflight_refusal_v1,
};
use crate::mcp_gateway::{
    CapturedToolResult, EffectClass, EphemeralSecrets, Freshness, FreshnessMetadata, McpError,
    McpErrorCode, ProviderCall, ProviderCancellation, ProviderDescriptor, ProviderError,
    ProviderTool, ReasoningTransportRecipientV1, RecipientLifecycleSinkV1,
    ResponseWriteCompletionV1, SideEffectClassification, StructuredResultCapture, ToolCancellation,
    ToolDiscovery, ToolExecution,
};
use crate::store::{ContextLeaseAcquisitionV1, ContextLedgerEventInputV1, Store};
use crate::task_lifecycle::{
    MAX_TASK_ACCEPTANCE_CRITERIA_V1, MAX_TASK_ACCEPTANCE_CRITERION_BYTES_V1,
    MAX_TASK_DEPENDENCIES_V1, MAX_TASK_LIST_ITEMS_V1, TaskClaimOutcomeV1, TaskDefinitionV1,
    TaskStateV1,
};
use crate::workspace_authority::{RepositoryObservationPlanV1, StateDigestV1};

const INTERNAL_COMPLETION_FIELD_V1: &str = "__again_context_completion_v1";
const MAX_CONTEXT_DELTA_ITEMS_V1: usize = 64;
const MAX_CONTEXT_TEXT_BYTES_V1: usize = 1024;
const MAX_ACTIVE_CONTEXT_TASKS_V1: usize = 64;
const DEFAULT_CONTEXT_LEASE_TTL_MS_V1: u64 = 30_000;
const TASK_COORDINATION_LEASE_TTL_MS_V1: u64 = 5 * 60_000;
const TASK_COORDINATION_DEADLINE_MS_V1: i64 = 24 * 60 * 60 * 1_000;
const MAX_TASK_START_SOURCE_PREVIEWS_V1: usize = 2;
const MAX_TASK_START_SOURCE_PREVIEW_BYTES_V1: u64 = 2 * 1024;
const MAX_TASK_START_EXCERPT_SOURCE_BYTES_V1: u64 = 256 * 1024;

pub(crate) fn source_excerpt_v1(text: &str, prompt: &str) -> (String, usize, Option<usize>) {
    source_excerpt_with_budget_v1(
        text,
        prompt,
        MAX_TASK_START_SOURCE_PREVIEW_BYTES_V1 as usize,
    )
}

pub(crate) fn source_excerpt_with_budget_v1(
    text: &str,
    prompt: &str,
    budget: usize,
) -> (String, usize, Option<usize>) {
    let mut terms = Vec::new();
    for word in prompt.split_whitespace() {
        let word = word.trim_matches(|character: char| {
            !character.is_ascii_alphanumeric() && character != '.' && character != '_'
        });
        if word.contains('/') {
            continue;
        }
        if let Some((_, suffix)) = word.rsplit_once('.')
            && (4..=64).contains(&suffix.len())
        {
            terms.push(suffix);
        }
        if (4..=64).contains(&word.len()) {
            terms.push(word);
        }
    }
    let anchor = preferred_declaration_anchor_v1(text, prompt)
        .or_else(|| {
            terms.iter().find_map(|term| {
                let mut offset = 0;
                for line in text.split_inclusive('\n') {
                    if (line.contains("fn ") || line.contains("def ") || line.contains("function "))
                        && let Some(position) = line.find(term)
                    {
                        return Some(offset + position);
                    }
                    offset += line.len();
                }
                None
            })
        })
        .or_else(|| terms.iter().find_map(|term| text.find(term)))
        .unwrap_or(0);
    let mut start = text[..anchor].rfind('\n').map_or(0, |index| index + 1);
    for _ in 0..2 {
        if start == 0 {
            break;
        }
        start = text[..start - 1].rfind('\n').map_or(0, |index| index + 1);
    }
    let budget = budget.min(text.len().saturating_sub(1)).max(1);
    if anchor.saturating_sub(start) >= budget / 2 {
        start = anchor.saturating_sub(budget / 4);
        while !text.is_char_boundary(start) {
            start += 1;
        }
    }
    let mut end = (start + budget).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let start_line = text[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
    let end_line = text[..end].bytes().filter(|byte| *byte == b'\n').count() + 1;
    (text[start..end].to_owned(), start_line, Some(end_line))
}

fn preferred_declaration_anchor_v1(text: &str, prompt: &str) -> Option<usize> {
    let mut prompt_terms = Vec::new();
    for part in prompt.split(|character: char| !character.is_ascii_alphanumeric()) {
        if part.len() >= 4 && prompt_terms.len() < 32 {
            let term = part.to_ascii_lowercase();
            if !prompt_terms.contains(&term) {
                prompt_terms.push(term);
            }
        }
    }
    let mut best = None;
    let mut offset = 0;
    let mut test_attribute = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let declaration = if trimmed.starts_with("fn ") {
            Some((0, 3))
        } else if trimmed.starts_with("def ") {
            Some((0, 4))
        } else if trimmed.starts_with("function ") {
            Some((0, 9))
        } else if trimmed.starts_with("pub ")
            || trimmed.starts_with("pub(")
            || trimmed.starts_with("async ")
            || trimmed.starts_with("unsafe ")
        {
            trimmed.find(" fn ").map(|index| (index + 1, index + 4))
        } else {
            None
        };
        if let Some((keyword_start, name_start)) = declaration {
            let name = trimmed[name_start..]
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .next()
                .unwrap_or_default();
            if !test_attribute && !name.starts_with("test_") && !name.contains("oracle") {
                let name_parts = name
                    .split('_')
                    .filter(|part| part.len() >= 4)
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>();
                let score = prompt_terms
                    .iter()
                    .filter_map(|term| {
                        name_parts.iter().find_map(|part| {
                            (part == term
                                || (part.len().min(term.len()) >= 6
                                    && (part.starts_with(term) || term.starts_with(part))))
                            .then_some(part.len().min(term.len()))
                        })
                    })
                    .sum::<usize>();
                if score > best.map_or(0, |(prior, _)| prior) {
                    best = Some((score, offset + line.len() - trimmed.len() + keyword_start));
                }
            }
        }
        test_attribute = trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test]");
        offset += line.len();
    }
    best.map(|(_, anchor)| anchor)
}
const MAX_INLINE_PREVIEW_FAST_PATH_SOURCE_FILES_V1: usize = 256;
const MAX_DIRECT_SEARCH_MATCH_SOURCE_BYTES_V1: u64 = 8 * 1024;
const MAX_CONTEXT_FRESHNESS_SOURCES_V1: usize = 256;

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
    workspace: PathBuf,
    repository_id: String,
    workspace_id: String,
    observed_workspace: SharedObservedWorkspaceV1,
    code_index: Mutex<CodeIntelligenceIndexV1>,
    source_inventory_overflow: AtomicBool,
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
            workspace: workspace.to_path_buf(),
            repository_id: format!("repository:{}", &digest[..24]),
            workspace_id: format!("workspace:{}", &digest[..24]),
            observed_workspace,
            code_index: Mutex::new(
                CodeIntelligenceIndexV1::new(CodeIntelligenceLimitsV1::default())
                    .expect("default code-intelligence limits are valid"),
            ),
            source_inventory_overflow: AtomicBool::new(false),
            active: Mutex::new(BTreeMap::new()),
            current: Mutex::new(BTreeMap::new()),
            acknowledged: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn source_inventory_overflow(&self) -> bool {
        self.source_inventory_overflow.load(Ordering::Acquire)
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

    fn activate_canonical(
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

    fn activate(
        &self,
        recipient: &ReasoningTransportRecipientV1,
        requested_task_id: &str,
        authorization_scope_digest: &str,
    ) -> Result<ContextLedgerIdentityV1> {
        let task = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .context_task_by_alias_v1(
                &self.repository_id,
                &self.workspace_id,
                authorization_scope_digest,
                requested_task_id,
            )?
            .ok_or_else(|| anyhow!("task_not_started"))?;
        self.activate_canonical(
            recipient,
            &task.canonical_task_id,
            authorization_scope_digest,
        )
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
        observation_plan: &RepositoryObservationPlanV1,
        repository_digest: &str,
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
        let plan_json = serde_json::to_vec(observation_plan)?;
        store.admit_context_source_recipe_v1(
            &identity,
            binding,
            gateway_result_id,
            repository_digest,
            &plan_json,
        )?;
        let admission_version =
            store.context_result_admission_version_v1(&identity, gateway_result_id)?;
        let envelope_material = if admission_version == 1 {
            gateway_result_id.to_owned()
        } else {
            format!("{gateway_result_id}:{admission_version}")
        };
        let fact_id = if admission_version == 1 {
            bounded_digest_id_v1("fact", binding.request_digest())
        } else {
            format!(
                "{}:{admission_version}",
                bounded_digest_id_v1("fact", binding.request_digest())
            )
        };
        let fact = store.context_fact_from_verified_observations_v1(
            &identity,
            &fact_id,
            true,
            std::slice::from_ref(&source),
        )?;
        let fact_envelope = event_digest_v1(
            b"again.context.verified-fact-envelope.v1\0",
            &identity,
            envelope_material.as_bytes(),
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
        let observation_id = if admission_version == 1 {
            bounded_digest_id_v1("observation", binding.request_digest())
        } else {
            format!(
                "{}:{admission_version}",
                bounded_digest_id_v1("observation", binding.request_digest())
            )
        };
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
            envelope_material.as_bytes(),
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
            envelope_material.as_bytes(),
        );
        let _ = store.append_context_event_v1(
            &identity,
            &reference_envelope,
            &ContextLedgerEventInputV1::ResultReference {
                reference: retrieval,
                reference_version: admission_version,
                verified_sources: vec![source],
            },
        )?;
        Ok(())
    }

    pub(super) fn admit_direct_observation(
        &self,
        call: &ProviderCall,
        binding: &crate::store::ValidatedGatewayReadV1,
        recipe_json: &[u8],
        repository_digest: &str,
        observation_id: &str,
    ) -> Result<()> {
        self.admit_direct_observation_with_locator(
            call,
            binding,
            recipe_json,
            repository_digest,
            observation_id,
            &source_locator_v1(call),
        )
    }

    pub(super) fn admit_direct_observation_with_locator(
        &self,
        call: &ProviderCall,
        binding: &crate::store::ValidatedGatewayReadV1,
        recipe_json: &[u8],
        repository_digest: &str,
        observation_id: &str,
        locator: &str,
    ) -> Result<()> {
        let Some(identity) = self.active_identity_for_call(call) else {
            return Ok(());
        };
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let source =
            store.context_verified_observation_v1(&identity, binding, observation_id, locator)?;
        store.admit_context_source_recipe_v1(
            &identity,
            binding,
            observation_id,
            repository_digest,
            recipe_json,
        )?;
        let fact_id = bounded_digest_id_v1("direct-fact", binding.request_digest());
        for _ in 0..3 {
            let Some(version) =
                store.context_direct_fact_admission_v1(&identity, &fact_id, observation_id)?
            else {
                return Ok(());
            };
            let fact = store.context_fact_from_verified_observations_v1(
                &identity,
                &fact_id,
                true,
                std::slice::from_ref(&source),
            )?;
            let material = format!("{observation_id}:{version}");
            let envelope = event_digest_v1(
                b"again.context.direct-fact-envelope.v1\0",
                &identity,
                material.as_bytes(),
            );
            match store.admit_context_fact_v1(
                &identity,
                &envelope,
                version,
                &fact,
                std::slice::from_ref(&source),
            ) {
                Ok(_) => return Ok(()),
                Err(error) => {
                    if store.context_direct_fact_admission_v1(
                        &identity,
                        &fact_id,
                        observation_id,
                    )? == Some(version)
                    {
                        return Err(error);
                    }
                }
            }
        }
        bail!("direct context fact admission did not converge")
    }

    pub(super) fn direct_observation_current(
        &self,
        call: &ProviderCall,
        binding: &crate::store::ValidatedGatewayReadV1,
        observation_id: &str,
    ) -> Result<bool> {
        let Some(identity) = self.active_identity_for_call(call) else {
            return Ok(false);
        };
        let fact_id = bounded_digest_id_v1("direct-fact", binding.request_digest());
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Ok(store
            .context_direct_fact_admission_v1(&identity, &fact_id, observation_id)?
            .is_none()
            && store.get_gateway_result(binding, observation_id)?.is_some())
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

    pub(super) fn invalidate_source_observation(
        &self,
        call: &ProviderCall,
        gateway_result_id: &str,
    ) -> Result<()> {
        let Some(identity) = self.active_identity_for_call(call) else {
            return Ok(());
        };
        let material = format!(
            "{gateway_result_id}\0{}\0{}",
            call.logical_call_id.as_str(),
            call.physical_attempt_id.get()
        );
        let envelope = event_digest_v1(
            b"again.context.source-observation-unavailable-envelope.v1\0",
            &identity,
            material.as_bytes(),
        );
        let _ = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .invalidate_context_source_observation_v1(&identity, &envelope, gateway_result_id)?;
        Ok(())
    }

    pub(super) fn result_reference_current(
        &self,
        call: &ProviderCall,
        gateway_result_id: &str,
    ) -> Result<bool> {
        let Some(identity) = self.active_identity_for_call(call) else {
            return Ok(false);
        };
        self.store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .context_result_reference_current_v1(&identity, gateway_result_id)
    }

    fn revalidate_source(
        &self,
        observed: &SharedObservedWorkspaceV1,
        call: &ProviderCall,
        identity: &ContextLedgerIdentityV1,
        gateway_result_id: &str,
    ) -> Result<bool> {
        let recipe = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .context_source_recipe_v1(identity, gateway_result_id)?;
        let current = match recipe {
            Some((expected_digest, plan_json)) => {
                if let Ok(recipe) = serde_json::from_slice::<Value>(&plan_json)
                    && recipe["schema"] == "again.context.direct-search-match-recipe.v1"
                {
                    direct_search_match_current_v1(observed, &recipe, &expected_digest)
                } else if let Ok(recipe) = serde_json::from_slice::<Value>(&plan_json)
                    && (recipe["schema"] == "again.context.direct-stat-recipe.v1"
                        || recipe["schema"] == "again.context.direct-repository-recipe.v1")
                {
                    let legacy_stat = recipe["schema"] == "again.context.direct-stat-recipe.v1";
                    let tool = if legacy_stat {
                        Some("stat")
                    } else {
                        match recipe["tool"].as_str() {
                            Some("repo.stat") => Some("stat"),
                            Some("repo.read") => Some("read"),
                            _ => None,
                        }
                    };
                    recipe.as_object().is_some_and(|object| object.len() == if legacy_stat { 3 } else { 4 })
                        && recipe["arguments"].is_object()
                        && recipe["outputDigest"] == expected_digest
                        && tool.is_some_and(|tool| {
                            crate::agent_gateway_runtime::repository_tools::execute_repository_tool_v1(
                                &observed.execution_epoch,
                                tool,
                                &recipe["arguments"],
                            )
                            .ok()
                            .is_some_and(|value| {
                                blake3::hash(&super::canonical_json_bytes_v1(&value))
                                    .to_hex()
                                    .as_str() == expected_digest
                            })
                        })
                } else {
                    match serde_json::from_slice::<RepositoryObservationPlanV1>(&plan_json) {
                        Ok(plan) => observed
                            .manifest
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .observe_repository(&plan)
                            .is_ok_and(|repository| {
                                repository.digest().to_hex() == expected_digest
                            }),
                        Err(_) => false,
                    }
                }
            }
            None => false,
        };
        if !current {
            self.invalidate_source_observation(call, gateway_result_id)?;
        }
        Ok(current)
    }

    fn refresh_current_sources(
        &self,
        call: &ProviderCall,
        identity: &ContextLedgerIdentityV1,
    ) -> Result<()> {
        let source_ids = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .current_context_source_ids_v1(identity, MAX_CONTEXT_FRESHNESS_SOURCES_V1)?;
        if source_ids.is_empty() {
            return Ok(());
        }
        let observed = SharedObservedWorkspaceV1::begin(&self.workspace)
            .map_err(|_| anyhow!("context_freshness_unavailable"))?;
        for result_id in source_ids {
            self.revalidate_source(&observed, call, identity, &result_id)?;
        }
        Ok(())
    }

    fn explicit_task_source_previews(&self, prompt: &str) -> Vec<Value> {
        let mut previews = Vec::new();
        let mut seen = BTreeSet::new();
        for token in prompt.split_whitespace() {
            let trimmed = token.trim_matches(|character: char| {
                matches!(
                    character,
                    '`' | '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';'
                )
            });
            let candidate = trimmed.split_once(':').map_or(trimmed, |(path, _)| path);
            let path = Path::new(candidate);
            if !path
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
                || !matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some("rs" | "py" | "pyi" | "go" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs")
                )
                || !seen.insert(candidate.to_owned())
            {
                continue;
            }
            let Ok(bytes) = self
                .observed_workspace
                .execution_epoch
                .read_repository_file(path, MAX_TASK_START_EXCERPT_SOURCE_BYTES_V1)
            else {
                continue;
            };
            let digest = StateDigestV1::from_domain_and_bytes(
                b"again.code-intelligence.source-bytes.v1",
                &bytes,
            )
            .to_hex();
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            let complete = text.len() as u64 <= MAX_TASK_START_SOURCE_PREVIEW_BYTES_V1;
            let (preview_text, start_line, end_line) = if complete {
                (text, 1, None)
            } else {
                source_excerpt_v1(&text, prompt)
            };
            previews.push(json!({
                "path": candidate,
                "sourceDigest": digest,
                "text": preview_text,
                "complete": complete,
                "startLine": start_line,
                "endLine": end_line,
                "origin": "explicit_task_path"
            }));
            if previews.len() == MAX_TASK_START_SOURCE_PREVIEWS_V1 {
                break;
            }
        }
        if previews.len() < MAX_TASK_START_SOURCE_PREVIEWS_V1
            && prompt.to_ascii_lowercase().contains("test")
            && let Some((source, extension)) = previews.iter().find_map(|preview| {
                preview["path"].as_str().and_then(|path| {
                    let path = Path::new(path);
                    let extension = path.extension()?.to_str()?;
                    (!path.starts_with("tests") && matches!(extension, "py" | "js" | "mjs" | "cjs"))
                        .then(|| {
                            Some((path.file_stem()?.to_str()?.to_owned(), extension.to_owned()))
                        })
                        .flatten()
                })
            })
        {
            let candidate = format!("tests/test_{source}.{extension}");
            if seen.insert(candidate.clone())
                && let Ok(bytes) = self
                    .observed_workspace
                    .execution_epoch
                    .read_repository_file(
                        Path::new(&candidate),
                        MAX_TASK_START_SOURCE_PREVIEW_BYTES_V1,
                    )
                && let Ok(text) = String::from_utf8(bytes.clone())
            {
                previews.push(json!({
                    "path": candidate,
                    "sourceDigest": StateDigestV1::from_domain_and_bytes(
                        b"again.code-intelligence.source-bytes.v1", &bytes
                    ).to_hex(),
                    "text": text,
                    "complete": true,
                    "origin": "test_path_convention_candidate",
                    "relevance": "unverified"
                }));
            }
        }
        previews
    }

    fn task_start(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(
            &call.arguments,
            &[
                "taskId",
                "task",
                "acceptanceCriteria",
                "parentTaskId",
                "dependencyTaskIds",
                "supersedesTaskId",
                "includeSourcePreviews",
                "previewOnly",
            ],
        )?;
        let requested_task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let include_source_previews = match call.arguments.get("includeSourcePreviews") {
            Some(value) => value
                .as_bool()
                .ok_or_else(|| anyhow!("includeSourcePreviews_must_be_boolean"))?,
            None => false,
        };
        let preview_only = match call.arguments.get("previewOnly") {
            Some(value) => value
                .as_bool()
                .ok_or_else(|| anyhow!("previewOnly_must_be_boolean"))?,
            None => false,
        };
        let prompt = call
            .arguments
            .get("task")
            .and_then(Value::as_str)
            .unwrap_or(requested_task_id);
        let acceptance_criteria = bounded_string_array_v1(
            &call.arguments,
            "acceptanceCriteria",
            MAX_TASK_ACCEPTANCE_CRITERIA_V1,
            MAX_TASK_ACCEPTANCE_CRITERION_BYTES_V1,
        )?;
        let dependencies = bounded_string_array_v1(
            &call.arguments,
            "dependencyTaskIds",
            MAX_TASK_DEPENDENCIES_V1,
            128,
        )?;
        let parent = optional_bounded_string_v1(&call.arguments, "parentTaskId", 128)?;
        let supersedes = optional_bounded_string_v1(&call.arguments, "supersedesTaskId", 128)?;
        let definition = TaskDefinitionV1::new(
            prompt,
            acceptance_criteria,
            parent,
            dependencies,
            supersedes,
        )?;
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let authorization_scope_digest =
            crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope);
        let task = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .start_task_v1(
                &self.repository_id,
                &self.workspace_id,
                &authorization_scope_digest,
                requested_task_id,
                &definition,
            )?;
        let identity = self.activate_canonical(
            recipient,
            &task.task.canonical_task_id,
            &authorization_scope_digest,
        )?;
        let coordination = if preview_only {
            let peer = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .preview_task_leader_v1(&identity)?;
            json!({
                "status": "preview",
                "stateGeneration": task.task.state_generation,
                "guidance": "claim_from_agent_session_before_coordinated_work",
                "peerActive": peer.is_some(),
                "peerLeaderAgentId": peer.as_ref().map(|item| item.0.as_str()),
                "peerLeaseExpiresAtMs": peer.as_ref().map(|item| item.1)
            })
        } else {
            let outcome = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .claim_task_v1(
                    &identity,
                    task.task.state_generation,
                    TASK_COORDINATION_LEASE_TTL_MS_V1,
                    now_ms_v1().saturating_add(TASK_COORDINATION_DEADLINE_MS_V1),
                )?;
            match outcome {
                TaskClaimOutcomeV1::Leader {
                    lease_id,
                    lease_generation,
                    state_generation,
                    expires_at_ms,
                } => json!({
                    "status": "leader",
                    "leaseId": lease_id,
                    "leaseGeneration": lease_generation,
                    "stateGeneration": state_generation,
                    "expiresAtMs": expires_at_ms,
                    "guidance": "proceed_and_publish_findings"
                }),
                TaskClaimOutcomeV1::Join {
                    lease_id,
                    lease_generation,
                    state_generation,
                    leader_agent_id,
                    expires_at_ms,
                } => json!({
                    "status": "join",
                    "leaseId": lease_id,
                    "leaseGeneration": lease_generation,
                    "stateGeneration": state_generation,
                    "leaderAgentId": leader_agent_id,
                    "expiresAtMs": expires_at_ms,
                    "guidance": "inspect_shared_context_before_repeating_work"
                }),
                TaskClaimOutcomeV1::Waiting {
                    state_generation,
                    blockers,
                } => json!({
                    "status": "waiting",
                    "stateGeneration": state_generation,
                    "blockers": blockers,
                    "guidance": "wait_for_completed_dependencies"
                }),
                TaskClaimOutcomeV1::Terminal {
                    state,
                    state_generation,
                } => json!({
                    "status": "terminal",
                    "state": state,
                    "stateGeneration": state_generation,
                    "guidance": "inspect_existing_task_history"
                }),
            }
        };
        let freshness_issue = match self.refresh_current_sources(call, &identity) {
            Ok(()) => None,
            Err(error)
                if matches!(
                    error.to_string().as_str(),
                    "context_freshness_capacity_exceeded" | "context_freshness_unavailable"
                ) =>
            {
                Some(error.to_string())
            }
            Err(error) => return Err(error),
        };
        let snapshot = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .context_task_snapshot_v1(&identity)?;
        let cursor = snapshot.cursor();
        let index_preflight_refusal = index_preflight_refusal_v1(
            &self.workspace,
            &CodeIntelligenceLimitsV1::default(),
            Duration::from_millis(50),
        );
        self.source_inventory_overflow.store(
            index_preflight_refusal == Some("index_preflight_file_budget_exceeded"),
            Ordering::Release,
        );
        let explicit_previews = if include_source_previews {
            self.explicit_task_source_previews(task.task.definition.prompt())
        } else {
            Vec::new()
        };
        let early_brain = if include_source_previews
            && explicit_previews.is_empty()
            && freshness_issue.is_none()
            && call.authorization_scope.as_str()
                == crate::brain::local_brain_scope_v1(&self.workspace)
        {
            let store = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            crate::brain::repository_brief_for_task_v1(
                &store,
                &self.workspace,
                &Value::Array(Vec::new()),
                &json!({ "candidates": [] }),
                crate::brain::BrainTaskQueryV1 {
                    task_text: prompt,
                    repository_id: &self.repository_id,
                    workspace_id: &self.workspace_id,
                    authorization_scope_digest: identity.authorization_scope_digest(),
                },
            )
            .ok()
            .flatten()
        } else {
            None
        };
        let brain_has_current_preview = early_brain.as_ref().is_some_and(|brain| {
            brain["recentCurrentFiles"].as_array().is_some_and(|files| {
                files.iter().any(|file| {
                    file["currentCompletePreview"].as_str().is_some()
                        || file["currentPartialPreview"]["text"].as_str().is_some()
                })
            })
        });
        let large_enough_for_preview_fast_path = !explicit_previews.is_empty()
            && index_preflight_refusal.is_none()
            && index_preflight_refusal_v1(
                &self.workspace,
                &CodeIntelligenceLimitsV1 {
                    max_files: MAX_INLINE_PREVIEW_FAST_PATH_SOURCE_FILES_V1,
                    ..CodeIntelligenceLimitsV1::default()
                },
                Duration::from_millis(50),
            )
            .is_some();
        let (mut code_brief, mut source_previews) = if brain_has_current_preview {
            (
                json!({
                    "schemaVersion": 1,
                    "candidates": [],
                    "incomplete": true,
                    "unknowns": [{ "kind": "index_skipped_for_current_brain_preview" }]
                }),
                explicit_previews,
            )
        } else if let Some(reason) = index_preflight_refusal {
            (
                json!({
                    "schemaVersion": 1,
                    "candidates": [],
                    "incomplete": true,
                    "unknowns": [{ "kind": reason }]
                }),
                explicit_previews,
            )
        } else if large_enough_for_preview_fast_path {
            (
                json!({
                    "schemaVersion": 1,
                    "candidates": [],
                    "incomplete": true,
                    "unknowns": [{ "kind": "index_skipped_for_complete_explicit_preview" }]
                }),
                explicit_previews,
            )
        } else {
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
            let request = EditBriefRequestV1::new(task.task.definition.prompt())
                .and_then(|request| request.with_maximum_candidates(24));
            match (status, request) {
                (Ok(_), Some(request)) => {
                    let brief = index.compile_edit_brief_v1(&request, None);
                    let mut previews = explicit_previews;
                    let mut seen = previews
                        .iter()
                        .filter_map(|preview| preview["path"].as_str())
                        .map(str::to_owned)
                        .collect::<BTreeSet<_>>();
                    for candidate in brief
                        .candidates()
                        .iter()
                        .filter(|_| include_source_previews)
                    {
                        if previews.len() == MAX_TASK_START_SOURCE_PREVIEWS_V1 {
                            break;
                        }
                        if candidate.kind() != EditBriefCandidateKindV1::File
                            || !seen.insert(candidate.locator().path().to_owned())
                        {
                            continue;
                        }
                        let locator = candidate.locator();
                        let path = Path::new(locator.path());
                        let Ok(bytes) = self
                            .observed_workspace
                            .execution_epoch
                            .read_repository_file(path, MAX_TASK_START_EXCERPT_SOURCE_BYTES_V1)
                        else {
                            continue;
                        };
                        if StateDigestV1::from_domain_and_bytes(
                            b"again.code-intelligence.source-bytes.v1",
                            &bytes,
                        )
                        .to_hex()
                            != locator.source_digest()
                        {
                            continue;
                        }
                        let Ok(text) = String::from_utf8(bytes) else {
                            continue;
                        };
                        let complete = text.len() as u64 <= MAX_TASK_START_SOURCE_PREVIEW_BYTES_V1;
                        let (preview_text, start_line, end_line) = if complete {
                            (text, 1, None)
                        } else {
                            source_excerpt_v1(&text, task.task.definition.prompt())
                        };
                        previews.push(json!({
                            "path": locator.path(),
                            "sourceDigest": locator.source_digest(),
                            "text": preview_text,
                            "complete": complete,
                            "startLine": start_line,
                            "endLine": end_line,
                            "origin": "indexed_candidate"
                        }));
                        if previews.len() == MAX_TASK_START_SOURCE_PREVIEWS_V1 {
                            break;
                        }
                    }
                    (serde_json::to_value(brief)?, previews)
                }
                _ => (
                    json!({
                        "schemaVersion": 1,
                        "candidates": [],
                        "incomplete": true,
                        "unknowns": [{ "kind": "index_unavailable" }]
                    }),
                    Vec::new(),
                ),
            }
        };
        if freshness_issue.is_some() {
            code_brief = json!({
                "schemaVersion": 1,
                "candidates": [],
                "incomplete": true,
                "unknowns": [{ "kind": "context_freshness_unverified" }]
            });
            source_previews.clear();
        }
        let delivery_key = Self::delivery_key(&identity);
        let acknowledged = self
            .acknowledged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&delivery_key)
            .copied();
        let (presentation, context, omitted_bytes) = if let Some(reason) = freshness_issue.as_ref()
        {
            let mut context = serde_json::to_value(&snapshot)?;
            let object = context
                .as_object_mut()
                .ok_or_else(|| anyhow!("context_task_corrupt"))?;
            object.insert("current_facts".to_owned(), json!([]));
            object.insert("result_references".to_owned(), json!([]));
            object.insert("incomplete".to_owned(), json!(true));
            object.insert("unknowns".to_owned(), json!([{ "kind": reason }]));
            ("full", context, 0)
        } else if let Some(after) = acknowledged {
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
        let again_brain = if brain_has_current_preview {
            early_brain
        } else if call.authorization_scope.as_str()
            == crate::brain::local_brain_scope_v1(&self.workspace)
        {
            let store = self
                .store
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            crate::brain::repository_brief_for_task_v1(
                &store,
                &self.workspace,
                &Value::Array(source_previews.clone()),
                &code_brief,
                crate::brain::BrainTaskQueryV1 {
                    task_text: prompt,
                    repository_id: &self.repository_id,
                    workspace_id: &self.workspace_id,
                    authorization_scope_digest: identity.authorization_scope_digest(),
                },
            )
            .ok()
            .flatten()
        } else {
            None
        };
        let structured = json!({
            "schemaVersion": 1,
            "operation": "task.start",
            "presentation": presentation,
            "taskId": identity.task_id(),
            "requestedTaskId": task.task.requested_task_id,
            "taskIntent": {
                "canonicalTaskId": task.task.canonical_task_id,
                "definition": task.task.definition,
                "revision": task.task.revision,
                "state": task.task.state,
                "stateGeneration": task.task.state_generation,
                "blockers": task.task.blockers,
                "matchedBy": task.matched_by,
                "authority": "agent_supplied_intent",
                "verified": false
            },
            "coordination": coordination,
            "cursor": cursor.sequence(),
            "context": context,
            "contextFreshness": match freshness_issue.as_ref() {
                Some(reason) => json!({ "status": "incomplete", "reason": reason }),
                None => json!({ "status": "current" }),
            },
            "relevantCode": code_brief,
            "sourcePreviews": source_previews,
            "againBrain": again_brain,
            "validationPreview": validation_preview_v1(&self.workspace, &source_previews, &code_brief),
            "compulsoryPlan": false
        });
        if freshness_issue.is_some() {
            return Ok(ContextOperationResultV1::exact(task_start_result_v1(
                structured,
            )));
        }
        Ok(ContextOperationResultV1::delivered(
            task_start_result_v1(structured),
            Box::new(ContextDeliveryCompletionV1 {
                coordinator: Arc::clone(self),
                identity,
                through: cursor,
                omitted_bytes,
            }),
        ))
    }

    fn task_inspect(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(&call.arguments, &["taskId"])?;
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let authorization =
            crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope);
        let task = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .inspect_task_v1(
                &self.repository_id,
                &self.workspace_id,
                &authorization,
                task_id,
            )?
            .ok_or_else(|| anyhow!("task_not_started"))?;
        Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
            "schemaVersion": 1,
            "operation": "task.inspect",
            "task": task
        }))))
    }

    fn task_list(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(&call.arguments, &["limit"])?;
        let limit = call
            .arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(MAX_TASK_LIST_ITEMS_V1 as u64);
        let limit = usize::try_from(limit).context("invalid_task_list_limit")?;
        let authorization =
            crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope);
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let tasks = store.list_tasks_v1(
            &self.repository_id,
            &self.workspace_id,
            &authorization,
            limit,
        )?;
        let quota = store.task_quota_status_v1(&self.repository_id, &self.workspace_id)?;
        Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
            "schemaVersion": 1,
            "operation": "task.list",
            "tasks": tasks,
            "quota": quota
        }))))
    }

    fn task_claim(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(
            &call.arguments,
            &["taskId", "expectedStateGeneration", "ttlMs"],
        )?;
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let expected = call
            .arguments
            .get("expectedStateGeneration")
            .and_then(Value::as_u64)
            .filter(|generation| *generation > 0)
            .ok_or_else(|| anyhow!("invalid_task_state_generation"))?;
        let ttl_ms = call
            .arguments
            .get("ttlMs")
            .and_then(Value::as_u64)
            .unwrap_or(TASK_COORDINATION_LEASE_TTL_MS_V1);
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let authorization =
            crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope);
        let identity = self.activate(recipient, task_id, &authorization)?;
        let outcome = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .claim_task_v1(
                &identity,
                expected,
                ttl_ms,
                now_ms_v1().saturating_add(TASK_COORDINATION_DEADLINE_MS_V1),
            )?;
        Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
            "schemaVersion": 1,
            "operation": "task.claim",
            "taskId": identity.task_id(),
            "outcome": outcome
        }))))
    }

    fn task_transition(self: &Arc<Self>, call: &ProviderCall) -> Result<ContextOperationResultV1> {
        require_keys_v1(
            &call.arguments,
            &[
                "taskId",
                "leaseId",
                "expectedStateGeneration",
                "state",
                "reason",
            ],
        )?;
        let task_id = bounded_string_v1(&call.arguments, "taskId", 128)?;
        let lease_id = bounded_string_v1(&call.arguments, "leaseId", 128)?;
        let expected = call
            .arguments
            .get("expectedStateGeneration")
            .and_then(Value::as_u64)
            .filter(|generation| *generation > 0)
            .ok_or_else(|| anyhow!("invalid_task_state_generation"))?;
        let target = TaskStateV1::parse(bounded_string_v1(&call.arguments, "state", 32)?)?;
        let reason = bounded_text_v1(&call.arguments, "reason", 512)?;
        let recipient = call
            .transport_recipient_v1()
            .ok_or_else(|| anyhow!("recipient_authority_required"))?;
        let authorization =
            crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope);
        let identity = self.activate(recipient, task_id, &authorization)?;
        let task = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .transition_task_v1(&identity, lease_id, expected, target, reason)?;
        Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
            "schemaVersion": 1,
            "operation": "task.transition",
            "task": task
        }))))
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
        if let Err(error) = self.refresh_current_sources(call, &identity) {
            let reason = error.to_string();
            if matches!(
                reason.as_str(),
                "context_freshness_capacity_exceeded" | "context_freshness_unavailable"
            ) {
                return Ok(ContextOperationResultV1::exact(tool_result_v1(json!({
                    "schemaVersion": 1,
                    "operation": "context.delta",
                    "presentation": "incomplete",
                    "delta": {
                        "after": after,
                        "cursor": after,
                        "has_more": true,
                        "events": [],
                        "incomplete": true,
                        "unknowns": [{ "kind": reason }]
                    }
                }))));
            }
            return Err(error);
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
            "work_heartbeat" => {
                require_keys_v1(&call.arguments, &["taskId", "kind", "leaseId", "ttlMs"])?;
                let lease_id = bounded_string_v1(&call.arguments, "leaseId", 128)?;
                let ttl_ms = call
                    .arguments
                    .get("ttlMs")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_CONTEXT_LEASE_TTL_MS_V1);
                let expires_at_ms =
                    store.heartbeat_context_lease_v1(&identity, lease_id, ttl_ms)?;
                json!({ "status": "renewed", "expiresAtMs": expires_at_ms })
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
        let identity = self
            .activate(
                recipient,
                task_id,
                &crate::mcp_gateway::authorization_scope_digest_v1(&call.authorization_scope),
            )
            .map_err(|error| {
                if error.to_string() == "task_not_started" {
                    anyhow!("retrieval_refused")
                } else {
                    error
                }
            })?;
        let current_reference = self
            .store
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .context_result_reference_current_v1(&identity, result_id)
            .map_err(|_| anyhow!("retrieval_refused"))?;
        if !current_reference {
            bail!("retrieval_refused");
        }
        let observed = SharedObservedWorkspaceV1::begin(&self.workspace)
            .map_err(|_| anyhow!("retrieval_refused"))?;
        if !self
            .revalidate_source(&observed, call, &identity, result_id)
            .map_err(|_| anyhow!("retrieval_refused"))?
        {
            bail!("retrieval_refused");
        }
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
            ContextProviderKindV1::Task => [
                (
                    "start",
                    "Start immutable task with shared context",
                    "Start a coding task with a stable task ID and exact task text. Converge exact duplicate intent, enforce dependency readiness, and return a bounded edit brief, shared findings, and coordination status. Set includeSourcePreviews=true to receive up to two digest-checked source previews: complete for small files or line-numbered partial excerpts for larger files. Use complete previews before redundant reads; inspect more of a partial file when the edit requires it. After editing, reread only when current bytes are needed and the edit result did not show them.",
                    json!({
                        "type": "object",
                        "properties": {
                            "taskId": { "type": "string", "maxLength": 128 },
                            "task": { "type": "string", "maxLength": 8192 },
                            "acceptanceCriteria": {
                                "type": "array", "maxItems": MAX_TASK_ACCEPTANCE_CRITERIA_V1,
                                "items": { "type": "string", "maxLength": MAX_TASK_ACCEPTANCE_CRITERION_BYTES_V1 }
                            },
                            "parentTaskId": { "type": "string", "maxLength": 128 },
                            "dependencyTaskIds": {
                                "type": "array", "maxItems": MAX_TASK_DEPENDENCIES_V1,
                                "items": { "type": "string", "maxLength": 128 }
                            },
                            "supersedesTaskId": { "type": "string", "maxLength": 128 },
                            "includeSourcePreviews": { "type": "boolean", "default": false },
                            "previewOnly": { "type": "boolean", "default": false }
                        },
                        "required": ["taskId"],
                        "additionalProperties": false
                    }),
                    false,
                ),
                (
                    "inspect",
                    "Inspect durable task",
                    "Read one authorized immutable task definition, state, generation, and dependency blockers.",
                    json!({
                        "type": "object",
                        "properties": { "taskId": { "type": "string", "maxLength": 128 } },
                        "required": ["taskId"],
                        "additionalProperties": false
                    }),
                    true,
                ),
                (
                    "list",
                    "List durable tasks",
                    "Read a bounded deterministic list of tasks in the authenticated workspace scope.",
                    json!({
                        "type": "object",
                        "properties": {
                            "limit": { "type": "integer", "minimum": 1, "maximum": MAX_TASK_LIST_ITEMS_V1 }
                        },
                        "additionalProperties": false
                    }),
                    true,
                ),
                (
                    "claim",
                    "Claim ready task",
                    "CAS-claim a ready or blocked task, or join its current same-scope leader lease.",
                    json!({
                        "type": "object",
                        "properties": {
                            "taskId": { "type": "string", "maxLength": 128 },
                            "expectedStateGeneration": { "type": "integer", "minimum": 1 },
                            "ttlMs": { "type": "integer", "minimum": 1, "maximum": TASK_COORDINATION_LEASE_TTL_MS_V1 }
                        },
                        "required": ["taskId", "expectedStateGeneration"],
                        "additionalProperties": false
                    }),
                    false,
                ),
                (
                    "transition",
                    "Transition claimed task",
                    "CAS-transition an actively claimed task to blocked or an immutable terminal state.",
                    json!({
                        "type": "object",
                        "properties": {
                            "taskId": { "type": "string", "maxLength": 128 },
                            "leaseId": { "type": "string", "maxLength": 128 },
                            "expectedStateGeneration": { "type": "integer", "minimum": 1 },
                            "state": { "type": "string", "enum": ["blocked", "completed", "failed", "cancelled"] },
                            "reason": { "type": "string", "maxLength": 512 }
                        },
                        "required": ["taskId", "leaseId", "expectedStateGeneration", "state", "reason"],
                        "additionalProperties": false
                    }),
                    false,
                ),
            ]
            .into_iter()
            .map(|(name, title, description, input_schema, read_only)| ProviderTool {
                name: name.to_owned(),
                title: Some(title.to_owned()),
                description: Some(description.to_owned()),
                input_schema,
                output_schema: Some(output()),
                annotations: Some(json!({ "readOnlyHint": read_only })),
                meta: None,
            })
            .collect(),
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
                            "kind": { "type": "string", "enum": ["suggestion", "unknown", "work_start", "work_heartbeat", "work_finish", "work_cancel"] },
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
                    description: Some(
                        match name {
                            "delta" => "Read current task findings and invalidations after the last seen cursor before repeating another agent's investigation. Returned facts are source-bound; agent suggestions remain unverified.",
                            "publish" => "Share a task-scoped suggestion, explicit unknown, or bounded work-lease update with other local agents. Agent-authored statements do not become verified facts.",
                            "retrieve" => "Retrieve the complete exact result bytes for a reference in this authenticated task scope. A result ID alone does not grant access.",
                            "cancel" => "Retire this recipient's active task context and compact delivery authority; optionally cancel a matching work lease.",
                            _ => unreachable!("closed context tool list"),
                        }
                        .to_owned(),
                    ),
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
        if matches!(
            upstream_tool_name,
            "delta" | "retrieve" | "inspect" | "list"
        ) {
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
            (ContextProviderKindV1::Task, "inspect") => self.coordinator.task_inspect(&call),
            (ContextProviderKindV1::Task, "list") => self.coordinator.task_list(&call),
            (ContextProviderKindV1::Task, "claim") => self.coordinator.task_claim(&call),
            (ContextProviderKindV1::Task, "transition") => self.coordinator.task_transition(&call),
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

fn package_validation_preview_v1(workspace: &Path, candidates: &[&str]) -> Option<Value> {
    let mut suggestions = Vec::new();
    for path in candidates
        .iter()
        .copied()
        .filter(|path| crate::validation_hint::is_javascript_source_v1(path))
    {
        let Some(suggestion) =
            crate::validation_hint::package_test_suggestion_for_source_v1(workspace, path)
        else {
            continue;
        };
        if suggestions
            .iter()
            .any(|prior: &crate::validation_hint::PackageTestSuggestionV1| {
                prior.manifest_path() == suggestion.manifest_path()
            })
        {
            continue;
        }
        suggestions.push(suggestion);
        if suggestions.len() == 2 {
            break;
        }
    }
    (!suggestions.is_empty()).then(|| {
        json!({
            "status": "execute_required",
            "selectors": suggestions
                .into_iter()
                .map(crate::validation_hint::PackageTestSuggestionV1::selector_json)
                .collect::<Vec<_>>(),
            "reason": "current package manifests declare test scripts; run each command in its workingDirectory to validate"
        })
    })
}

fn validation_preview_v1(
    workspace: &Path,
    source_previews: &[Value],
    relevant_code: &Value,
) -> Value {
    let unittest_candidate = source_previews.iter().any(|preview| {
        matches!(
            preview["origin"].as_str(),
            Some("test_path_convention_candidate" | "indexed_candidate")
        ) && preview["complete"] == true
            && preview["path"]
                .as_str()
                .is_some_and(|path| path.starts_with("tests/test_") && path.ends_with(".py"))
            && preview["text"].as_str().is_some_and(|text| {
                text.contains("import unittest") && text.contains("unittest.TestCase")
            })
    });
    let node_test_candidate = source_previews.iter().find_map(|preview| {
        let path = preview["path"].as_str()?;
        (matches!(
            preview["origin"].as_str(),
            Some("test_path_convention_candidate" | "indexed_candidate")
        ) && preview["complete"] == true
            && path.starts_with("tests/test_")
            && path.len() <= 256
            && path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
            })
            && Path::new(path)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            && matches!(
                Path::new(path).extension().and_then(|ext| ext.to_str()),
                Some("js" | "mjs" | "cjs")
            )
            && preview["text"]
                .as_str()
                .is_some_and(|text| text.contains("node:test")))
        .then(|| format!("node --test {path}"))
    });
    let candidates = source_previews
        .iter()
        .filter_map(|preview| preview["path"].as_str())
        .chain(
            relevant_code["candidates"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|candidate| candidate["locator"]["path"].as_str()),
        )
        .take(16)
        .collect::<Vec<_>>();
    let explicit_javascript_paths = source_previews
        .iter()
        .filter(|preview| preview["origin"] == "explicit_task_path" && preview["complete"] == true)
        .filter_map(|preview| preview["path"].as_str())
        .filter(|path| crate::validation_hint::is_javascript_source_v1(path))
        .collect::<Vec<_>>();
    let mut rust_source = false;
    let mut go_source = false;
    let mut javascript_source = false;
    for path in &candidates {
        rust_source |= path.ends_with(".rs");
        go_source |= path.ends_with(".go");
        javascript_source |= crate::validation_hint::is_javascript_source_v1(path);
    }
    let (command, basis, reason) = if unittest_candidate {
        (
            Some("python3 -m unittest discover -s tests"),
            "complete_test_preview",
            "unverified unittest convention; run the command to validate",
        )
    } else if let Some(command) = node_test_candidate.as_deref() {
        (
            Some(command),
            "complete_node_test_preview",
            "unverified Node test convention; run the command to validate",
        )
    } else if rust_source && workspace.join("Cargo.toml").is_file() {
        (
            Some("cargo test"),
            "current_manifest_and_source_candidate",
            "unverified Cargo convention; run the command to validate",
        )
    } else if go_source && workspace.join("go.mod").is_file() {
        (
            Some("go test ./..."),
            "current_manifest_and_source_candidate",
            "unverified Go convention; run the command to validate",
        )
    } else if javascript_source
        && let Some(preview) = package_validation_preview_v1(
            workspace,
            if explicit_javascript_paths.is_empty() {
                &candidates
            } else {
                &explicit_javascript_paths
            },
        )
    {
        return preview;
    } else {
        (None, "", "")
    };
    if let Some(command) = command {
        json!({
            "status": "execute_required",
            "selectors": [{
                "command": command,
                "basis": basis,
                "verified": false
            }],
            "reason": reason
        })
    } else {
        json!({
            "status": "execute_required",
            "selectors": [],
            "reason": "no qualified validation profile supplied a proven selector"
        })
    }
}

fn task_start_result_v1(structured: Value) -> Value {
    let candidates = structured["relevantCode"]["candidates"]
        .as_array()
        .into_iter()
        .flatten()
        .take(8)
        .map(|candidate| {
            json!({
                "kind": candidate["kind"],
                "name": candidate["name"],
                "path": candidate["locator"]["path"],
                "line": candidate["locator"]["startLine"],
                "sourceDigest": candidate["locator"]["sourceDigest"]
            })
        })
        .collect::<Vec<_>>();
    let summary = json!({
        "schemaVersion": 1,
        "operation": "task.start",
        "taskId": structured["taskId"],
        "presentation": structured["presentation"],
        "coordination": structured["coordination"],
        "cursor": structured["cursor"],
        "context": structured["context"],
        "contextFreshness": structured["contextFreshness"],
        "sourcePreviews": structured["sourcePreviews"],
        "againBrain": structured["againBrain"],
        "relevantCode": {
            "candidates": candidates,
            "incomplete": structured["relevantCode"]["incomplete"],
            "unknowns": structured["relevantCode"]["unknowns"]
        },
        "validationPreview": structured["validationPreview"],
        "fullStructuredResultAvailable": true
    });
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string(&summary).expect("task-start summary serializes") }],
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

fn optional_bounded_string_v1(
    arguments: &Value,
    name: &str,
    maximum: usize,
) -> Result<Option<String>> {
    match arguments.get(name) {
        None => Ok(None),
        Some(_) => bounded_string_v1(arguments, name, maximum).map(|value| Some(value.to_owned())),
    }
}

fn bounded_string_array_v1(
    arguments: &Value,
    name: &str,
    maximum_items: usize,
    maximum_item_bytes: usize,
) -> Result<Vec<String>> {
    let Some(value) = arguments.get(name) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| anyhow!("invalid_argument"))?;
    if values.len() > maximum_items {
        bail!("invalid_argument");
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= maximum_item_bytes
                        && value.chars().all(|character| {
                            character == '\n' || character == '\t' || !character.is_control()
                        })
                })
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("invalid_argument"))
        })
        .collect()
}

fn direct_search_match_current_v1(
    observed: &SharedObservedWorkspaceV1,
    recipe: &Value,
    expected_digest: &str,
) -> bool {
    if recipe.as_object().is_none_or(|object| object.len() != 6) {
        return false;
    }
    let (Some(path), Some(pattern), Some(line), Some(snippet), Some(truncated)) = (
        recipe["path"].as_str(),
        recipe["pattern"].as_str(),
        recipe["line"].as_u64(),
        recipe["text"].as_str(),
        recipe["lineTruncated"].as_bool(),
    ) else {
        return false;
    };
    let relative = Path::new(path);
    if path.is_empty()
        || path.len() > 512
        || pattern.is_empty()
        || pattern.len() > 4096
        || snippet.len() > 4096
        || line == 0
        || !relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return false;
    }
    let Ok(bytes) = observed
        .execution_epoch
        .read_repository_file(relative, MAX_DIRECT_SEARCH_MATCH_SOURCE_BYTES_V1)
    else {
        return false;
    };
    if blake3::hash(&bytes).to_hex().as_str() != expected_digest {
        return false;
    }
    let Ok(content) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let Some(actual) = usize::try_from(line - 1)
        .ok()
        .and_then(|index| content.lines().nth(index))
    else {
        return false;
    };
    actual.contains(pattern)
        && if truncated {
            actual.starts_with(snippet) && actual.len() > snippet.len()
        } else {
            actual == snippet
        }
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
        "context_freshness_capacity_exceeded" => "context_freshness_capacity_exceeded",
        "context_freshness_unavailable" => "context_freshness_unavailable",
        "context_task_capacity_exceeded" => "context_task_capacity_exceeded",
        "context_task_alias_capacity_exceeded" => "context_task_alias_capacity_exceeded",
        "task_definition_conflict" => "task_definition_conflict",
        "task_not_started" => "task_not_started",
        "context_task_corrupt" => "context_task_corrupt",
        "context_task_relation_corrupt" => "context_task_corrupt",
        "task_relation_unavailable" => "task_relation_unavailable",
        "task_graph_self_edge" => "task_graph_invalid",
        "task_graph_cycle" => "task_graph_invalid",
        "task_graph_depth_exceeded" => "task_graph_invalid",
        "duplicate_task_dependency" => "task_graph_invalid",
        "task_dependency_capacity_exceeded" => "task_graph_invalid",
        "task_acceptance_capacity_exceeded" => "invalid_acceptance_criteria",
        "duplicate_acceptance_criterion" => "invalid_acceptance_criteria",
        "invalid_acceptance_criterion" => "invalid_acceptance_criteria",
        "invalid_task_description" => "invalid_task_description",
        "invalid_task_list_limit" => "invalid_task_list_limit",
        "invalid_task_state" => "invalid_task_transition",
        "invalid_task_transition" => "invalid_task_transition",
        "task_state_cas_mismatch" => "task_state_cas_mismatch",
        "task_terminal_immutable" => "task_terminal_immutable",
        "sensitive_content_refused" => "sensitive_content_refused",
        "task_quota_counter_corrupt" => "task_quota_corrupt",
        "task_context_quota_exceeded" => "task_quota_exceeded",
        "workspace_state_quota_exceeded" => "workspace_quota_exceeded",
        "workspace_maintenance_mode" => "workspace_maintenance_mode",
        "lease_not_current" => "lease_not_current",
        "lease_expired" => "lease_expired",
        "owner_mismatch" => "owner_mismatch",
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

#[cfg(test)]
mod validation_preview_tests {
    use super::*;

    #[test]
    fn large_named_source_excerpt_is_bounded_and_locates_task_term() {
        let source = format!(
            "{}fn repository_search_v1() {{\n    let marker = \"search\";\n}}\n{}",
            "let unrelated = 0;\n".repeat(200),
            "let later = 1;\n".repeat(200)
        );
        let (excerpt, start, end) = source_excerpt_v1(&source, "Fix repo.search truncation");
        assert!(excerpt.len() <= MAX_TASK_START_SOURCE_PREVIEW_BYTES_V1 as usize);
        assert!(excerpt.contains("fn repository_search_v1()"));
        assert!(start > 100);
        assert!(end.unwrap() >= start);
    }

    #[test]
    fn larger_brain_budget_can_include_a_complete_relevant_function() {
        let source = format!(
            "{}fn repository_search_v1() {{\n{}    let final_marker = true;\n}}\n{}",
            "// unrelated prelude\n".repeat(70),
            "    let intermediate = 1;\n".repeat(130),
            "// unrelated suffix\n".repeat(200)
        );
        let (short, _, _) = source_excerpt_v1(&source, "Fix repository_search_v1");
        let (long, _, _) =
            source_excerpt_with_budget_v1(&source, "Fix repository_search_v1", 5 * 1024);
        assert!(!short.contains("final_marker"));
        assert!(long.contains("fn repository_search_v1()"));
        assert!(long.contains("final_marker"));
        assert!(long.len() <= 5 * 1024);
    }

    #[test]
    fn source_excerpt_prefers_relevant_implementation_over_matching_oracle_tests() {
        let source = format!(
            "{}fn python_imports_v1() {{}}\n{}fn sanitize_line_v1() {{\n    let implementation = true;\n}}\n{}#[test]\nfn closing_triple_quote_at_line_end() {{}}\n#[test]\nfn triple_marker_inside_regular_string() {{}}\n",
            "// prelude\n".repeat(100),
            "// unrelated\n".repeat(80),
            "// middle\n".repeat(700),
        );
        let (excerpt, start, _) = source_excerpt_with_budget_v1(
            &source,
            "Fix the Python code index sanitizer: triple-quote markers at line boundaries",
            5 * 1024,
        );
        assert!(excerpt.contains("fn sanitize_line_v1"));
        assert!(excerpt.contains("let implementation = true"));
        assert!(!excerpt.contains("fn closing_triple_quote_at_line_end"));
        assert!(start > 100);
    }

    #[test]
    fn complete_unittest_companion_suggests_execution_without_claiming_proof() {
        let workspace = tempfile::tempdir().unwrap();
        let preview = json!({
            "origin": "test_path_convention_candidate",
            "complete": true,
            "path": "tests/test_calculator.py",
            "text": "import unittest\nclass CalculatorTests(unittest.TestCase): pass\n"
        });
        let result = validation_preview_v1(workspace.path(), &[preview], &json!({}));
        assert_eq!(result["status"], "execute_required");
        assert_eq!(
            result["selectors"][0]["command"],
            "python3 -m unittest discover -s tests"
        );
        assert_eq!(result["selectors"][0]["verified"], false);
        let indexed = json!({
            "origin": "indexed_candidate",
            "complete": true,
            "path": "tests/test_balance.py",
            "text": "import unittest\nclass BalanceTests(unittest.TestCase): pass\n"
        });
        assert_eq!(
            validation_preview_v1(workspace.path(), &[indexed], &json!({}))["selectors"][0]["command"],
            "python3 -m unittest discover -s tests"
        );
    }

    #[test]
    fn incomplete_or_non_unittest_preview_does_not_suggest_a_command() {
        let workspace = tempfile::tempdir().unwrap();
        for preview in [
            json!({"origin":"test_path_convention_candidate","complete":false,"path":"tests/test_x.py","text":"import unittest\nclass X(unittest.TestCase): pass"}),
            json!({"origin":"test_path_convention_candidate","complete":true,"path":"tests/test_x.py","text":"def test_x(): pass"}),
            json!({"origin":"explicit_task_path","complete":true,"path":"tests/test_x.py","text":"import unittest\nclass X(unittest.TestCase): pass"}),
        ] {
            assert_eq!(
                validation_preview_v1(workspace.path(), &[preview], &json!({}))["selectors"],
                json!([])
            );
        }
    }

    #[test]
    fn complete_node_test_preview_suggests_exact_required_execution() {
        let workspace = tempfile::tempdir().unwrap();
        let preview = json!({
            "origin":"test_path_convention_candidate",
            "complete":true,
            "path":"tests/test_calculator.mjs",
            "text":"import test from 'node:test';\ntest('sum', () => {});\n"
        });
        let result = validation_preview_v1(workspace.path(), &[preview.clone()], &json!({}));
        assert_eq!(result["status"], "execute_required");
        assert_eq!(
            result["selectors"][0]["command"],
            "node --test tests/test_calculator.mjs"
        );
        assert_eq!(result["selectors"][0]["verified"], false);

        let mut incomplete = preview.clone();
        incomplete["complete"] = json!(false);
        assert_eq!(
            validation_preview_v1(workspace.path(), &[incomplete], &json!({}))["selectors"],
            json!([])
        );
        let mut unsafe_path = preview;
        unsafe_path["path"] = json!("tests/test_x;touch_bad.mjs");
        assert_eq!(
            validation_preview_v1(workspace.path(), &[unsafe_path], &json!({}))["selectors"],
            json!([])
        );
    }

    #[test]
    fn manifest_and_source_candidate_suggest_test_without_claiming_proof() {
        let workspace = tempfile::tempdir().unwrap();
        let rust = json!({"candidates":[{"locator":{"path":"src/lib.rs"}}]});
        let go = json!({"candidates":[{"locator":{"path":"pkg/ledger.go"}}]});
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &rust)["selectors"],
            json!([])
        );
        std::fs::write(
            workspace.path().join("Cargo.toml"),
            "[package]\nname='ledger'\n",
        )
        .unwrap();
        let suggested = validation_preview_v1(workspace.path(), &[], &rust);
        assert_eq!(suggested["selectors"][0]["command"], "cargo test");
        assert_eq!(suggested["selectors"][0]["verified"], false);
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &go)["selectors"],
            json!([])
        );
        std::fs::write(workspace.path().join("go.mod"), "module ledger\n").unwrap();
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &go)["selectors"][0]["command"],
            "go test ./..."
        );
    }

    #[test]
    fn package_test_script_suggests_execution_with_current_source_evidence() {
        let workspace = tempfile::tempdir().unwrap();
        let javascript = json!({"candidates":[{"locator":{"path":"src/ledger.ts"}}]});
        std::fs::create_dir(workspace.path().join("src")).unwrap();
        std::fs::write(
            workspace.path().join("src/ledger.ts"),
            "export const total = 1;\n",
        )
        .unwrap();
        let manifest = br#"{"scripts":{"test":"vitest run"}}"#;
        std::fs::write(workspace.path().join("package.json"), manifest).unwrap();
        let npm = validation_preview_v1(workspace.path(), &[], &javascript);
        assert_eq!(npm["status"], "execute_required");
        assert_eq!(npm["selectors"][0]["command"], "npm test");
        assert_eq!(npm["selectors"][0]["workingDirectory"], ".");
        assert_eq!(npm["selectors"][0]["verified"], false);
        assert_eq!(npm["selectors"][0]["source"]["testScript"], "vitest run");
        assert_eq!(
            npm["selectors"][0]["source"]["digest"],
            blake3::hash(manifest).to_hex().to_string()
        );
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &json!({}))["selectors"],
            json!([])
        );

        std::fs::write(
            workspace.path().join("package.json"),
            r#"{"packageManager":"pnpm@9.0.0","scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        std::fs::write(
            workspace.path().join("pnpm-lock.yaml"),
            "lockfileVersion: 9\n",
        )
        .unwrap();
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &javascript)["selectors"][0]["command"],
            "pnpm test"
        );
        std::fs::write(
            workspace.path().join("yarn.lock"),
            "# conflicting manager\n",
        )
        .unwrap();
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &javascript)["selectors"],
            json!([])
        );
    }

    #[test]
    fn nested_packages_get_distinct_current_test_commands() {
        let workspace = tempfile::tempdir().unwrap();
        for package in ["alpha", "beta"] {
            std::fs::create_dir_all(workspace.path().join(format!("packages/{package}/src")))
                .unwrap();
            std::fs::write(
                workspace
                    .path()
                    .join(format!("packages/{package}/src/index.ts")),
                "export const value = 1;\n",
            )
            .unwrap();
        }
        std::fs::write(
            workspace.path().join("package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        std::fs::write(
            workspace.path().join("packages/alpha/package.json"),
            r#"{"packageManager":"pnpm@9.0.0","scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        std::fs::write(
            workspace.path().join("packages/beta/package.json"),
            r#"{"packageManager":"npm@11.0.0","scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        let code = json!({"candidates":[
            {"locator":{"path":"packages/alpha/src/index.ts"}},
            {"locator":{"path":"packages/beta/src/index.ts"}},
            {"locator":{"path":"packages/alpha/src/index.ts"}}
        ]});
        let preview = validation_preview_v1(workspace.path(), &[], &code);
        assert_eq!(preview["status"], "execute_required");
        assert_eq!(preview["selectors"].as_array().unwrap().len(), 2);
        assert_eq!(preview["selectors"][0]["command"], "pnpm test");
        assert_eq!(
            preview["selectors"][0]["workingDirectory"],
            "packages/alpha"
        );
        assert_eq!(
            preview["selectors"][0]["source"]["path"],
            "packages/alpha/package.json"
        );
        assert_eq!(preview["selectors"][1]["command"], "npm test");
        assert_eq!(preview["selectors"][1]["workingDirectory"], "packages/beta");
        assert_eq!(preview["selectors"][0]["verified"], false);
    }

    #[test]
    fn nested_package_refuses_ambiguous_manager_and_symlinked_directory() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join("packages/alpha/src")).unwrap();
        std::fs::write(
            workspace.path().join("packages/alpha/src/index.ts"),
            "export const value = 1;\n",
        )
        .unwrap();
        std::fs::write(
            workspace.path().join("packages/alpha/package.json"),
            r#"{"scripts":{"test":"node --test"}}"#,
        )
        .unwrap();
        let code = json!({"candidates":[{"locator":{"path":"packages/alpha/src/index.ts"}}]});
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &code)["selectors"],
            json!([])
        );
        std::fs::write(
            workspace.path().join("packages/alpha/pnpm-lock.yaml"),
            "lockfileVersion: 9\n",
        )
        .unwrap();
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &code)["selectors"][0]["command"],
            "pnpm test"
        );
        std::fs::write(
            workspace.path().join("packages/alpha/yarn.lock"),
            "# lock\n",
        )
        .unwrap();
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &code)["selectors"],
            json!([])
        );
        #[cfg(unix)]
        {
            std::fs::remove_file(workspace.path().join("packages/alpha/yarn.lock")).unwrap();
            std::fs::rename(
                workspace.path().join("packages/alpha"),
                workspace.path().join("packages/real"),
            )
            .unwrap();
            std::os::unix::fs::symlink("real", workspace.path().join("packages/alpha")).unwrap();
            assert_eq!(
                validation_preview_v1(workspace.path(), &[], &code)["selectors"],
                json!([])
            );
        }
    }

    #[test]
    fn explicit_package_with_stale_test_script_does_not_suggest_unrelated_package() {
        let workspace = tempfile::tempdir().unwrap();
        for package in ["alpha", "beta"] {
            std::fs::create_dir_all(workspace.path().join(format!("packages/{package}/src")))
                .unwrap();
            std::fs::write(
                workspace
                    .path()
                    .join(format!("packages/{package}/src/index.ts")),
                "export const value = 1;\n",
            )
            .unwrap();
        }
        std::fs::write(
            workspace.path().join("packages/alpha/package.json"),
            r#"{"packageManager":"npm@11.0.0","scripts":{"test":"echo no test specified && exit 1"}}"#,
        )
        .unwrap();
        std::fs::write(
            workspace.path().join("packages/beta/package.json"),
            r#"{"packageManager":"pnpm@9.0.0","scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        let explicit = json!({
            "origin": "explicit_task_path", "complete": true,
            "path": "packages/alpha/src/index.ts", "text": "export const value = 1;\n"
        });
        let indexed = json!({"candidates":[
            {"locator":{"path":"packages/beta/src/index.ts"}}
        ]});
        assert_eq!(
            validation_preview_v1(workspace.path(), &[explicit], &indexed)["selectors"],
            json!([])
        );
    }

    #[test]
    fn package_test_script_refuses_placeholder_or_untrusted_manifest_shape() {
        let workspace = tempfile::tempdir().unwrap();
        let javascript = json!({"candidates":[{"locator":{"path":"src/ledger.js"}}]});
        let path = workspace.path().join("package.json");
        std::fs::write(
            &path,
            r#"{"scripts":{"test":"echo no test specified && exit 1"}}"#,
        )
        .unwrap();
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &javascript)["selectors"],
            json!([])
        );
        std::fs::write(
            &path,
            r#"{"scripts":{"test":"node --test"},"packageManager":"unknown@1"}"#,
        )
        .unwrap();
        assert_eq!(
            validation_preview_v1(workspace.path(), &[], &javascript)["selectors"],
            json!([])
        );
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            std::fs::write(
                workspace.path().join("outside.json"),
                r#"{"scripts":{"test":"node --test"}}"#,
            )
            .unwrap();
            std::os::unix::fs::symlink(workspace.path().join("outside.json"), &path).unwrap();
            assert_eq!(
                validation_preview_v1(workspace.path(), &[], &javascript)["selectors"],
                json!([])
            );
        }
    }
}
