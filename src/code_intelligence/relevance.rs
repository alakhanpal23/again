use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use serde::Serialize;

use super::{
    CODE_INTELLIGENCE_SCHEMA_VERSION_V1, CodeDefinitionV1, CodeIntelligenceIndexV1,
    CodeIntelligenceUnknownKindV1, CodeIntelligenceUnknownV1, SourceLocatorV1, push_unknown_v1,
};

const MAX_ACTIVE_RANKERS_V1: usize = 2;
const MAX_RANKING_TIMEOUT_V1: Duration = Duration::from_millis(250);
const MAX_RANKING_INPUT_BYTES_V1: usize = 64 * 1024;
static ACTIVE_RANKERS_V1: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EditBriefCandidateKindV1 {
    File,
    Symbol,
    Test,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EditBriefRelevanceReasonV1 {
    ExactTaskToken,
    PartialTaskToken,
    PathToken,
    ChangedPath,
    VerifiedFactToken,
    ReferencedDefinition,
    ImportedModule,
    TestAssociation,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EditBriefRankingSourceV1 {
    Deterministic,
    OptionalProvider,
    DeterministicFallback,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditBriefCandidateV1 {
    candidate_id: String,
    kind: EditBriefCandidateKindV1,
    name: String,
    deterministic_score: u32,
    reasons: Vec<EditBriefRelevanceReasonV1>,
    locator: SourceLocatorV1,
    related_locators: Vec<SourceLocatorV1>,
}

impl EditBriefCandidateV1 {
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    pub const fn kind(&self) -> EditBriefCandidateKindV1 {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn deterministic_score(&self) -> u32 {
        self.deterministic_score
    }

    pub fn reasons(&self) -> &[EditBriefRelevanceReasonV1] {
        &self.reasons
    }

    pub fn locator(&self) -> &SourceLocatorV1 {
        &self.locator
    }

    pub fn related_locators(&self) -> &[SourceLocatorV1] {
        &self.related_locators
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditBriefV1 {
    schema_version: u16,
    index_generation: u64,
    index_digest: String,
    ranking_source: EditBriefRankingSourceV1,
    total_candidates: usize,
    candidates: Vec<EditBriefCandidateV1>,
    unknowns: Vec<CodeIntelligenceUnknownV1>,
    incomplete: bool,
}

impl EditBriefV1 {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn index_generation(&self) -> u64 {
        self.index_generation
    }

    pub fn index_digest(&self) -> &str {
        &self.index_digest
    }

    pub const fn ranking_source(&self) -> EditBriefRankingSourceV1 {
        self.ranking_source
    }

    pub const fn total_candidates(&self) -> usize {
        self.total_candidates
    }

    pub fn candidates(&self) -> &[EditBriefCandidateV1] {
        &self.candidates
    }

    pub fn unknowns(&self) -> &[CodeIntelligenceUnknownV1] {
        &self.unknowns
    }

    pub const fn incomplete(&self) -> bool {
        self.incomplete
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("bounded edit brief serializes")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditBriefRequestV1 {
    task: String,
    changed_paths: Vec<String>,
    verified_fact_terms: Vec<String>,
    maximum_candidates: Option<usize>,
}

impl EditBriefRequestV1 {
    pub fn new(task: &str) -> Option<Self> {
        (!task.is_empty() && task.len() <= 8 * 1024).then(|| Self {
            task: task.to_owned(),
            changed_paths: Vec::new(),
            verified_fact_terms: Vec::new(),
            maximum_candidates: None,
        })
    }

    /// Changed paths affect candidate ordering only. They do not establish
    /// freshness, source validity, or fact authority.
    pub fn with_changed_paths(mut self, mut paths: Vec<String>) -> Option<Self> {
        if paths.len() > 256
            || paths
                .iter()
                .any(|path| path.is_empty() || path.len() > 4_096)
        {
            return None;
        }
        paths.iter().try_fold(0usize, |total, path| {
            total
                .checked_add(path.len())
                .filter(|total| *total <= 64 * 1024)
        })?;
        paths.sort();
        paths.dedup();
        self.changed_paths = paths;
        Some(self)
    }

    pub fn with_maximum_candidates(mut self, maximum: usize) -> Option<Self> {
        if maximum == 0 || maximum > 256 {
            return None;
        }
        self.maximum_candidates = Some(maximum);
        Some(self)
    }

    /// Only the context-ledger/compiler integration may add terms from facts
    /// that it has freshly revalidated. Even then, terms only affect ranking.
    #[allow(dead_code)]
    pub(crate) fn with_verified_fact_terms_v1(mut self, mut terms: Vec<String>) -> Option<Self> {
        if terms.len() > 256
            || terms
                .iter()
                .any(|term| term.is_empty() || term.len() > 1_024)
        {
            return None;
        }
        terms.iter().try_fold(0usize, |total, term| {
            total
                .checked_add(term.len())
                .filter(|total| *total <= 64 * 1024)
        })?;
        terms.sort();
        terms.dedup();
        self.verified_fact_terms = terms;
        Some(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RankingCandidateV1 {
    candidate_id: String,
    name: String,
    path: String,
    deterministic_ordinal: usize,
}

impl RankingCandidateV1 {
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn deterministic_ordinal(&self) -> usize {
        self.deterministic_ordinal
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateRankingRequestV1 {
    schema_version: u16,
    task: String,
    candidates: Vec<RankingCandidateV1>,
}

impl CandidateRankingRequestV1 {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn task(&self) -> &str {
        &self.task
    }

    pub fn candidates(&self) -> &[RankingCandidateV1] {
        &self.candidates
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateRankingBudgetV1 {
    maximum_input_bytes: usize,
    maximum_output_ids: usize,
    timeout: Duration,
}

impl CandidateRankingBudgetV1 {
    pub fn new(
        maximum_input_bytes: usize,
        maximum_output_ids: usize,
        timeout: Duration,
    ) -> Option<Self> {
        (maximum_input_bytes > 0
            && maximum_input_bytes <= MAX_RANKING_INPUT_BYTES_V1
            && maximum_output_ids > 0
            && maximum_output_ids <= 256
            && !timeout.is_zero()
            && timeout <= MAX_RANKING_TIMEOUT_V1)
            .then_some(Self {
                maximum_input_bytes,
                maximum_output_ids,
                timeout,
            })
    }

    pub const fn maximum_input_bytes(&self) -> usize {
        self.maximum_input_bytes
    }

    pub const fn maximum_output_ids(&self) -> usize {
        self.maximum_output_ids
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateRankingFailureV1 {
    ProviderUnavailable,
    BudgetExceeded,
    Timeout,
    InvalidResponse,
    Saturated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRankingResponseV1 {
    ordered_candidate_ids: Vec<String>,
}

impl CandidateRankingResponseV1 {
    pub fn new(ordered_candidate_ids: Vec<String>) -> Self {
        Self {
            ordered_candidate_ids,
        }
    }

    pub fn ordered_candidate_ids(&self) -> &[String] {
        &self.ordered_candidate_ids
    }
}

/// Optional ranking providers receive only bounded candidate metadata. Their
/// response can reorder known candidate IDs; it cannot create candidates,
/// locators, definitions, facts, or any serving authority.
pub trait CandidateRankerV1: Send + Sync + 'static {
    fn rank_candidates(
        &self,
        request: CandidateRankingRequestV1,
        budget: CandidateRankingBudgetV1,
    ) -> Result<CandidateRankingResponseV1, CandidateRankingFailureV1>;
}

pub trait CodeIntelligenceProviderV1 {
    fn compile_edit_brief_v1(
        &self,
        request: &EditBriefRequestV1,
        optional_ranker: Option<(Arc<dyn CandidateRankerV1>, CandidateRankingBudgetV1)>,
    ) -> EditBriefV1;
}

impl CodeIntelligenceProviderV1 for CodeIntelligenceIndexV1 {
    fn compile_edit_brief_v1(
        &self,
        request: &EditBriefRequestV1,
        optional_ranker: Option<(Arc<dyn CandidateRankerV1>, CandidateRankingBudgetV1)>,
    ) -> EditBriefV1 {
        if request.task.len() > self.limits.max_task_bytes {
            return EditBriefV1 {
                schema_version: CODE_INTELLIGENCE_SCHEMA_VERSION_V1,
                index_generation: self.generation,
                index_digest: self.index_digest.clone(),
                ranking_source: EditBriefRankingSourceV1::DeterministicFallback,
                total_candidates: 0,
                candidates: Vec::new(),
                unknowns: vec![CodeIntelligenceUnknownV1::new(
                    CodeIntelligenceUnknownKindV1::TaskByteLimitExceeded,
                    None,
                )],
                incomplete: true,
            };
        }
        let task_tokens = relevance_tokens_v1(&request.task);
        let verified_tokens: BTreeSet<_> = request
            .verified_fact_terms
            .iter()
            .flat_map(|term| relevance_tokens_v1(term))
            .collect();
        let changed_paths: BTreeSet<_> = request.changed_paths.iter().cloned().collect();
        let mut candidates = Vec::new();
        for indexed in self.files.values() {
            candidates.push(file_candidate_v1(
                indexed,
                &task_tokens,
                &verified_tokens,
                &changed_paths,
                self,
            ));
            for definition in &indexed.definitions {
                candidates.push(definition_candidate_v1(
                    definition,
                    &task_tokens,
                    &verified_tokens,
                    &changed_paths,
                    self,
                ));
            }
        }
        candidates.sort_by(deterministic_candidate_order_v1);
        candidates.dedup_by(|left, right| left.candidate_id == right.candidate_id);
        let total_candidates = candidates.len();
        let maximum = request
            .maximum_candidates
            .unwrap_or(self.limits.max_candidates)
            .min(self.limits.max_candidates);
        let mut unknowns = self.snapshot().unknowns;
        if candidates.len() > maximum {
            candidates.truncate(maximum);
            push_unknown_v1(
                &mut unknowns,
                self.limits.max_unknowns,
                CodeIntelligenceUnknownV1::new(
                    CodeIntelligenceUnknownKindV1::CandidateLimitExceeded,
                    None,
                ),
            );
        }

        let (ranking_source, candidates) = if let Some((ranker, budget)) = optional_ranker {
            match apply_optional_ranking_v1(&request.task, candidates.clone(), ranker, budget) {
                Ok(ranked) => (EditBriefRankingSourceV1::OptionalProvider, ranked),
                Err(failure) => {
                    push_unknown_v1(
                        &mut unknowns,
                        self.limits.max_unknowns,
                        CodeIntelligenceUnknownV1::new(
                            if failure == CandidateRankingFailureV1::InvalidResponse {
                                CodeIntelligenceUnknownKindV1::OptionalRankingInvalid
                            } else {
                                CodeIntelligenceUnknownKindV1::OptionalRankingUnavailable
                            },
                            None,
                        ),
                    );
                    (EditBriefRankingSourceV1::DeterministicFallback, candidates)
                }
            }
        } else {
            (EditBriefRankingSourceV1::Deterministic, candidates)
        };

        unknowns.sort();
        unknowns.dedup();
        unknowns.truncate(self.limits.max_unknowns);
        let mut brief = EditBriefV1 {
            schema_version: CODE_INTELLIGENCE_SCHEMA_VERSION_V1,
            index_generation: self.generation,
            index_digest: self.index_digest.clone(),
            ranking_source,
            total_candidates,
            candidates,
            incomplete: !unknowns.is_empty(),
            unknowns,
        };
        while brief.canonical_bytes().len() > self.limits.max_brief_bytes
            && !brief.candidates.is_empty()
        {
            brief.candidates.pop();
            push_unknown_v1(
                &mut brief.unknowns,
                self.limits.max_unknowns,
                CodeIntelligenceUnknownV1::new(
                    CodeIntelligenceUnknownKindV1::BriefByteLimitExceeded,
                    None,
                ),
            );
            brief.incomplete = true;
        }
        if brief.canonical_bytes().len() > self.limits.max_brief_bytes {
            brief.unknowns.clear();
            brief.unknowns.push(CodeIntelligenceUnknownV1::new(
                CodeIntelligenceUnknownKindV1::BriefByteLimitExceeded,
                None,
            ));
            brief.incomplete = true;
        }
        brief
    }
}

fn file_candidate_v1(
    indexed: &super::IndexedFileV1,
    task_tokens: &BTreeSet<String>,
    verified_tokens: &BTreeSet<String>,
    changed_paths: &BTreeSet<String>,
    index: &CodeIntelligenceIndexV1,
) -> EditBriefCandidateV1 {
    let mut reasons = BTreeSet::new();
    let mut score = score_text_v1(
        &format!("{} {}", indexed.file.path, indexed.file.module_name),
        task_tokens,
        verified_tokens,
        &mut reasons,
    )
    .saturating_add(5);
    if changed_paths.contains(&indexed.file.path) {
        score = score.saturating_add(1_000);
        reasons.insert(EditBriefRelevanceReasonV1::ChangedPath);
    }
    for import in &indexed.imports {
        if relevance_tokens_v1(&import.module)
            .iter()
            .any(|token| task_tokens.contains(token))
        {
            score = score.saturating_add(15);
            reasons.insert(EditBriefRelevanceReasonV1::ImportedModule);
        }
    }
    if index
        .test_associations
        .iter()
        .any(|association| association.test_locator.path == indexed.file.path)
    {
        score = score.saturating_add(10);
        reasons.insert(EditBriefRelevanceReasonV1::TestAssociation);
    }
    let name = indexed.file.module_name.clone();
    EditBriefCandidateV1 {
        candidate_id: candidate_identity_v1(
            EditBriefCandidateKindV1::File,
            &name,
            &indexed.file.locator,
        ),
        kind: EditBriefCandidateKindV1::File,
        name,
        deterministic_score: score,
        reasons: reasons.into_iter().collect(),
        locator: indexed.file.locator.clone(),
        related_locators: indexed
            .definitions
            .iter()
            .take(index.limits.max_related_locators)
            .map(|definition| definition.locator.clone())
            .collect(),
    }
}

fn definition_candidate_v1(
    definition: &CodeDefinitionV1,
    task_tokens: &BTreeSet<String>,
    verified_tokens: &BTreeSet<String>,
    changed_paths: &BTreeSet<String>,
    index: &CodeIntelligenceIndexV1,
) -> EditBriefCandidateV1 {
    let mut reasons = BTreeSet::new();
    let mut score = score_text_v1(&definition.name, task_tokens, verified_tokens, &mut reasons)
        .saturating_add(10);
    if changed_paths.contains(&definition.locator.path) {
        score = score.saturating_add(1_000);
        reasons.insert(EditBriefRelevanceReasonV1::ChangedPath);
    }
    let references = index.references_to(&definition.definition_id);
    if !references.is_empty() {
        score = score.saturating_add((references.len().min(10) as u32).saturating_mul(3));
        reasons.insert(EditBriefRelevanceReasonV1::ReferencedDefinition);
    }
    if definition.is_test {
        score = score.saturating_add(10);
        reasons.insert(EditBriefRelevanceReasonV1::TestAssociation);
    }
    EditBriefCandidateV1 {
        candidate_id: candidate_identity_v1(
            if definition.is_test {
                EditBriefCandidateKindV1::Test
            } else {
                EditBriefCandidateKindV1::Symbol
            },
            &definition.name,
            &definition.locator,
        ),
        kind: if definition.is_test {
            EditBriefCandidateKindV1::Test
        } else {
            EditBriefCandidateKindV1::Symbol
        },
        name: definition.name.clone(),
        deterministic_score: score,
        reasons: reasons.into_iter().collect(),
        locator: definition.locator.clone(),
        related_locators: references
            .into_iter()
            .take(index.limits.max_related_locators)
            .map(|reference| reference.locator.clone())
            .collect(),
    }
}

fn score_text_v1(
    text: &str,
    task_tokens: &BTreeSet<String>,
    verified_tokens: &BTreeSet<String>,
    reasons: &mut BTreeSet<EditBriefRelevanceReasonV1>,
) -> u32 {
    let candidate_tokens = relevance_tokens_v1(text);
    let lowered = text.to_ascii_lowercase();
    let mut score = 0u32;
    for token in task_tokens {
        if candidate_tokens.contains(token) {
            score = score.saturating_add(100);
            reasons.insert(EditBriefRelevanceReasonV1::ExactTaskToken);
        } else if token.len() >= 3 && lowered.contains(token) {
            score = score.saturating_add(30);
            reasons.insert(EditBriefRelevanceReasonV1::PartialTaskToken);
        }
        if text.contains('/') && lowered.split('/').any(|component| component == token) {
            score = score.saturating_add(25);
            reasons.insert(EditBriefRelevanceReasonV1::PathToken);
        }
    }
    for token in verified_tokens.intersection(&candidate_tokens) {
        if !token.is_empty() {
            score = score.saturating_add(15);
            reasons.insert(EditBriefRelevanceReasonV1::VerifiedFactToken);
        }
    }
    score
}

fn relevance_tokens_v1(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut tokens = BTreeSet::new();
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_alphanumeric() {
            start.get_or_insert(index);
        } else if let Some(token_start) = start.take() {
            if index.saturating_sub(token_start) >= 2 {
                tokens.insert(text[token_start..index].to_ascii_lowercase());
            }
        }
    }
    if let Some(token_start) = start {
        if bytes.len().saturating_sub(token_start) >= 2 {
            tokens.insert(text[token_start..].to_ascii_lowercase());
        }
    }
    tokens
}

fn deterministic_candidate_order_v1(
    left: &EditBriefCandidateV1,
    right: &EditBriefCandidateV1,
) -> std::cmp::Ordering {
    right
        .deterministic_score
        .cmp(&left.deterministic_score)
        .then_with(|| left.locator.path.cmp(&right.locator.path))
        .then_with(|| left.locator.start_line.cmp(&right.locator.start_line))
        .then_with(|| {
            left.locator
                .start_column_byte
                .cmp(&right.locator.start_column_byte)
        })
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.name.cmp(&right.name))
}

fn candidate_identity_v1(
    kind: EditBriefCandidateKindV1,
    name: &str,
    locator: &SourceLocatorV1,
) -> String {
    let bytes =
        serde_json::to_vec(&(kind, name, locator)).expect("bounded candidate identity serializes");
    crate::workspace_authority::StateDigestV1::from_domain_and_bytes(
        b"again.edit-brief-candidate.v1",
        &bytes,
    )
    .to_hex()
}

fn apply_optional_ranking_v1(
    task: &str,
    candidates: Vec<EditBriefCandidateV1>,
    ranker: Arc<dyn CandidateRankerV1>,
    budget: CandidateRankingBudgetV1,
) -> Result<Vec<EditBriefCandidateV1>, CandidateRankingFailureV1> {
    let request = CandidateRankingRequestV1 {
        schema_version: CODE_INTELLIGENCE_SCHEMA_VERSION_V1,
        task: task.to_owned(),
        candidates: candidates
            .iter()
            .enumerate()
            .map(|(ordinal, candidate)| RankingCandidateV1 {
                candidate_id: candidate.candidate_id.clone(),
                name: candidate.name.clone(),
                path: candidate.locator.path.clone(),
                deterministic_ordinal: ordinal,
            })
            .collect(),
    };
    let encoded =
        serde_json::to_vec(&request).map_err(|_| CandidateRankingFailureV1::BudgetExceeded)?;
    if encoded.len() > budget.maximum_input_bytes {
        return Err(CandidateRankingFailureV1::BudgetExceeded);
    }
    acquire_ranker_slot_v1()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("again-candidate-ranker-v1".to_owned())
        .spawn(move || {
            struct SlotGuardV1;
            impl Drop for SlotGuardV1 {
                fn drop(&mut self) {
                    ACTIVE_RANKERS_V1.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _guard = SlotGuardV1;
            let response = ranker.rank_candidates(request, budget);
            let _ = sender.send(response);
        })
        .map_err(|_| {
            ACTIVE_RANKERS_V1.fetch_sub(1, Ordering::AcqRel);
            CandidateRankingFailureV1::ProviderUnavailable
        })?;
    let response = receiver
        .recv_timeout(budget.timeout)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => CandidateRankingFailureV1::Timeout,
            mpsc::RecvTimeoutError::Disconnected => CandidateRankingFailureV1::ProviderUnavailable,
        })??;
    if response.ordered_candidate_ids.len() > budget.maximum_output_ids {
        return Err(CandidateRankingFailureV1::InvalidResponse);
    }
    let mut by_id: BTreeMap<_, _> = candidates
        .into_iter()
        .map(|candidate| (candidate.candidate_id.clone(), candidate))
        .collect();
    let mut ranked = Vec::new();
    let mut seen = BTreeSet::new();
    for identity in response.ordered_candidate_ids {
        if !seen.insert(identity.clone()) {
            return Err(CandidateRankingFailureV1::InvalidResponse);
        }
        let Some(candidate) = by_id.remove(&identity) else {
            return Err(CandidateRankingFailureV1::InvalidResponse);
        };
        ranked.push(candidate);
    }
    let mut remainder: Vec<_> = by_id.into_values().collect();
    remainder.sort_by(deterministic_candidate_order_v1);
    ranked.extend(remainder);
    Ok(ranked)
}

fn acquire_ranker_slot_v1() -> Result<(), CandidateRankingFailureV1> {
    let mut active = ACTIVE_RANKERS_V1.load(Ordering::Acquire);
    loop {
        if active >= MAX_ACTIVE_RANKERS_V1 {
            return Err(CandidateRankingFailureV1::Saturated);
        }
        match ACTIVE_RANKERS_V1.compare_exchange_weak(
            active,
            active + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(current) => active = current,
        }
    }
}
