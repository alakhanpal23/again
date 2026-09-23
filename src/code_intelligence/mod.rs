//! Bounded deterministic repository-local code intelligence.
//!
//! The index is a derived observation, not reuse or retrieval authority. Every
//! emitted item carries the exact manifest observation and source-byte digests
//! from which it was derived. Only the crate-private manifest adapter can
//! populate current entries; public ranking interfaces may only reorder an
//! already-bounded candidate set.

// Terminal E lands before the task-start consumer. Keep the manifest adapter
// compiled and tested without pretending MCP integration already exists.
#[allow(dead_code)]
mod extract;
mod relevance;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::workspace_authority::{
    AuthorityResult, IncompleteToolStateV1, ManifestDependentKindV1, ManifestDependentV1,
    ObservedManifestV1, RepositoryNodeKindV1, RepositoryObservationKindV1,
    RepositoryObservationPlanV1, StateDigestV1, WorkspaceAuthorityLimitsV1,
    WorkspaceExecutionEpochV1,
};

pub use relevance::{
    CandidateRankerV1, CandidateRankingBudgetV1, CandidateRankingFailureV1,
    CandidateRankingRequestV1, CandidateRankingResponseV1, CodeIntelligenceProviderV1,
    EditBriefCandidateKindV1, EditBriefCandidateV1, EditBriefRankingSourceV1,
    EditBriefRelevanceReasonV1, EditBriefRequestV1, EditBriefV1, RankingCandidateV1,
};

pub const CODE_INTELLIGENCE_SCHEMA_VERSION_V1: u16 = 1;

#[allow(dead_code)]
const INVENTORY_DEPENDENT_DOMAIN_V1: &[u8] = b"again.code-intelligence.inventory.v1";
#[allow(dead_code)]
const FILE_DEPENDENT_DOMAIN_V1: &[u8] = b"again.code-intelligence.file.v1";

#[derive(Clone, Debug)]
pub struct CodeIntelligenceLimitsV1 {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_depth: usize,
    pub max_lines_per_file: usize,
    pub max_line_bytes: usize,
    pub max_definitions_per_file: usize,
    pub max_occurrences_per_file: usize,
    pub max_imports_per_file: usize,
    pub max_references: usize,
    pub max_test_associations: usize,
    pub max_unknowns: usize,
    pub max_candidates: usize,
    pub max_related_locators: usize,
    pub max_task_bytes: usize,
    pub max_brief_bytes: usize,
    pub max_parse_time: Duration,
}

impl Default for CodeIntelligenceLimitsV1 {
    fn default() -> Self {
        Self {
            max_files: 4_096,
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_depth: 64,
            max_lines_per_file: 100_000,
            max_line_bytes: 16 * 1024,
            max_definitions_per_file: 2_048,
            max_occurrences_per_file: 16_384,
            max_imports_per_file: 1_024,
            max_references: 65_536,
            max_test_associations: 8_192,
            max_unknowns: 64,
            max_candidates: 32,
            max_related_locators: 8,
            max_task_bytes: 8 * 1024,
            max_brief_bytes: 64 * 1024,
            max_parse_time: Duration::from_secs(2),
        }
    }
}

impl CodeIntelligenceLimitsV1 {
    fn is_valid(&self) -> bool {
        self.max_files > 0
            && self.max_file_bytes > 0
            && self.max_total_bytes >= self.max_file_bytes
            && self.max_depth > 0
            && self.max_lines_per_file > 0
            && self.max_line_bytes > 0
            && self.max_definitions_per_file > 0
            && self.max_occurrences_per_file > 0
            && self.max_imports_per_file > 0
            && self.max_references > 0
            && self.max_test_associations > 0
            && self.max_unknowns > 0
            && self.max_candidates > 0
            && self.max_related_locators > 0
            && self.max_task_bytes > 0
            && self.max_brief_bytes >= 4 * 1024
            && !self.max_parse_time.is_zero()
    }
}

/// This untrusted admission preflight may only decline optional indexing. It
/// never issues source locators or facts; the manifest adapter remains the
/// authority for every candidate that is actually returned.
pub(crate) fn index_preflight_refusal_v1(
    workspace: &Path,
    limits: &CodeIntelligenceLimitsV1,
    time_budget: Duration,
) -> Option<&'static str> {
    let started = Instant::now();
    let mut pending = VecDeque::from([PathBuf::new()]);
    let mut source_files = 0usize;
    while let Some(directory) = pending.pop_front() {
        if started.elapsed() >= time_budget {
            return Some("index_preflight_time_budget_exceeded");
        }
        let Ok(entries) = fs::read_dir(workspace.join(&directory)) else {
            return Some("index_preflight_unavailable");
        };
        for entry in entries {
            if started.elapsed() >= time_budget {
                return Some("index_preflight_time_budget_exceeded");
            }
            let Ok(entry) = entry else {
                return Some("index_preflight_unavailable");
            };
            let path = directory.join(entry.file_name());
            let Ok(kind) = entry.file_type() else {
                return Some("index_preflight_unavailable");
            };
            if kind.is_dir() {
                if !should_skip_directory_v1(&path) {
                    pending.push_back(path);
                }
            } else if kind.is_file()
                && CodeLanguageV1::from_path(&path).is_some()
                && !is_generated_path_v1(&path)
            {
                source_files += 1;
                if source_files > limits.max_files {
                    return Some("index_preflight_file_budget_exceeded");
                }
            }
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeLanguageV1 {
    Rust,
    Python,
    TypeScript,
    JavaScript,
    Go,
}

impl CodeLanguageV1 {
    #[allow(dead_code)]
    fn from_path(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?;
        match extension {
            "rs" => Some(Self::Rust),
            "py" | "pyi" => Some(Self::Python),
            "ts" | "tsx" => Some(Self::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "go" => Some(Self::Go),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeSymbolKindV1 {
    Function,
    Method,
    Struct,
    Enum,
    Trait,
    Interface,
    Class,
    TypeAlias,
    Module,
    Constant,
    Variable,
    Macro,
    Test,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeReferenceResolutionV1 {
    LexicallyUniqueDefinition,
    AmbiguousDefinitions,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestAssociationKindV1 {
    LexicalReference,
    FileConvention,
    UnknownTarget,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeExtractionCoverageV1 {
    ConservativeSyntaxSubset,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeIntelligenceUnknownKindV1 {
    FileLimitExceeded,
    TotalByteLimitExceeded,
    DepthLimitExceeded,
    TaskByteLimitExceeded,
    FileTooLarge,
    BinaryFile,
    NonUtf8Path,
    NonUtf8Source,
    GeneratedFileSkipped,
    LineLimitExceeded,
    LineByteLimitExceeded,
    DefinitionLimitExceeded,
    OccurrenceLimitExceeded,
    ImportLimitExceeded,
    ReferenceLimitExceeded,
    TestAssociationLimitExceeded,
    AmbiguousSyntax,
    ParseTimeExceeded,
    UnknownTestTarget,
    CandidateLimitExceeded,
    BriefByteLimitExceeded,
    OptionalRankingUnavailable,
    OptionalRankingInvalid,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLocatorV1 {
    path: String,
    start_line: u32,
    start_column_byte: u32,
    end_line: u32,
    end_column_byte: u32,
    source_digest: String,
    observation_digest: String,
}

impl SourceLocatorV1 {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn start_line(&self) -> u32 {
        self.start_line
    }

    pub const fn start_column_byte(&self) -> u32 {
        self.start_column_byte
    }

    pub const fn end_line(&self) -> u32 {
        self.end_line
    }

    pub const fn end_column_byte(&self) -> u32 {
        self.end_column_byte
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeFileV1 {
    path: String,
    language: CodeLanguageV1,
    bytes: u64,
    lines: u32,
    module_name: String,
    extraction_coverage: CodeExtractionCoverageV1,
    locator: SourceLocatorV1,
}

impl CodeFileV1 {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn language(&self) -> CodeLanguageV1 {
        self.language
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub const fn lines(&self) -> u32 {
        self.lines
    }

    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    pub const fn extraction_coverage(&self) -> CodeExtractionCoverageV1 {
        self.extraction_coverage
    }

    pub fn locator(&self) -> &SourceLocatorV1 {
        &self.locator
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeDefinitionV1 {
    definition_id: String,
    name: String,
    kind: CodeSymbolKindV1,
    is_test: bool,
    locator: SourceLocatorV1,
}

impl CodeDefinitionV1 {
    pub fn definition_id(&self) -> &str {
        &self.definition_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn kind(&self) -> CodeSymbolKindV1 {
        self.kind
    }

    pub const fn is_test(&self) -> bool {
        self.is_test
    }

    pub fn locator(&self) -> &SourceLocatorV1 {
        &self.locator
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeReferenceV1 {
    name: String,
    target_definition_id: Option<String>,
    resolution: CodeReferenceResolutionV1,
    locator: SourceLocatorV1,
}

impl CodeReferenceV1 {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn target_definition_id(&self) -> Option<&str> {
        self.target_definition_id.as_deref()
    }

    pub const fn resolution(&self) -> CodeReferenceResolutionV1 {
        self.resolution
    }

    pub fn locator(&self) -> &SourceLocatorV1 {
        &self.locator
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeImportV1 {
    module: String,
    locator: SourceLocatorV1,
}

impl CodeImportV1 {
    pub fn module(&self) -> &str {
        &self.module
    }

    pub fn locator(&self) -> &SourceLocatorV1 {
        &self.locator
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestAssociationV1 {
    test_definition_id: String,
    kind: TestAssociationKindV1,
    test_locator: SourceLocatorV1,
    target_locators: Vec<SourceLocatorV1>,
}

impl TestAssociationV1 {
    pub fn test_definition_id(&self) -> &str {
        &self.test_definition_id
    }

    pub const fn kind(&self) -> TestAssociationKindV1 {
        self.kind
    }

    pub fn test_locator(&self) -> &SourceLocatorV1 {
        &self.test_locator
    }

    pub fn target_locators(&self) -> &[SourceLocatorV1] {
        &self.target_locators
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeIntelligenceUnknownV1 {
    kind: CodeIntelligenceUnknownKindV1,
    path: Option<String>,
}

impl CodeIntelligenceUnknownV1 {
    fn new(kind: CodeIntelligenceUnknownKindV1, path: Option<String>) -> Self {
        Self { kind, path }
    }

    pub const fn kind(&self) -> CodeIntelligenceUnknownKindV1 {
        self.kind
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeIntelligenceSnapshotV1 {
    schema_version: u16,
    generation: u64,
    index_digest: String,
    files: Vec<CodeFileV1>,
    definitions: Vec<CodeDefinitionV1>,
    references: Vec<CodeReferenceV1>,
    imports: Vec<CodeImportV1>,
    test_associations: Vec<TestAssociationV1>,
    unknowns: Vec<CodeIntelligenceUnknownV1>,
    incomplete: bool,
}

impl CodeIntelligenceSnapshotV1 {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn index_digest(&self) -> &str {
        &self.index_digest
    }

    pub fn files(&self) -> &[CodeFileV1] {
        &self.files
    }

    pub fn definitions(&self) -> &[CodeDefinitionV1] {
        &self.definitions
    }

    pub fn references(&self) -> &[CodeReferenceV1] {
        &self.references
    }

    pub fn imports(&self) -> &[CodeImportV1] {
        &self.imports
    }

    pub fn test_associations(&self) -> &[TestAssociationV1] {
        &self.test_associations
    }

    pub fn unknowns(&self) -> &[CodeIntelligenceUnknownV1] {
        &self.unknowns
    }

    pub const fn incomplete(&self) -> bool {
        self.incomplete
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("bounded code-intelligence snapshot serializes")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeIntelligenceRefreshV1 {
    generation: u64,
    discovered_files: usize,
    rebuilt_files: usize,
    reused_files: usize,
    removed_files: usize,
    invalidated_dependents: usize,
    incomplete: bool,
}

impl CodeIntelligenceRefreshV1 {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn discovered_files(&self) -> usize {
        self.discovered_files
    }

    pub const fn rebuilt_files(&self) -> usize {
        self.rebuilt_files
    }

    pub const fn reused_files(&self) -> usize {
        self.reused_files
    }

    pub const fn removed_files(&self) -> usize {
        self.removed_files
    }

    pub const fn invalidated_dependents(&self) -> usize {
        self.invalidated_dependents
    }

    pub const fn incomplete(&self) -> bool {
        self.incomplete
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct OccurrenceV1 {
    name: String,
    locator: SourceLocatorV1,
}

#[allow(dead_code)]
#[derive(Clone)]
struct IndexedFileV1 {
    file: CodeFileV1,
    definitions: Vec<CodeDefinitionV1>,
    occurrences: Vec<OccurrenceV1>,
    imports: Vec<CodeImportV1>,
    unknowns: Vec<CodeIntelligenceUnknownV1>,
}

/// A bounded read model. Its entries are useful orientation metadata, not
/// capabilities and not independently sufficient to admit a verified fact.
pub struct CodeIntelligenceIndexV1 {
    limits: CodeIntelligenceLimitsV1,
    generation: u64,
    index_digest: String,
    files: BTreeMap<String, IndexedFileV1>,
    references: Vec<CodeReferenceV1>,
    test_associations: Vec<TestAssociationV1>,
    unknowns: Vec<CodeIntelligenceUnknownV1>,
}

impl std::fmt::Debug for CodeIntelligenceIndexV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodeIntelligenceIndexV1")
            .field("generation", &self.generation)
            .field("file_count", &self.files.len())
            .field("reference_count", &self.references.len())
            .field("test_association_count", &self.test_associations.len())
            .field("incomplete", &!self.unknowns.is_empty())
            .finish()
    }
}

impl CodeIntelligenceIndexV1 {
    pub fn new(limits: CodeIntelligenceLimitsV1) -> Option<Self> {
        limits.is_valid().then(|| Self {
            limits,
            generation: 0,
            index_digest: StateDigestV1::from_domain_and_bytes(
                b"again.code-intelligence.empty.v1",
                b"empty",
            )
            .to_hex(),
            files: BTreeMap::new(),
            references: Vec::new(),
            test_associations: Vec::new(),
            unknowns: Vec::new(),
        })
    }

    pub fn snapshot(&self) -> CodeIntelligenceSnapshotV1 {
        let mut files = Vec::with_capacity(self.files.len());
        let mut definitions = Vec::new();
        let mut imports = Vec::new();
        let mut unknowns = self.unknowns.clone();
        for indexed in self.files.values() {
            files.push(indexed.file.clone());
            definitions.extend(indexed.definitions.iter().cloned());
            imports.extend(indexed.imports.iter().cloned());
            unknowns.extend(indexed.unknowns.iter().cloned());
        }
        definitions.sort();
        imports.sort();
        unknowns.sort();
        unknowns.dedup();
        unknowns.truncate(self.limits.max_unknowns);
        CodeIntelligenceSnapshotV1 {
            schema_version: CODE_INTELLIGENCE_SCHEMA_VERSION_V1,
            generation: self.generation,
            index_digest: self.index_digest.clone(),
            files,
            definitions,
            references: self.references.clone(),
            imports,
            test_associations: self.test_associations.clone(),
            incomplete: !unknowns.is_empty(),
            unknowns,
        }
    }

    pub fn definitions_named(&self, name: &str) -> Vec<&CodeDefinitionV1> {
        self.files
            .values()
            .flat_map(|file| file.definitions.iter())
            .filter(|definition| definition.name == name)
            .collect()
    }

    pub fn references_to(&self, definition_id: &str) -> Vec<&CodeReferenceV1> {
        self.references
            .iter()
            .filter(|reference| reference.target_definition_id.as_deref() == Some(definition_id))
            .collect()
    }

    pub fn imports_for(&self, path: &str) -> Vec<&CodeImportV1> {
        self.files
            .get(path)
            .map_or_else(Vec::new, |file| file.imports.iter().collect())
    }

    pub fn tests_for_path(&self, path: &str) -> Vec<&TestAssociationV1> {
        self.test_associations
            .iter()
            .filter(|association| {
                association
                    .target_locators
                    .iter()
                    .any(|locator| locator.path == path)
            })
            .collect()
    }

    /// Refresh from the live shared-manifest authority. This method is
    /// crate-private so callers cannot mint current entries from arbitrary
    /// bytes or serialized digests.
    #[allow(dead_code)]
    pub(crate) fn refresh_from_manifest(
        &mut self,
        execution_epoch: &WorkspaceExecutionEpochV1,
        manifest: &mut ObservedManifestV1,
        authority_limits: &WorkspaceAuthorityLimitsV1,
    ) -> AuthorityResult<CodeIntelligenceRefreshV1> {
        let started = Instant::now();
        let invalidated_dependents: usize = manifest
            .take_invalidations()
            .iter()
            .map(|event| event.dependents().len())
            .sum();
        let discovery = discover_source_files_v1(
            execution_epoch,
            manifest,
            authority_limits,
            &self.limits,
            started,
        )?;
        let previous_count = self.files.len();
        let mut staged = BTreeMap::new();
        let mut rebuilt_files = 0usize;
        let mut reused_files = 0usize;
        let mut total_bytes = 0u64;
        let mut refresh_unknowns = discovery.unknowns;

        let mut selected = Vec::new();
        // Task orientation is optional. Leave bounded manifest capacity for
        // subsequent direct repository tools in the same agent session.
        let direct_tool_reserve = (authority_limits.max_plan_entries / 8).min(16);
        let available_observations = manifest
            .remaining_observation_slots_v1()
            .saturating_sub(direct_tool_reserve);
        let mut new_observations = 0usize;
        for discovered in &discovery.files {
            let path = &discovered.path;
            let Some(path_text) = path.to_str().map(str::to_owned) else {
                push_unknown_v1(
                    &mut refresh_unknowns,
                    self.limits.max_unknowns,
                    CodeIntelligenceUnknownV1::new(
                        CodeIntelligenceUnknownKindV1::NonUtf8Path,
                        None,
                    ),
                );
                continue;
            };
            if discovered.bytes > self.limits.max_file_bytes {
                push_unknown_v1(
                    &mut refresh_unknowns,
                    self.limits.max_unknowns,
                    CodeIntelligenceUnknownV1::new(
                        CodeIntelligenceUnknownKindV1::FileTooLarge,
                        Some(path_text),
                    ),
                );
                continue;
            }
            total_bytes = match total_bytes.checked_add(discovered.bytes) {
                Some(total) if total <= self.limits.max_total_bytes => total,
                _ => {
                    push_unknown_v1(
                        &mut refresh_unknowns,
                        self.limits.max_unknowns,
                        CodeIntelligenceUnknownV1::new(
                            CodeIntelligenceUnknownKindV1::TotalByteLimitExceeded,
                            None,
                        ),
                    );
                    break;
                }
            };

            if !manifest.has_content_observation_v1(path) {
                if new_observations >= available_observations {
                    push_unknown_v1(
                        &mut refresh_unknowns,
                        self.limits.max_unknowns,
                        CodeIntelligenceUnknownV1::new(
                            CodeIntelligenceUnknownKindV1::FileLimitExceeded,
                            None,
                        ),
                    );
                    break;
                }
                new_observations += 1;
            }

            selected.push((discovered, path_text));
        }

        // One manifest call validates a bounded group of source paths. The
        // previous per-file calls repeatedly reobserved Git control state and
        // made warm task starts scale poorly even when extraction was reused.
        'batches: for batch in selected.chunks(64) {
            if started.elapsed() > self.limits.max_parse_time {
                push_unknown_v1(
                    &mut refresh_unknowns,
                    self.limits.max_unknowns,
                    CodeIntelligenceUnknownV1::new(
                        CodeIntelligenceUnknownKindV1::ParseTimeExceeded,
                        None,
                    ),
                );
                break;
            }
            let plan = RepositoryObservationPlanV1::new(
                batch.iter().map(|(file, _)| file.path.clone()).collect(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            let before = content_digests_v1(&manifest.observe_repository(&plan)?);
            let mut timed_out = false;
            for (discovered, path_text) in batch {
                if started.elapsed() > self.limits.max_parse_time {
                    push_unknown_v1(
                        &mut refresh_unknowns,
                        self.limits.max_unknowns,
                        CodeIntelligenceUnknownV1::new(
                            CodeIntelligenceUnknownKindV1::ParseTimeExceeded,
                            None,
                        ),
                    );
                    timed_out = true;
                    break;
                }
                let path = &discovered.path;
                let observation_digest = before.get(path).ok_or_else(|| {
                    IncompleteToolStateV1::unknown(
                        crate::workspace_authority::StateDimensionV1::RepositoryIndex,
                        "resolve code-intelligence source observation",
                    )
                })?;
                if let Some(cached) = self.files.get(path_text)
                    && cached.file.locator.observation_digest == observation_digest.to_hex()
                {
                    reused_files += 1;
                    staged.insert(path_text.clone(), cached.clone());
                    continue;
                }

                let bytes =
                    execution_epoch.read_repository_file(path, self.limits.max_file_bytes)?;
                let source_digest = StateDigestV1::from_domain_and_bytes(
                    b"again.code-intelligence.source-bytes.v1",
                    &bytes,
                )
                .to_hex();
                let indexed = extract::extract_file_v1(
                    path,
                    discovered.language,
                    &bytes,
                    &source_digest,
                    &observation_digest.to_hex(),
                    &self.limits,
                );
                staged.insert(path_text.clone(), indexed);
                rebuilt_files += 1;
            }
            let after = content_digests_v1(&manifest.observe_repository(&plan)?);
            if before != after {
                return Err(IncompleteToolStateV1::unknown(
                    crate::workspace_authority::StateDimensionV1::RepositoryContent,
                    "fence code-intelligence source observation",
                ));
            }
            if timed_out {
                break 'batches;
            }
        }

        let final_inventory = manifest.observe_repository(&discovery.inventory_plan)?;
        if inventory_digests_v1(&final_inventory) != discovery.inventory_digests {
            return Err(IncompleteToolStateV1::unknown(
                crate::workspace_authority::StateDimensionV1::RepositoryContent,
                "fence code-intelligence inventory observation",
            ));
        }

        let inventory_identity = inventory_dependent_v1(&discovery.inventory_plan);
        manifest.register_dependent(&discovery.inventory_plan, inventory_identity)?;
        for path_text in staged.keys() {
            let path = Path::new(path_text);
            let plan = RepositoryObservationPlanV1::new(
                vec![path.to_path_buf()],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            manifest.register_dependent(&plan, file_dependent_v1(path))?;
        }

        let removed_files = previous_count.saturating_sub(
            self.files
                .keys()
                .filter(|path| staged.contains_key(*path))
                .count(),
        );
        // A warm task start still validates the complete observed inventory
        // and every indexed file above. Once those exact observations match,
        // rebuilding cross-file references and changing the index identity
        // would only repeat work and invalidate otherwise stable briefs.
        let unchanged = self.generation > 0
            && rebuilt_files == 0
            && removed_files == 0
            && staged.len() == self.files.len()
            && refresh_unknowns == self.unknowns;
        if !unchanged {
            self.files = staged;
            self.unknowns = refresh_unknowns;
            self.rebuild_cross_file_indexes_v1();
            self.generation = self.generation.checked_add(1).ok_or_else(|| {
                IncompleteToolStateV1::unknown(
                    crate::workspace_authority::StateDimensionV1::RepositoryIndex,
                    "advance code-intelligence generation",
                )
            })?;
            self.index_digest = self.compute_index_digest_v1();
        }
        Ok(CodeIntelligenceRefreshV1 {
            generation: self.generation,
            discovered_files: discovery.files.len(),
            rebuilt_files,
            reused_files,
            removed_files,
            invalidated_dependents: invalidated_dependents
                + manifest
                    .take_invalidations()
                    .iter()
                    .map(|event| event.dependents().len())
                    .sum::<usize>(),
            incomplete: !self.unknowns.is_empty()
                || self.files.values().any(|file| !file.unknowns.is_empty()),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn locator_is_current_v1(
        &self,
        locator: &SourceLocatorV1,
        manifest: &mut ObservedManifestV1,
    ) -> AuthorityResult<bool> {
        let path = PathBuf::from(&locator.path);
        let plan = RepositoryObservationPlanV1::new(
            vec![path.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let repository = manifest.observe_repository(&plan)?;
        Ok(exact_observation_digest_v1(
            &repository,
            RepositoryObservationKindV1::ContentPath,
            &path,
        )?
        .to_hex()
            == locator.observation_digest)
    }

    #[allow(dead_code)]
    fn rebuild_cross_file_indexes_v1(&mut self) {
        let mut definitions_by_name: BTreeMap<String, Vec<CodeDefinitionV1>> = BTreeMap::new();
        let mut definition_locations = BTreeSet::new();
        for file in self.files.values() {
            for definition in &file.definitions {
                definitions_by_name
                    .entry(definition.name.clone())
                    .or_default()
                    .push(definition.clone());
                definition_locations.insert((
                    definition.locator.path.clone(),
                    definition.locator.start_line,
                    definition.locator.start_column_byte,
                ));
            }
        }
        let mut references = Vec::new();
        for file in self.files.values() {
            for occurrence in &file.occurrences {
                if references.len() >= self.limits.max_references {
                    push_unknown_v1(
                        &mut self.unknowns,
                        self.limits.max_unknowns,
                        CodeIntelligenceUnknownV1::new(
                            CodeIntelligenceUnknownKindV1::ReferenceLimitExceeded,
                            None,
                        ),
                    );
                    break;
                }
                if definition_locations.contains(&(
                    occurrence.locator.path.clone(),
                    occurrence.locator.start_line,
                    occurrence.locator.start_column_byte,
                )) {
                    continue;
                }
                let Some(definitions) = definitions_by_name.get(&occurrence.name) else {
                    continue;
                };
                let (target_definition_id, resolution) = if definitions.len() == 1 {
                    (
                        Some(definitions[0].definition_id.clone()),
                        CodeReferenceResolutionV1::LexicallyUniqueDefinition,
                    )
                } else {
                    (None, CodeReferenceResolutionV1::AmbiguousDefinitions)
                };
                references.push(CodeReferenceV1 {
                    name: occurrence.name.clone(),
                    target_definition_id,
                    resolution,
                    locator: occurrence.locator.clone(),
                });
            }
        }
        references.sort();
        references.dedup();
        self.references = references;
        self.rebuild_test_associations_v1();
    }

    #[allow(dead_code)]
    fn rebuild_test_associations_v1(&mut self) {
        let definitions: BTreeMap<_, _> = self
            .files
            .values()
            .flat_map(|file| file.definitions.iter())
            .map(|definition| (definition.definition_id.clone(), definition.clone()))
            .collect();
        let mut associations = Vec::new();
        for test in definitions.values().filter(|definition| definition.is_test) {
            if associations.len() >= self.limits.max_test_associations {
                push_unknown_v1(
                    &mut self.unknowns,
                    self.limits.max_unknowns,
                    CodeIntelligenceUnknownV1::new(
                        CodeIntelligenceUnknownKindV1::TestAssociationLimitExceeded,
                        None,
                    ),
                );
                break;
            }
            let mut targets: Vec<_> = self
                .references
                .iter()
                .filter(|reference| {
                    reference.locator.path == test.locator.path
                        && reference.locator.start_line >= test.locator.start_line
                })
                .filter_map(|reference| reference.target_definition_id.as_ref())
                .filter_map(|identity| definitions.get(identity))
                .filter(|definition| !definition.is_test)
                .map(|definition| definition.locator.clone())
                .collect();
            targets.sort();
            targets.dedup();
            targets.truncate(self.limits.max_related_locators);
            let mut kind = TestAssociationKindV1::LexicalReference;
            if targets.is_empty() {
                targets = conventional_test_targets_v1(
                    &test.locator.path,
                    &self.files,
                    self.limits.max_related_locators,
                );
                kind = if targets.is_empty() {
                    push_unknown_v1(
                        &mut self.unknowns,
                        self.limits.max_unknowns,
                        CodeIntelligenceUnknownV1::new(
                            CodeIntelligenceUnknownKindV1::UnknownTestTarget,
                            Some(test.locator.path.clone()),
                        ),
                    );
                    TestAssociationKindV1::UnknownTarget
                } else {
                    TestAssociationKindV1::FileConvention
                };
            }
            associations.push(TestAssociationV1 {
                test_definition_id: test.definition_id.clone(),
                kind,
                test_locator: test.locator.clone(),
                target_locators: targets,
            });
        }
        associations.sort();
        self.test_associations = associations;
    }

    #[allow(dead_code)]
    fn compute_index_digest_v1(&self) -> String {
        let mut snapshot = self.snapshot();
        snapshot.index_digest.clear();
        StateDigestV1::from_domain_and_bytes(
            b"again.code-intelligence.index.v1",
            &snapshot.canonical_bytes(),
        )
        .to_hex()
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct DiscoveredSourceV1 {
    path: PathBuf,
    language: CodeLanguageV1,
    bytes: u64,
}

#[allow(dead_code)]
struct DiscoveryV1 {
    files: Vec<DiscoveredSourceV1>,
    inventory_plan: RepositoryObservationPlanV1,
    inventory_digests: BTreeMap<PathBuf, StateDigestV1>,
    unknowns: Vec<CodeIntelligenceUnknownV1>,
}

#[allow(dead_code)]
fn discover_source_files_v1(
    execution_epoch: &WorkspaceExecutionEpochV1,
    manifest: &mut ObservedManifestV1,
    authority_limits: &WorkspaceAuthorityLimitsV1,
    limits: &CodeIntelligenceLimitsV1,
    started: Instant,
) -> AuthorityResult<DiscoveryV1> {
    let mut pending = VecDeque::from([PathBuf::new()]);
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut unknowns = Vec::new();
    while let Some(directory) = pending.pop_front() {
        if started.elapsed() > limits.max_parse_time {
            push_unknown_v1(
                &mut unknowns,
                limits.max_unknowns,
                CodeIntelligenceUnknownV1::new(
                    CodeIntelligenceUnknownKindV1::ParseTimeExceeded,
                    None,
                ),
            );
            break;
        }
        let depth = directory.components().count();
        if depth > limits.max_depth {
            push_unknown_v1(
                &mut unknowns,
                limits.max_unknowns,
                CodeIntelligenceUnknownV1::new(
                    CodeIntelligenceUnknownKindV1::DepthLimitExceeded,
                    directory.to_str().map(str::to_owned),
                ),
            );
            continue;
        }
        let plan = RepositoryObservationPlanV1::new(
            Vec::new(),
            Vec::new(),
            vec![directory.clone()],
            Vec::new(),
        );
        let before = manifest.observe_repository(&plan)?;
        let before_digest = exact_observation_digest_v1(
            &before,
            RepositoryObservationKindV1::DirectoryListing,
            &directory,
        )?;
        let entries = execution_epoch.list_source_directory(&directory, authority_limits)?;
        let after = manifest.observe_repository(&plan)?;
        let after_digest = exact_observation_digest_v1(
            &after,
            RepositoryObservationKindV1::DirectoryListing,
            &directory,
        )?;
        if before_digest != after_digest {
            return Err(IncompleteToolStateV1::unknown(
                crate::workspace_authority::StateDimensionV1::RepositoryContent,
                "fence code-intelligence directory discovery",
            ));
        }
        directories.push(directory);
        for entry in entries {
            match entry.kind() {
                RepositoryNodeKindV1::Directory => {
                    if !should_skip_directory_v1(entry.relative_path()) {
                        pending.push_back(entry.relative_path().to_path_buf());
                    }
                }
                RepositoryNodeKindV1::Regular => {
                    if entry.relative_path().to_str().is_none() {
                        push_unknown_v1(
                            &mut unknowns,
                            limits.max_unknowns,
                            CodeIntelligenceUnknownV1::new(
                                CodeIntelligenceUnknownKindV1::NonUtf8Path,
                                None,
                            ),
                        );
                        continue;
                    }
                    let Some(language) = CodeLanguageV1::from_path(entry.relative_path()) else {
                        continue;
                    };
                    if is_generated_path_v1(entry.relative_path()) {
                        push_unknown_v1(
                            &mut unknowns,
                            limits.max_unknowns,
                            CodeIntelligenceUnknownV1::new(
                                CodeIntelligenceUnknownKindV1::GeneratedFileSkipped,
                                entry.relative_path().to_str().map(str::to_owned),
                            ),
                        );
                        continue;
                    }
                    if files.len() >= limits.max_files {
                        push_unknown_v1(
                            &mut unknowns,
                            limits.max_unknowns,
                            CodeIntelligenceUnknownV1::new(
                                CodeIntelligenceUnknownKindV1::FileLimitExceeded,
                                None,
                            ),
                        );
                        pending.clear();
                        break;
                    }
                    files.push(DiscoveredSourceV1 {
                        path: entry.relative_path().to_path_buf(),
                        language,
                        bytes: entry.bytes(),
                    });
                }
                RepositoryNodeKindV1::Missing => {}
            }
        }
    }
    directories.sort_by(|left, right| path_sort_key_v1(left).cmp(path_sort_key_v1(right)));
    files.sort_by(|left, right| path_sort_key_v1(&left.path).cmp(path_sort_key_v1(&right.path)));
    let inventory_plan =
        RepositoryObservationPlanV1::new(Vec::new(), Vec::new(), directories, Vec::new());
    let inventory = manifest.observe_repository(&inventory_plan)?;
    let inventory_digests = inventory_digests_v1(&inventory);
    Ok(DiscoveryV1 {
        files,
        inventory_plan,
        inventory_digests,
        unknowns,
    })
}

#[allow(dead_code)]
fn exact_observation_digest_v1(
    repository: &crate::workspace_authority::RepositoryEpochV1,
    kind: RepositoryObservationKindV1,
    path: &Path,
) -> AuthorityResult<StateDigestV1> {
    repository
        .observations()
        .iter()
        .find(|observation| observation.kind() == kind && observation.path() == path)
        .map(|observation| observation.digest())
        .ok_or_else(|| {
            IncompleteToolStateV1::unknown(
                crate::workspace_authority::StateDimensionV1::RepositoryIndex,
                "resolve code-intelligence source observation",
            )
        })
}

#[allow(dead_code)]
fn content_digests_v1(
    repository: &crate::workspace_authority::RepositoryEpochV1,
) -> BTreeMap<PathBuf, StateDigestV1> {
    repository
        .observations()
        .iter()
        .filter(|observation| observation.kind() == RepositoryObservationKindV1::ContentPath)
        .map(|observation| (observation.path().to_path_buf(), observation.digest()))
        .collect()
}

#[allow(dead_code)]
fn inventory_digests_v1(
    repository: &crate::workspace_authority::RepositoryEpochV1,
) -> BTreeMap<PathBuf, StateDigestV1> {
    repository
        .observations()
        .iter()
        .filter(|observation| observation.kind() == RepositoryObservationKindV1::DirectoryListing)
        .map(|observation| (observation.path().to_path_buf(), observation.digest()))
        .collect()
}

#[allow(dead_code)]
fn inventory_dependent_v1(plan: &RepositoryObservationPlanV1) -> ManifestDependentV1 {
    let mut bytes = Vec::new();
    for path in plan.directory_listings() {
        bytes.extend_from_slice(path_sort_key_v1(path));
        bytes.push(0);
    }
    ManifestDependentV1::new(
        ManifestDependentKindV1::Observation,
        StateDigestV1::from_domain_and_bytes(INVENTORY_DEPENDENT_DOMAIN_V1, &bytes),
    )
}

#[allow(dead_code)]
fn file_dependent_v1(path: &Path) -> ManifestDependentV1 {
    ManifestDependentV1::new(
        ManifestDependentKindV1::Observation,
        StateDigestV1::from_domain_and_bytes(FILE_DEPENDENT_DOMAIN_V1, path_sort_key_v1(path)),
    )
}

#[allow(dead_code)]
fn should_skip_directory_v1(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    name.starts_with('.')
        || matches!(
            name,
            "target"
                | "node_modules"
                | "vendor"
                | "dist"
                | "build"
                | "coverage"
                | "__pycache__"
                | ".venv"
                | "venv"
        )
}

#[allow(dead_code)]
fn is_generated_path_v1(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".min.js")
        || name.ends_with(".min.mjs")
        || name.ends_with(".d.ts")
        || name.ends_with(".generated.go")
        || name.ends_with("_generated.rs")
}

#[allow(dead_code)]
fn conventional_test_targets_v1(
    test_path: &str,
    files: &BTreeMap<String, IndexedFileV1>,
    maximum: usize,
) -> Vec<SourceLocatorV1> {
    let path = Path::new(test_path);
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let mut candidate_names = BTreeSet::new();
    if let Some(stem) = file_name.strip_prefix("test_") {
        candidate_names.insert(stem.to_owned());
    }
    if let Some(stem) = file_name.strip_suffix("_test.go") {
        candidate_names.insert(format!("{stem}.go"));
    }
    for marker in [".test.ts", ".spec.ts", ".test.js", ".spec.js"] {
        if let Some(stem) = file_name.strip_suffix(marker) {
            let extension = marker.rsplit('.').next().unwrap_or("ts");
            candidate_names.insert(format!("{stem}.{extension}"));
        }
    }
    let mut targets: Vec<_> = files
        .values()
        .filter(|file| {
            file.file.path != test_path
                && candidate_names.contains(
                    Path::new(&file.file.path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default(),
                )
        })
        .map(|file| file.file.locator.clone())
        .collect();
    targets.sort();
    targets.truncate(maximum);
    targets
}

fn push_unknown_v1(
    unknowns: &mut Vec<CodeIntelligenceUnknownV1>,
    maximum: usize,
    unknown: CodeIntelligenceUnknownV1,
) {
    if unknowns.len() < maximum && !unknowns.contains(&unknown) {
        unknowns.push(unknown);
    }
}

#[cfg(unix)]
#[allow(dead_code)]
fn path_sort_key_v1(path: &Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes()
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn path_sort_key_v1(path: &Path) -> &[u8] {
    path.to_str().unwrap_or_default().as_bytes()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;
    use crate::code_intelligence::relevance::{
        CandidateRankingFailureV1, CandidateRankingResponseV1,
    };

    #[test]
    fn preflight_declines_large_source_inventory_without_issuing_candidates() {
        let workspace = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        for index in 0..4 {
            fs::write(
                workspace.path().join(format!("src/file_{index}.py")),
                b"value = 1\n",
            )
            .unwrap();
        }
        let limits = CodeIntelligenceLimitsV1 {
            max_files: 3,
            ..CodeIntelligenceLimitsV1::default()
        };
        assert_eq!(
            index_preflight_refusal_v1(workspace.path(), &limits, Duration::from_secs(1)),
            Some("index_preflight_file_budget_exceeded")
        );
        fs::remove_file(workspace.path().join("src/file_3.py")).unwrap();
        assert_eq!(
            index_preflight_refusal_v1(workspace.path(), &limits, Duration::from_secs(1)),
            None
        );
    }

    const FIXTURES: [(&str, &str); 9] = [
        (
            "rust/src/lib.rs",
            include_str!("../../tests/fixtures/code_intelligence/rust/src/lib.rs"),
        ),
        (
            "rust/src/model.rs",
            include_str!("../../tests/fixtures/code_intelligence/rust/src/model.rs"),
        ),
        (
            "rust/tests/widget.rs",
            include_str!("../../tests/fixtures/code_intelligence/rust/tests/widget.rs"),
        ),
        (
            "python/widget.py",
            include_str!("../../tests/fixtures/code_intelligence/python/widget.py"),
        ),
        (
            "python/test_widget.py",
            include_str!("../../tests/fixtures/code_intelligence/python/test_widget.py"),
        ),
        (
            "typescript/widget.ts",
            include_str!("../../tests/fixtures/code_intelligence/typescript/widget.ts"),
        ),
        (
            "typescript/widget.test.ts",
            include_str!("../../tests/fixtures/code_intelligence/typescript/widget.test.ts"),
        ),
        (
            "go/widget.go",
            include_str!("../../tests/fixtures/code_intelligence/go/widget.go"),
        ),
        (
            "go/widget_test.go",
            include_str!("../../tests/fixtures/code_intelligence/go/widget_test.go"),
        ),
    ];

    fn fixture_workspace_v1() -> TempDir {
        let temporary = tempfile::tempdir().unwrap();
        for (path, source) in FIXTURES {
            let target = temporary.path().join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, source).unwrap();
        }
        temporary
    }

    fn refresh_fixture_v1(
        temporary: &TempDir,
        limits: CodeIntelligenceLimitsV1,
    ) -> (
        WorkspaceExecutionEpochV1,
        ObservedManifestV1,
        CodeIntelligenceIndexV1,
        CodeIntelligenceRefreshV1,
    ) {
        let authority_limits = WorkspaceAuthorityLimitsV1::default();
        let canonical = fs::canonicalize(temporary.path()).unwrap();
        let epoch = WorkspaceExecutionEpochV1::begin(&canonical, &authority_limits).unwrap();
        let mut manifest = epoch.begin_observed_manifest(&authority_limits).unwrap();
        let mut index = CodeIntelligenceIndexV1::new(limits).unwrap();
        let refresh = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        (epoch, manifest, index, refresh)
    }

    #[test]
    fn four_language_index_has_exact_definitions_references_imports_and_tests() {
        let temporary = fixture_workspace_v1();
        let (_epoch, _manifest, index, refresh) =
            refresh_fixture_v1(&temporary, CodeIntelligenceLimitsV1::default());
        assert_eq!(refresh.discovered_files(), 9);
        assert_eq!(refresh.rebuilt_files(), 9);
        assert_eq!(refresh.reused_files(), 0);

        let snapshot = index.snapshot();
        assert_eq!(snapshot.files().len(), 9);
        for expected in [
            "parse_widget",
            "Widget",
            "build_widget",
            "renderWidget",
            "BuildWidget",
        ] {
            assert!(
                snapshot
                    .definitions()
                    .iter()
                    .any(|definition| definition.name() == expected),
                "missing definition {expected}"
            );
        }
        for expected in ["widget", "./widget", "testing", "fixture"] {
            assert!(
                snapshot
                    .imports()
                    .iter()
                    .any(|import| import.module() == expected),
                "missing import {expected}"
            );
        }
        let parse = index.definitions_named("parse_widget");
        assert_eq!(parse.len(), 1);
        assert!(!index.references_to(parse[0].definition_id()).is_empty());
        assert!(snapshot.test_associations().len() >= 4);
        for file in snapshot.files() {
            assert_eq!(
                file.extraction_coverage(),
                CodeExtractionCoverageV1::ConservativeSyntaxSubset
            );
            assert_eq!(file.locator().source_digest().len(), 64);
            assert_eq!(file.locator().observation_digest().len(), 64);
            assert!(!file.locator().path().starts_with('/'));
        }
        for definition in snapshot.definitions() {
            assert!(definition.locator().start_line() > 0);
            assert!(definition.locator().start_column_byte() > 0);
        }
    }

    #[test]
    fn optional_index_capacity_returns_partial_brief_without_poisoning_shared_manifest() {
        let temporary = fixture_workspace_v1();
        let authority_limits = WorkspaceAuthorityLimitsV1 {
            max_plan_entries: 12,
            ..WorkspaceAuthorityLimitsV1::default()
        };
        let canonical = fs::canonicalize(temporary.path()).unwrap();
        let epoch = WorkspaceExecutionEpochV1::begin(&canonical, &authority_limits).unwrap();
        let mut manifest = epoch.begin_observed_manifest(&authority_limits).unwrap();
        let mut index = CodeIntelligenceIndexV1::new(CodeIntelligenceLimitsV1::default()).unwrap();

        let refresh = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        assert!(refresh.incomplete());
        assert!(
            index.snapshot().unknowns().iter().any(|unknown| {
                unknown.kind() == CodeIntelligenceUnknownKindV1::FileLimitExceeded
            })
        );
        let remaining = FIXTURES
            .iter()
            .map(|(path, _)| PathBuf::from(path))
            .find(|path| !manifest.has_content_observation_v1(path))
            .unwrap();
        let direct_tool_plan =
            RepositoryObservationPlanV1::new(vec![remaining], Vec::new(), Vec::new(), Vec::new());
        manifest.observe_repository(&direct_tool_plan).unwrap();
    }

    #[test]
    fn unchanged_refresh_keeps_cross_file_index_identity() {
        let temporary = fixture_workspace_v1();
        let authority_limits = WorkspaceAuthorityLimitsV1::default();
        let (epoch, mut manifest, mut index, first) =
            refresh_fixture_v1(&temporary, CodeIntelligenceLimitsV1::default());
        let first_snapshot = index.snapshot();

        let warm = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        assert_eq!(warm.rebuilt_files(), 0);
        assert_eq!(warm.reused_files(), first.discovered_files());
        assert_eq!(warm.generation(), first.generation());
        assert_eq!(index.snapshot(), first_snapshot);

        fs::write(
            temporary.path().join("python/widget.py"),
            "def changed_widget() -> None:\n    pass\n",
        )
        .unwrap();
        let changed = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        assert_eq!(changed.rebuilt_files(), 1);
        assert!(changed.generation() > warm.generation());
        assert_ne!(index.snapshot(), first_snapshot);
    }

    #[test]
    fn mutation_rebuilds_only_the_affected_file_and_stales_the_old_locator() {
        let temporary = fixture_workspace_v1();
        let authority_limits = WorkspaceAuthorityLimitsV1::default();
        let (epoch, mut manifest, mut index, first) =
            refresh_fixture_v1(&temporary, CodeIntelligenceLimitsV1::default());
        assert_eq!(first.rebuilt_files(), 9);
        let old_locator = index.definitions_named("build_widget")[0].locator().clone();
        fs::write(
            temporary.path().join("python/widget.py"),
            "class Widget:\n    pass\n\ndef make_widget(name: str) -> Widget:\n    return Widget()\n",
        )
        .unwrap();

        assert!(
            !index
                .locator_is_current_v1(&old_locator, &mut manifest)
                .unwrap()
        );
        let second = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        assert_eq!(second.rebuilt_files(), 1);
        assert_eq!(second.reused_files(), 8);
        assert!(second.invalidated_dependents() >= 1);
        assert!(index.definitions_named("build_widget").is_empty());
        assert_eq!(index.definitions_named("make_widget").len(), 1);
        assert_eq!(second.removed_files(), 0);
    }

    #[test]
    fn deterministic_brief_is_bounded_and_model_cannot_add_candidates() {
        let temporary = fixture_workspace_v1();
        let (_epoch, _manifest, mut index, _refresh) =
            refresh_fixture_v1(&temporary, CodeIntelligenceLimitsV1::default());
        let request = EditBriefRequestV1::new("fix widget rendering and its tests")
            .unwrap()
            .with_changed_paths(vec!["typescript/widget.ts".to_owned()])
            .unwrap()
            .with_maximum_candidates(12)
            .unwrap();
        let first = index.compile_edit_brief_v1(&request, None);
        let second = index.compile_edit_brief_v1(&request, None);
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert!(first.canonical_bytes().len() <= 64 * 1024);
        assert_eq!(
            first.ranking_source(),
            EditBriefRankingSourceV1::Deterministic
        );
        assert_eq!(
            first.candidates()[0].locator().path(),
            "typescript/widget.ts"
        );

        struct ForgedRankerV1;
        impl CandidateRankerV1 for ForgedRankerV1 {
            fn rank_candidates(
                &self,
                _request: CandidateRankingRequestV1,
                _budget: CandidateRankingBudgetV1,
            ) -> Result<CandidateRankingResponseV1, CandidateRankingFailureV1> {
                Ok(CandidateRankingResponseV1::new(vec![
                    "model-invented-candidate".to_owned(),
                ]))
            }
        }
        let budget =
            CandidateRankingBudgetV1::new(64 * 1024, 32, Duration::from_millis(50)).unwrap();
        let fallback =
            index.compile_edit_brief_v1(&request, Some((Arc::new(ForgedRankerV1), budget)));
        assert_eq!(
            fallback.ranking_source(),
            EditBriefRankingSourceV1::DeterministicFallback
        );
        assert_eq!(
            first
                .candidates()
                .iter()
                .map(EditBriefCandidateV1::candidate_id)
                .collect::<BTreeSet<_>>(),
            fallback
                .candidates()
                .iter()
                .map(EditBriefCandidateV1::candidate_id)
                .collect::<BTreeSet<_>>()
        );
        assert!(fallback.unknowns().iter().any(|unknown| {
            unknown.kind() == CodeIntelligenceUnknownKindV1::OptionalRankingInvalid
        }));

        index.limits.max_brief_bytes = 4 * 1024;
        let byte_bounded = index.compile_edit_brief_v1(&request, None);
        assert!(byte_bounded.canonical_bytes().len() <= 4 * 1024);
        assert!(byte_bounded.unknowns().iter().any(|unknown| {
            unknown.kind() == CodeIntelligenceUnknownKindV1::BriefByteLimitExceeded
        }));
        index.limits.max_task_bytes = 4;
        let task_bounded = index.compile_edit_brief_v1(&request, None);
        assert!(task_bounded.candidates().is_empty());
        assert!(task_bounded.unknowns().iter().any(|unknown| {
            unknown.kind() == CodeIntelligenceUnknownKindV1::TaskByteLimitExceeded
        }));
    }

    #[test]
    fn optional_ranker_timeout_falls_back_without_blocking_the_brief() {
        let temporary = fixture_workspace_v1();
        let (_epoch, _manifest, index, _refresh) =
            refresh_fixture_v1(&temporary, CodeIntelligenceLimitsV1::default());
        let request = EditBriefRequestV1::new("widget").unwrap();
        struct SlowRankerV1;
        impl CandidateRankerV1 for SlowRankerV1 {
            fn rank_candidates(
                &self,
                _request: CandidateRankingRequestV1,
                _budget: CandidateRankingBudgetV1,
            ) -> Result<CandidateRankingResponseV1, CandidateRankingFailureV1> {
                thread::sleep(Duration::from_millis(100));
                Ok(CandidateRankingResponseV1::new(Vec::new()))
            }
        }
        let budget =
            CandidateRankingBudgetV1::new(64 * 1024, 32, Duration::from_millis(5)).unwrap();
        let started = Instant::now();
        let brief = index.compile_edit_brief_v1(&request, Some((Arc::new(SlowRankerV1), budget)));
        assert!(started.elapsed() < Duration::from_millis(80));
        assert_eq!(
            brief.ranking_source(),
            EditBriefRankingSourceV1::DeterministicFallback
        );
        assert!(!brief.candidates().is_empty());
    }

    #[test]
    fn generated_vendor_large_binary_and_ambiguous_sources_are_explicit() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("vendor")).unwrap();
        fs::write(
            temporary.path().join("vendor/hidden.py"),
            "def should_not_index():\n    pass\n",
        )
        .unwrap();
        fs::write(
            temporary.path().join("generated.py"),
            "# Code generated. DO NOT EDIT.\ndef generated():\n    pass\n",
        )
        .unwrap();
        fs::write(temporary.path().join("binary.py"), b"def x():\0\n").unwrap();
        fs::write(temporary.path().join("large.rs"), "x".repeat(2_048)).unwrap();
        fs::write(temporary.path().join("broken.go"), "func Broken( {\n").unwrap();
        let limits = CodeIntelligenceLimitsV1 {
            max_file_bytes: 1024,
            ..CodeIntelligenceLimitsV1::default()
        };
        let (_epoch, _manifest, index, refresh) = refresh_fixture_v1(&temporary, limits);
        assert!(refresh.incomplete());
        let snapshot = index.snapshot();
        assert!(
            !snapshot
                .files()
                .iter()
                .any(|file| file.path().contains("vendor"))
        );
        for expected in [
            CodeIntelligenceUnknownKindV1::GeneratedFileSkipped,
            CodeIntelligenceUnknownKindV1::BinaryFile,
            CodeIntelligenceUnknownKindV1::FileTooLarge,
            CodeIntelligenceUnknownKindV1::AmbiguousSyntax,
        ] {
            assert!(
                snapshot
                    .unknowns()
                    .iter()
                    .any(|unknown| unknown.kind() == expected),
                "missing unknown marker {expected:?}"
            );
        }
    }

    #[test]
    #[ignore = "diagnostic cold/warm/incremental 1k-file code-intelligence benchmark"]
    fn benchmark_code_intelligence_1k_cold_warm_and_incremental() {
        let temporary = tempfile::tempdir().unwrap();
        for index in 0..1_000 {
            let path = temporary.path().join(format!("src/module_{index:04}.rs"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                path,
                format!("pub fn symbol_{index:04}() -> usize {{ {index} }}\n"),
            )
            .unwrap();
        }
        let limits = CodeIntelligenceLimitsV1 {
            max_parse_time: Duration::from_secs(30),
            ..CodeIntelligenceLimitsV1::default()
        };
        let authority_limits = WorkspaceAuthorityLimitsV1::default();
        let canonical = fs::canonicalize(temporary.path()).unwrap();
        let epoch = WorkspaceExecutionEpochV1::begin(&canonical, &authority_limits).unwrap();
        let mut manifest = epoch.begin_observed_manifest(&authority_limits).unwrap();
        let mut index = CodeIntelligenceIndexV1::new(limits).unwrap();
        let cold_started = Instant::now();
        let cold = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        let cold_elapsed = cold_started.elapsed();
        let warm_started = Instant::now();
        let warm = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        let warm_elapsed = warm_started.elapsed();
        fs::write(
            temporary.path().join("src/module_0500.rs"),
            "pub fn changed_symbol() -> usize { 500 }\n",
        )
        .unwrap();
        let mutation_started = Instant::now();
        let mutation = index
            .refresh_from_manifest(&epoch, &mut manifest, &authority_limits)
            .unwrap();
        eprintln!(
            "cold={cold_elapsed:?} warm={warm_elapsed:?} incremental={:?} cold_rebuilt={} warm_reused={} incremental_rebuilt={}",
            mutation_started.elapsed(),
            cold.rebuilt_files(),
            warm.reused_files(),
            mutation.rebuilt_files()
        );
        assert_eq!(cold.rebuilt_files(), 1_000);
        assert_eq!(warm.reused_files(), 1_000);
        assert_eq!(mutation.rebuilt_files(), 1);
    }
}
