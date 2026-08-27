#[path = "../src/agent_candidate_validation.rs"]
mod agent_candidate_validation;
#[allow(dead_code, unused_imports)]
#[path = "../src/agent_gateway.rs"]
mod agent_gateway;
#[allow(dead_code)]
#[path = "../src/workspace_authority.rs"]
mod workspace_authority;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use agent_candidate_validation::{
    CandidateSuggestionLimitsV1, CandidateValidationContextV1, DependencyProofReferenceV1,
    DeterministicValidationRequestV1, DeterministicValidationStatusV1,
    DeterministicValidatorIdentityV1, FreshExecutionReasonV1, FreshExecutionRequiredV1,
    ValidationOnlyArtifactV1, build_deterministic_validation_requests_v1,
    execute_fresh_after_validation_v1,
};
use agent_gateway::{
    AgentCallIdentityV1, CandidateFreshnessV1, CanonicalArguments, DigestReferenceV1, EffectClass,
    FreshnessRequirementV1, GatewayDecision, GatewayToolCallInputV1, GatewayToolCallV1,
    ModelIdentityV1, PermissionClass, PresentationMode, ProviderIdentityV1,
    RepositoryEnvironmentStateV1, ReuseCandidateV1, RoutingCandidatesV1, StateDigestReferenceV1,
    TaskIdentityV1, ToolIdentityV1, WorkspaceIdentityV1, route,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use workspace_authority::{
    CompleteToolStateV1, EnvironmentObservationPlanV1, EnvironmentRelevanceProofV1,
    ExternalFreshnessV1, RepositoryObservationPlanV1, StateDigestV1, StateDimensionV1,
    TaskStateInputV1, TaskStateV1, WorkspaceAuthorityLimitsV1, observe_environment_v1,
    observe_repository_v1, validated_no_external_dependencies_for_test_v1,
};

const RETRIEVAL_EPOCH: u64 = 7;
const NOW_MILLIS: u64 = 150;

fn digest(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn state_digest(value: &[u8]) -> StateDigestV1 {
    StateDigestV1::from_domain_and_bytes(b"again.candidate-validation-test.v1", value)
}

fn workspace_limits() -> WorkspaceAuthorityLimitsV1 {
    WorkspaceAuthorityLimitsV1::default()
}

fn complete_state(revision: u64) -> CompleteToolStateV1 {
    let temporary = TempDir::new().unwrap();
    let root = fs::canonicalize(temporary.path())
        .unwrap()
        .join("repository");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("input"), format!("revision-{revision}\n")).unwrap();
    let repository = observe_repository_v1(
        &root,
        &RepositoryObservationPlanV1::new(
            vec![PathBuf::from("input")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        &workspace_limits(),
    )
    .unwrap();

    let environment_dimensions = [
        StateDimensionV1::OperatingSystem,
        StateDimensionV1::Architecture,
        StateDimensionV1::Kernel,
        StateDimensionV1::Executables,
        StateDimensionV1::WorkingDirectory,
        StateDimensionV1::EnvironmentValues,
        StateDimensionV1::ResourceProfile,
        StateDimensionV1::SandboxBackend,
        StateDimensionV1::McpProviderToolSchema,
        StateDimensionV1::AuthorizationScope,
    ];
    let exclusions = environment_dimensions
        .into_iter()
        .map(|dimension| (dimension, b"excluded by deterministic test schema".to_vec()))
        .collect();
    let environment = observe_environment_v1(
        &EnvironmentObservationPlanV1::new().with_relevance_proof(
            EnvironmentRelevanceProofV1::from_exclusions(exclusions, &workspace_limits()).unwrap(),
        ),
        &workspace_limits(),
    )
    .unwrap();
    let task = TaskStateV1::from_input(
        TaskStateInputV1 {
            task_id: "candidate-validation-task".into(),
            task_revision: revision,
            user_goal_digest: state_digest(b"goal"),
            accepted_constraints_digest: state_digest(b"constraints"),
            branch_identity: "refs/heads/test".into(),
            worktree_identity: "candidate-validation-worktree".into(),
            patch_digest: state_digest(format!("patch-{revision}").as_bytes()),
            plan_revision: revision,
            compaction_epoch: 1,
        },
        &workspace_limits(),
    )
    .unwrap();
    let external = ExternalFreshnessV1::no_external_dependencies(
        validated_no_external_dependencies_for_test_v1(
            b"test schema has no external dependencies",
            &workspace_limits(),
        )
        .unwrap(),
    );
    CompleteToolStateV1::new(repository, environment, task, external)
}

fn canonical_call(
    state: &CompleteToolStateV1,
    arguments: &str,
    effect: EffectClass,
    state_known: bool,
) -> GatewayToolCallV1 {
    let request_state = if state_known {
        RepositoryEnvironmentStateV1::Known {
            reference: StateDigestReferenceV1 {
                schema_version: state.schema_version(),
                repository: DigestReferenceV1::new(
                    "blake3",
                    state.agent_context().repository().digest().to_hex(),
                )
                .unwrap(),
                environment: DigestReferenceV1::new(
                    "blake3",
                    state.agent_context().environment().digest().to_hex(),
                )
                .unwrap(),
            },
        }
    } else {
        RepositoryEnvironmentStateV1::Unknown
    };
    GatewayToolCallV1::from_input(GatewayToolCallInputV1 {
        schema_version: 1,
        provider: ProviderIdentityV1 {
            id: "provider".into(),
            version: "1".into(),
        },
        model: ModelIdentityV1 {
            id: "model".into(),
            version: "1".into(),
        },
        tool: ToolIdentityV1 {
            id: "read-tool".into(),
            version: "1".into(),
        },
        arguments: CanonicalArguments::from_json_str(arguments).unwrap(),
        workspace: WorkspaceIdentityV1 {
            workspace_id: "workspace".into(),
            cwd: ".".into(),
        },
        call: AgentCallIdentityV1 {
            agent_id: "agent".into(),
            session_id: "session".into(),
            turn_id: "turn".into(),
            call_id: "call".into(),
        },
        task: Some(TaskIdentityV1 {
            task_id: "candidate-validation-task".into(),
            version: "1".into(),
        }),
        state: request_state,
        permission_class: PermissionClass::Preapproved,
        effect_class: effect,
        freshness: FreshnessRequirementV1::Snapshot,
        presentation: PresentationMode::Exact,
    })
    .unwrap()
}

fn validator(version: &str) -> DeterministicValidatorIdentityV1 {
    DeterministicValidatorIdentityV1::new("validator", version, &digest(b'c')).unwrap()
}

fn proof(version: &str, seed: u8) -> DependencyProofReferenceV1 {
    DependencyProofReferenceV1::new(1, "dependency-proof", version, &digest(seed)).unwrap()
}

fn suggestion_document(
    call: &GatewayToolCallV1,
    state: &CompleteToolStateV1,
    suggestions: Value,
) -> Value {
    json!({
        "schema_version": 1,
        "request_digest": call.request_digest().as_str(),
        "complete_state_digest": state.digest().to_hex(),
        "retrieval_epoch": RETRIEVAL_EPOCH,
        "observed_at_millis": 100,
        "expires_at_millis": 200,
        "suggestions": suggestions
    })
}

fn build(
    document: &Value,
    call: &GatewayToolCallV1,
    state: &CompleteToolStateV1,
    validator: &DeterministicValidatorIdentityV1,
    proof: &DependencyProofReferenceV1,
) -> Result<Vec<DeterministicValidationRequestV1>, FreshExecutionRequiredV1> {
    build_deterministic_validation_requests_v1(
        &serde_json::to_vec(document).unwrap(),
        CandidateValidationContextV1 {
            canonical_request: call,
            complete_state: state,
            validator,
            dependency_proof: proof,
            expected_retrieval_epoch: RETRIEVAL_EPOCH,
            now_millis: NOW_MILLIS,
        },
        &CandidateSuggestionLimitsV1::default(),
    )
}

fn assert_validation_only<T: ValidationOnlyArtifactV1>() {}

const _: () = {
    assert!(!DeterministicValidationRequestV1::GRANTS_EXACT);
    assert!(!DeterministicValidationRequestV1::GRANTS_COVERAGE);
    assert!(!DeterministicValidationRequestV1::GRANTS_REPLAY);
    assert!(!DeterministicValidationRequestV1::GRANTS_EXECUTION);
    assert!(!DeterministicValidationRequestV1::GRANTS_REUSE);
    assert!(!DeterministicValidationRequestV1::GRANTS_SERVE);
    assert!(!FreshExecutionRequiredV1::GRANTS_SERVE);
};

#[test]
fn compile_time_surface_returns_only_validation_artifacts() {
    assert_validation_only::<DeterministicValidationRequestV1>();
    assert_validation_only::<FreshExecutionRequiredV1>();

    let state = complete_state(1);
    let call = canonical_call(
        &state,
        r#"{"query":"diamond"}"#,
        EffectClass::SnapshotRead,
        true,
    );
    let validator = validator("1");
    let proof = proof("1", b'd');
    let document = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque:model-run-7" }]),
    );
    let output: Result<Vec<DeterministicValidationRequestV1>, FreshExecutionRequiredV1> =
        build(&document, &call, &state, &validator, &proof);
    assert_eq!(output.unwrap().len(), 1);
}

#[test]
fn admitted_suggestion_binds_every_deterministic_validator_input() {
    let state = complete_state(1);
    let call = canonical_call(
        &state,
        r#"{"query":"diamond"}"#,
        EffectClass::SnapshotRead,
        true,
    );
    let validator = validator("validator-v3");
    let proof = proof("proof-v5", b'd');
    let document = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque:model-run-7" }]),
    );
    let requests = build(&document, &call, &state, &validator, &proof).unwrap();
    let request = &requests[0];
    assert_eq!(request.validation_request_id().len(), 64);
    assert_eq!(
        request.canonical_request_digest(),
        call.request_digest().as_str()
    );
    assert_eq!(request.canonical_request_bytes(), call.canonical_bytes());
    assert_eq!(request.complete_state_digest(), state.digest().to_hex());
    assert_eq!(request.complete_state_bytes(), state.canonical_bytes());
    assert_eq!(request.source_result_id().as_str(), digest(b'a'));
    assert_eq!(request.model_provenance().as_str(), "opaque:model-run-7");
    assert_eq!(request.model_provenance().digest().len(), 64);
    assert_eq!(request.validator().validator_id(), "validator");
    assert_eq!(request.validator().validator_version(), "validator-v3");
    assert_eq!(request.validator().implementation_digest(), digest(b'c'));
    assert_eq!(request.dependency_proof().schema_version(), 1);
    assert_eq!(request.dependency_proof().proof_id(), "dependency-proof");
    assert_eq!(request.dependency_proof().proof_version(), "proof-v5");
    assert_eq!(request.dependency_proof().proof_digest(), digest(b'd'));
    assert_eq!(request.retrieval_epoch(), RETRIEVAL_EPOCH);
    let debug = format!("{request:?}");
    assert!(!debug.contains("opaque:model-run-7"));
    assert!(!debug.contains(&digest(b'a')));
}

#[test]
fn validation_request_identity_changes_for_every_required_binding() {
    let state = complete_state(1);
    let call = canonical_call(
        &state,
        r#"{"query":"diamond"}"#,
        EffectClass::SnapshotRead,
        true,
    );
    let base_validator = validator("1");
    let base_proof = proof("1", b'd');
    let base_document = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque:one" }]),
    );
    let base = build(&base_document, &call, &state, &base_validator, &base_proof)
        .unwrap()
        .remove(0)
        .validation_request_id()
        .to_owned();
    let mut identities = BTreeSet::from([base]);

    let changed_call = canonical_call(
        &state,
        r#"{"query":"changed"}"#,
        EffectClass::SnapshotRead,
        true,
    );
    let changed_call_document = suggestion_document(
        &changed_call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque:one" }]),
    );
    identities.insert(
        build(
            &changed_call_document,
            &changed_call,
            &state,
            &base_validator,
            &base_proof,
        )
        .unwrap()[0]
            .validation_request_id()
            .into(),
    );

    let changed_state = complete_state(2);
    let changed_state_call = canonical_call(
        &changed_state,
        r#"{"query":"diamond"}"#,
        EffectClass::SnapshotRead,
        true,
    );
    let changed_state_document = suggestion_document(
        &changed_state_call,
        &changed_state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque:one" }]),
    );
    identities.insert(
        build(
            &changed_state_document,
            &changed_state_call,
            &changed_state,
            &base_validator,
            &base_proof,
        )
        .unwrap()[0]
            .validation_request_id()
            .into(),
    );

    for (result, provenance, validator, proof) in [
        (digest(b'b'), "opaque:one", validator("1"), proof("1", b'd')),
        (digest(b'a'), "opaque:two", validator("1"), proof("1", b'd')),
        (digest(b'a'), "opaque:one", validator("2"), proof("1", b'd')),
        (digest(b'a'), "opaque:one", validator("1"), proof("2", b'e')),
    ] {
        let document = suggestion_document(
            &call,
            &state,
            json!([{ "result_id": result, "model_provenance": provenance }]),
        );
        identities.insert(
            build(&document, &call, &state, &validator, &proof).unwrap()[0]
                .validation_request_id()
                .into(),
        );
    }
    assert_eq!(identities.len(), 7);
}

#[test]
fn suggestions_are_deterministically_sorted_and_duplicates_refuse() {
    let state = complete_state(1);
    let call = canonical_call(&state, r#"{}"#, EffectClass::DeterministicCompute, true);
    let validator = validator("1");
    let proof = proof("1", b'd');
    let document = suggestion_document(
        &call,
        &state,
        json!([
            { "result_id": digest(b'b'), "model_provenance": "opaque:b" },
            { "result_id": digest(b'a'), "model_provenance": "opaque:a" }
        ]),
    );
    let requests = build(&document, &call, &state, &validator, &proof).unwrap();
    assert_eq!(requests[0].source_result_id().as_str(), digest(b'a'));
    assert_eq!(requests[1].source_result_id().as_str(), digest(b'b'));

    let duplicate = suggestion_document(
        &call,
        &state,
        json!([
            { "result_id": digest(b'a'), "model_provenance": "opaque:first" },
            { "result_id": digest(b'a'), "model_provenance": "opaque:second" }
        ]),
    );
    assert_eq!(
        build(&duplicate, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::DuplicateSuggestion
    );
}

#[test]
fn oversized_input_candidates_and_provenance_refuse() {
    let state = complete_state(1);
    let call = canonical_call(&state, r#"{}"#, EffectClass::SnapshotRead, true);
    let validator = validator("1");
    let proof = proof("1", b'd');
    let document = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque" }]),
    );
    let tiny_limits = CandidateSuggestionLimitsV1 {
        max_input_bytes: 8,
        ..CandidateSuggestionLimitsV1::default()
    };
    let oversized_input = build_deterministic_validation_requests_v1(
        &serde_json::to_vec(&document).unwrap(),
        CandidateValidationContextV1 {
            canonical_request: &call,
            complete_state: &state,
            validator: &validator,
            dependency_proof: &proof,
            expected_retrieval_epoch: RETRIEVAL_EPOCH,
            now_millis: NOW_MILLIS,
        },
        &tiny_limits,
    )
    .unwrap_err();
    assert_eq!(
        oversized_input.reason(),
        FreshExecutionReasonV1::SuggestionTooLarge
    );

    let oversized_provenance = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "x".repeat(1_025) }]),
    );
    assert_eq!(
        build(&oversized_provenance, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::SuggestionTooLarge
    );

    let too_many = suggestion_document(
        &call,
        &state,
        Value::Array(
            (0..65)
                .map(|index| {
                    json!({
                        "result_id": format!("{index:064x}"),
                        "model_provenance": "opaque"
                    })
                })
                .collect(),
        ),
    );
    assert_eq!(
        build(&too_many, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::SuggestionTooLarge
    );
}

#[test]
fn stale_epoch_cross_request_and_cross_state_suggestions_refuse() {
    let state = complete_state(1);
    let call = canonical_call(&state, r#"{}"#, EffectClass::SnapshotRead, true);
    let validator = validator("1");
    let proof = proof("1", b'd');
    let base = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque" }]),
    );

    let mut stale = base.clone();
    stale["expires_at_millis"] = json!(149);
    assert_eq!(
        build(&stale, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::StaleSuggestion
    );

    let mut wrong_epoch = base.clone();
    wrong_epoch["retrieval_epoch"] = json!(RETRIEVAL_EPOCH + 1);
    assert_eq!(
        build(&wrong_epoch, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::RetrievalEpochMismatch
    );

    let mut cross_request = base.clone();
    cross_request["request_digest"] = json!(digest(b'f'));
    assert_eq!(
        build(&cross_request, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::CrossRequest
    );

    let mut cross_state = base;
    cross_state["complete_state_digest"] = json!(digest(b'e'));
    assert_eq!(
        build(&cross_state, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::CrossState
    );
}

#[test]
fn malformed_duplicate_key_and_extra_model_fields_refuse() {
    let state = complete_state(1);
    let call = canonical_call(&state, r#"{}"#, EffectClass::SnapshotRead, true);
    let validator = validator("1");
    let proof = proof("1", b'd');
    let context = || CandidateValidationContextV1 {
        canonical_request: &call,
        complete_state: &state,
        validator: &validator,
        dependency_proof: &proof,
        expected_retrieval_epoch: RETRIEVAL_EPOCH,
        now_millis: NOW_MILLIS,
    };
    for malformed_input in [b"{".as_slice(), b"[]".as_slice()] {
        assert_eq!(
            build_deterministic_validation_requests_v1(
                malformed_input,
                context(),
                &CandidateSuggestionLimitsV1::default(),
            )
            .unwrap_err()
            .reason(),
            FreshExecutionReasonV1::MalformedSuggestion
        );
    }

    let duplicate = format!(
        "{{\"schema_version\":1,\"schema_version\":1,\"request_digest\":\"{}\",\"complete_state_digest\":\"{}\",\"retrieval_epoch\":7,\"observed_at_millis\":100,\"expires_at_millis\":200,\"suggestions\":[]}}",
        call.request_digest().as_str(),
        state.digest().to_hex()
    );
    assert_eq!(
        build_deterministic_validation_requests_v1(
            duplicate.as_bytes(),
            context(),
            &CandidateSuggestionLimitsV1::default(),
        )
        .unwrap_err()
        .reason(),
        FreshExecutionReasonV1::DuplicateSuggestion
    );

    let extra_model_field = suggestion_document(
        &call,
        &state,
        json!([{
            "result_id": digest(b'a'),
            "model_provenance": "opaque",
            "score": 0.99
        }]),
    );
    assert_eq!(
        build(&extra_model_field, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::MalformedSuggestion
    );

    let invalid_result = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": "not-a-result-id", "model_provenance": "opaque" }]),
    );
    assert_eq!(
        build(&invalid_result, &call, &state, &validator, &proof)
            .unwrap_err()
            .reason(),
        FreshExecutionReasonV1::MalformedSuggestion
    );
}

#[test]
fn incomplete_state_and_non_validatable_effects_execute_fresh() {
    let state = complete_state(1);
    let validator = validator("1");
    let proof = proof("1", b'd');

    let unknown_state_call = canonical_call(&state, r#"{}"#, EffectClass::SnapshotRead, false);
    let unknown_state_document = suggestion_document(
        &unknown_state_call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque" }]),
    );
    assert_eq!(
        build(
            &unknown_state_document,
            &unknown_state_call,
            &state,
            &validator,
            &proof,
        )
        .unwrap_err()
        .reason(),
        FreshExecutionReasonV1::IncompleteState
    );

    let mutation_call = canonical_call(&state, r#"{}"#, EffectClass::Mutation, true);
    let mutation_document = suggestion_document(
        &mutation_call,
        &state,
        json!([{ "result_id": digest(b'a'), "model_provenance": "opaque" }]),
    );
    assert_eq!(
        build(
            &mutation_document,
            &mutation_call,
            &state,
            &validator,
            &proof,
        )
        .unwrap_err()
        .reason(),
        FreshExecutionReasonV1::EffectNotDeterministicallyValidatable
    );
}

#[test]
fn failed_and_incomplete_validation_return_execute_fresh_only() {
    assert!(execute_fresh_after_validation_v1(DeterministicValidationStatusV1::Complete).is_none());
    let failed = execute_fresh_after_validation_v1(DeterministicValidationStatusV1::Failed)
        .expect("failed validation must execute fresh");
    assert_eq!(failed.code(), "execute_fresh");
    assert_eq!(failed.reason(), FreshExecutionReasonV1::ValidationFailed);
    assert_eq!(failed.reason().code(), "validation_failed");

    let incomplete = execute_fresh_after_validation_v1(DeterministicValidationStatusV1::Incomplete)
        .expect("incomplete validation must execute fresh");
    assert_eq!(incomplete.code(), "execute_fresh");
    assert_eq!(
        incomplete.reason(),
        FreshExecutionReasonV1::ValidationIncomplete
    );
}

#[test]
fn ai_candidate_never_reaches_a_serve_decision_directly() {
    let state = complete_state(1);
    let call = canonical_call(&state, r#"{}"#, EffectClass::SnapshotRead, true);
    let result_id = digest(b'a');
    let semantic = ReuseCandidateV1::semantic_or_ai_candidate(
        call.request_digest(),
        DigestReferenceV1::new("blake3", &result_id).unwrap(),
        "opaque-provider",
        "opaque-model",
        "opaque-version",
        CandidateFreshnessV1::ExactSnapshot,
    )
    .unwrap();
    let routed = route(
        &call,
        &RoutingCandidatesV1::default().with_semantic_candidate(semantic),
    );
    assert_eq!(routed, GatewayDecision::ValidateSemanticCandidate);
    assert!(!matches!(
        routed,
        GatewayDecision::ServeExact | GatewayDecision::ServeDeterministicCoverage
    ));

    let validator = validator("1");
    let proof = proof("1", b'd');
    let document = suggestion_document(
        &call,
        &state,
        json!([{ "result_id": result_id, "model_provenance": "opaque:model" }]),
    );
    let request = build(&document, &call, &state, &validator, &proof)
        .unwrap()
        .remove(0);
    assert_eq!(request.source_result_id().as_str(), digest(b'a'));
}
