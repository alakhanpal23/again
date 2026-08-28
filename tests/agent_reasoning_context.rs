#[allow(dead_code)]
#[path = "../src/agent_gateway/context.rs"]
mod context;
#[allow(dead_code)]
#[path = "../src/agent_gateway/protocol.rs"]
mod protocol;

mod agent_gateway {
    pub(crate) use crate::context;
    pub(crate) use crate::protocol;
}

#[allow(dead_code)]
#[path = "../src/agent_gateway_runtime/context_compiler.rs"]
mod context_compiler;

use context::{
    CompletedReasoningObservationV1, InvalidatedReasoningFactV1, MAX_REASONING_DEPTH_V1,
    MAX_REASONING_ITEMS_V1, ReasoningBriefInputV1, ReasoningContextRefusalV1, ReasoningFactScopeV1,
    ReasoningFactV1, ReasoningInvalidationV1, ReasoningRecipientV1, ReasoningRetrievalIdentityV1,
    ReasoningScopeV1, ReasoningSourceReferenceV1, ReasoningUnknownV1,
};
use context_compiler::{
    ReasoningBriefPresentationRequestV1, ReasoningBriefPresentationV1, compile_reasoning_brief_v1,
    complete_reasoning_brief_delivery_v1,
};

fn digest(label: &str) -> String {
    blake3::hash(label.as_bytes()).to_hex().to_string()
}

fn scope(task: &str, state: &str, authorization: &str) -> ReasoningScopeV1 {
    ReasoningScopeV1::new(
        task,
        "repository-01",
        "workspace-01",
        &digest(state),
        &digest("dependencies-01"),
        &digest(authorization),
    )
    .unwrap()
}

fn recipient(agent: &str) -> ReasoningRecipientV1 {
    ReasoningRecipientV1::new(
        agent,
        "session-01",
        "turn-01",
        &digest("connection-01"),
        0,
        1,
    )
    .unwrap()
}

fn source(
    current_scope: &ReasoningScopeV1,
    result: &str,
    state: &str,
    authorization: &str,
) -> ReasoningSourceReferenceV1 {
    ReasoningSourceReferenceV1::new(
        result,
        &digest(result),
        current_scope.repository_id(),
        current_scope.workspace_id(),
        &digest(state),
        current_scope.dependency_digest(),
        &digest(authorization),
        &format!("src/{result}.rs:1"),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn fact(
    current_scope: &ReasoningScopeV1,
    id: &str,
    topic: &str,
    value: &str,
    fact_scope: ReasoningFactScopeV1,
    task: Option<&str>,
    state: &str,
    authorization: &str,
) -> ReasoningFactV1 {
    ReasoningFactV1::new(
        id,
        topic,
        &format!("verified observation {id} remains available for review"),
        &digest(value),
        fact_scope,
        task,
        vec![source(current_scope, id, state, authorization)],
    )
    .unwrap()
}

fn input() -> ReasoningBriefInputV1 {
    let scope = scope("task-01", "state-01", "authorization-01");
    let mut input = ReasoningBriefInputV1::empty(scope.clone(), recipient("agent-01"));
    let source = source(&scope, "result-01", "state-01", "authorization-01");
    input.known_facts.push(
        ReasoningFactV1::new(
            "fact-01",
            "compiler-result",
            &"verified repository observation remains current ".repeat(12),
            &digest("value-01"),
            ReasoningFactScopeV1::RepositoryWide,
            None,
            vec![source.clone()],
        )
        .unwrap(),
    );
    input.completed_observations.push(
        CompletedReasoningObservationV1::new(
            "observation-01",
            "the exact result completed and remains available through checked retrieval",
            37,
            ReasoningRetrievalIdentityV1::new("result-01", &digest("result-01"), 4096).unwrap(),
            vec![source],
        )
        .unwrap(),
    );
    input
}

fn json(compiled: &context_compiler::CompiledReasoningBriefV1) -> serde_json::Value {
    serde_json::from_slice(compiled.bytes()).unwrap()
}

#[test]
fn task_specific_fact_never_crosses_task_identity() {
    let current_scope = scope("task-b", "state-01", "authorization-01");
    let mut input = ReasoningBriefInputV1::empty(current_scope.clone(), recipient("agent-b"));
    input.known_facts.push(fact(
        &current_scope,
        "task-fact",
        "task-result",
        "value-a",
        ReasoningFactScopeV1::TaskSpecific,
        Some("task-a"),
        "state-01",
        "authorization-01",
    ));

    let compiled =
        compile_reasoning_brief_v1(&input, ReasoningBriefPresentationRequestV1::Full).unwrap();
    let output = json(&compiled);
    assert_eq!(
        output["task"]["verified_facts"].as_array().unwrap().len(),
        0
    );
    assert_eq!(
        output["invalidated_or_quarantined_facts"][0]["reason"],
        "task_changed"
    );
    assert_eq!(compiled.metrics().facts_reused, 0);
    assert_eq!(compiled.metrics().invalidated_facts, 1);
}

#[test]
fn repository_mutation_and_authorization_change_make_sources_stale() {
    for (state, authorization, expected) in [
        ("state-before", "authorization-01", "state_changed"),
        ("state-01", "authorization-before", "authorization_changed"),
    ] {
        let current_scope = scope("task-01", "state-01", "authorization-01");
        let mut input = ReasoningBriefInputV1::empty(current_scope.clone(), recipient("agent-01"));
        input.known_facts.push(fact(
            &current_scope,
            "stale-fact",
            "repository-state",
            "value-a",
            ReasoningFactScopeV1::RepositoryWide,
            None,
            state,
            authorization,
        ));
        let output = json(
            &compile_reasoning_brief_v1(&input, ReasoningBriefPresentationRequestV1::Full).unwrap(),
        );
        assert_eq!(
            output["repository"]["verified_facts"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            output["invalidated_or_quarantined_facts"][0]["reason"],
            expected
        );
    }
}

#[test]
fn stale_source_reference_is_explicitly_invalidated() {
    let current_scope = scope("task-01", "state-01", "authorization-01");
    let stale = fact(
        &current_scope,
        "missing-source",
        "source-availability",
        "value-a",
        ReasoningFactScopeV1::RepositoryWide,
        None,
        "state-01",
        "authorization-01",
    );
    let mut input = ReasoningBriefInputV1::empty(current_scope, recipient("agent-01"));
    input.invalidated_facts.push(
        InvalidatedReasoningFactV1::new(
            stale,
            ReasoningInvalidationV1::SourceUnavailable,
            Vec::new(),
        )
        .unwrap(),
    );

    let output = json(
        &compile_reasoning_brief_v1(&input, ReasoningBriefPresentationRequestV1::Full).unwrap(),
    );
    assert_eq!(
        output["invalidated_or_quarantined_facts"][0]["reason"],
        "source_unavailable"
    );
    assert_eq!(
        output["repository"]["verified_facts"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn contradictory_verified_facts_are_all_quarantined() {
    let current_scope = scope("task-01", "state-01", "authorization-01");
    let mut input = ReasoningBriefInputV1::empty(current_scope.clone(), recipient("agent-01"));
    for (id, value) in [("fact-a", "value-a"), ("fact-b", "value-b")] {
        input.known_facts.push(fact(
            &current_scope,
            id,
            "same-topic",
            value,
            ReasoningFactScopeV1::RepositoryWide,
            None,
            "state-01",
            "authorization-01",
        ));
    }

    let compiled =
        compile_reasoning_brief_v1(&input, ReasoningBriefPresentationRequestV1::Full).unwrap();
    let output = json(&compiled);
    assert_eq!(
        output["invalidated_or_quarantined_facts"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        output["invalidated_or_quarantined_facts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|fact| fact["reason"] == "contradictory_evidence")
    );
    assert_eq!(compiled.metrics().facts_reused, 0);
    assert_eq!(compiled.metrics().false_hit_quarantines, 1);
}

#[test]
fn result_id_or_digest_cannot_reuse_an_acknowledgment_for_changed_evidence() {
    let first_input = input();
    let full = compile_reasoning_brief_v1(&first_input, ReasoningBriefPresentationRequestV1::Full)
        .unwrap();
    let acknowledgment = complete_reasoning_brief_delivery_v1(
        &first_input.recipient,
        &full,
        full.bytes(),
        true,
        true,
        true,
    )
    .unwrap();

    let mut forged = input();
    forged.known_facts[0] = fact(
        &forged.scope,
        "forged-result-id",
        "compiler-result",
        "value-02",
        ReasoningFactScopeV1::RepositoryWide,
        None,
        "state-01",
        "authorization-01",
    );
    let compiled = compile_reasoning_brief_v1(
        &forged,
        ReasoningBriefPresentationRequestV1::PreferCompact {
            acknowledgment: Some(&acknowledgment),
        },
    )
    .unwrap();
    assert_eq!(compiled.presentation(), ReasoningBriefPresentationV1::Full);
    assert_eq!(compiled.metrics().confirmed_tokens_avoided, 0);
}

#[test]
fn compaction_restart_cancellation_and_session_change_invalidate_delivery() {
    let original = input();
    let full =
        compile_reasoning_brief_v1(&original, ReasoningBriefPresentationRequestV1::Full).unwrap();
    let acknowledgment = complete_reasoning_brief_delivery_v1(
        &original.recipient,
        &full,
        full.bytes(),
        true,
        true,
        true,
    )
    .unwrap();

    let mut recipients = vec![
        original.recipient.after_compaction().unwrap(),
        original
            .recipient
            .after_restart(&digest("connection-02"))
            .unwrap(),
        original.recipient.after_cancellation().unwrap(),
    ];
    recipients.push(
        ReasoningRecipientV1::new(
            "agent-01",
            "session-02",
            "turn-01",
            &digest("connection-01"),
            0,
            1,
        )
        .unwrap(),
    );
    for recipient in recipients {
        let mut changed = input();
        changed.recipient = recipient;
        let compiled = compile_reasoning_brief_v1(
            &changed,
            ReasoningBriefPresentationRequestV1::PreferCompact {
                acknowledgment: Some(&acknowledgment),
            },
        )
        .unwrap();
        assert_eq!(compiled.presentation(), ReasoningBriefPresentationV1::Full);
        assert_eq!(compiled.metrics().delivery_confirmed_bytes_omitted, 0);
    }
}

#[test]
fn confirmed_compact_form_retains_explicit_full_retrieval_identity() {
    let input = input();
    let full =
        compile_reasoning_brief_v1(&input, ReasoningBriefPresentationRequestV1::Full).unwrap();
    let acknowledgment = complete_reasoning_brief_delivery_v1(
        &input.recipient,
        &full,
        full.bytes(),
        true,
        true,
        true,
    )
    .unwrap();
    let compact = compile_reasoning_brief_v1(
        &input,
        ReasoningBriefPresentationRequestV1::PreferCompact {
            acknowledgment: Some(&acknowledgment),
        },
    )
    .unwrap();

    assert_eq!(
        compact.presentation(),
        ReasoningBriefPresentationV1::CompactReference
    );
    assert!(compact.full_retrieval() == full.full_retrieval());
    assert_eq!(compact.full_exact_bytes(), full.bytes());
    assert_eq!(
        json(&compact)["full_result_retrieval"][0]["result_id"],
        "result-01"
    );
    assert!(!compact.grants_reuse());
}

#[test]
fn canonical_output_is_independent_of_input_order() {
    let current_scope = scope("task-01", "state-01", "authorization-01");
    let first_fact = fact(
        &current_scope,
        "fact-a",
        "topic-a",
        "value-a",
        ReasoningFactScopeV1::RepositoryWide,
        None,
        "state-01",
        "authorization-01",
    );
    let second_fact = fact(
        &current_scope,
        "fact-b",
        "topic-b",
        "value-b",
        ReasoningFactScopeV1::RepositoryWide,
        None,
        "state-01",
        "authorization-01",
    );
    let mut first = ReasoningBriefInputV1::empty(current_scope.clone(), recipient("agent-01"));
    first.known_facts = vec![first_fact.clone(), second_fact.clone()];
    let mut second = ReasoningBriefInputV1::empty(current_scope, recipient("agent-01"));
    second.known_facts = vec![second_fact, first_fact];

    let first =
        compile_reasoning_brief_v1(&first, ReasoningBriefPresentationRequestV1::Full).unwrap();
    let second =
        compile_reasoning_brief_v1(&second, ReasoningBriefPresentationRequestV1::Full).unwrap();
    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.full_digest(), second.full_digest());
}

#[test]
fn item_byte_depth_and_sensitive_content_bounds_fail_closed() {
    assert_eq!(MAX_REASONING_DEPTH_V1, 6);
    let mut too_many = input();
    too_many.known_facts.clear();
    too_many.completed_observations.clear();
    for index in 0..=MAX_REASONING_ITEMS_V1 {
        too_many.explicit_unknowns.push(
            ReasoningUnknownV1::new(&format!("unknown-{index}"), "bounded unknown observation")
                .unwrap(),
        );
    }
    assert_eq!(
        compile_reasoning_brief_v1(&too_many, ReasoningBriefPresentationRequestV1::Full,)
            .unwrap_err(),
        ReasoningContextRefusalV1::ItemBound
    );

    let current_scope = scope("task-01", "state-01", "authorization-01");
    let mut too_large = ReasoningBriefInputV1::empty(current_scope.clone(), recipient("agent-01"));
    for index in 0..MAX_REASONING_ITEMS_V1 {
        let id = format!("large-{index:02}");
        too_large.known_facts.push(
            ReasoningFactV1::new(
                &id,
                &format!("topic-{index:02}"),
                &"x".repeat(1024),
                &digest(&id),
                ReasoningFactScopeV1::RepositoryWide,
                None,
                vec![source(&current_scope, &id, "state-01", "authorization-01")],
            )
            .unwrap(),
        );
    }
    assert_eq!(
        compile_reasoning_brief_v1(&too_large, ReasoningBriefPresentationRequestV1::Full,)
            .unwrap_err(),
        ReasoningContextRefusalV1::ByteBound
    );

    let mut sensitive = input();
    sensitive.known_facts[0] = ReasoningFactV1::new(
        "sensitive-fact",
        "sensitive-topic",
        "verified password value was present in the observation",
        &digest("sensitive-value"),
        ReasoningFactScopeV1::RepositoryWide,
        None,
        vec![source(
            &sensitive.scope,
            "sensitive-result",
            "state-01",
            "authorization-01",
        )],
    )
    .unwrap();
    assert_eq!(
        compile_reasoning_brief_v1(&sensitive, ReasoningBriefPresentationRequestV1::Full,)
            .unwrap_err(),
        ReasoningContextRefusalV1::SensitiveContent
    );
}
