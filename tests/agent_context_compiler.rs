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
    ReasoningBriefInputV1, ReasoningFactScopeV1, ReasoningFactV1, ReasoningRecipientV1,
    ReasoningScopeV1, ReasoningSourceReferenceV1,
};
use context_compiler::{
    ContextCompilerRefusalV1, ContextIdentityV1, ContextPresentationRequestV1, ContextResultV1,
    MAX_CONTEXT_EXCERPT_BYTES_V1, MAX_CONTEXT_RESULT_BYTES_V1, ReasoningBriefPresentationRequestV1,
    ReasoningBriefPresentationV1, compile_context_presentation_v1, compile_reasoning_brief_v1,
    complete_exact_delivery_v1, complete_reasoning_brief_delivery_v1,
};

fn context(agent: &str, session: &str, turn: &str, generation: u64) -> ContextIdentityV1 {
    ContextIdentityV1::new(agent, session, turn, generation).unwrap()
}

fn result() -> ContextResultV1 {
    ContextResultV1::new("result-01", &[0xff, b'A', 0x80, b'B', b'C', b'D']).unwrap()
}

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn reasoning_input() -> ReasoningBriefInputV1 {
    let scope = ReasoningScopeV1::new(
        "task-01",
        "repo-01",
        "workspace-01",
        &digest('a'),
        &digest('b'),
        &digest('c'),
    )
    .unwrap();
    let recipient =
        ReasoningRecipientV1::new("agent-01", "session-01", "turn-01", &digest('d'), 3, 1).unwrap();
    let source = ReasoningSourceReferenceV1::new(
        "result-01",
        &digest('e'),
        "repo-01",
        "workspace-01",
        &digest('a'),
        &digest('b'),
        &digest('c'),
        "src/lib.rs:17",
    )
    .unwrap();
    let mut input = ReasoningBriefInputV1::empty(scope, recipient);
    input.known_facts.push(
        ReasoningFactV1::new(
            "fact-01",
            "compiler-state",
            &"the verified compiler observation remains current ".repeat(12),
            &digest('f'),
            ReasoningFactScopeV1::RepositoryWide,
            None,
            vec![source],
        )
        .unwrap(),
    );
    input
}

#[test]
fn exact_full_result_is_binary_safe_and_preserves_retrieval_identity() {
    let context = context("agent", "session", "turn", 4);
    let result = result();
    let compiled =
        compile_context_presentation_v1(&context, &result, ContextPresentationRequestV1::ExactFull)
            .unwrap();

    assert_eq!(
        compiled.exact_bytes(),
        Some(&[0xff, b'A', 0x80, b'B', b'C', b'D'][..])
    );
    assert_eq!(compiled.identity(), result.identity());
    assert_eq!(compiled.identity().result_id(), "result-01");
    assert_eq!(compiled.identity().total_bytes(), 6);
    assert_eq!(compiled.source_bytes_omitted(), 0);
    assert_eq!(compiled.estimated_tokens(), 2);
    assert!(!compiled.grants_reuse());
    assert!(!compiled.grants_execution());
}

#[test]
fn excerpt_uses_exact_byte_offsets_and_deterministic_accounting() {
    let context = context("agent", "session", "turn", 0);
    let result = result();
    let request = ContextPresentationRequestV1::DeterministicExcerpt {
        start: 1,
        max_bytes: 3,
    };
    let first = compile_context_presentation_v1(&context, &result, request).unwrap();
    let second = compile_context_presentation_v1(&context, &result, request).unwrap();

    assert_eq!(first, second);
    let (bytes, offsets) = first.excerpt().unwrap();
    assert_eq!(bytes, &[b'A', 0x80, b'B']);
    assert_eq!(offsets.start(), 1);
    assert_eq!(offsets.end_exclusive(), 4);
    assert_eq!(first.identity(), result.identity());
    assert_eq!(first.source_bytes_omitted(), 3);
    assert_eq!(first.estimated_tokens(), 1);
    assert!(first.exact_bytes().is_none());
    assert!(first.compact_reference_bytes().is_none());
}

#[test]
fn compact_reference_requires_exact_same_context_delivery_authority() {
    let context = context("agent", "session", "turn", 7);
    let result = result();
    let authority = complete_exact_delivery_v1(
        &context,
        &result,
        &[0xff, b'A', 0x80, b'B', b'C', b'D'],
        true,
        true,
    )
    .unwrap();
    let compiled = compile_context_presentation_v1(
        &context,
        &result,
        ContextPresentationRequestV1::CompactContentAddressed {
            authority: &authority,
        },
    )
    .unwrap();

    let reference = compiled.compact_reference_bytes().unwrap();
    assert!(reference.starts_with(b"again-result-v1:blake3:"));
    assert!(reference.ends_with(b":6"));
    assert_eq!(compiled.identity(), result.identity());
    assert_eq!(compiled.source_bytes_omitted(), 6);
    assert_eq!(
        compiled.estimated_tokens(),
        (reference.len() as u64).div_ceil(4)
    );
    assert!(compiled.exact_bytes().is_none());
    assert!(compiled.excerpt().is_none());
    assert!(!reference.windows(3).any(|window| window == b"ABC"));
}

#[test]
fn cross_agent_session_turn_and_compaction_authority_are_refused() {
    let original = context("agent", "session", "turn", 2);
    let result = result();
    let authority = complete_exact_delivery_v1(
        &original,
        &result,
        &[0xff, b'A', 0x80, b'B', b'C', b'D'],
        true,
        true,
    )
    .unwrap();
    let compact = |candidate: &ContextIdentityV1| {
        compile_context_presentation_v1(
            candidate,
            &result,
            ContextPresentationRequestV1::CompactContentAddressed {
                authority: &authority,
            },
        )
    };

    for mismatched in [
        context("other", "session", "turn", 2),
        context("agent", "other", "turn", 2),
        context("agent", "session", "other", 2),
        original.after_compaction().unwrap(),
    ] {
        assert_eq!(
            compact(&mismatched).unwrap_err(),
            ContextCompilerRefusalV1::DeliveryAuthority
        );
    }
}

#[test]
fn authority_is_bound_to_the_exact_result_identity() {
    let context = context("agent", "session", "turn", 0);
    let result = result();
    let authority = complete_exact_delivery_v1(
        &context,
        &result,
        &[0xff, b'A', 0x80, b'B', b'C', b'D'],
        true,
        true,
    )
    .unwrap();
    for changed in [
        ContextResultV1::new("other-id", &[0xff, b'A', 0x80, b'B', b'C', b'D']).unwrap(),
        ContextResultV1::new("result-01", &[0xff, b'A', 0x80, b'B', b'C', b'X']).unwrap(),
    ] {
        assert_eq!(
            compile_context_presentation_v1(
                &context,
                &changed,
                ContextPresentationRequestV1::CompactContentAddressed {
                    authority: &authority,
                },
            )
            .unwrap_err(),
            ContextCompilerRefusalV1::DeliveryAuthority
        );
    }
}

#[test]
fn presenter_refuses_partial_bytes_missing_status_or_missing_completion() {
    let context = context("agent", "session", "turn", 0);
    let result = result();
    for (bytes, status, completion) in [
        (&[0xff, b'A'][..], true, true),
        (&[0xff, b'A', 0x80, b'B', b'C', b'D'][..], false, true),
        (&[0xff, b'A', 0x80, b'B', b'C', b'D'][..], true, false),
    ] {
        assert_eq!(
            complete_exact_delivery_v1(&context, &result, bytes, status, completion).unwrap_err(),
            ContextCompilerRefusalV1::DeliveryIncomplete
        );
    }
}

#[test]
fn result_and_excerpt_bounds_fail_closed() {
    for invalid in ["", "has space", "line\nbreak", &"x".repeat(129)] {
        assert_eq!(
            ContextResultV1::new(invalid, b"x").unwrap_err(),
            ContextCompilerRefusalV1::Identifier
        );
    }
    assert_eq!(
        ContextResultV1::new("large", &vec![0; MAX_CONTEXT_RESULT_BYTES_V1 + 1]).unwrap_err(),
        ContextCompilerRefusalV1::ResultBound
    );

    let context = context("agent", "session", "turn", 0);
    let result = result();
    for (start, max_bytes, expected) in [
        (0, 0, ContextCompilerRefusalV1::ExcerptBound),
        (
            0,
            MAX_CONTEXT_EXCERPT_BYTES_V1 as u64 + 1,
            ContextCompilerRefusalV1::ExcerptBound,
        ),
        (7, 1, ContextCompilerRefusalV1::ExcerptRange),
    ] {
        assert_eq!(
            compile_context_presentation_v1(
                &context,
                &result,
                ContextPresentationRequestV1::DeterministicExcerpt { start, max_bytes },
            )
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn result_digest_and_reference_change_for_every_content_mutation() {
    let context = context("agent", "session", "turn", 0);
    let first = ContextResultV1::new("result", b"payload").unwrap();
    let second = ContextResultV1::new("result", b"payloaD").unwrap();
    assert_ne!(first.identity().digest(), second.identity().digest());

    let authority = complete_exact_delivery_v1(&context, &first, b"payload", true, true).unwrap();
    let reference = compile_context_presentation_v1(
        &context,
        &first,
        ContextPresentationRequestV1::CompactContentAddressed {
            authority: &authority,
        },
    )
    .unwrap();
    let repeated = compile_context_presentation_v1(
        &context,
        &first,
        ContextPresentationRequestV1::CompactContentAddressed {
            authority: &authority,
        },
    )
    .unwrap();
    assert_eq!(reference, repeated);
}

#[test]
fn compaction_overflow_and_debug_output_are_payload_free() {
    let context = context("secret-agent", "secret-session", "secret-turn", u64::MAX);
    assert_eq!(
        context.after_compaction().unwrap_err(),
        ContextCompilerRefusalV1::GenerationOverflow
    );
    let result = ContextResultV1::new("secret-result", b"secret-payload").unwrap();
    for debug in [format!("{context:?}"), format!("{result:?}")] {
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret"));
    }
    assert_eq!(
        ContextCompilerRefusalV1::DeliveryAuthority.code(),
        "delivery_authority_mismatch"
    );
}

#[test]
fn reasoning_brief_is_canonical_and_unconfirmed_delivery_saves_nothing() {
    let input = reasoning_input();
    let first = compile_reasoning_brief_v1(
        &input,
        ReasoningBriefPresentationRequestV1::PreferCompact {
            acknowledgment: None,
        },
    )
    .unwrap();
    let second =
        compile_reasoning_brief_v1(&input, ReasoningBriefPresentationRequestV1::Full).unwrap();

    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.full_digest(), second.full_digest());
    assert_eq!(first.presentation(), ReasoningBriefPresentationV1::Full);
    assert_eq!(first.metrics().delivery_confirmed_bytes_omitted, 0);
    assert_eq!(first.metrics().confirmed_tokens_avoided, 0);
    assert!(!first.grants_reuse());
    assert!(!first.grants_execution());
}

#[test]
fn compact_reasoning_reference_requires_exact_recipient_acknowledgment() {
    let input = reasoning_input();
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
    assert!(compact.bytes().len() < full.bytes().len());
    assert_eq!(compact.full_exact_bytes(), full.bytes());
    assert!(compact.metrics().delivery_confirmed_bytes_omitted > 0);
    assert!(compact.metrics().confirmed_tokens_avoided > 0);

    let mut after_compaction = input.clone();
    after_compaction.recipient = input.recipient.after_compaction().unwrap();
    let invalidated = compile_reasoning_brief_v1(
        &after_compaction,
        ReasoningBriefPresentationRequestV1::PreferCompact {
            acknowledgment: Some(&acknowledgment),
        },
    )
    .unwrap();
    assert_eq!(
        invalidated.presentation(),
        ReasoningBriefPresentationV1::Full
    );
    assert_eq!(invalidated.metrics().confirmed_tokens_avoided, 0);
}

#[test]
fn incomplete_reasoning_delivery_cannot_issue_acknowledgment() {
    let input = reasoning_input();
    let full =
        compile_reasoning_brief_v1(&input, ReasoningBriefPresentationRequestV1::Full).unwrap();

    assert_eq!(
        complete_reasoning_brief_delivery_v1(
            &input.recipient,
            &full,
            &full.bytes()[..full.bytes().len() - 1],
            true,
            true,
            true,
        )
        .unwrap_err()
        .code(),
        "reasoning_delivery_incomplete"
    );
}
