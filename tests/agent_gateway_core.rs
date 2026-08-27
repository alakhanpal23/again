// This legacy path-based module test predates the library wiring. Supply only
// the opaque store-proof type surface required to compile the pure router; no
// test constructor exists and these stubs can never authorize a route.
mod store {
    pub struct StoreExactResultProofV1;
    pub struct StoreInflightJoinProofV1;

    impl StoreExactResultProofV1 {
        pub(crate) fn authorizes_router_call_v1(
            &self,
            _call: &crate::agent_gateway::GatewayToolCallV1,
        ) -> bool {
            false
        }
    }

    impl StoreInflightJoinProofV1 {
        pub(crate) fn authorizes_router_call_v1(
            &self,
            _call: &crate::agent_gateway::GatewayToolCallV1,
        ) -> bool {
            false
        }
    }
}

#[allow(dead_code, unused_imports)]
#[path = "../src/agent_gateway.rs"]
mod agent_gateway;

use std::collections::BTreeSet;

use agent_gateway::context::presenter_complete_exact_delivery_v1;
use agent_gateway::protocol::{
    GATEWAY_TOOL_CALL_SCHEMA_VERSION, MAX_CANONICAL_JSON_BYTES, MAX_CANONICAL_JSON_DEPTH,
    MAX_CANONICAL_JSON_NODES,
};
use agent_gateway::{
    AgentCallIdentityV1, AgentContextIdentityV1, CandidateFreshnessV1, CanonicalArguments,
    CanonicalJsonError, DigestReferenceV1, EffectClass, FreshnessRequirementV1,
    GatewayAdapterToolCallV1, GatewayCandidateKindV1, GatewayCandidateRequestV1, GatewayDecision,
    GatewayEffectClassV1, GatewayProtocolError, GatewayProtocolRefusalV1, GatewayResultIdentityV1,
    GatewayRouteDecisionV1, GatewayRouteRefusalV1, GatewayToolCallInputV1, GatewayToolCallV1,
    ModelIdentityV1, PermissionClass, PresentationContextV1, PresentationDecisionV1,
    PresentationMode, PresentationRefusalV1, ProviderIdentityV1, RepositoryEnvironmentStateV1,
    ReuseCandidateV1, RoutingCandidatesV1, StateDigestReferenceV1, TaskIdentityV1, ToolIdentityV1,
    WorkspaceIdentityV1, decide_presentation_v1, route, route_gateway_candidate_v1,
    select_presentation,
};

fn call(effect: GatewayEffectClassV1) -> GatewayAdapterToolCallV1 {
    GatewayAdapterToolCallV1::new(
        "call_01",
        "exec_command",
        effect,
        br#"{"z":[3,2,1],"a":{"second":true,"first":null}}"#,
    )
    .unwrap()
}

#[test]
fn canonical_call_sorts_every_object_and_round_trips_exactly() {
    let call = call(GatewayEffectClassV1::WorkspaceRead);
    assert_eq!(call.call_id(), "call_01");
    assert_eq!(call.tool(), "exec_command");
    assert_eq!(call.effect(), GatewayEffectClassV1::WorkspaceRead);
    assert_eq!(
        call.canonical_argument_bytes(),
        br#"{"a":{"first":null,"second":true},"z":[3,2,1]}"#
    );
    assert_eq!(
        call.canonical_bytes(),
        br#"{"arguments":{"a":{"first":null,"second":true},"z":[3,2,1]},"call_id":"call_01","effect":"workspace_read","schema":"again.gateway-tool-call.v1","tool":"exec_command"}"#
    );
    let decoded = GatewayAdapterToolCallV1::from_canonical_bytes(call.canonical_bytes()).unwrap();
    assert_eq!(decoded, call);
    assert_eq!(decoded.digest(), call.digest());
}

#[test]
fn duplicate_keys_are_refused_at_top_level_and_at_every_nested_shape() {
    for malformed in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"outer":{"x":1,"x":2}}"#.as_slice(),
        br#"{"outer":[{"x":1,"x":2}]}"#.as_slice(),
    ] {
        assert_eq!(
            GatewayAdapterToolCallV1::new("call", "tool", GatewayEffectClassV1::Pure, malformed)
                .unwrap_err(),
            GatewayProtocolRefusalV1::DuplicateKey
        );
    }

    let duplicate_envelope = br#"{"arguments":{},"call_id":"a","effect":"pure","schema":"again.gateway-tool-call.v1","tool":"x","tool":"y"}"#;
    assert_eq!(
        GatewayAdapterToolCallV1::from_canonical_bytes(duplicate_envelope).unwrap_err(),
        GatewayProtocolRefusalV1::DuplicateKey
    );
}

#[test]
fn canonical_decoder_rejects_alternate_bytes_for_the_same_value() {
    for noncanonical in [
        br#"{ "arguments":{},"call_id":"a","effect":"pure","schema":"again.gateway-tool-call.v1","tool":"x"}"#.as_slice(),
        br#"{"tool":"x","schema":"again.gateway-tool-call.v1","effect":"pure","call_id":"a","arguments":{}}"#.as_slice(),
        br#"{"arguments":{"n":-0},"call_id":"a","effect":"pure","schema":"again.gateway-tool-call.v1","tool":"x"}"#.as_slice(),
    ] {
        assert_eq!(
            GatewayAdapterToolCallV1::from_canonical_bytes(noncanonical).unwrap_err(),
            GatewayProtocolRefusalV1::NonCanonical
        );
    }
}

#[test]
fn envelope_schema_fields_and_types_are_closed() {
    let cases: &[(&[u8], GatewayProtocolRefusalV1)] = &[
        (b"[]", GatewayProtocolRefusalV1::TopLevelNotObject),
        (
            br#"{"arguments":{},"call_id":"a","effect":"pure","schema":"again.gateway-tool-call.v1"}"#,
            GatewayProtocolRefusalV1::MissingField,
        ),
        (
            br#"{"arguments":{},"call_id":"a","effect":"pure","extra":1,"schema":"again.gateway-tool-call.v1","tool":"x"}"#,
            GatewayProtocolRefusalV1::UnknownField,
        ),
        (
            br#"{"arguments":{},"call_id":"a","effect":"pure","schema":"again.gateway-tool-call.v2","tool":"x"}"#,
            GatewayProtocolRefusalV1::InvalidSchema,
        ),
        (
            br#"{"arguments":{},"call_id":1,"effect":"pure","schema":"again.gateway-tool-call.v1","tool":"x"}"#,
            GatewayProtocolRefusalV1::InvalidFieldType,
        ),
        (
            br#"{"arguments":[],"call_id":"a","effect":"pure","schema":"again.gateway-tool-call.v1","tool":"x"}"#,
            GatewayProtocolRefusalV1::ArgumentsNotObject,
        ),
        (
            br#"{"arguments":{},"call_id":"a","effect":"invented","schema":"again.gateway-tool-call.v1","tool":"x"}"#,
            GatewayProtocolRefusalV1::InvalidEffect,
        ),
    ];
    for (wire, expected) in cases {
        assert_eq!(
            GatewayAdapterToolCallV1::from_canonical_bytes(wire).unwrap_err(),
            *expected
        );
    }
}

#[test]
fn identifiers_are_ascii_bounded_and_tool_grammar_is_explicit() {
    for invalid_call_id in ["", "has space", "é", &"a".repeat(129)] {
        assert_eq!(
            GatewayAdapterToolCallV1::new(
                invalid_call_id,
                "tool",
                GatewayEffectClassV1::Pure,
                b"{}",
            )
            .unwrap_err(),
            GatewayProtocolRefusalV1::InvalidIdentifier
        );
    }
    for invalid_tool in ["", "has space", "tool?", "é"] {
        assert_eq!(
            GatewayAdapterToolCallV1::new("id", invalid_tool, GatewayEffectClassV1::Pure, b"{}",)
                .unwrap_err(),
            GatewayProtocolRefusalV1::InvalidIdentifier
        );
    }
    assert!(
        GatewayAdapterToolCallV1::new(
            "id-_9",
            "mcp__server/tool.name:v1",
            GatewayEffectClassV1::Pure,
            b"{}"
        )
        .is_ok()
    );
}

#[test]
fn json_numbers_depth_collections_nodes_strings_and_wire_bytes_are_bounded() {
    assert_eq!(
        GatewayAdapterToolCallV1::new("id", "tool", GatewayEffectClassV1::Pure, br#"{"x":1.0}"#,)
            .unwrap_err(),
        GatewayProtocolRefusalV1::NonIntegralNumber
    );

    let mut deep = String::from(r#"{"x":"#);
    for _ in 0..33 {
        deep.push('[');
    }
    deep.push_str("null");
    for _ in 0..33 {
        deep.push(']');
    }
    deep.push('}');
    assert_eq!(
        GatewayAdapterToolCallV1::new("id", "tool", GatewayEffectClassV1::Pure, deep.as_bytes(),)
            .unwrap_err(),
        GatewayProtocolRefusalV1::DepthExceeded
    );

    let collection = format!(
        "{{\"x\":[{}]}}",
        std::iter::repeat_n("null", 257)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        GatewayAdapterToolCallV1::new(
            "id",
            "tool",
            GatewayEffectClassV1::Pure,
            collection.as_bytes()
        )
        .unwrap_err(),
        GatewayProtocolRefusalV1::CollectionLimitExceeded
    );

    let member = format!(
        "[{}]",
        std::iter::repeat_n("null", 256)
            .collect::<Vec<_>>()
            .join(",")
    );
    let nodes = format!(
        "{{{}}}",
        (0..17)
            .map(|index| format!("\"k{index}\":{member}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        GatewayAdapterToolCallV1::new("id", "tool", GatewayEffectClassV1::Pure, nodes.as_bytes(),)
            .unwrap_err(),
        GatewayProtocolRefusalV1::NodeLimitExceeded
    );

    let large_string = format!("{{\"x\":\"{}\"}}", "a".repeat(49 * 1024));
    assert_eq!(
        GatewayAdapterToolCallV1::new(
            "id",
            "tool",
            GatewayEffectClassV1::Pure,
            large_string.as_bytes()
        )
        .unwrap_err(),
        GatewayProtocolRefusalV1::StringLimitExceeded
    );

    assert_eq!(
        GatewayAdapterToolCallV1::new(
            "id",
            "tool",
            GatewayEffectClassV1::Pure,
            &vec![b' '; 64 * 1024 + 1]
        )
        .unwrap_err(),
        GatewayProtocolRefusalV1::ArgumentTooLarge
    );
}

#[test]
fn every_effect_has_one_stable_wire_name_and_closed_validation_policy() {
    let expected = [
        (GatewayEffectClassV1::Pure, "pure", true, false),
        (
            GatewayEffectClassV1::WorkspaceRead,
            "workspace_read",
            true,
            false,
        ),
        (
            GatewayEffectClassV1::ExternalRead,
            "external_read",
            false,
            true,
        ),
        (
            GatewayEffectClassV1::WorkspaceWrite,
            "workspace_write",
            false,
            true,
        ),
        (
            GatewayEffectClassV1::ExternalWrite,
            "external_write",
            false,
            true,
        ),
        (GatewayEffectClassV1::Privileged, "privileged", false, true),
        (GatewayEffectClassV1::Unknown, "unknown", false, false),
    ];
    assert_eq!(GatewayEffectClassV1::ALL.len(), expected.len());
    for (effect, name, validates, fresh) in expected {
        assert_eq!(effect.as_str(), name);
        assert_eq!(effect.supports_deterministic_validation(), validates);
        assert_eq!(effect.requires_fresh_execution(), fresh);
        let call = call(effect);
        assert!(String::from_utf8_lossy(call.canonical_bytes()).contains(name));
    }
}

#[test]
fn routing_matrix_never_grants_reuse_and_ai_semantic_only_request_validation() {
    for effect in GatewayEffectClassV1::ALL {
        let call = call(effect);
        for candidate in GatewayCandidateKindV1::ALL {
            for request in GatewayCandidateRequestV1::ALL {
                let decision = route_gateway_candidate_v1(&call, candidate, request);
                assert!(!decision.grants_reuse());
                if effect == GatewayEffectClassV1::Unknown {
                    assert_eq!(
                        decision,
                        GatewayRouteDecisionV1::Reject(GatewayRouteRefusalV1::UnknownEffect)
                    );
                    continue;
                }
                if matches!(
                    candidate,
                    GatewayCandidateKindV1::Semantic | GatewayCandidateKindV1::Ai
                ) && request != GatewayCandidateRequestV1::DeterministicValidation
                {
                    assert_eq!(
                        decision,
                        GatewayRouteDecisionV1::Reject(
                            GatewayRouteRefusalV1::CandidateMayOnlyRequestValidation
                        )
                    );
                    continue;
                }
                match request {
                    GatewayCandidateRequestV1::ExecuteFresh => {
                        assert_eq!(decision, GatewayRouteDecisionV1::ExecuteFresh);
                        assert!(decision.executes_tool());
                    }
                    GatewayCandidateRequestV1::DeterministicValidation
                        if effect.supports_deterministic_validation() =>
                    {
                        assert_eq!(
                            decision,
                            GatewayRouteDecisionV1::RequireDeterministicValidation
                        );
                    }
                    GatewayCandidateRequestV1::DeterministicValidation => assert_eq!(
                        decision,
                        GatewayRouteDecisionV1::Reject(
                            GatewayRouteRefusalV1::EffectNotDeterministicallyValidatable
                        )
                    ),
                    GatewayCandidateRequestV1::Reuse => assert_eq!(
                        decision,
                        GatewayRouteDecisionV1::Reject(GatewayRouteRefusalV1::DirectReuseForbidden)
                    ),
                }
            }
        }
    }
}

fn context(
    session: &str,
    turn: &str,
    agent: Option<&str>,
    environment: &str,
    cwd: u8,
    tty: bool,
    ceiling: u64,
) -> PresentationContextV1 {
    PresentationContextV1::new(session, turn, agent, environment, [cwd; 32], tty, ceiling).unwrap()
}

#[test]
fn presentation_requires_exact_context_call_result_counts_status_and_confirmation() {
    let active_context = context("session", "turn", Some("agent"), "local", 1, false, 4096);
    let call = rich_call();
    let result = GatewayResultIdentityV1::from_streams(0, b"stdout", b"stderr").unwrap();
    let exact =
        presenter_complete_exact_delivery_v1(&active_context, &call, result, 6, 6, true, true)
            .unwrap();
    assert_eq!(
        decide_presentation_v1(&active_context, &call, result, Some(&exact)),
        PresentationDecisionV1::ExactPriorDeliveryReference
    );
    assert!(!PresentationDecisionV1::ExactPriorDeliveryReference.grants_reuse());

    let contexts = [
        context("other", "turn", Some("agent"), "local", 1, false, 4096),
        context("session", "other", Some("agent"), "local", 1, false, 4096),
        context("session", "turn", Some("other"), "local", 1, false, 4096),
        context("session", "turn", None, "local", 1, false, 4096),
        context("session", "turn", Some("agent"), "remote", 1, false, 4096),
        context("session", "turn", Some("agent"), "local", 2, false, 4096),
        context("session", "turn", Some("agent"), "local", 1, true, 4096),
        context("session", "turn", Some("agent"), "local", 1, false, 4095),
    ];
    for mismatched in contexts {
        assert_eq!(
            decide_presentation_v1(&mismatched, &call, result, Some(&exact)),
            PresentationDecisionV1::FullResult
        );
    }

    let mut other_input = rich_input();
    other_input.call.call_id = "other".to_owned();
    let other_call = GatewayToolCallV1::from_input(other_input).unwrap();
    assert_eq!(
        decide_presentation_v1(&active_context, &other_call, result, Some(&exact)),
        PresentationDecisionV1::FullResult
    );
    let other_result = GatewayResultIdentityV1::from_streams(1, b"stdout", b"stderr").unwrap();
    assert_eq!(
        decide_presentation_v1(&active_context, &call, other_result, Some(&exact)),
        PresentationDecisionV1::FullResult
    );

    for delivery in [
        (5, 6, true, true),
        (6, 5, true, true),
        (6, 6, false, true),
        (6, 6, true, false),
    ] {
        assert_eq!(
            presenter_complete_exact_delivery_v1(
                &active_context,
                &call,
                result,
                delivery.0,
                delivery.1,
                delivery.2,
                delivery.3,
            ),
            Err(PresentationRefusalV1::IncompleteDelivery)
        );
    }
    assert_eq!(
        decide_presentation_v1(&active_context, &call, result, None),
        PresentationDecisionV1::FullResult
    );
}

#[test]
fn delivery_counts_context_identifiers_and_streams_are_bounded() {
    for invalid in ["", "line\nbreak", &"x".repeat(129)] {
        assert_eq!(
            PresentationContextV1::new(invalid, "turn", None, "local", [0; 32], false, 1)
                .unwrap_err(),
            PresentationRefusalV1::InvalidIdentifier
        );
    }
    let context = context("session", "turn", None, "local", 0, false, 1);
    assert_eq!(context.output_ceiling(), 1);
    let call = rich_call();
    let result = GatewayResultIdentityV1::from_streams(0, b"x", b"").unwrap();
    assert_eq!(
        presenter_complete_exact_delivery_v1(&context, &call, result, 2, 0, true, true)
            .unwrap_err(),
        PresentationRefusalV1::InvalidDeliveryCount
    );
    assert_eq!(
        GatewayResultIdentityV1::from_streams(0, &vec![0; 64 * 1024 * 1024 + 1], b"").unwrap_err(),
        PresentationRefusalV1::StreamBoundExceeded
    );
}

#[test]
fn mutations_partition_call_and_result_identity_and_debug_is_redacted() {
    let first = call(GatewayEffectClassV1::Pure);
    let second = GatewayAdapterToolCallV1::new(
        "call_01",
        "exec_command",
        GatewayEffectClassV1::Pure,
        br#"{"z":[3,2,0],"a":{"second":true,"first":null}}"#,
    )
    .unwrap();
    assert_ne!(first.digest(), second.digest());
    let debug = format!("{first:?}");
    assert!(!debug.contains("call_01"));
    assert!(!debug.contains("exec_command"));
    assert!(!debug.contains("second"));

    let baseline = GatewayResultIdentityV1::from_streams(0, b"out", b"err").unwrap();
    for changed in [
        GatewayResultIdentityV1::from_streams(1, b"out", b"err").unwrap(),
        GatewayResultIdentityV1::from_streams(0, b"OUT", b"err").unwrap(),
        GatewayResultIdentityV1::from_streams(0, b"out", b"ERR").unwrap(),
    ] {
        assert_ne!(baseline, changed);
    }
}

#[test]
fn refusal_codes_are_stable_and_payload_free() {
    assert_eq!(
        GatewayProtocolRefusalV1::DuplicateKey.code(),
        "duplicate_key"
    );
    assert_eq!(
        GatewayRouteRefusalV1::DirectReuseForbidden.code(),
        "direct_reuse_forbidden"
    );
    assert_eq!(
        PresentationRefusalV1::InvalidDeliveryCount.code(),
        "invalid_delivery_count"
    );
}

fn digest_ref(value: &str) -> DigestReferenceV1 {
    DigestReferenceV1::new("blake3", value).unwrap()
}

fn rich_input() -> GatewayToolCallInputV1 {
    GatewayToolCallInputV1 {
        schema_version: GATEWAY_TOOL_CALL_SCHEMA_VERSION,
        provider: ProviderIdentityV1 {
            id: "provider".to_owned(),
            version: "1".to_owned(),
        },
        model: ModelIdentityV1 {
            id: "model".to_owned(),
            version: "1".to_owned(),
        },
        tool: ToolIdentityV1 {
            id: "tool".to_owned(),
            version: "1".to_owned(),
        },
        arguments: CanonicalArguments::from_json_str(r#"{"query":"diamond"}"#).unwrap(),
        workspace: WorkspaceIdentityV1 {
            workspace_id: "workspace".to_owned(),
            cwd: "src".to_owned(),
        },
        call: AgentCallIdentityV1 {
            agent_id: "agent".to_owned(),
            session_id: "session".to_owned(),
            turn_id: "turn".to_owned(),
            call_id: "call".to_owned(),
        },
        task: Some(TaskIdentityV1 {
            task_id: "task".to_owned(),
            version: "1".to_owned(),
        }),
        state: RepositoryEnvironmentStateV1::Known {
            reference: StateDigestReferenceV1 {
                schema_version: GATEWAY_TOOL_CALL_SCHEMA_VERSION,
                repository: digest_ref("repository-1"),
                environment: digest_ref("environment-1"),
            },
        },
        permission_class: PermissionClass::Preapproved,
        effect_class: EffectClass::SnapshotRead,
        freshness: FreshnessRequirementV1::Snapshot,
        presentation: PresentationMode::Exact,
    }
}

fn rich_call() -> GatewayToolCallV1 {
    GatewayToolCallV1::from_input(rich_input()).unwrap()
}

#[test]
fn rich_digest_partitions_state_task_model_and_tool_versions() {
    let baseline_call = rich_call();
    let baseline = baseline_call.request_digest();
    assert_ne!(
        baseline.as_str(),
        blake3::hash(baseline_call.canonical_bytes())
            .to_hex()
            .as_str()
    );

    let mut variants = Vec::new();
    let mut state = rich_input();
    state.state = RepositoryEnvironmentStateV1::Known {
        reference: StateDigestReferenceV1 {
            schema_version: 1,
            repository: digest_ref("repository-2"),
            environment: digest_ref("environment-1"),
        },
    };
    variants.push(state);

    let mut environment = rich_input();
    environment.state = RepositoryEnvironmentStateV1::Known {
        reference: StateDigestReferenceV1 {
            schema_version: 1,
            repository: digest_ref("repository-1"),
            environment: digest_ref("environment-2"),
        },
    };
    variants.push(environment);

    let mut task = rich_input();
    task.task.as_mut().unwrap().version = "2".to_owned();
    variants.push(task);

    let mut model = rich_input();
    model.model.version = "2".to_owned();
    variants.push(model);

    let mut tool = rich_input();
    tool.tool.version = "2".to_owned();
    variants.push(tool);

    macro_rules! variant {
        ($field:expr, $value:expr) => {{
            let mut input = rich_input();
            $field(&mut input, $value);
            variants.push(input);
        }};
    }
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.provider.id = value,
        "provider-2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.provider.version = value,
        "2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.model.id = value,
        "model-2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.tool.id = value,
        "tool-2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.workspace.workspace_id = value,
        "workspace-2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.workspace.cwd = value,
        "other".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.call.agent_id = value,
        "agent-2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.call.session_id = value,
        "session-2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.call.turn_id = value,
        "turn-2".to_owned()
    );
    variant!(
        |input: &mut GatewayToolCallInputV1, value| input.call.call_id = value,
        "call-2".to_owned()
    );

    let mut arguments = rich_input();
    arguments.arguments = CanonicalArguments::from_json_str(r#"{"query":"other"}"#).unwrap();
    variants.push(arguments);
    let mut no_task = rich_input();
    no_task.task = None;
    variants.push(no_task);
    let mut permission = rich_input();
    permission.permission_class = PermissionClass::RequiresApproval;
    variants.push(permission);
    let mut effect = rich_input();
    effect.effect_class = EffectClass::DeterministicCompute;
    variants.push(effect);
    let mut freshness = rich_input();
    freshness.freshness = FreshnessRequirementV1::RequireRevalidation;
    variants.push(freshness);
    let mut presentation = rich_input();
    presentation.presentation = PresentationMode::DeterministicExcerpt;
    variants.push(presentation);

    let mut digests = BTreeSet::from([baseline.as_str().to_owned()]);
    for input in variants {
        let variant = GatewayToolCallV1::from_input(input).unwrap();
        assert!(digests.insert(variant.request_digest().as_str().to_owned()));
    }
}

#[test]
fn rich_canonical_numbers_strings_and_owned_round_trip_are_stable() {
    let left = CanonicalArguments::from_json_str(
        r#" { "z": -0.0, "a": { "two": 2.0, "one": 1e0 }, "s": "\u0061" } "#,
    )
    .unwrap();
    let right =
        CanonicalArguments::from_json_str(r#"{"s":"a","a":{"one":1,"two":2},"z":0}"#).unwrap();
    assert_eq!(left, right);
    assert_eq!(
        left.canonical_json(),
        r#"{"a":{"one":1,"two":2},"s":"a","z":0}"#
    );

    let call = rich_call();
    let serialized = serde_json::to_vec(&call).unwrap();
    assert_eq!(serialized, call.canonical_bytes());
    let decoded = GatewayToolCallV1::from_json_slice(call.canonical_bytes()).unwrap();
    assert_eq!(call, decoded);
    assert_eq!(call.request_digest(), decoded.request_digest());
}

#[test]
fn rich_metadata_is_bounded_and_errors_and_debug_are_payload_free() {
    let mut oversized = rich_input();
    oversized.provider.id = "sensitive".repeat(40);
    let error = GatewayToolCallV1::from_input(oversized).unwrap_err();
    assert_eq!(error, GatewayProtocolError::InvalidField);
    assert_eq!(format!("{error:?}"), "InvalidField");

    assert_eq!(
        DigestReferenceV1::new("blake3", "x".repeat(257)).unwrap_err(),
        GatewayProtocolError::InvalidField
    );
    let call = rich_call();
    let debug = format!("{call:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("diamond"));
    assert!(!debug.contains(call.request_digest().as_str()));
}

#[test]
fn rich_router_executes_unknown_state_and_never_replays_mutations() {
    let mut unknown = rich_input();
    unknown.state = RepositoryEnvironmentStateV1::Unknown;
    let unknown = GatewayToolCallV1::from_input(unknown).unwrap();
    assert_eq!(
        route(&unknown, &RoutingCandidatesV1::default()),
        GatewayDecision::Execute
    );

    for effect in [
        EffectClass::Mutation,
        EffectClass::ExternalSideEffect,
        EffectClass::Unknown,
    ] {
        let mut input = rich_input();
        input.effect_class = effect;
        let call = GatewayToolCallV1::from_input(input).unwrap();
        assert_eq!(
            route(&call, &RoutingCandidatesV1::default()),
            GatewayDecision::ExecuteNonReplayable
        );
    }
}

#[test]
fn rich_router_covers_permission_decisions_without_public_authority_constructors() {
    let mut approval = rich_input();
    approval.permission_class = PermissionClass::RequiresApproval;
    assert_eq!(
        route(
            &GatewayToolCallV1::from_input(approval).unwrap(),
            &RoutingCandidatesV1::default()
        ),
        GatewayDecision::RequireApproval
    );
    let mut denied = rich_input();
    denied.permission_class = PermissionClass::Denied;
    assert_eq!(
        route(
            &GatewayToolCallV1::from_input(denied).unwrap(),
            &RoutingCandidatesV1::default()
        ),
        GatewayDecision::Refuse
    );
}

#[test]
fn rich_semantic_candidates_can_only_request_validation() {
    let call = rich_call();
    let semantic = || {
        ReuseCandidateV1::semantic_or_ai_candidate(
            call.request_digest(),
            digest_ref("semantic"),
            "provider",
            "model",
            "1",
            CandidateFreshnessV1::Revalidated,
        )
        .unwrap()
    };
    let candidates = RoutingCandidatesV1::default().with_semantic_candidate(semantic());
    assert_eq!(
        route(&call, &candidates),
        GatewayDecision::ValidateSemanticCandidate
    );
}

#[test]
fn compact_receipts_separate_agent_session_turn_result_and_compaction() {
    let presentation = context("session", "turn", Some("agent"), "local", 1, false, 4096);
    let call = rich_call();
    let identity = GatewayResultIdentityV1::from_streams(0, b"out", b"err").unwrap();
    let receipt =
        presenter_complete_exact_delivery_v1(&presentation, &call, identity, 3, 3, true, true)
            .unwrap();
    let original = receipt.context().clone();
    let result = receipt.exact_result().clone();
    assert_eq!(
        select_presentation(
            PresentationMode::CompactReference,
            &original,
            &result,
            Some(&receipt)
        ),
        PresentationMode::CompactReference
    );
    let contexts = [
        AgentContextIdentityV1::new("other", "session", "turn", 0).unwrap(),
        AgentContextIdentityV1::new("agent", "other", "turn", 0).unwrap(),
        AgentContextIdentityV1::new("agent", "session", "other", 0).unwrap(),
        original.after_compaction().unwrap(),
    ];
    for context in contexts {
        assert_eq!(
            select_presentation(
                PresentationMode::CompactReference,
                &context,
                &result,
                Some(&receipt)
            ),
            PresentationMode::FullRetrievalRequired
        );
    }
    assert_eq!(
        select_presentation(
            PresentationMode::CompactReference,
            &original,
            &digest_ref("other-result"),
            Some(&receipt)
        ),
        PresentationMode::FullRetrievalRequired
    );
}

#[test]
fn canonical_argument_boundaries_and_malformed_numbers_fail_closed() {
    fn nested(depth: usize) -> String {
        format!("{}null{}", "[".repeat(depth - 1), "]".repeat(depth - 1))
    }
    CanonicalArguments::from_json_str(&nested(MAX_CANONICAL_JSON_DEPTH)).unwrap();
    assert!(matches!(
        CanonicalArguments::from_json_str(&nested(MAX_CANONICAL_JSON_DEPTH + 1)),
        Err(CanonicalJsonError::DepthLimitExceeded)
    ));

    let boundary = format!("[{}]", vec!["null"; MAX_CANONICAL_JSON_NODES - 1].join(","));
    CanonicalArguments::from_json_str(&boundary).unwrap();
    let over = format!("[{}]", vec!["null"; MAX_CANONICAL_JSON_NODES].join(","));
    assert!(matches!(
        CanonicalArguments::from_json_str(&over),
        Err(CanonicalJsonError::NodeLimitExceeded)
    ));

    assert!(matches!(
        CanonicalArguments::from_value(serde_json::Value::String(
            "x".repeat(MAX_CANONICAL_JSON_BYTES)
        )),
        Err(CanonicalJsonError::EncodedTooLarge)
    ));
    for malformed in ["{", r#"{"x":NaN}"#, r#"{"x":Infinity}"#, "null null"] {
        assert!(matches!(
            CanonicalArguments::from_json_str(malformed),
            Err(CanonicalJsonError::Malformed)
        ));
    }
}
