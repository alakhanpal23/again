use again::agent_gateway::{
    AgentCallIdentityV1, CanonicalArguments, CommandInvocationV1, CompleteToolStreamsV1,
    DigestReferenceV1, EffectClass, FreshnessRequirementV1, GatewayToolCallInputV1,
    GatewayToolCallV1, ModelIdentityV1, PermissionClass, PresentationContextV1,
    PresentationDecisionV1, PresentationMode, ProfileFamilyV1, ProfileQualificationV1,
    ProfileSelectionStatusV1, ProviderIdentityV1, RepositoryEnvironmentStateV1, ReuseValueModelV1,
    RoutingCandidatesV1, SealedProfileRegistryV1, StateDigestReferenceV1, TaskIdentityV1,
    ToolCapabilityClassV1, ToolIdentityV1, ToolInteractionModeV1, ToolStdinModeV1,
    UniversalActionContextV1, UniversalGatewayDecisionV1, UniversalGatewayMetricEventV1,
    UniversalGatewayMetricsV1, WorkspaceIdentityV1, classify_action_v1,
    decide_complete_stream_presentation_v1, route_automatically_v1,
};

fn digest(value: &str) -> DigestReferenceV1 {
    DigestReferenceV1::new("blake3", value).unwrap()
}

fn call(tool: &str, effect: EffectClass, freshness: FreshnessRequirementV1) -> GatewayToolCallV1 {
    GatewayToolCallV1::from_input(GatewayToolCallInputV1 {
        schema_version: 1,
        provider: ProviderIdentityV1 {
            id: "provider-identity".to_owned(),
            version: "descriptor-state-v1".to_owned(),
        },
        model: ModelIdentityV1 {
            id: "untrusted-model".to_owned(),
            version: "claims-cacheable".to_owned(),
        },
        tool: ToolIdentityV1 {
            id: tool.to_owned(),
            version: "schema-digest".to_owned(),
        },
        arguments: CanonicalArguments::from_json_str("{}").unwrap(),
        workspace: WorkspaceIdentityV1 {
            workspace_id: "workspace".to_owned(),
            cwd: ".".to_owned(),
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
                schema_version: 1,
                repository: digest("repository"),
                environment: digest("environment"),
            },
        },
        permission_class: PermissionClass::Preapproved,
        effect_class: effect,
        freshness,
        presentation: PresentationMode::Exact,
    })
    .unwrap()
}

fn positive_value() -> ReuseValueModelV1 {
    ReuseValueModelV1::measured(1_000, 10, 20, 30, 1)
}

#[test]
fn only_the_thirteen_existing_read_tools_are_qualified() {
    let registry = SealedProfileRegistryV1::builtin();
    let qualified = [
        "repo.read",
        "repo.search",
        "repo.list",
        "repo.tree",
        "repo.stat",
        "repo.glob",
        "repo.references",
        "repo.manifest",
        "git.status",
        "git.diff",
        "git.log",
        "git.show",
        "git.blame",
    ];
    for tool in qualified {
        let classified = registry.classify(
            &call(
                tool,
                EffectClass::SnapshotRead,
                FreshnessRequirementV1::Snapshot,
            ),
            &UniversalActionContextV1::batch_without_stdin(),
        );
        assert_eq!(classified.status(), ProfileSelectionStatusV1::Qualified);
        assert_eq!(
            classified.capability(),
            ToolCapabilityClassV1::ExactStateBoundRead
        );
        assert_eq!(
            classified.profile().unwrap().qualification(),
            ProfileQualificationV1::QualifiedExactRead
        );
    }

    let contracts = registry.contracts();
    assert_eq!(contracts.len(), 8);
    for family in [
        ProfileFamilyV1::Pytest,
        ProfileFamilyV1::Rust,
        ProfileFamilyV1::TypeScript,
        ProfileFamilyV1::Python,
        ProfileFamilyV1::Go,
        ProfileFamilyV1::Build,
    ] {
        assert!(contracts.iter().any(|profile| {
            profile.family() == family
                && profile.qualification() == ProfileQualificationV1::ContractOnly
        }));
    }
}

#[test]
fn automatic_decision_is_total_and_unsafe_classes_never_store() {
    let cases = [
        ("secret.read", ToolCapabilityClassV1::CredentialOperation),
        ("chat.send", ToolCapabilityClassV1::Communication),
        ("deploy.start", ToolCapabilityClassV1::Deployment),
        ("payment.create", ToolCapabilityClassV1::Payment),
        ("browser.open", ToolCapabilityClassV1::NonReusableRead),
        ("unregistered.tool", ToolCapabilityClassV1::Unknown),
    ];
    for (tool, capability) in cases {
        let call = call(tool, EffectClass::Unknown, FreshnessRequirementV1::Snapshot);
        let classified =
            classify_action_v1(&call, &UniversalActionContextV1::batch_without_stdin());
        assert_eq!(classified.capability(), capability);
        assert_eq!(
            route_automatically_v1(
                &call,
                &RoutingCandidatesV1::default(),
                &UniversalActionContextV1::batch_without_stdin(),
                positive_value(),
            ),
            UniversalGatewayDecisionV1::PassthroughWithoutStorage
        );
    }

    let mutation = call(
        "workspace.write",
        EffectClass::Mutation,
        FreshnessRequirementV1::Snapshot,
    );
    assert_eq!(
        classify_action_v1(&mutation, &UniversalActionContextV1::batch_without_stdin())
            .capability(),
        ToolCapabilityClassV1::Mutation
    );
}

#[test]
fn interactive_watch_repl_and_stdin_dependent_calls_always_pass_through() {
    let read = call(
        "repo.read",
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
    );
    let contexts = [
        UniversalActionContextV1::new(
            ToolInteractionModeV1::Interactive,
            ToolStdinModeV1::Closed,
            None,
        ),
        UniversalActionContextV1::new(ToolInteractionModeV1::Watch, ToolStdinModeV1::Closed, None),
        UniversalActionContextV1::new(ToolInteractionModeV1::Repl, ToolStdinModeV1::Closed, None),
        UniversalActionContextV1::new(
            ToolInteractionModeV1::Batch,
            ToolStdinModeV1::Inherited,
            None,
        ),
        UniversalActionContextV1::new(
            ToolInteractionModeV1::Batch,
            ToolStdinModeV1::DeclaredDigest,
            None,
        ),
    ];
    for context in contexts {
        assert_eq!(
            classify_action_v1(&read, &context).capability(),
            ToolCapabilityClassV1::Interactive
        );
        assert_eq!(
            route_automatically_v1(
                &read,
                &RoutingCandidatesV1::default(),
                &context,
                positive_value(),
            ),
            UniversalGatewayDecisionV1::PassthroughWithoutStorage
        );
    }
}

#[test]
fn command_shapes_are_non_authoritative_contracts_and_basenames_do_not_upgrade() {
    let unknown = call(
        "shell.exec",
        EffectClass::DeterministicCompute,
        FreshnessRequirementV1::Snapshot,
    );
    let cargo_basename = UniversalActionContextV1::new(
        ToolInteractionModeV1::Batch,
        ToolStdinModeV1::Closed,
        Some(CommandInvocationV1::new(vec!["cargo".to_owned()]).unwrap()),
    );
    assert_eq!(
        classify_action_v1(&unknown, &cargo_basename).status(),
        ProfileSelectionStatusV1::Unprofiled
    );

    let cargo_check = UniversalActionContextV1::new(
        ToolInteractionModeV1::Batch,
        ToolStdinModeV1::Closed,
        Some(CommandInvocationV1::new(vec!["cargo".to_owned(), "check".to_owned()]).unwrap()),
    );
    let classified = classify_action_v1(&unknown, &cargo_check);
    assert_eq!(classified.status(), ProfileSelectionStatusV1::ContractOnly);
    assert_eq!(
        classified.capability(),
        ToolCapabilityClassV1::DeterministicCommand
    );
    assert_eq!(
        route_automatically_v1(
            &unknown,
            &RoutingCandidatesV1::default(),
            &cargo_check,
            positive_value(),
        ),
        UniversalGatewayDecisionV1::PassthroughWithoutStorage
    );
}

#[test]
fn pytest_contract_is_exact_and_never_upgrades_to_storage() {
    let shell = call(
        "shell.exec",
        EffectClass::DeterministicCompute,
        FreshnessRequirementV1::Snapshot,
    );
    let context = |argv: &[&str]| {
        UniversalActionContextV1::new(
            ToolInteractionModeV1::Batch,
            ToolStdinModeV1::Closed,
            Some(
                CommandInvocationV1::new(argv.iter().map(|value| (*value).to_owned()).collect())
                    .unwrap(),
            ),
        )
    };
    let exact = context(&[
        ".venv/bin/python",
        "-I",
        "-m",
        "pytest",
        "tests/test_unit.py::test_value",
    ]);
    assert_eq!(
        classify_action_v1(&shell, &exact).status(),
        ProfileSelectionStatusV1::ContractOnly
    );
    assert_eq!(
        route_automatically_v1(
            &shell,
            &RoutingCandidatesV1::default(),
            &exact,
            positive_value(),
        ),
        UniversalGatewayDecisionV1::PassthroughWithoutStorage
    );

    for rejected in [
        context(&[".venv/bin/python", "-I", "-m", "pytest", "--pdb"]),
        context(&[
            ".venv/bin/python",
            "-I",
            "-m",
            "pytest",
            "tests/test_unit.py",
            "tests/test_other.py",
        ]),
        context(&[
            "/tmp/.venv/bin/python",
            "-I",
            "-m",
            "pytest",
            "tests/test_unit.py",
        ]),
    ] {
        assert_eq!(
            classify_action_v1(&shell, &rejected).status(),
            ProfileSelectionStatusV1::Unprofiled
        );
    }
}

#[test]
fn negative_value_bypasses_reusable_lookup_lane_and_invalid_profiles_refuse() {
    let read = call(
        "repo.read",
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
    );
    assert_eq!(
        route_automatically_v1(
            &read,
            &RoutingCandidatesV1::default(),
            &UniversalActionContextV1::batch_without_stdin(),
            ReuseValueModelV1::unknown(),
        ),
        UniversalGatewayDecisionV1::PassthroughWithoutStorage
    );
    assert_eq!(
        route_automatically_v1(
            &read,
            &RoutingCandidatesV1::default(),
            &UniversalActionContextV1::batch_without_stdin(),
            positive_value(),
        ),
        UniversalGatewayDecisionV1::ExecuteAndObserve
    );

    let invalid = call(
        "repo.read",
        EffectClass::Mutation,
        FreshnessRequirementV1::Snapshot,
    );
    assert_eq!(
        route_automatically_v1(
            &invalid,
            &RoutingCandidatesV1::default(),
            &UniversalActionContextV1::batch_without_stdin(),
            positive_value(),
        ),
        UniversalGatewayDecisionV1::RefuseDangerousInvalidConfiguration
    );
}

#[test]
fn complete_streams_default_to_full_and_metrics_cover_every_required_dimension() {
    assert!(CompleteToolStreamsV1::new(0, vec![], vec![], false, true).is_err());
    let streams =
        CompleteToolStreamsV1::new(0, b"out".to_vec(), b"err".to_vec(), true, true).unwrap();
    let call = call(
        "repo.read",
        EffectClass::SnapshotRead,
        FreshnessRequirementV1::Snapshot,
    );
    let context = PresentationContextV1::new(
        "session",
        "turn",
        Some("agent"),
        "environment",
        [7; 32],
        false,
        1_024,
    )
    .unwrap();
    assert_eq!(
        decide_complete_stream_presentation_v1(&context, &call, &streams, None).unwrap(),
        PresentationDecisionV1::FullResult
    );

    let mut metrics = UniversalGatewayMetricsV1::default();
    for event in [
        UniversalGatewayMetricEventV1::Route,
        UniversalGatewayMetricEventV1::Miss,
        UniversalGatewayMetricEventV1::Join,
        UniversalGatewayMetricEventV1::Candidate,
        UniversalGatewayMetricEventV1::Promotion,
        UniversalGatewayMetricEventV1::Invalidation,
        UniversalGatewayMetricEventV1::Quarantine,
        UniversalGatewayMetricEventV1::Bytes(123),
        UniversalGatewayMetricEventV1::MeasuredTimeMicros(456),
    ] {
        metrics.record(event).unwrap();
    }
    assert_eq!(
        (
            metrics.routes(),
            metrics.misses(),
            metrics.joins(),
            metrics.candidates(),
            metrics.promotions(),
            metrics.invalidations(),
            metrics.quarantines(),
            metrics.bytes(),
            metrics.measured_time_micros(),
        ),
        (1, 1, 1, 1, 1, 1, 1, 123, 456)
    );
}
