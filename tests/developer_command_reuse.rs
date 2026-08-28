use again::execution_backend::{
    DeveloperCommandAssessmentV1, DeveloperCommandDispositionV1, DeveloperCommandShapeV1,
    RequiredReuseBindingV1, assess_developer_command_v1,
};

fn assess(argv: &[&str]) -> DeveloperCommandAssessmentV1 {
    assess_developer_command_v1(
        &argv
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>(),
    )
}

fn assert_passthrough(assessment: &DeveloperCommandAssessmentV1) {
    assert_eq!(
        assessment.disposition(),
        DeveloperCommandDispositionV1::PassthroughWithoutStorage
    );
    assert!(!assessment.grants_execution_authority());
    assert!(!assessment.permits_storage());
    assert!(!assessment.permits_reuse());
    assert!(assessment.requires_normal_passthrough());
}

#[test]
fn exact_cargo_fmt_check_syntax_is_observable_but_never_authoritative() {
    let exact = assess(&["cargo", "fmt", "--all", "--check"]);
    assert_eq!(exact.shape(), DeveloperCommandShapeV1::ExactCheckOnlySyntax);
    assert_passthrough(&exact);

    for argv in [
        &["cargo", "fmt"][..],
        &["cargo", "fmt", "--all"][..],
        &["cargo", "fmt", "--check"][..],
        &["cargo", "fmt", "--", "--check"][..],
        &["cargo", "fmt", "--all", "--check", "--quiet"][..],
        &["cargo", "+nightly", "fmt", "--all", "--check"][..],
    ] {
        let assessment = assess(argv);
        assert_ne!(
            assessment.shape(),
            DeveloperCommandShapeV1::ExactCheckOnlySyntax,
            "unexpected exact qualification for {argv:?}"
        );
        assert_passthrough(&assessment);
    }
}

#[test]
fn mutating_interactive_snapshot_and_network_modes_are_never_qualified() {
    let cases = [
        (
            &["cargo", "fmt"][..],
            DeveloperCommandShapeV1::MutationCapable,
        ),
        (
            &["ruff", "check", "--fix"][..],
            DeveloperCommandShapeV1::MutationCapable,
        ),
        (
            &["jest", "--updateSnapshot"][..],
            DeveloperCommandShapeV1::MutationCapable,
        ),
        (
            &["pytest", "--accept-changes"][..],
            DeveloperCommandShapeV1::MutationCapable,
        ),
        (
            &["vitest", "--watch"][..],
            DeveloperCommandShapeV1::InteractiveOrWatch,
        ),
        (
            &["pytest", "-i"][..],
            DeveloperCommandShapeV1::InteractiveOrWatch,
        ),
        (
            &["cargo", "publish"][..],
            DeveloperCommandShapeV1::NetworkCapable,
        ),
        (
            &["npm", "install"][..],
            DeveloperCommandShapeV1::NetworkCapable,
        ),
        (
            &["cargo", "test", "--online"][..],
            DeveloperCommandShapeV1::NetworkCapable,
        ),
    ];
    for (argv, expected) in cases {
        let assessment = assess(argv);
        assert_eq!(assessment.shape(), expected, "wrong shape for {argv:?}");
        assert_passthrough(&assessment);
    }
}

#[test]
fn check_like_unknown_flags_and_unknown_commands_all_pass_through_without_storage() {
    for argv in [
        &["cargo", "test"][..],
        &["cargo", "check"][..],
        &["cargo", "clippy"][..],
        &["pytest"][..],
        &["ruff", "check"][..],
        &["tsc", "--noEmit"][..],
    ] {
        let assessment = assess(argv);
        assert_eq!(
            assessment.shape(),
            DeveloperCommandShapeV1::CheckLikeButIncomplete
        );
        assert_passthrough(&assessment);
    }

    for argv in [
        &[][..],
        &["mystery"][..],
        &["cargo", "test", "--unknown-flag"][..],
        &["/replaced/path/cargo", "test"][..],
        &["cargo", "+unmodeled-toolchain", "test"][..],
    ] {
        let assessment = assess(argv);
        assert_eq!(
            assessment.shape(),
            DeveloperCommandShapeV1::UnknownOrIncompletelyModeled
        );
        assert_passthrough(&assessment);
    }
}

#[test]
fn every_required_identity_and_dependency_binding_remains_explicitly_unproven() {
    let assessment = assess(&["cargo", "test"]);
    assert_eq!(
        assessment.unproven_reuse_bindings(),
        &[
            RequiredReuseBindingV1::ResolvedExecutableIdentity,
            RequiredReuseBindingV1::ToolchainIdentity,
            RequiredReuseBindingV1::ExactArgv,
            RequiredReuseBindingV1::CanonicalWorkingDirectory,
            RequiredReuseBindingV1::NormalizedEnvironment,
            RequiredReuseBindingV1::RepositoryState,
            RequiredReuseBindingV1::Lockfiles,
            RequiredReuseBindingV1::Configuration,
            RequiredReuseBindingV1::Plugins,
            RequiredReuseBindingV1::GeneratedInputs,
            RequiredReuseBindingV1::CompleteDependencyClosure,
        ]
    );

    // These are the adversarial changes that the rejected prototype failed to
    // bind. None can manufacture a lookup or publication because this API has
    // no reusable disposition.
    for (dimension, mutation) in [
        ("executable", "same path, replaced inode and bytes"),
        ("PATH", "different resolution order"),
        ("toolchain", "changed rustup override"),
        ("configuration", "changed .cargo and test-runner config"),
        ("plugin", "added or replaced plugin"),
        ("lockfile", "changed Cargo.lock or package lock"),
        ("environment", "changed normalized relevant variable"),
        ("repository", "dirty tracked input"),
        ("repository", "untracked relevant input"),
        ("generated input", "changed build output"),
        ("dependency", "changed transitive dependency"),
    ] {
        assert!(
            !assessment.permits_reuse() && !assessment.permits_storage(),
            "{dimension} mutation `{mutation}` manufactured a hit"
        );
    }
}

#[test]
fn deterministic_cold_and_warm_assessments_have_zero_false_hits() {
    let commands = [
        &["cargo", "fmt", "--all", "--check"][..],
        &["cargo", "test"][..],
        &["cargo", "fmt"][..],
        &["vitest", "--watch"][..],
        &["mystery", "--unknown"][..],
    ];
    let cold = commands.iter().map(|argv| assess(argv)).collect::<Vec<_>>();
    let warm = commands.iter().map(|argv| assess(argv)).collect::<Vec<_>>();
    assert_eq!(cold, warm);
    assert_eq!(
        cold.iter()
            .filter(|assessment| assessment.permits_reuse())
            .count(),
        0,
        "a passthrough-only qualifier manufactured a false hit"
    );
}
