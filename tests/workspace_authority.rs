#[allow(dead_code)]
#[path = "../src/workspace_authority.rs"]
mod workspace_authority;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use workspace_authority::*;

struct RepositoryFixture {
    temporary: TempDir,
    root: PathBuf,
}

impl RepositoryFixture {
    fn git() -> Self {
        let temporary = TempDir::new().expect("temporary repository");
        let root = fs::canonicalize(temporary.path())
            .expect("canonical temporary root")
            .join("repository");
        fs::create_dir(&root).expect("repository root");
        let fixture = Self { temporary, root };
        fixture.run_git(&["init", "-q"]);
        fixture.run_git(&["config", "user.name", "Again Authority Tests"]);
        fixture.run_git(&["config", "user.email", "authority-tests@example.invalid"]);
        fixture.run_git(&["config", "commit.gpgsign", "false"]);
        fixture
    }

    fn plain() -> Self {
        let temporary = TempDir::new().expect("temporary repository");
        let root = fs::canonicalize(temporary.path())
            .expect("canonical temporary root")
            .join("repository");
        fs::create_dir(&root).expect("repository root");
        Self { temporary, root }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn write(&self, relative: &str, contents: &[u8]) {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("file parent");
        }
        fs::write(path, contents).expect("fixture file");
    }

    fn commit_all(&self, message: &str) {
        self.run_git(&["add", "--all"]);
        self.run_git(&["commit", "-q", "-m", message]);
    }

    fn run_git(&self, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(&self.root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("Git output is UTF-8")
            .trim()
            .to_owned()
    }
}

fn limits() -> WorkspaceAuthorityLimitsV1 {
    WorkspaceAuthorityLimitsV1::default()
}

fn content_plan(path: &str) -> RepositoryObservationPlanV1 {
    RepositoryObservationPlanV1::new(
        vec![PathBuf::from(path)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

fn source_plan(path: &str) -> RepositoryObservationPlanV1 {
    RepositoryObservationPlanV1::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
        .with_source_trees(vec![PathBuf::from(path)])
}

fn digest(value: &[u8]) -> StateDigestV1 {
    StateDigestV1::from_domain_and_bytes(b"again.authority-test.v1", value)
}

fn classify_environment(
    plan: EnvironmentObservationPlanV1,
    observed: &[StateDimensionV1],
) -> EnvironmentObservationPlanV1 {
    let exclusions = [
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
    ]
    .into_iter()
    .filter(|dimension| !observed.contains(dimension))
    .map(|dimension| (dimension, b"test tool schema excludes dimension".to_vec()))
    .collect();
    plan.with_relevance_proof(
        EnvironmentRelevanceProofV1::from_exclusions(exclusions, &limits()).unwrap(),
    )
}

fn no_external() -> ExternalFreshnessV1 {
    ExternalFreshnessV1::no_external_dependencies(
        validated_no_external_dependencies_for_test_v1(
            b"test schema has no external inputs",
            &limits(),
        )
        .unwrap(),
    )
}

fn task(revision: u64) -> TaskStateV1 {
    TaskStateV1::from_input(
        TaskStateInputV1 {
            task_id: "task-123".to_owned(),
            task_revision: revision,
            user_goal_digest: digest(b"goal"),
            accepted_constraints_digest: digest(b"constraints"),
            branch_identity: "refs/heads/test".to_owned(),
            worktree_identity: "worktree-123".to_owned(),
            patch_digest: digest(b"patch"),
            plan_revision: 7,
            compaction_epoch: 3,
        },
        &limits(),
    )
    .expect("task state")
}

#[test]
fn tracked_file_mutation_changes_repository_epoch() {
    let fixture = RepositoryFixture::git();
    fixture.write("src/input.rs", b"first\n");
    fixture.commit_all("initial");
    let before = observe_repository_v1(fixture.root(), &content_plan("src/input.rs"), &limits())
        .expect("initial epoch");

    fixture.write("src/input.rs", b"second\n");
    let after = observe_repository_v1(fixture.root(), &content_plan("src/input.rs"), &limits())
        .expect("mutated epoch");
    assert_ne!(before.digest(), after.digest());
}

#[test]
fn untracked_addition_under_recursive_scope_changes_epoch() {
    let fixture = RepositoryFixture::git();
    fixture.write("src/tracked.rs", b"tracked\n");
    fixture.commit_all("initial");
    let plan = RepositoryObservationPlanV1::new(
        Vec::new(),
        vec![PathBuf::from("src")],
        Vec::new(),
        Vec::new(),
    );
    let before =
        observe_repository_v1(fixture.root(), &plan, &limits()).expect("initial tree epoch");
    fixture.write("src/untracked.rs", b"untracked\n");
    let after =
        observe_repository_v1(fixture.root(), &plan, &limits()).expect("expanded tree epoch");
    assert_ne!(before.digest(), after.digest());
    assert_eq!(after.observations()[0].entries(), 3);
}

#[test]
fn source_tree_binds_untracked_source_but_not_git_control_files() {
    let fixture = RepositoryFixture::git();
    fixture.write("src/lib.rs", b"pub fn stable() {}\n");
    fixture.commit_all("initial");
    let plan = source_plan(".");
    let before = observe_repository_v1(fixture.root(), &plan, &limits()).expect("source epoch");

    fixture.write("src/untracked.rs", b"pub fn added() {}\n");
    let with_source =
        observe_repository_v1(fixture.root(), &plan, &limits()).expect("source addition epoch");
    assert_ne!(before.digest(), with_source.digest());

    let control = fixture.root().join(".git/again-test-control");
    fs::write(&control, b"not a source input").expect("Git control file");
    let after_control =
        observe_repository_v1(fixture.root(), &plan, &limits()).expect("control-file epoch");
    assert_eq!(with_source.digest(), after_control.digest());
}

#[test]
fn directory_listing_addition_changes_epoch_without_reading_file_contents() {
    let fixture = RepositoryFixture::plain();
    fixture.write("inputs/first", b"first\n");
    let plan = RepositoryObservationPlanV1::new(
        Vec::new(),
        Vec::new(),
        vec![PathBuf::from("inputs")],
        Vec::new(),
    );
    let before = observe_repository_v1(fixture.root(), &plan, &limits()).unwrap();
    fixture.write("inputs/second", b"second\n");
    let after = observe_repository_v1(fixture.root(), &plan, &limits()).unwrap();
    assert_ne!(before.digest(), after.digest());
    assert_eq!(after.observations()[0].bytes(), 0);
}

#[test]
fn negative_dependency_becoming_present_changes_epoch() {
    let fixture = RepositoryFixture::plain();
    fixture.write("src/existing", b"existing\n");
    let plan = RepositoryObservationPlanV1::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![PathBuf::from("src/generated")],
    );
    let absent = observe_repository_v1(fixture.root(), &plan, &limits()).expect("absent epoch");
    assert!(!absent.observations()[0].is_present());
    fixture.write("src/generated", b"now present\n");
    let present = observe_repository_v1(fixture.root(), &plan, &limits()).expect("present epoch");
    assert!(present.observations()[0].is_present());
    assert_ne!(absent.digest(), present.digest());
}

#[test]
fn git_head_and_index_changes_are_bound() {
    let fixture = RepositoryFixture::git();
    fixture.write("tracked", b"one\n");
    fixture.commit_all("first");
    let empty_plan =
        RepositoryObservationPlanV1::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let initial =
        observe_repository_v1(fixture.root(), &empty_plan, &limits()).expect("initial Git epoch");

    fixture.write("staged", b"staged\n");
    fixture.run_git(&["add", "staged"]);
    let staged =
        observe_repository_v1(fixture.root(), &empty_plan, &limits()).expect("staged Git epoch");
    assert_ne!(initial.digest(), staged.digest(), "index identity is bound");

    fixture.commit_all("second");
    let committed =
        observe_repository_v1(fixture.root(), &empty_plan, &limits()).expect("committed Git epoch");
    assert_ne!(
        staged.digest(),
        committed.digest(),
        "HEAD identity is bound"
    );
}

#[test]
fn git_control_configuration_changes_are_bound() {
    let fixture = RepositoryFixture::git();
    fixture.write("src/input.rs", b"fn input() {}\n");
    fixture.commit_all("initial");
    let before = observe_repository_v1(fixture.root(), &content_plan("src/input.rs"), &limits())
        .expect("initial Git control state");

    fixture.run_git(&["config", "diff.algorithm", "histogram"]);
    let after = observe_repository_v1(fixture.root(), &content_plan("src/input.rs"), &limits())
        .expect("changed Git control state");
    assert_ne!(before.digest(), after.digest());
}

#[test]
fn external_git_configuration_dependencies_fail_closed() {
    for key in [
        "include.path",
        "core.excludesFile",
        "core.attributesFile",
        "core.worktree",
        "diff.orderFile",
        "blame.ignoreRevsFile",
    ] {
        let fixture = RepositoryFixture::git();
        fixture.write("tracked", b"tracked\n");
        fixture.commit_all("initial");
        let external = fixture.temporary.path().join("external-git-input");
        fs::write(&external, b"# external Git input\n").unwrap();
        fixture.run_git(&["config", key, external.to_str().unwrap()]);

        let refusal = observe_repository_v1(
            fixture.root(),
            &RepositoryObservationPlanV1::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()),
            &limits(),
        )
        .unwrap_err();
        assert_eq!(
            refusal.primary_code(),
            IncompleteReasonCodeV1::UnknownRelevantState,
            "{key} must not create unobserved reuse authority"
        );
    }
}

#[test]
fn nested_workspace_discovers_its_enclosing_git_identity() {
    let fixture = RepositoryFixture::git();
    fixture.write("nested/workspace/input", b"input\n");
    fixture.commit_all("initial");
    let nested = fixture.root().join("nested/workspace");
    let epoch = observe_repository_v1(&nested, &content_plan("input"), &limits()).unwrap();
    match epoch.git_state() {
        RepositoryGitStateV1::Git { worktree_root, .. } => {
            assert_eq!(worktree_root, &fs::canonicalize(fixture.root()).unwrap());
        }
        RepositoryGitStateV1::NotGitRepository => panic!("nested workspace lost Git identity"),
    }
}

#[test]
fn task_revision_changes_task_and_complete_state() {
    let fixture = RepositoryFixture::plain();
    fixture.write("input", b"input\n");
    let repository =
        observe_repository_v1(fixture.root(), &content_plan("input"), &limits()).unwrap();
    let environment = observe_environment_v1(
        &classify_environment(
            EnvironmentObservationPlanV1::new().with_operating_system(),
            &[StateDimensionV1::OperatingSystem],
        ),
        &limits(),
    )
    .unwrap();
    let first = CompleteToolStateV1::new(
        repository.clone(),
        environment.clone(),
        task(1),
        no_external(),
    );
    let second = CompleteToolStateV1::new(repository, environment, task(2), no_external());
    assert_ne!(
        first.agent_context().task().digest(),
        second.agent_context().task().digest()
    );
    assert_ne!(first.digest(), second.digest());
    let first_digest = first.digest();
    assert_eq!(
        first.into_reusable_authority().complete_state_digest(),
        first_digest
    );
}

#[test]
fn environment_and_tool_versions_change_environment_authority() {
    let fixture = RepositoryFixture::plain();
    fixture.write("tool", b"stable executable bytes\n");
    let build = |version: &[u8]| {
        let executable = ExecutableObservationRequestV1::new(
            "compiler",
            fixture.root().join("tool"),
            version,
            &limits(),
        )
        .unwrap();
        observe_environment_v1(
            &classify_environment(
                EnvironmentObservationPlanV1::new()
                    .with_operating_system()
                    .with_architecture()
                    .with_kernel_identity("test-kernel")
                    .with_executable(executable),
                &[
                    StateDimensionV1::OperatingSystem,
                    StateDimensionV1::Architecture,
                    StateDimensionV1::Kernel,
                    StateDimensionV1::Executables,
                ],
            ),
            &limits(),
        )
        .unwrap()
    };
    let first = build(b"compiler 1.0");
    let second = build(b"compiler 2.0");
    assert_ne!(first.digest(), second.digest());

    fixture.write("tool", b"new executable bytes\n");
    let third = build(b"compiler 2.0");
    assert_ne!(second.digest(), third.digest());
}

#[test]
fn irrelevant_path_is_stable_only_because_plan_excludes_it() {
    let fixture = RepositoryFixture::plain();
    fixture.write("selected/input", b"selected\n");
    fixture.write("irrelevant/first", b"first\n");
    let plan = content_plan("selected/input");
    let before = observe_repository_v1(fixture.root(), &plan, &limits()).unwrap();
    fixture.write("irrelevant/second", b"second\n");
    let after = observe_repository_v1(fixture.root(), &plan, &limits()).unwrap();
    assert_eq!(before.digest(), after.digest());
    assert_eq!(before.plan(), after.plan());
}

#[test]
fn symlinks_and_special_files_are_typed_refusals() {
    let fixture = RepositoryFixture::plain();
    fixture.write("target", b"target\n");
    symlink("target", fixture.root().join("link")).expect("fixture symlink");
    let symlink_refusal =
        observe_repository_v1(fixture.root(), &content_plan("link"), &limits()).unwrap_err();
    assert_eq!(
        symlink_refusal.primary_code(),
        IncompleteReasonCodeV1::SymlinkRefused
    );

    let special_path = fixture.root().join("named-pipe");
    let status = Command::new("mkfifo")
        .arg(&special_path)
        .status()
        .expect("create fixture named pipe");
    assert!(status.success());
    let special_refusal =
        observe_repository_v1(fixture.root(), &content_plan("named-pipe"), &limits()).unwrap_err();
    assert_eq!(
        special_refusal.primary_code(),
        IncompleteReasonCodeV1::SpecialFileRefused
    );
}

#[test]
fn intermediate_symlink_and_replacement_never_read_outside_scope() {
    let fixture = RepositoryFixture::plain();
    fixture.write("inside/value", b"inside\n");
    let external = TempDir::new().unwrap();
    fs::write(external.path().join("value"), b"outside-secret\n").unwrap();

    symlink(external.path(), fixture.root().join("escape")).unwrap();
    let refusal = observe_repository_v1(fixture.root(), &content_plan("escape/value"), &limits())
        .unwrap_err();
    assert_eq!(
        refusal.primary_code(),
        IncompleteReasonCodeV1::SymlinkRefused
    );

    let inside = fixture.root().join("inside");
    let displaced = fixture.root().join("inside-old");
    let refusal = observe_repository_with_test_hook_v1(
        fixture.root(),
        &content_plan("inside/value"),
        &limits(),
        || {
            fs::rename(&inside, &displaced).unwrap();
            symlink(external.path(), &inside).unwrap();
        },
    )
    .unwrap_err();
    assert!(matches!(
        refusal.primary_code(),
        IncompleteReasonCodeV1::SymlinkRefused
            | IncompleteReasonCodeV1::RepositoryReplaced
            | IncompleteReasonCodeV1::ConcurrentMutation
    ));
}

#[test]
fn executable_and_cwd_intermediate_symlinks_are_refused() {
    let fixture = RepositoryFixture::plain();
    fixture.write("tool", b"tool\n");
    let alias = fixture.root().join("alias");
    symlink(fixture.root(), &alias).unwrap();
    let executable =
        ExecutableObservationRequestV1::new("tool", alias.join("tool"), b"version", &limits())
            .unwrap();
    let executable_refusal = observe_environment_v1(
        &classify_environment(
            EnvironmentObservationPlanV1::new().with_executable(executable),
            &[StateDimensionV1::Executables],
        ),
        &limits(),
    )
    .unwrap_err();
    assert_eq!(
        executable_refusal.primary_code(),
        IncompleteReasonCodeV1::SymlinkRefused
    );

    let cwd_refusal = observe_environment_v1(
        &classify_environment(
            EnvironmentObservationPlanV1::new().with_cwd(alias),
            &[StateDimensionV1::WorkingDirectory],
        ),
        &limits(),
    )
    .unwrap_err();
    assert_eq!(
        cwd_refusal.primary_code(),
        IncompleteReasonCodeV1::SymlinkRefused
    );
}

#[test]
fn environment_omissions_are_unknown_and_relevance_proof_is_bound() {
    let empty =
        observe_environment_v1(&EnvironmentObservationPlanV1::new(), &limits()).unwrap_err();
    assert_eq!(
        empty.primary_code(),
        IncompleteReasonCodeV1::UnknownRelevantState
    );

    let build = |evidence: &[u8]| {
        let exclusions = [
            StateDimensionV1::Architecture,
            StateDimensionV1::Kernel,
            StateDimensionV1::Executables,
            StateDimensionV1::WorkingDirectory,
            StateDimensionV1::EnvironmentValues,
            StateDimensionV1::ResourceProfile,
            StateDimensionV1::SandboxBackend,
            StateDimensionV1::McpProviderToolSchema,
            StateDimensionV1::AuthorizationScope,
        ]
        .into_iter()
        .map(|dimension| (dimension, evidence.to_vec()))
        .collect();
        observe_environment_v1(
            &EnvironmentObservationPlanV1::new()
                .with_operating_system()
                .with_relevance_proof(
                    EnvironmentRelevanceProofV1::from_exclusions(exclusions, &limits()).unwrap(),
                ),
            &limits(),
        )
        .unwrap()
    };
    assert_ne!(build(b"schema-a").digest(), build(b"schema-b").digest());
}

#[test]
fn repository_replacement_during_observation_is_refused() {
    let fixture = RepositoryFixture::plain();
    fixture.write("input", b"input\n");
    let original = fixture.root().to_path_buf();
    let displaced = fixture.temporary.path().join("displaced");
    let refusal = observe_repository_with_test_hook_v1(
        fixture.root(),
        &content_plan("input"),
        &limits(),
        || {
            fs::rename(&original, &displaced).expect("displace observed repository");
            fs::create_dir(&original).expect("replacement repository");
            fs::write(original.join("input"), b"input\n").expect("replacement input");
        },
    )
    .unwrap_err();
    assert_eq!(
        refusal.primary_code(),
        IncompleteReasonCodeV1::RepositoryReplaced
    );
}

#[test]
fn canonical_encoding_is_deterministic_and_plan_order_independent() {
    let fixture = RepositoryFixture::plain();
    fixture.write("a", b"a\n");
    fixture.write("b", b"b\n");
    let forward = RepositoryObservationPlanV1::new(
        vec![PathBuf::from("a"), PathBuf::from("b")],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let reverse = RepositoryObservationPlanV1::new(
        vec![PathBuf::from("b"), PathBuf::from("a")],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let first = observe_repository_v1(fixture.root(), &forward, &limits()).unwrap();
    let second = observe_repository_v1(fixture.root(), &reverse, &limits()).unwrap();
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.digest().to_hex().len(), 64);

    let environment_value_a =
        EnvironmentValueDigestV1::from_value(OsStr::new("A"), OsStr::new("1"), &limits()).unwrap();
    let environment_value_b =
        EnvironmentValueDigestV1::from_value(OsStr::new("B"), OsStr::new("2"), &limits()).unwrap();
    let environment_forward = observe_environment_v1(
        &classify_environment(
            EnvironmentObservationPlanV1::new()
                .with_environment_value(environment_value_a.clone())
                .with_environment_value(environment_value_b.clone()),
            &[StateDimensionV1::EnvironmentValues],
        ),
        &limits(),
    )
    .unwrap();
    let environment_reverse = observe_environment_v1(
        &classify_environment(
            EnvironmentObservationPlanV1::new()
                .with_environment_value(environment_value_b)
                .with_environment_value(environment_value_a),
            &[StateDimensionV1::EnvironmentValues],
        ),
        &limits(),
    )
    .unwrap();
    assert_eq!(
        environment_forward.canonical_bytes(),
        environment_reverse.canonical_bytes()
    );

    let external_a = ExternalDependencyObservationV1::from_token(
        "provider",
        b"resource-a",
        b"token-a",
        &limits(),
    )
    .unwrap();
    let external_b = ExternalDependencyObservationV1::from_token(
        "provider",
        b"resource-b",
        b"token-b",
        &limits(),
    )
    .unwrap();
    let external_forward = ExternalFreshnessV1::from_observations(
        vec![external_a.clone(), external_b.clone()],
        &limits(),
    )
    .unwrap();
    let external_reverse =
        ExternalFreshnessV1::from_observations(vec![external_b, external_a], &limits()).unwrap();
    assert_eq!(external_forward.digest(), external_reverse.digest());
}

#[test]
fn explicit_not_git_unknown_environment_and_sparse_states_fail_closed() {
    let plain = RepositoryFixture::plain();
    let no_git = observe_repository_v1(
        plain.root(),
        &RepositoryObservationPlanV1::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        &limits(),
    )
    .unwrap();
    assert_eq!(no_git.git_state(), &RepositoryGitStateV1::NotGitRepository);

    let unknown = observe_environment_v1(
        &EnvironmentObservationPlanV1::new()
            .with_unknown_dimension(StateDimensionV1::Kernel)
            .with_relevance_proof(
                EnvironmentRelevanceProofV1::from_exclusions(
                    [
                        StateDimensionV1::OperatingSystem,
                        StateDimensionV1::Architecture,
                        StateDimensionV1::Executables,
                        StateDimensionV1::WorkingDirectory,
                        StateDimensionV1::EnvironmentValues,
                        StateDimensionV1::ResourceProfile,
                        StateDimensionV1::SandboxBackend,
                        StateDimensionV1::McpProviderToolSchema,
                        StateDimensionV1::AuthorizationScope,
                    ]
                    .into_iter()
                    .map(|dimension| (dimension, b"excluded".to_vec()))
                    .collect(),
                    &limits(),
                )
                .unwrap(),
            ),
        &limits(),
    )
    .unwrap_err();
    assert_eq!(
        unknown.primary_code(),
        IncompleteReasonCodeV1::UnknownRelevantState
    );

    let sparse = RepositoryFixture::git();
    sparse.write("tracked", b"tracked\n");
    sparse.commit_all("initial");
    fs::create_dir_all(sparse.root().join(".git/info")).unwrap();
    fs::write(sparse.root().join(".git/info/sparse-checkout"), b"/*\n").unwrap();
    let refusal = observe_repository_v1(
        sparse.root(),
        &RepositoryObservationPlanV1::new(Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        &limits(),
    )
    .unwrap_err();
    assert_eq!(
        refusal.primary_code(),
        IncompleteReasonCodeV1::SparseCheckoutAmbiguous
    );
}

#[test]
fn secret_bearing_inputs_are_bounded_and_never_retained_as_plaintext() {
    let mut tiny = limits();
    tiny.max_environment_value_bytes = 5;
    let oversized =
        EnvironmentValueDigestV1::from_value(OsStr::new("TOKEN"), OsStr::new("secret"), &tiny)
            .unwrap_err();
    assert_eq!(
        oversized.primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let value = EnvironmentValueDigestV1::from_value(
        OsStr::new("TOKEN"),
        OsStr::new("plain-secret-value"),
        &limits(),
    )
    .unwrap();
    assert!(!format!("{value:?}").contains("plain-secret-value"));

    let external = ExternalDependencyObservationV1::from_token(
        "provider",
        b"private-resource",
        b"private-freshness-token",
        &limits(),
    )
    .unwrap();
    assert!(!format!("{external:?}").contains("private-freshness-token"));
}

#[test]
fn every_configurable_input_bound_fails_closed() {
    let fixture = RepositoryFixture::plain();
    fixture.write("large", b"123456");
    fixture.write("tree/a", b"a");
    fixture.write("tree/b", b"b");
    fixture.write("tree/nested/deep/value", b"deep");

    let mut file_limits = limits();
    file_limits.max_file_bytes = 5;
    assert_eq!(
        observe_repository_v1(fixture.root(), &content_plan("large"), &file_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut total_limits = limits();
    total_limits.max_file_bytes = 6;
    total_limits.max_total_bytes = 6;
    let two_files = RepositoryObservationPlanV1::new(
        vec![PathBuf::from("large"), PathBuf::from("tree/a")],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        observe_repository_v1(fixture.root(), &two_files, &total_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut entry_limits = limits();
    entry_limits.max_tree_entries = 2;
    let tree = RepositoryObservationPlanV1::new(
        Vec::new(),
        vec![PathBuf::from("tree")],
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        observe_repository_v1(fixture.root(), &tree, &entry_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut directory_limits = limits();
    directory_limits.max_directory_entries = 2;
    assert_eq!(
        observe_repository_v1(fixture.root(), &tree, &directory_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut depth_limits = limits();
    depth_limits.max_tree_depth = 1;
    assert_eq!(
        observe_repository_v1(fixture.root(), &tree, &depth_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut plan_limits = limits();
    plan_limits.max_plan_entries = 1;
    assert_eq!(
        observe_repository_v1(fixture.root(), &two_files, &plan_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut path_limits = limits();
    path_limits.max_path_bytes = 3;
    assert_eq!(
        observe_repository_v1(fixture.root(), &content_plan("large"), &path_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut environment_limits = limits();
    environment_limits.max_environment_entries = 1;
    let first =
        EnvironmentValueDigestV1::from_value(OsStr::new("A"), OsStr::new("1"), &limits()).unwrap();
    let second =
        EnvironmentValueDigestV1::from_value(OsStr::new("B"), OsStr::new("2"), &limits()).unwrap();
    assert_eq!(
        observe_environment_v1(
            &classify_environment(
                EnvironmentObservationPlanV1::new()
                    .with_environment_value(first)
                    .with_environment_value(second),
                &[StateDimensionV1::EnvironmentValues],
            ),
            &environment_limits,
        )
        .unwrap_err()
        .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut name_limits = limits();
    name_limits.max_environment_name_bytes = 1;
    assert_eq!(
        EnvironmentValueDigestV1::from_value(
            OsStr::new("LONG"),
            OsStr::new("value"),
            &name_limits,
        )
        .unwrap_err()
        .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut identity_limits = limits();
    identity_limits.max_identity_bytes = 3;
    assert_eq!(
        EnvironmentObservationPlanV1::new()
            .with_authorization_scope_identifier(b"scope", &identity_limits)
            .unwrap_err()
            .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut task_limits = limits();
    task_limits.max_task_field_bytes = 3;
    let task_error = TaskStateV1::from_input(
        TaskStateInputV1 {
            task_id: "long".to_owned(),
            task_revision: 1,
            user_goal_digest: digest(b"goal"),
            accepted_constraints_digest: digest(b"constraints"),
            branch_identity: "ref".to_owned(),
            worktree_identity: "id".to_owned(),
            patch_digest: digest(b"patch"),
            plan_revision: 1,
            compaction_epoch: 1,
        },
        &task_limits,
    )
    .unwrap_err();
    assert_eq!(
        task_error.primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let mut external_limits = limits();
    external_limits.max_external_token_bytes = 2;
    assert_eq!(
        ExternalDependencyObservationV1::from_token(
            "provider",
            b"resource",
            b"long",
            &external_limits,
        )
        .unwrap_err()
        .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );

    let first_external =
        ExternalDependencyObservationV1::from_token("provider", b"resource-one", b"one", &limits())
            .unwrap();
    let second_external =
        ExternalDependencyObservationV1::from_token("provider", b"resource-two", b"two", &limits())
            .unwrap();
    let mut dependency_limits = limits();
    dependency_limits.max_external_dependencies = 1;
    assert_eq!(
        ExternalFreshnessV1::from_observations(
            vec![first_external, second_external],
            &dependency_limits,
        )
        .unwrap_err()
        .primary_code(),
        IncompleteReasonCodeV1::InputLimitExceeded
    );
}
