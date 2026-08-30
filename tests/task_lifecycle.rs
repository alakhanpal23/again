use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use again::agent_gateway::context::ContextLedgerIdentityV1;
use again::store::{ContextTaskMatchV1, Store};
use again::task_lifecycle::{TaskClaimOutcomeV1, TaskDefinitionV1, TaskStateV1};
use rusqlite::Connection;
use tempfile::TempDir;

fn digest(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn private_temp() -> TempDir {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

fn deadline() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
    .saturating_add(60_000)
}

fn identity(task_id: &str, agent: &str, session: &str) -> ContextLedgerIdentityV1 {
    ContextLedgerIdentityV1::new(
        "repository",
        "workspace",
        task_id,
        &digest("authorization"),
        agent,
        session,
        "turn-one",
        &digest(&format!("connection:{agent}:{session}")),
        0,
        1,
    )
    .unwrap()
}

fn definition(prompt: &str) -> TaskDefinitionV1 {
    TaskDefinitionV1::new(prompt, Vec::new(), None, Vec::new(), None).unwrap()
}

fn leader(outcome: TaskClaimOutcomeV1) -> (String, u64) {
    match outcome {
        TaskClaimOutcomeV1::Leader {
            lease_id,
            state_generation,
            ..
        } => (lease_id, state_generation),
        other => panic!("expected leader, got {other:?}"),
    }
}

#[test]
fn dependencies_block_claims_then_blocked_work_requires_a_new_cas_claim() {
    let temp = private_temp();
    let store = Store::open(temp.path()).unwrap();
    let authorization = digest("authorization");
    let dependency = store
        .start_task_v1(
            "repository",
            "workspace",
            &authorization,
            "dependency",
            &definition("Complete the prerequisite"),
        )
        .unwrap();
    let dependent_definition = TaskDefinitionV1::new(
        "Perform dependent work",
        vec!["The prerequisite is complete".to_owned()],
        None,
        vec!["dependency".to_owned()],
        None,
    )
    .unwrap();
    let dependent = store
        .start_task_v1(
            "repository",
            "workspace",
            &authorization,
            "dependent",
            &dependent_definition,
        )
        .unwrap();
    assert_eq!(dependency.task.state, TaskStateV1::Active);
    assert_eq!(dependent.task.state, TaskStateV1::Waiting);
    assert_eq!(dependent.task.blockers[0].reason, "dependency_incomplete");

    let dependent_identity = identity("dependent", "agent-b", "session-b");
    store
        .activate_context_recipient_v1(&dependent_identity)
        .unwrap();
    assert!(matches!(
        store
            .claim_task_v1(&dependent_identity, 1, 30_000, deadline())
            .unwrap(),
        TaskClaimOutcomeV1::Waiting { .. }
    ));

    let dependency_identity = identity("dependency", "agent-a", "session-a");
    store
        .activate_context_recipient_v1(&dependency_identity)
        .unwrap();
    let (dependency_lease, dependency_generation) = leader(
        store
            .claim_task_v1(&dependency_identity, 1, 30_000, deadline())
            .unwrap(),
    );
    assert_eq!(dependency_generation, 1);
    store
        .transition_task_v1(
            &dependency_identity,
            &dependency_lease,
            1,
            TaskStateV1::Completed,
            "acceptance criteria satisfied",
        )
        .unwrap();

    let (first_lease, active_generation) = leader(
        store
            .claim_task_v1(&dependent_identity, 1, 30_000, deadline())
            .unwrap(),
    );
    assert_eq!(active_generation, 2);
    let blocked = store
        .transition_task_v1(
            &dependent_identity,
            &first_lease,
            2,
            TaskStateV1::Blocked,
            "waiting for an explicit local decision",
        )
        .unwrap();
    assert_eq!(blocked.state, TaskStateV1::Blocked);
    assert_eq!(blocked.state_generation, 3);
    assert!(
        store
            .claim_task_v1(&dependent_identity, 2, 30_000, deadline())
            .is_err()
    );

    let (second_lease, resumed_generation) = leader(
        store
            .claim_task_v1(&dependent_identity, 3, 30_000, deadline())
            .unwrap(),
    );
    assert_ne!(first_lease, second_lease);
    assert_eq!(resumed_generation, 4);
    let completed = store
        .transition_task_v1(
            &dependent_identity,
            &second_lease,
            4,
            TaskStateV1::Completed,
            "all acceptance criteria satisfied",
        )
        .unwrap();
    assert_eq!(completed.state, TaskStateV1::Completed);
    assert_eq!(completed.state_generation, 5);
    assert!(matches!(
        store
            .claim_task_v1(&dependent_identity, 5, 30_000, deadline())
            .unwrap(),
        TaskClaimOutcomeV1::Terminal {
            state: TaskStateV1::Completed,
            ..
        }
    ));
    assert!(
        store
            .transition_task_v1(
                &dependent_identity,
                &second_lease,
                5,
                TaskStateV1::Failed,
                "must remain immutable",
            )
            .is_err()
    );

    let export = store
        .export_task_v1("repository", "workspace", &authorization, "dependent")
        .unwrap()
        .unwrap();
    assert_eq!(export.transitions.len(), 5);
    assert_eq!(
        export.transitions.last().unwrap().to_state,
        TaskStateV1::Completed
    );
}

#[test]
fn concurrent_exact_definitions_converge_but_changed_criteria_conflict() {
    let temp = private_temp();
    drop(Store::open(temp.path()).unwrap());
    let root = temp.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));
    let handles = ["external-a", "external-b"].map(|requested| {
        let root = root.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let store = Store::open(root).unwrap();
            let definition = TaskDefinitionV1::new(
                "Implement exact lifecycle",
                vec!["All transition races converge".to_owned()],
                None,
                Vec::new(),
                None,
            )
            .unwrap();
            barrier.wait();
            store
                .start_task_v1(
                    "repository",
                    "workspace",
                    &digest("authorization"),
                    requested,
                    &definition,
                )
                .unwrap()
        })
    });
    let first = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        first[0].task.canonical_task_id,
        first[1].task.canonical_task_id
    );
    assert!(
        first
            .iter()
            .any(|outcome| outcome.matched_by == ContextTaskMatchV1::Created)
    );
    assert!(
        first
            .iter()
            .any(|outcome| outcome.matched_by == ContextTaskMatchV1::JoinedByPrompt)
    );

    let store = Store::open(temp.path()).unwrap();
    assert_eq!(
        store
            .list_tasks_v1("repository", "workspace", &digest("authorization"), 10)
            .unwrap()
            .len(),
        1
    );
    let conflicting = TaskDefinitionV1::new(
        "Implement exact lifecycle",
        vec!["A different acceptance contract".to_owned()],
        None,
        Vec::new(),
        None,
    )
    .unwrap();
    assert_eq!(
        store
            .start_task_v1(
                "repository",
                "workspace",
                &digest("authorization"),
                "external-a",
                &conflicting,
            )
            .unwrap_err()
            .to_string(),
        "task_definition_conflict"
    );
}

#[test]
fn schema_twelve_tasks_migrate_to_active_revision_one_with_history() {
    let temp = private_temp();
    {
        let store = Store::open(temp.path()).unwrap();
        store
            .resolve_context_task_v1(
                "repository",
                "workspace",
                &digest("authorization"),
                "legacy-task",
                Some("Preserve this exact legacy prompt"),
            )
            .unwrap();
    }
    let database = temp.path().join("again.sqlite");
    Connection::open(&database)
        .unwrap()
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TABLE context_workspace_quota_v1;
             DROP TABLE context_task_transitions_v1;
             DROP TABLE context_task_relations_v1;
             DROP INDEX context_tasks_state_idx;
             DROP INDEX context_tasks_definition_idx;
             CREATE UNIQUE INDEX context_tasks_prompt_idx ON context_tasks_v1(
                 repository_id, workspace_id, authorization_scope_digest, prompt_digest
             );
             ALTER TABLE context_tasks_v1 DROP COLUMN state_generation;
             ALTER TABLE context_tasks_v1 DROP COLUMN state;
             ALTER TABLE context_tasks_v1 DROP COLUMN revision;
             ALTER TABLE context_tasks_v1 DROP COLUMN acceptance_criteria_json;
             ALTER TABLE context_tasks_v1 DROP COLUMN definition_digest;
             PRAGMA user_version = 12;",
        )
        .unwrap();

    let migrated = Store::open(temp.path()).unwrap();
    let task = migrated
        .inspect_task_v1(
            "repository",
            "workspace",
            &digest("authorization"),
            "legacy-task",
        )
        .unwrap()
        .unwrap();
    assert_eq!(task.revision, 1);
    assert_eq!(task.state, TaskStateV1::Active);
    assert_eq!(task.state_generation, 1);
    assert!(task.definition.dependency_task_ids().is_empty());
    let export = migrated
        .export_task_v1(
            "repository",
            "workspace",
            &digest("authorization"),
            "legacy-task",
        )
        .unwrap()
        .unwrap();
    assert_eq!(export.transitions.len(), 1);
    assert_eq!(export.transitions[0].reason, "schema_v12_migration");
}

#[test]
fn quota_corruption_and_partial_schema_fail_closed() {
    let temp = private_temp();
    {
        let store = Store::open(temp.path()).unwrap();
        store
            .start_task_v1(
                "repository",
                "workspace",
                &digest("authorization"),
                "task",
                &definition("Exercise quota integrity"),
            )
            .unwrap();
    }
    let database = temp.path().join("again.sqlite");
    Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE context_workspace_quota_v1
             SET task_context_bytes = task_context_bytes + 1",
            [],
        )
        .unwrap();
    let error = Store::open(temp.path())
        .err()
        .expect("corrupt quota must fail");
    assert!(error.to_string().contains("quota accounting is corrupt"));

    let partial = private_temp();
    drop(Store::open(partial.path()).unwrap());
    Connection::open(partial.path().join("again.sqlite"))
        .unwrap()
        .execute_batch("PRAGMA foreign_keys = OFF; DROP TABLE context_task_transitions_v1;")
        .unwrap();
    assert!(Store::open(partial.path()).is_err());
}

#[test]
fn deletion_requires_terminal_unreferenced_work_and_sensitive_text_never_persists() {
    let temp = private_temp();
    let store = Store::open(temp.path()).unwrap();
    let authorization = digest("authorization");
    let secret_error =
        TaskDefinitionV1::new("password=hunter2", Vec::new(), None, Vec::new(), None).unwrap_err();
    assert_eq!(secret_error.to_string(), "sensitive_content_refused");
    assert!(
        store
            .inspect_task_v1("repository", "workspace", &authorization, "secret-task",)
            .unwrap()
            .is_none()
    );

    store
        .start_task_v1(
            "repository",
            "workspace",
            &authorization,
            "parent",
            &definition("Parent task"),
        )
        .unwrap();
    let parent_identity = identity("parent", "parent-agent", "parent-session");
    store
        .activate_context_recipient_v1(&parent_identity)
        .unwrap();
    let (parent_lease, _) = leader(
        store
            .claim_task_v1(&parent_identity, 1, 30_000, deadline())
            .unwrap(),
    );
    store
        .transition_task_v1(
            &parent_identity,
            &parent_lease,
            1,
            TaskStateV1::Completed,
            "parent complete",
        )
        .unwrap();
    let child = TaskDefinitionV1::new(
        "Child task",
        Vec::new(),
        Some("parent".to_owned()),
        Vec::new(),
        None,
    )
    .unwrap();
    store
        .start_task_v1("repository", "workspace", &authorization, "child", &child)
        .unwrap();
    assert!(
        store
            .delete_task_v1("repository", "workspace", &authorization, "parent",)
            .is_err()
    );

    let child_identity = identity("child", "agent", "session");
    store
        .activate_context_recipient_v1(&child_identity)
        .unwrap();
    let (lease, generation) = leader(
        store
            .claim_task_v1(&child_identity, 1, 30_000, deadline())
            .unwrap(),
    );
    assert_eq!(generation, 1);
    store
        .transition_task_v1(
            &child_identity,
            &lease,
            1,
            TaskStateV1::Cancelled,
            "explicit user cancellation",
        )
        .unwrap();
    assert!(
        store
            .delete_task_v1("repository", "workspace", &authorization, "child",)
            .unwrap()
    );
    assert!(
        store
            .inspect_task_v1("repository", "workspace", &authorization, "child",)
            .unwrap()
            .is_none()
    );
}

#[test]
fn transition_matrix_and_stale_leader_authority_fail_closed() {
    let temp = private_temp();
    let store = Store::open(temp.path()).unwrap();
    let authorization = digest("authorization");
    for (index, target) in [
        TaskStateV1::Blocked,
        TaskStateV1::Completed,
        TaskStateV1::Failed,
        TaskStateV1::Cancelled,
    ]
    .into_iter()
    .enumerate()
    {
        let task_id = format!("valid-{index}");
        store
            .start_task_v1(
                "repository",
                "workspace",
                &authorization,
                &task_id,
                &definition(&format!("valid transition {index}")),
            )
            .unwrap();
        let identity = identity(
            &task_id,
            &format!("agent-{index}"),
            &format!("session-{index}"),
        );
        store.activate_context_recipient_v1(&identity).unwrap();
        let (lease, _) = leader(
            store
                .claim_task_v1(&identity, 1, 30_000, deadline())
                .unwrap(),
        );
        assert!(
            store
                .transition_task_v1(&identity, &lease, 1, target, "matrix transition")
                .is_ok()
        );
    }
    for (index, target) in [TaskStateV1::Waiting, TaskStateV1::Active]
        .into_iter()
        .enumerate()
    {
        let task_id = format!("invalid-{index}");
        store
            .start_task_v1(
                "repository",
                "workspace",
                &authorization,
                &task_id,
                &definition(&format!("invalid transition {index}")),
            )
            .unwrap();
        let identity = identity(
            &task_id,
            &format!("invalid-agent-{index}"),
            &format!("invalid-session-{index}"),
        );
        store.activate_context_recipient_v1(&identity).unwrap();
        let (lease, _) = leader(
            store
                .claim_task_v1(&identity, 1, 30_000, deadline())
                .unwrap(),
        );
        assert_eq!(
            store
                .transition_task_v1(&identity, &lease, 1, target, "invalid matrix edge")
                .unwrap_err()
                .to_string(),
            "invalid_task_transition"
        );
    }

    store
        .start_task_v1(
            "repository",
            "workspace",
            &authorization,
            "takeover",
            &definition("recover after leader loss"),
        )
        .unwrap();
    let stale = identity("takeover", "same-agent", "same-session");
    store.activate_context_recipient_v1(&stale).unwrap();
    let (stale_lease, _) = leader(store.claim_task_v1(&stale, 1, 30_000, deadline()).unwrap());
    assert!(store.retire_context_recipient_v1(&stale).unwrap());
    let current = stale
        .after_lifecycle_change(&digest("replacement-connection"))
        .unwrap();
    store.activate_context_recipient_v1(&current).unwrap();
    let (current_lease, _) = leader(
        store
            .claim_task_v1(&current, 1, 30_000, deadline())
            .unwrap(),
    );
    assert_ne!(stale_lease, current_lease);
    assert!(
        store
            .transition_task_v1(
                &stale,
                &stale_lease,
                1,
                TaskStateV1::Completed,
                "stale authority",
            )
            .is_err()
    );
    store
        .transition_task_v1(
            &current,
            &current_lease,
            1,
            TaskStateV1::Completed,
            "current authority",
        )
        .unwrap();
}

#[test]
fn graph_edges_are_scope_checked_immutable_and_revision_bound() {
    let temp = private_temp();
    let store = Store::open(temp.path()).unwrap();
    let authorization = digest("authorization");
    let other_authorization = digest("other-authorization");
    store
        .start_task_v1(
            "repository",
            "workspace",
            &authorization,
            "revision-one",
            &definition("original task"),
        )
        .unwrap();
    store
        .start_task_v1(
            "repository",
            "workspace",
            &other_authorization,
            "other-scope",
            &definition("private task"),
        )
        .unwrap();
    let cross_scope = TaskDefinitionV1::new(
        "must not cross scope",
        Vec::new(),
        None,
        vec!["other-scope".to_owned()],
        None,
    )
    .unwrap();
    assert_eq!(
        store
            .start_task_v1(
                "repository",
                "workspace",
                &authorization,
                "cross-scope",
                &cross_scope,
            )
            .unwrap_err()
            .to_string(),
        "task_relation_unavailable"
    );
    let self_edge = TaskDefinitionV1::new(
        "self edge",
        Vec::new(),
        Some("self-edge".to_owned()),
        Vec::new(),
        None,
    )
    .unwrap();
    assert_eq!(
        store
            .start_task_v1(
                "repository",
                "workspace",
                &authorization,
                "self-edge",
                &self_edge,
            )
            .unwrap_err()
            .to_string(),
        "task_graph_self_edge"
    );
    assert!(
        TaskDefinitionV1::new(
            "duplicate edges",
            Vec::new(),
            None,
            vec!["revision-one".to_owned(), "revision-one".to_owned()],
            None,
        )
        .is_err()
    );

    let revision_two_definition = TaskDefinitionV1::new(
        "revised task",
        vec!["New immutable acceptance".to_owned()],
        None,
        Vec::new(),
        Some("revision-one".to_owned()),
    )
    .unwrap();
    let revision_two = store
        .start_task_v1(
            "repository",
            "workspace",
            &authorization,
            "revision-two",
            &revision_two_definition,
        )
        .unwrap();
    assert_eq!(revision_two.task.revision, 2);
    assert_eq!(
        revision_two.task.definition.supersedes_task_id(),
        Some("revision-one")
    );
    assert_ne!(
        revision_two.task.definition.definition_digest(),
        definition("revised task").definition_digest()
    );
    let changed_revision = TaskDefinitionV1::new(
        "revised task",
        vec!["Mutated acceptance".to_owned()],
        None,
        Vec::new(),
        Some("revision-one".to_owned()),
    )
    .unwrap();
    assert!(
        store
            .start_task_v1(
                "repository",
                "workspace",
                &authorization,
                "revision-two",
                &changed_revision,
            )
            .is_err()
    );
}
