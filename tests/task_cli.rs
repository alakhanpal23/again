#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use again::agent_gateway::context::ContextLedgerIdentityV1;
use again::store::Store;
use again::task_lifecycle::{TaskClaimOutcomeV1, TaskDefinitionV1, TaskStateV1};
use serde_json::Value;
use tempfile::TempDir;

const AUTHORIZATION_SCOPE: &str = "human-task-cli-test";

struct Fixture {
    temporary: TempDir,
    workspace: PathBuf,
    state: PathBuf,
    repository_id: String,
    workspace_id: String,
    authorization_digest: String,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap();
        let workspace = temporary.path().join("workspace");
        let state = temporary.path().join("state");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("README.md"), b"task CLI fixture\n").unwrap();
        assert!(
            Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&workspace)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .unwrap()
                .success()
        );
        let workspace = fs::canonicalize(workspace).unwrap();
        let workspace_digest = domain_digest(
            b"again.local-context.workspace.v1\0",
            workspace.as_os_str().as_encoded_bytes(),
        );
        let authorization_digest = length_prefixed_digest(
            b"again.mcp.delivery-scope.v1\0",
            AUTHORIZATION_SCOPE.as_bytes(),
        );
        Self {
            temporary,
            workspace,
            state,
            repository_id: format!("repository:{}", &workspace_digest[..24]),
            workspace_id: format!("workspace:{}", &workspace_digest[..24]),
            authorization_digest,
        }
    }

    fn command(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_again"))
            .args(arguments)
            .args([
                "--workspace",
                self.workspace.to_str().unwrap(),
                "--authorization-scope",
                AUTHORIZATION_SCOPE,
            ])
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temporary.path().join("home"))
            .env("AGAIN_HOME", &self.state)
            .output()
            .unwrap()
    }

    fn store(&self) -> Store {
        Store::open(&self.state).unwrap()
    }

    fn start(&self, task_id: &str, prompt: &str) {
        self.store()
            .start_task_v1(
                &self.repository_id,
                &self.workspace_id,
                &self.authorization_digest,
                task_id,
                &TaskDefinitionV1::new(prompt, Vec::new(), None, Vec::new(), None).unwrap(),
            )
            .unwrap();
    }

    fn complete(&self, task_id: &str) {
        let store = self.store();
        let identity = ContextLedgerIdentityV1::new(
            &self.repository_id,
            &self.workspace_id,
            task_id,
            &self.authorization_digest,
            "human-task-cli-test-agent",
            &format!("session-{task_id}"),
            "turn-one",
            &domain_digest(b"connection\0", task_id.as_bytes()),
            0,
            1,
        )
        .unwrap();
        store.activate_context_recipient_v1(&identity).unwrap();
        let (lease_id, state_generation) = match store
            .claim_task_v1(&identity, 1, 30_000, deadline())
            .unwrap()
        {
            TaskClaimOutcomeV1::Leader {
                lease_id,
                state_generation,
                ..
            } => (lease_id, state_generation),
            outcome => panic!("expected leader, got {outcome:?}"),
        };
        store
            .transition_task_v1(
                &identity,
                &lease_id,
                state_generation,
                TaskStateV1::Completed,
                "acceptance criteria satisfied",
            )
            .unwrap();
    }
}

fn domain_digest(domain: &[u8], value: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().to_hex().to_string()
}

fn length_prefixed_digest(domain: &[u8], value: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
    hasher.finalize().to_hex().to_string()
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

fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn error(output: &Output) -> String {
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn list_inspect_export_and_delete_are_scoped_private_and_explicit() {
    let fixture = Fixture::new();
    fixture.start("terminal-task", "Finish the terminal integration");

    let listed = json(&fixture.command(&["task", "list", "--limit", "10"]));
    assert_eq!(listed["operation"], "task.list");
    assert_eq!(listed["tasks"][0]["canonical_task_id"], "terminal-task");
    assert_eq!(listed["tasks"][0]["state"], "active");
    assert_eq!(listed["quota"]["maintenance_mode"], false);

    let inspected = json(&fixture.command(&["task", "inspect", "terminal-task"]));
    assert_eq!(
        inspected["task"]["definition"]["prompt"],
        "Finish the terminal integration"
    );
    assert!(error(&fixture.command(&["task", "delete", "terminal-task"])).contains("--yes"));
    assert!(
        error(&fixture.command(&["task", "delete", "terminal-task", "--yes"]))
            .contains("task_delete_requires_terminal")
    );

    fixture.complete("terminal-task");
    let export = fixture.temporary.path().join("terminal-task.json");
    let exported = json(&fixture.command(&[
        "task",
        "export",
        "terminal-task",
        "--output",
        export.to_str().unwrap(),
    ]));
    assert_eq!(exported["status"], "exported");
    assert_eq!(
        fs::metadata(&export).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let document: Value = serde_json::from_slice(&fs::read(&export).unwrap()).unwrap();
    assert_eq!(document["export"]["task"]["state"], "completed");
    assert_eq!(
        document["export"]["transitions"].as_array().unwrap().len(),
        2
    );
    assert!(
        error(&fixture.command(&[
            "task",
            "export",
            "terminal-task",
            "--output",
            export.to_str().unwrap(),
        ]))
        .contains("create new private task export")
    );
    assert!(
        error(&fixture.command(&[
            "task",
            "export",
            "terminal-task",
            "--output",
            "relative.json",
        ]))
        .contains("absolute path")
    );

    let deleted = json(&fixture.command(&["task", "delete", "terminal-task", "--yes"]));
    assert_eq!(deleted["status"], "deleted");
    assert!(
        error(&fixture.command(&["task", "inspect", "terminal-task"]))
            .contains("task does not exist")
    );
}

#[test]
fn prune_is_bounded_and_never_applies_without_an_explicit_mode() {
    let fixture = Fixture::new();
    fixture.start("old-terminal", "Prune this terminal task");
    fixture.complete("old-terminal");
    fixture.start("active-task", "Keep this active task");
    thread::sleep(Duration::from_millis(5));

    assert!(
        error(&fixture.command(&["task", "prune", "--terminal-before-days", "0",]))
            .contains("exactly one")
    );
    let preview =
        json(&fixture.command(&["task", "prune", "--terminal-before-days", "0", "--dry-run"]));
    assert_eq!(
        preview["candidateTaskIds"],
        serde_json::json!(["old-terminal"])
    );
    assert!(
        fixture
            .store()
            .inspect_task_v1(
                &fixture.repository_id,
                &fixture.workspace_id,
                &fixture.authorization_digest,
                "old-terminal",
            )
            .unwrap()
            .is_some()
    );

    let applied =
        json(&fixture.command(&["task", "prune", "--terminal-before-days", "0", "--apply"]));
    assert_eq!(
        applied["deletedTaskIds"],
        serde_json::json!(["old-terminal"])
    );
    let remaining = json(&fixture.command(&["task", "list"]));
    assert_eq!(remaining["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(remaining["tasks"][0]["canonical_task_id"], "active-task");
}
