#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

const FAKE_CODEX: &str = r#"#!/bin/sh
set -eu
state_file="$FAKE_MCP_STATE"
state=absent
if [ -f "$state_file" ]; then state=$(sed -n '1p' "$state_file"); fi
printf '%s\n' "$*" >> "$FAKE_MCP_LOG"
if [ "$1" != mcp ]; then exit 64; fi
case "$2" in
  add)
    if [ "${3:-}" = --help ]; then printf 'Usage: codex mcp add NAME -- COMMAND\n'; exit 0; fi
    if [ "${FAKE_FAIL_ADD:-0}" = 1 ]; then printf 'ghp_setup_output_must_not_leak\n' >&2; exit 70; fi
    printf 'exact\n' > "$state_file"
    ;;
  get)
    if [ "${3:-}" = --help ]; then
      if [ "${FAKE_UNSUPPORTED:-0}" = 1 ]; then printf 'Usage: codex mcp get NAME\n';
      else printf 'Usage: codex mcp get NAME --json\n'; fi
      exit 0
    fi
    if [ "$state" = absent ]; then exit 1; fi
    if [ "$state" = conflict ]; then command=/other/binary; else command=$EXPECTED_AGAIN; fi
    printf '{"name":"again","transport":{"type":"stdio","command":"%s","args":["mcp","connect","--workspace","%s"]}}\n' "$command" "$EXPECTED_WORKSPACE"
    ;;
  list)
    if [ "${3:-}" = --help ]; then printf 'Usage: codex mcp list --json\n'; exit 0; fi
    if [ "$state" = absent ]; then printf '[]\n'; else printf '[{"name":"again"}]\n'; fi
    ;;
  remove)
    if [ "${3:-}" = --help ]; then printf 'Usage: codex mcp remove NAME\n'; exit 0; fi
    printf 'absent\n' > "$state_file"
    ;;
  *) exit 64 ;;
esac
"#;

struct Fixture {
    temporary: TempDir,
    workspace: PathBuf,
    state: PathBuf,
    log: PathBuf,
    path: String,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap();
        let bin = temporary.path().join("bin");
        let home = temporary.path().join("home");
        let workspace = temporary.path().join("workspace");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&home).unwrap();
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(workspace.join(".git")).unwrap();
        let codex = bin.join("codex");
        fs::write(&codex, FAKE_CODEX).unwrap();
        fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            temporary,
            workspace: fs::canonicalize(workspace).unwrap(),
            state: home.join("state"),
            log: home.join("argv.log"),
            path: format!("{}:/usr/bin:/bin", bin.display()),
        }
    }

    fn run(&self, arguments: &[&str], extra_environment: &[(&str, &str)]) -> Output {
        let executable = Path::new(env!("CARGO_BIN_EXE_again"));
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", self.temporary.path().join("home"))
            .env("AGAIN_HOME", self.temporary.path().join("again-state"))
            .env("FAKE_MCP_STATE", &self.state)
            .env("FAKE_MCP_LOG", &self.log)
            .env("EXPECTED_AGAIN", executable)
            .env("EXPECTED_WORKSPACE", &self.workspace)
            .current_dir(&self.workspace)
            .args(arguments);
        for (name, value) in extra_environment {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn setup_args(&self, operation: &str) -> Vec<String> {
        vec![
            "mcp".to_owned(),
            "setup".to_owned(),
            "--client".to_owned(),
            "codex".to_owned(),
            "--workspace".to_owned(),
            self.workspace.to_string_lossy().into_owned(),
            operation.to_owned(),
            "--json".to_owned(),
        ]
    }
}

fn string_args(arguments: &[String]) -> Vec<&str> {
    arguments.iter().map(String::as_str).collect()
}

#[test]
fn official_cli_apply_inspect_remove_are_exact_and_verified() {
    let fixture = Fixture::new();
    let arguments = fixture.setup_args("--apply");
    let applied = fixture.run(&string_args(&arguments), &[]);
    assert!(applied.status.success(), "{:?}", applied.stderr);
    let applied: Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied["before"], "absent");
    assert_eq!(applied["after"], "exact");
    assert_eq!(applied["changed"], true);
    assert_eq!(applied["verified"], true);

    let arguments = fixture.setup_args("--inspect");
    let inspected = fixture.run(&string_args(&arguments), &[]);
    assert!(inspected.status.success(), "{:?}", inspected.stderr);
    let inspected: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(inspected["before"], "exact");
    assert_eq!(inspected["changed"], false);

    let arguments = fixture.setup_args("--remove");
    let removed = fixture.run(&string_args(&arguments), &[]);
    assert!(removed.status.success(), "{:?}", removed.stderr);
    let removed: Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed["after"], "absent");
    assert_eq!(removed["changed"], true);

    let log = fs::read_to_string(&fixture.log).unwrap();
    assert!(log.contains("mcp add again -- "));
    assert!(log.contains(" mcp connect --workspace "));
    assert!(log.contains("mcp remove again"));
}

#[test]
fn conflicts_and_unsupported_clients_fail_without_guessing_or_leaking_output() {
    let fixture = Fixture::new();
    fs::write(&fixture.state, "conflict\n").unwrap();
    let arguments = fixture.setup_args("--apply");
    let conflict = fixture.run(&string_args(&arguments), &[]);
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("conflicts"));
    assert_eq!(fs::read_to_string(&fixture.state).unwrap(), "conflict\n");

    fs::write(&fixture.state, "absent\n").unwrap();
    let unsupported = fixture.run(&string_args(&arguments), &[("FAKE_UNSUPPORTED", "1")]);
    assert!(!unsupported.status.success());
    let diagnostic = String::from_utf8_lossy(&unsupported.stderr);
    assert!(diagnostic.contains("run manually: codex mcp add again --"));

    let failed = fixture.run(&string_args(&arguments), &[("FAKE_FAIL_ADD", "1")]);
    assert!(!failed.status.success());
    let diagnostic = String::from_utf8_lossy(&failed.stderr);
    assert!(diagnostic.contains("CLI rejected"));
    assert!(!diagnostic.contains("ghp_setup_output_must_not_leak"));
}
