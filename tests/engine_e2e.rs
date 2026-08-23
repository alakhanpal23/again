use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[cfg(target_os = "macos")]
use serde_json::Value;
use serde_json::json;
use tempfile::TempDir;

const AGAIN_SENTINEL: &str = "AGAIN_CODEX_HOOK_V1=1";

fn again_binary() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_again")
        .map(PathBuf::from)
        .expect("Cargo must provide the compiled again binary to integration tests")
}

fn run_process(root: &Path, executable: &Path, args: &[String], stdin: Option<&str>) -> Output {
    let state = root.join(".again-state");
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(root)
        .env("AGAIN_HOME", state)
        .env("HOME", home)
        .env_remove("AGAIN_FULL");
    if let Some(stdin) = stdin {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    } else {
        command.output().unwrap()
    }
}

fn run_again(root: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    run_process(root, &again_binary(), &args, stdin)
}

fn pre_tool_use(session_id: &str, cwd: &Path, command: &str) -> String {
    json!({
        "session_id": session_id,
        "transcript_path": cwd.join("transcript.jsonl").display().to_string(),
        "cwd": cwd.display().to_string(),
        "hook_event_name": "PreToolUse",
        "model": "gpt-test",
        "permission_mode": "default",
        "turn_id": "turn-test",
        "tool_name": "Bash",
        "tool_use_id": "call-test",
        "tool_input": {"command": command}
    })
    .to_string()
}

/// Return the shell-free argv encoded by the official hook rewrite.
#[cfg(target_os = "macos")]
fn rewritten_argv(output: &Output) -> Option<Vec<String>> {
    assert!(output.status.success(), "hook failed: {:?}", output.stderr);
    if output.stdout.is_empty() {
        return None;
    }
    let encoded: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(encoded["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(encoded["hookSpecificOutput"]["permissionDecision"], "allow");
    let command = encoded["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert!(!command.contains(AGAIN_SENTINEL));
    Some(shell_words::split(command).unwrap())
}

#[cfg(target_os = "macos")]
fn hook_rewrite(root: &Path, session_id: &str, command: &str) -> Option<Vec<String>> {
    let input = pre_tool_use(session_id, root, command);
    rewritten_argv(&run_again(root, &["hook"], Some(&input)))
}

#[cfg(target_os = "macos")]
fn run_rewritten(root: &Path, argv: &[String]) -> Output {
    run_process(root, Path::new(&argv[0]), &argv[1..], None)
}

#[cfg(target_os = "macos")]
fn result_id_from_compact(stdout: &[u8]) -> String {
    let text = String::from_utf8_lossy(stdout);
    let prefix = "[again: exact repeat of result ";
    let start = text.find(prefix).expect("expected compact Again reference") + prefix.len();
    text[start..]
        .split(';')
        .next()
        .expect("compact reference result id")
        .to_owned()
}

#[test]
#[cfg(target_os = "macos")]
fn codex_hook_rewrites_executes_compacts_recovers_and_invalidates_on_input_change() {
    let temp = TempDir::new().unwrap();
    let workspace = temp.path();
    let input = workspace.join("input.txt");
    fs::write(&input, b"alpha\n").unwrap();

    let first_argv = hook_rewrite(workspace, "session-one", "cat input.txt")
        .expect("eligible cat should be rewritten");
    let first = run_rewritten(workspace, &first_argv);
    assert!(first.status.success(), "exec failed: {:?}", first.stderr);
    assert_eq!(first.stdout, b"alpha\n");

    let second_argv = hook_rewrite(workspace, "session-one", "cat input.txt").unwrap();
    let second = run_rewritten(workspace, &second_argv);
    assert!(
        second.status.success(),
        "repeat failed: {:?}",
        second.stderr
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("duplicate bytes omitted"));
    let result_id = result_id_from_compact(&second.stdout);

    let shown = run_again(workspace, &["show", &result_id], None);
    assert!(shown.status.success(), "show failed: {:?}", shown.stderr);
    assert_eq!(shown.stdout, b"alpha\n");

    fs::write(&input, b"beta\n").unwrap();
    let changed_argv = hook_rewrite(workspace, "session-one", "cat input.txt").unwrap();
    let changed = run_rewritten(workspace, &changed_argv);
    assert!(
        changed.status.success(),
        "changed input failed: {:?}",
        changed.stderr
    );
    assert_eq!(changed.stdout, b"beta\n");
    assert!(!String::from_utf8_lossy(&changed.stdout).contains("duplicate bytes omitted"));
}

#[test]
fn unsafe_commands_are_left_untouched_by_the_hook() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("input.txt"), b"alpha\n").unwrap();
    for command in [
        "curl https://example.com",
        "cat input.txt | wc -l",
        "touch created-by-test.txt",
    ] {
        let output = run_again(
            temp.path(),
            &["hook"],
            Some(&pre_tool_use("session-unsafe", temp.path(), command)),
        );
        assert!(output.status.success(), "hook failed for {command}");
        assert!(output.stdout.is_empty(), "unexpected rewrite for {command}");
        assert!(
            output.stderr.is_empty(),
            "unexpected hook stderr for {command}"
        );
    }
    assert!(!temp.path().join("created-by-test.txt").exists());
}

#[test]
fn malformed_hook_json_fails_instead_of_rewriting() {
    let temp = TempDir::new().unwrap();
    let output = run_again(temp.path(), &["hook"], Some("not valid JSON\n"));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("parse Codex PreToolUse JSON"));
}

#[test]
#[cfg(target_os = "macos")]
fn eligible_nonzero_reads_are_executed_again_and_never_cached() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("input.txt"), b"alpha\n").unwrap();
    let command = "grep needle input.txt";

    for _ in 0..2 {
        let rewritten = hook_rewrite(temp.path(), "session-nonzero", command)
            .expect("eligible grep should be rewritten");
        let output = run_rewritten(temp.path(), &rewritten);
        assert_eq!(output.status.code(), Some(1));
    }

    let stats = run_again(temp.path(), &["stats", "--json"], None);
    assert!(stats.status.success(), "stats failed: {:?}", stats.stderr);
    let stats: Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["executions"], 0);
    assert_eq!(stats["compact_replays"], 0);
    assert_eq!(stats["bypasses"], 2);
}

#[test]
fn project_setup_dry_run_does_not_touch_global_or_project_state() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let output = run_again(
        &project,
        &["setup", "--project", "--codex", "--dry-run"],
        None,
    );
    assert!(output.status.success(), "setup failed: {:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# dry run:"));
    assert!(stdout.contains(AGAIN_SENTINEL));
    assert!(!project.join(".codex/hooks.json").exists());
    assert!(!temp.path().join("home/.codex/hooks.json").exists());
    assert!(!temp.path().join(".again-state/again.sqlite").exists());
}
