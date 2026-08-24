use std::fs;
#[cfg(target_os = "macos")]
use std::io::Read;
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[cfg(target_os = "macos")]
use rusqlite::Connection;
use serde_json::Value;
use serde_json::json;
use tempfile::TempDir;

#[cfg(target_os = "macos")]
const AGAIN_SENTINEL: &str = "AGAIN_CODEX_HOOK_V1=1";

#[cfg(target_os = "macos")]
fn audited_host_profile_available() -> bool {
    again::executable::host_audited_apple_profile().is_ok()
}

fn again_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_again"))
}

fn state_dir(root: &Path) -> PathBuf {
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("workspace");
    root.parent()
        .unwrap_or(root)
        .join(format!(".{name}.again-state"))
}

fn run_process(root: &Path, executable: &Path, args: &[String], stdin: Option<&str>) -> Output {
    run_process_with_env(root, executable, args, stdin, &[])
}

fn run_process_with_env(
    root: &Path,
    executable: &Path,
    args: &[String],
    stdin: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Output {
    let state = state_dir(root);
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let mut command = Command::new(executable);
    remove_unmodeled_ambient_inputs(&mut command);
    command
        .args(args)
        .current_dir(root)
        .env("AGAIN_HOME", state)
        .env("HOME", home)
        .env_remove("AGAIN_FULL");
    for (name, value) in extra_env {
        command.env(name, value);
    }
    if let Some(stdin) = stdin {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let write_result = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        if let Err(error) = write_result {
            // The production hook intentionally may exit without reading its
            // input. Its status and exact streams below remain the test oracle;
            // a closed stdin pipe is not itself a harness failure.
            assert_eq!(
                error.kind(),
                ErrorKind::BrokenPipe,
                "failed to write child stdin: {error}"
            );
        }
        child.wait_with_output().unwrap()
    } else {
        command.output().unwrap()
    }
}

fn remove_unmodeled_ambient_inputs(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        let Some(name_text) = name.to_str() else {
            command.env_remove(name);
            continue;
        };
        if name_text.starts_with("DYLD_")
            || name_text.starts_with("LD_")
            || name_text.starts_with("Malloc")
            || name_text.starts_with("MALLOC_")
            || matches!(
                name_text,
                "ASAN_OPTIONS"
                    | "LSAN_OPTIONS"
                    | "MSAN_OPTIONS"
                    | "TSAN_OPTIONS"
                    | "UBSAN_OPTIONS"
                    | "GCONV_PATH"
                    | "LOCPATH"
                    | "NLSPATH"
                    | "PATH_LOCALE"
                    | "TERMCAP"
                    | "TERMINFO"
                    | "TERMINFO_DIRS"
                    | "TZDIR"
            )
        {
            command.env_remove(name);
        }
    }
}

fn run_again(root: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    run_process(root, &again_binary(), &args, stdin)
}

#[test]
fn rootless_namespace_probe_is_closed_and_non_qualifying() {
    let temp = TempDir::new().unwrap();
    let output = run_again(temp.path(), &["__linux-pytest-namespace-probe-v1"], None);
    assert!(
        output.stderr.is_empty(),
        "probe wrote unexpected stderr: {:?}",
        output.stderr
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "again.linux-pytest-namespace-probe.v1");
    assert_eq!(report["profile_id"], "linux-pytest-v1");
    assert_eq!(
        report["scope"],
        json!({
            "kind": "fixed_no_command_namespace_bootstrap",
            "profile_qualification": false,
            "accepts_command": false,
            "execution_authority": false,
        })
    );
    match output.status.code() {
        Some(0) => {
            assert_eq!(report["status"], "completed");
            assert!(report["refusal"].is_null());
        }
        Some(77) => {
            assert_eq!(report["status"], "unavailable");
            assert_eq!(report["refusal"]["cleanup_complete"], true);
            assert!(report["refusal"]["code"].is_string());
            assert!(report["refusal"]["stage"].is_string());
            assert!(report["refusal"]["reason"].is_string());
        }
        status => panic!("probe returned broken status {status:?}: {report}"),
    }
    assert!(!state_dir(temp.path()).exists());

    let rejected = run_again(
        temp.path(),
        &["__linux-pytest-namespace-probe-v1", "unexpected-command"],
        None,
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("unexpected argument"),
        "unexpected rejection: {:?}",
        rejected.stderr
    );
    assert!(!state_dir(temp.path()).exists());
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn rootless_namespace_probe_rejects_loader_injection_before_clone() {
    let temp = TempDir::new().unwrap();
    let output = run_process_with_env(
        temp.path(),
        &again_binary(),
        &["__linux-pytest-namespace-probe-v1".to_owned()],
        None,
        &[("LD_LIBRARY_PATH", "/dev/null/again-loader-path")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "probe wrote unexpected stderr: {:?}",
        output.stderr
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "broken");
    assert_eq!(report["refusal"]["reason"], "loader_injection_environment");
    assert_eq!(report["refusal"]["stage"], "dedicated_helper");
    assert_eq!(report["refusal"]["cleanup_complete"], true);
    assert!(!state_dir(temp.path()).exists());
}

fn run_experimental_hook(root: &Path, stdin: &str) -> Output {
    run_process_with_env(
        root,
        &again_binary(),
        &[
            "hook".to_owned(),
            "--experimental-unsafe-rewrite".to_owned(),
        ],
        Some(stdin),
        &[],
    )
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

fn compact_event(event: &str, session_id: &str, cwd: &Path) -> String {
    json!({
        "session_id": session_id,
        "transcript_path": null,
        "cwd": cwd.display().to_string(),
        "hook_event_name": event,
        "model": "gpt-test",
        "turn_id": "turn-test",
        "trigger": "auto"
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
    rewritten_argv(&run_experimental_hook(root, &input))
}

#[cfg(target_os = "macos")]
fn run_rewritten(root: &Path, argv: &[String]) -> Output {
    run_process(root, Path::new(&argv[0]), &argv[1..], None)
}

#[test]
fn automatic_hook_rewrite_is_disabled_by_default() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("input.txt"), b"alpha\n").unwrap();
    let input = pre_tool_use("session-default-off", temp.path(), "/bin/cat input.txt");
    let output = run_again(temp.path(), &["hook"], Some(&input));
    assert!(output.status.success(), "hook failed: {:?}", output.stderr);
    assert!(output.stdout.is_empty(), "disabled hook rewrote a command");
    assert!(!state_dir(temp.path()).join("again.sqlite").exists());
}

#[test]
#[cfg(unix)]
fn custom_state_inside_workspace_is_rejected_without_mutation() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join(".git")).unwrap();
    let state = temp.path().join("custom-state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(again_binary());
    remove_unmodeled_ambient_inputs(&mut command);
    let output = command
        .args(["stats", "--json"])
        .current_dir(temp.path())
        .env("AGAIN_HOME", &state)
        .env("HOME", temp.path().join("home"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be outside the active workspace")
    );
    assert!(!state.join("again.sqlite").exists());
    assert_eq!(
        fs::symlink_metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
#[cfg(target_os = "macos")]
fn default_state_is_external_and_cold_execution_does_not_mutate_workspace() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let workspace = temp.path().join("workspace");
    let system_temp = temp.path().join("system-temp");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&system_temp).unwrap();
    fs::write(workspace.join("fixture.txt"), b"fixture\n").unwrap();

    let native = Command::new("/bin/ls")
        .args(["--color=never", "-A", "."])
        .current_dir(&workspace)
        .output()
        .unwrap();
    assert!(native.status.success());

    let mut command = Command::new(again_binary());
    remove_unmodeled_ambient_inputs(&mut command);
    let first = command
        .args(["run", "--", "ls", "--color=never", "-A", "."])
        .current_dir(&workspace)
        .env_remove("AGAIN_HOME")
        .env("TMPDIR", &system_temp)
        .output()
        .unwrap();
    assert!(first.status.success(), "Again failed: {:?}", first.stderr);
    assert_eq!(first.stdout, native.stdout);
    assert!(!workspace.join(".again").exists());
    assert_eq!(fs::read_dir(&workspace).unwrap().count(), 1);

    let workspaces = system_temp.join(format!(
        "again-{}/workspaces",
        // SAFETY: `geteuid` has no preconditions.
        unsafe { libc::geteuid() }
    ));
    assert_eq!(fs::read_dir(&workspaces).unwrap().count(), 1);

    let mut command = Command::new(again_binary());
    remove_unmodeled_ambient_inputs(&mut command);
    let stats = command
        .args(["stats", "--json"])
        .current_dir(&workspace)
        .env_remove("AGAIN_HOME")
        .env("TMPDIR", &system_temp)
        .output()
        .unwrap();
    assert!(stats.status.success(), "stats failed: {:?}", stats.stderr);
    let stats: Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["executions"], 1);
}

#[test]
fn relative_configured_state_is_rejected_without_creation() {
    let temp = TempDir::new().unwrap();
    let mut command = Command::new(again_binary());
    remove_unmodeled_ambient_inputs(&mut command);
    let output = command
        .args(["stats", "--json"])
        .current_dir(temp.path())
        .env("AGAIN_HOME", "relative-state")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must be an absolute path"));
    assert!(!temp.path().join("relative-state").exists());
}

#[test]
#[cfg(target_os = "macos")]
fn explicit_run_replays_full_output_preserves_argv_and_invalidates() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    fs::write(&input, b"alpha\nbeta\n").unwrap();

    for _ in 0..2 {
        let output = run_again(temp.path(), &["run", "--", "grep", "", "input.txt"], None);
        assert!(
            output.status.success(),
            "direct run failed: {:?}",
            output.stderr
        );
        assert_eq!(output.stdout, b"alpha\nbeta\n");
        assert!(output.stderr.is_empty());
    }

    let stats = run_again(temp.path(), &["stats", "--json"], None);
    let stats: Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["executions"], 1);
    assert_eq!(stats["full_replays"], 1);
    assert_eq!(stats["compact_replays"], 0);

    fs::write(&input, b"changed\n").unwrap();
    let changed = run_again(temp.path(), &["run", "--", "grep", "", "input.txt"], None);
    assert!(changed.status.success());
    assert_eq!(changed.stdout, b"changed\n");

    let rejected = run_again(temp.path(), &["run", "--", "cat", "", "input.txt"], None);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("UNSUPPORTED_PATH"),
        "unexpected rejection: {:?}",
        rejected.stderr
    );
}

#[test]
#[cfg(target_os = "macos")]
fn explicit_reference_is_compact_verified_and_never_executes_on_a_miss() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let input = vec![b'x'; 64 * 1024];
    fs::write(temp.path().join("input.txt"), &input).unwrap();

    let cold_reference = run_again(temp.path(), &["reference", "--", "cat", "input.txt"], None);
    assert!(!cold_reference.status.success());
    assert!(cold_reference.stdout.is_empty());
    assert!(String::from_utf8_lossy(&cold_reference.stderr).contains("no command was executed"));

    let cold = run_again(temp.path(), &["run", "--", "cat", "input.txt"], None);
    assert!(cold.status.success(), "cold run failed: {:?}", cold.stderr);
    assert_eq!(cold.stdout, input);

    let reference = run_again(temp.path(), &["reference", "--", "cat", "input.txt"], None);
    assert!(
        reference.status.success(),
        "reference failed: {:?}",
        reference.stderr
    );
    assert!(reference.stderr.is_empty());
    assert!(reference.stdout.len() < 512);
    let reference_json: Value = serde_json::from_slice(&reference.stdout).unwrap();
    assert_eq!(reference_json["schema"], "again.reference.v1");
    assert_eq!(reference_json["exit_code"], 0);
    assert_eq!(reference_json["stdout"]["bytes"], input.len() as u64);
    assert_eq!(reference_json["stderr"]["bytes"], 0);
    assert_eq!(
        reference_json["stdout"]["blake3"],
        blake3::hash(&input).to_hex().as_str()
    );
    let result_id = reference_json["result_id"].as_str().unwrap();

    let shown = run_again(temp.path(), &["show", result_id], None);
    assert!(shown.status.success(), "show failed: {:?}", shown.stderr);
    assert_eq!(shown.stdout, input);

    fs::write(temp.path().join("input.txt"), b"changed\n").unwrap();
    let stale_reference = run_again(temp.path(), &["reference", "--", "cat", "input.txt"], None);
    assert!(!stale_reference.status.success());
    assert!(stale_reference.stdout.is_empty());
    assert!(String::from_utf8_lossy(&stale_reference.stderr).contains("no command was executed"));

    let stats = run_again(temp.path(), &["stats", "--json"], None);
    assert!(stats.status.success(), "stats failed: {:?}", stats.stderr);
    let stats: Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["executions"], 1);
    assert_eq!(stats["full_replays"], 0);
    assert_eq!(stats["compact_replays"], 1);
    assert_eq!(stats["bypasses"], 2);
    assert!(stats["duplicate_bytes_omitted"].as_u64().unwrap() > 60 * 1024);
}

#[test]
#[cfg(target_os = "macos")]
fn explicit_reference_quarantines_corrupt_blob_bytes_without_execution() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let input = vec![b'x'; 64 * 1024];
    fs::write(temp.path().join("input.txt"), &input).unwrap();

    let cold = run_again(temp.path(), &["run", "--", "cat", "input.txt"], None);
    assert!(cold.status.success(), "cold run failed: {:?}", cold.stderr);
    assert_eq!(cold.stdout, input);

    let database = state_dir(temp.path()).join("again.sqlite");
    let connection = Connection::open(&database).unwrap();
    let stdout_digest: String = connection
        .query_row(
            "SELECT stdout_digest FROM results WHERE quarantined = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let blob = state_dir(temp.path())
        .join("blobs")
        .join(&stdout_digest[..2])
        .join(&stdout_digest[2..]);
    fs::write(blob, b"corrupt").unwrap();

    let reference = run_again(temp.path(), &["reference", "--", "cat", "input.txt"], None);
    assert!(!reference.status.success());
    assert!(reference.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&reference.stderr).contains("invalid blob and was quarantined"),
        "unexpected stderr: {:?}",
        reference.stderr
    );

    let connection = Connection::open(database).unwrap();
    let (quarantined, reason): (bool, String) = connection
        .query_row(
            "SELECT quarantined, quarantine_reason FROM results LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(quarantined);
    assert_eq!(reason, "stdout_blob_invalid");

    let stats = run_again(temp.path(), &["stats", "--json"], None);
    assert!(stats.status.success(), "stats failed: {:?}", stats.stderr);
    let stats: Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["executions"], 1);
    assert_eq!(stats["compact_replays"], 0);
    assert_eq!(stats["quarantines"], 1);
}

#[test]
#[cfg(target_os = "macos")]
fn cached_output_preserves_broken_pipe_status_and_is_not_counted_as_delivered() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let input = vec![b'x'; 256 * 1024];
    fs::write(temp.path().join("large.txt"), &input).unwrap();

    let warmup = run_again(temp.path(), &["run", "--", "cat", "large.txt"], None);
    assert!(
        warmup.status.success(),
        "warmup failed: {:?}",
        warmup.stderr
    );
    assert_eq!(warmup.stdout, input);

    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let mut command = Command::new(again_binary());
    remove_unmodeled_ambient_inputs(&mut command);
    let mut child = command
        .args(["run", "--", "cat", "large.txt"])
        .current_dir(temp.path())
        .env("AGAIN_HOME", state_dir(temp.path()))
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut first_byte = [0_u8; 1];
    stdout.read_exact(&mut first_byte).unwrap();
    drop(stdout);
    assert_eq!(child.wait().unwrap().code(), Some(141));

    let stats = run_again(temp.path(), &["stats", "--json"], None);
    let stats: Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["executions"], 1);
    assert_eq!(stats["full_replays"], 0);
}

#[test]
#[cfg(target_os = "macos")]
fn resource_limit_profile_partitions_cache_hits() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("input.txt"), b"bounded\n").unwrap();
    let normal = run_again(temp.path(), &["run", "--", "cat", "input.txt"], None);
    assert!(
        normal.status.success(),
        "normal run failed: {:?}",
        normal.stderr
    );

    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let script = "ulimit -n 128; exec \"$0\" run -- cat input.txt";
    for _ in 0..2 {
        let mut command = Command::new("/bin/sh");
        remove_unmodeled_ambient_inputs(&mut command);
        let limited = command
            .args(["-c", script])
            .arg(again_binary())
            .current_dir(temp.path())
            .env("AGAIN_HOME", state_dir(temp.path()))
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            limited.status.success(),
            "limited run failed: {:?}",
            limited.stderr
        );
        assert_eq!(limited.stdout, b"bounded\n");
    }

    let stats = run_again(temp.path(), &["stats", "--json"], None);
    let stats: Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["executions"], 2);
    assert_eq!(stats["full_replays"], 1);
}

#[test]
#[cfg(target_os = "macos")]
fn codex_hook_rewrites_executes_replays_full_and_invalidates_on_input_change() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let workspace = temp.path();
    let input = workspace.join("input.txt");
    fs::write(&input, b"alpha\n").unwrap();

    let first_argv = hook_rewrite(workspace, "session-one", "/bin/cat input.txt")
        .expect("eligible cat should be rewritten");
    let first = run_rewritten(workspace, &first_argv);
    assert!(first.status.success(), "exec failed: {:?}", first.stderr);
    assert_eq!(first.stdout, b"alpha\n");

    let second_argv = hook_rewrite(workspace, "session-one", "/bin/cat input.txt").unwrap();
    let second = run_rewritten(workspace, &second_argv);
    assert!(
        second.status.success(),
        "repeat failed: {:?}",
        second.stderr
    );
    assert_eq!(second.stdout, b"alpha\n");
    assert!(!String::from_utf8_lossy(&second.stdout).contains("duplicate bytes omitted"));

    let explained = run_again(workspace, &["explain", "--json"], None);
    assert!(
        explained.status.success(),
        "explain failed: {:?}",
        explained.stderr
    );
    let explained: Value = serde_json::from_slice(&explained.stdout).unwrap();
    let result_id = explained["result_id"].as_str().unwrap().to_owned();

    let shown = run_again(workspace, &["show", &result_id], None);
    assert!(shown.status.success(), "show failed: {:?}", shown.stderr);
    assert_eq!(shown.stdout, b"alpha\n");

    let compact = run_again(
        workspace,
        &["hook"],
        Some(&compact_event("PreCompact", "session-one", workspace)),
    );
    assert!(
        compact.status.success(),
        "compact hook failed: {:?}",
        compact.stderr
    );
    assert!(compact.stdout.is_empty());
    let after_compact_argv = hook_rewrite(workspace, "session-one", "/bin/cat input.txt").unwrap();
    let after_compact = run_rewritten(workspace, &after_compact_argv);
    assert!(after_compact.status.success());
    assert_eq!(after_compact.stdout, b"alpha\n");
    assert!(!String::from_utf8_lossy(&after_compact.stdout).contains("duplicate bytes omitted"));

    fs::write(&input, b"beta\n").unwrap();
    let changed_argv = hook_rewrite(workspace, "session-one", "/bin/cat input.txt").unwrap();
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
        let input = pre_tool_use("session-unsafe", temp.path(), command);
        let output = run_experimental_hook(temp.path(), &input);
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
fn production_hook_is_a_true_noop_even_for_unknown_input() {
    let temp = TempDir::new().unwrap();
    let output = run_again(temp.path(), &["hook"], Some("not valid JSON\n"));
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!state_dir(temp.path()).exists());

    let malformed_experimental = run_experimental_hook(temp.path(), "not valid JSON\n");
    assert!(!malformed_experimental.status.success());
    assert!(
        String::from_utf8_lossy(&malformed_experimental.stderr).contains("parse Codex hook JSON")
    );
}

#[test]
fn production_compaction_hooks_are_fresh_state_noops_for_both_events() {
    let temp = TempDir::new().unwrap();
    for event in ["PreCompact", "PostCompact"] {
        let output = run_again(
            temp.path(),
            &["hook"],
            Some(&compact_event(event, "session-fresh", temp.path())),
        );
        assert!(
            output.status.success(),
            "{event} failed: {:?}",
            output.stderr
        );
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert!(!state_dir(temp.path()).exists());
    }
}

#[test]
#[cfg(target_os = "macos")]
fn eligible_nonzero_reads_are_executed_again_and_never_cached() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("input.txt"), b"alpha\n").unwrap();
    let command = "/usr/bin/grep needle input.txt";

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
#[cfg(target_os = "macos")]
fn tampered_result_metadata_is_quarantined_and_never_served() {
    if !audited_host_profile_available() {
        return;
    }
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("input.txt"), b"trusted output\n").unwrap();
    let first_argv = hook_rewrite(temp.path(), "session-tamper", "/bin/cat input.txt").unwrap();
    let first = run_rewritten(temp.path(), &first_argv);
    assert!(first.status.success());
    assert_eq!(first.stdout, b"trusted output\n");

    let database = state_dir(temp.path()).join("again.sqlite");
    let connection = Connection::open(database).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE results SET policy_version = 'tampered-policy' WHERE quarantined = 0",
                [],
            )
            .unwrap(),
        1
    );
    drop(connection);

    let repeat_argv = hook_rewrite(temp.path(), "session-tamper", "/bin/cat input.txt").unwrap();
    let repeat = run_rewritten(temp.path(), &repeat_argv);
    assert!(!repeat.status.success());
    assert!(repeat.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&repeat.stderr).contains("failed metadata validation"),
        "unexpected stderr: {:?}",
        repeat.stderr
    );

    let connection = Connection::open(state_dir(temp.path()).join("again.sqlite")).unwrap();
    let quarantined: bool = connection
        .query_row("SELECT quarantined FROM results LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(quarantined);
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
    assert!(stdout.contains("name: again"));
    assert!(stdout.contains("again run --"));
    assert!(!project.join(".agents/skills/again/SKILL.md").exists());
    assert!(
        !temp
            .path()
            .join("home/.agents/skills/again/SKILL.md")
            .exists()
    );
    assert!(!project.join(".codex/hooks.json").exists());
    assert!(!temp.path().join("home/.codex/hooks.json").exists());
    assert!(!state_dir(&project).join("again.sqlite").exists());
}

#[test]
fn personal_codex_skill_setup_is_idempotent_and_reversible() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("project");
    fs::create_dir(&project).unwrap();
    let skill = project.join("home/.agents/skills/again/SKILL.md");

    let first = run_again(&project, &["setup", "--codex"], None);
    assert!(first.status.success(), "setup failed: {:?}", first.stderr);
    assert!(String::from_utf8_lossy(&first.stdout).contains("Installed Again's Codex skill"));
    // run_process scopes HOME beneath the current root (`project/home`).
    assert!(skill.is_file());

    let second = run_again(&project, &["setup", "--codex"], None);
    assert!(second.status.success());
    assert!(String::from_utf8_lossy(&second.stdout).contains("already current"));

    let removed = run_again(&project, &["setup", "--codex", "--remove"], None);
    assert!(
        removed.status.success(),
        "remove failed: {:?}",
        removed.stderr
    );
    assert!(!skill.exists());
}
