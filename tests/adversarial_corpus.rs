#![cfg(feature = "hook")]

//! Deterministic, process-level checks for Again's fail-closed hook boundary.
//!
//! These cases intentionally test the public JSON adapter rather than the
//! policy module directly: a policy decision is only useful if it survives
//! executable identity, workspace, and hook parsing checks.

use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[cfg(target_os = "macos")]
use serde_json::Value;
use serde_json::json;
use tempfile::TempDir;

#[cfg(target_os = "macos")]
fn audited_host_profile_available() -> bool {
    again::executable::host_audited_apple_profile().is_ok()
}

fn again_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_again"))
}

fn hook_event(event_name: &str, tool_name: &str, cwd: &Path, command: Option<&str>) -> String {
    let mut event = json!({
        "session_id": "adversarial-session",
        "transcript_path": null,
        "cwd": cwd,
        "hook_event_name": event_name,
        "model": "test-model",
        "permission_mode": "default",
        "turn_id": "adversarial-turn",
        "tool_name": tool_name,
        "tool_use_id": "adversarial-use",
        "tool_input": {}
    });
    if let Some(command) = command {
        event["tool_input"]["command"] = json!(command);
    }
    event.to_string()
}

fn invoke_hook(root: &Path, input: &str, path: Option<&Path>) -> Output {
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("workspace");
    let state = root
        .parent()
        .unwrap_or(root)
        .join(format!(".{name}-again-state"));
    let home = root.join("home");
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

    let mut command = Command::new(again_binary());
    remove_unmodeled_ambient_inputs(&mut command);
    command
        .arg("hook")
        .arg("--experimental-unsafe-rewrite")
        .current_dir(root)
        .env("AGAIN_HOME", state)
        .env("HOME", home)
        .env_remove("AGAIN_FULL");
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Again hook");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(input.as_bytes())
        .expect("write hook input");
    child.wait_with_output().expect("wait for Again hook")
}

fn remove_unmodeled_ambient_inputs(command: &mut Command) {
    for (name, _) in env::vars_os() {
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

fn assert_no_rewrite(root: &Path, command: &str, path: Option<&Path>) {
    let input = hook_event("PreToolUse", "Bash", root, Some(command));
    let output = invoke_hook(root, &input, path);
    assert!(
        output.status.success(),
        "hook failed for {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.iter().all(u8::is_ascii_whitespace),
        "unsafe or unknown command was rewritten: {command:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(target_os = "macos")]
fn assert_rewrite(root: &Path, command: &str) {
    let input = hook_event("PreToolUse", "Bash", root, Some(command));
    let output = invoke_hook(root, &input, None);
    assert!(
        output.status.success(),
        "eligible hook failed for {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "eligible command was not rewritten: {command:?}: {error}; stdout={:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(
        value["hookSpecificOutput"]["permissionDecision"], "allow",
        "unexpected hook output for {command:?}: {value}"
    );
    assert!(
        value["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .is_some_and(|rewritten| rewritten.contains(" exec --call ")),
        "eligible command lacked opaque rewrite: {value}"
    );
}

fn assert_malformed(root: &Path, input: &str) {
    let output = invoke_hook(root, input, None);
    assert!(
        !output.status.success(),
        "malformed hook event unexpectedly succeeded: {input}"
    );
    assert!(
        output.stdout.iter().all(u8::is_ascii_whitespace),
        "malformed hook event emitted a decision: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn deterministic_adversarial_corpus_is_fail_closed() {
    let temp = TempDir::new().unwrap();
    let workspace = temp.path().join("workspace");
    fs::create_dir_all(workspace.join(".git")).unwrap();
    fs::create_dir_all(workspace.join(".again")).unwrap();
    fs::write(workspace.join("input.txt"), b"needle\nsecond\n").unwrap();
    fs::write(temp.path().join("outside.txt"), b"outside\n").unwrap();

    // Keep every generated command deterministic. The hook never executes
    // these commands, so even nonexistent operands exercise only admission.
    let mut generated = 0usize;
    for index in 0..1_024 {
        let command = match index % 16 {
            0 => format!("curl https://example.invalid/{index}"),
            1 => format!("wget https://example.invalid/{index}"),
            2 => "cat input.txt | wc -l".to_owned(),
            3 => format!("cat input.txt > output-{index}.txt"),
            4 => format!("cat input.txt; echo {index}"),
            5 => "echo $HOME".to_owned(),
            6 => "echo $(cat input.txt)".to_owned(),
            7 => "cat ../outside.txt".to_owned(),
            8 => format!("cat .again/cache-{index}"),
            9 => "cat .git/logs/HEAD".to_owned(),
            10 => format!("git push origin branch-{index}"),
            11 => format!("rm -f output-{index}.txt"),
            12 => format!("touch output-{index}.txt"),
            13 => format!("cat --unsupported-{index} input.txt"),
            14 => format!("unknown-again-command-{index} input.txt"),
            _ => format!("VAR_{index}=value cat input.txt"),
        };
        assert_no_rewrite(&workspace, &command, None);
        generated += 1;
    }

    // Explicit category sentinels make review failures diagnostic even if the
    // generated corpus is later refactored.
    for command in [
        "curl https://example.invalid/file",
        "cat input.txt | wc -l",
        "cat input.txt > result.txt",
        "echo $HOME",
        "cat ../outside.txt",
        "cat .again/cache.db",
        "cat .git/logs/HEAD",
        "git push origin main",
        "rm -f input.txt",
        "cat --bad-flag input.txt",
        "rg needle -n",
        "rg needle --no-ignore",
        "rg -E utf-8 needle",
        "grep needle -n input.txt",
        "definitely-not-an-audited-command input.txt",
    ] {
        assert_no_rewrite(&workspace, command, None);
    }

    let mut malformed = 0usize;
    for input in [
        "not json",
        &hook_event("PostToolUse", "Bash", &workspace, Some("cat input.txt")),
        &hook_event("PreToolUse", "Write", &workspace, Some("cat input.txt")),
        &hook_event("PreToolUse", "Bash", &workspace, None),
        r#"{"session_id":"s","cwd":42,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat input.txt"}}"#,
    ] {
        assert_malformed(&workspace, input);
        malformed += 1;
    }

    #[cfg(target_os = "macos")]
    let eligible = [
        "/bin/cat input.txt",
        "/usr/bin/head -n 1 input.txt",
        "/usr/bin/wc -l input.txt",
        "/bin/ls --color=never input.txt",
        "/bin/pwd -P",
    ];
    #[cfg(target_os = "macos")]
    let eligible_profile_available = audited_host_profile_available();
    #[cfg(target_os = "macos")]
    for command in eligible {
        if eligible_profile_available {
            assert_rewrite(&workspace, command);
        } else {
            assert_no_rewrite(&workspace, command, None);
        }
    }
    // Even the controlled experimental path never rewrites a bare command:
    // shell aliases/functions and startup files are outside the hook envelope.
    assert_no_rewrite(&workspace, "cat input.txt", None);
    #[cfg(not(target_os = "macos"))]
    for command in [
        "/bin/cat input.txt",
        "/usr/bin/head -n 1 input.txt",
        "/usr/bin/wc -l input.txt",
    ] {
        assert_no_rewrite(&workspace, command, None);
    }

    // A basename match is not an executable identity. This fake `cat` is
    // deliberately first on PATH and must never receive an auto-approval.
    let fake_bin = temp.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let fake_cat = fake_bin.join("cat");
    fs::write(&fake_cat, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&fake_cat, fs::Permissions::from_mode(0o755)).unwrap();
    assert_no_rewrite(
        &workspace,
        &format!("{} input.txt", fake_cat.display()),
        Some(&fake_bin),
    );

    #[cfg(target_os = "macos")]
    let eligible_count = if eligible_profile_available {
        eligible.len()
    } else {
        0
    };
    #[cfg(not(target_os = "macos"))]
    let eligible_count = 0;
    eprintln!(
        "adversarial corpus: generated={generated}, eligible={eligible_count}, malformed={malformed}"
    );
}
