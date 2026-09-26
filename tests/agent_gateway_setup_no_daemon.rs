#![cfg(all(unix, not(feature = "daemon")))]

use std::fs;
use std::process::Command;

#[test]
fn setup_refuses_to_install_a_connect_command_absent_from_this_binary() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("home");
    let workspace = temporary.path().join("workspace");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(workspace.join(".git")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_again"))
        .env_clear()
        .env("HOME", &home)
        .args([
            "mcp",
            "setup",
            "--client",
            "codex",
            "--workspace",
            workspace.to_str().unwrap(),
            "--apply",
            "--with-skill",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--features daemon"));
    assert!(!home.join(".agents/skills/again").exists());
}
