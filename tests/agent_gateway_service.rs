#![cfg(all(feature = "daemon", unix))]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use again::agent_gateway_service::{
    GatewayDaemonV1, GatewayServiceError, connect_mcp_v1, daemon_status_v1, stop_daemon_v1,
};
use again::mcp_gateway::AuthorizationScopeId;
use serde_json::{Value, json};
use tempfile::TempDir;

fn workspace() -> TempDir {
    let workspace = TempDir::new().unwrap();
    fs::write(workspace.path().join("README.md"), b"daemon fixture\n").unwrap();
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(workspace.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap()
            .success()
    );
    workspace
}

fn daemon(workspace: &Path) -> GatewayDaemonV1 {
    GatewayDaemonV1::bind(
        workspace,
        AuthorizationScopeId::new("daemon-test-scope").unwrap(),
    )
    .unwrap()
}

fn start_daemon(workspace: &Path) -> (std::path::PathBuf, thread::JoinHandle<()>) {
    let daemon = daemon(workspace);
    let socket = daemon.socket_path().to_owned();
    let handle = thread::spawn(move || daemon.serve().unwrap());
    (socket, handle)
}

fn request(writer: &mut impl Write, id: &str, method: &str, params: Value) {
    serde_json::to_writer(
        &mut *writer,
        &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
    )
    .unwrap();
    writer.write_all(b"\n").unwrap();
    writer.flush().unwrap();
}

fn response(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    assert!(reader.read_line(&mut line).unwrap() > 0);
    serde_json::from_str(&line).unwrap()
}

fn cli(workspace: &Path, fixture: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_again"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", fixture.join("home"))
        .env("AGAIN_HOME", fixture.join("state"))
        .current_dir(workspace);
    command
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("child did not exit within the bounded deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn socket_is_private_singleton_and_drop_never_unlinks_a_replacement() {
    let workspace = workspace();
    let first_daemon = daemon(workspace.path());
    let socket = first_daemon.socket_path().to_owned();
    let parent = fs::symlink_metadata(socket.parent().unwrap()).unwrap();
    let socket_metadata = fs::symlink_metadata(&socket).unwrap();
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);
    // SAFETY: geteuid has no preconditions and mutates no process state.
    assert_eq!(parent.uid(), unsafe { libc::geteuid() });
    assert_eq!(socket_metadata.permissions().mode() & 0o777, 0o600);
    assert!(matches!(
        GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("other-scope").unwrap()
        ),
        Err(GatewayServiceError::SocketExists)
    ));

    let original = socket.with_extension("original-test-socket");
    fs::rename(&socket, &original).unwrap();
    fs::write(&socket, b"replacement owned by test").unwrap();
    drop(first_daemon);
    assert_eq!(fs::read(&socket).unwrap(), b"replacement owned by test");
    fs::remove_file(&socket).unwrap();
    fs::remove_file(original).unwrap();

    // Even an attacker who learned the prior socket cannot pre-create the
    // next random name. The known hostile path is neither used nor removed.
    fs::write(&socket, b"hostile old socket path").unwrap();
    let replacement = daemon(workspace.path());
    assert_ne!(replacement.socket_path(), socket);
    assert_eq!(fs::read(&socket).unwrap(), b"hostile old socket path");
    drop(replacement);
    fs::remove_file(&socket).unwrap();
}

#[test]
fn same_uid_status_and_stop_are_workspace_bound_and_clean() {
    let workspace = workspace();
    let (socket, server) = start_daemon(workspace.path());
    let mut malformed = UnixStream::connect(&socket).unwrap();
    malformed.write_all(&[0_u8; 57]).unwrap();
    malformed.shutdown(std::net::Shutdown::Write).unwrap();
    malformed
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut refused = Vec::new();
    let _ = malformed.read_to_end(&mut refused);
    let status = daemon_status_v1(workspace.path()).unwrap();
    assert_eq!(status.workspace_digest().len(), 64);
    assert!(status.active_connections() <= 1);
    stop_daemon_v1(workspace.path()).unwrap();
    server.join().unwrap();
    assert!(!socket.exists());
}

#[test]
fn daemon_drains_a_live_gateway_session_before_shutdown() {
    let workspace = workspace();
    let (socket, server) = start_daemon(workspace.path());
    let mut stream = connect_mcp_v1(workspace.path()).unwrap();
    let reader_stream = stream.try_clone().unwrap();
    reader_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(reader_stream);

    request(
        &mut stream,
        "init",
        "initialize",
        json!({
            "protocolVersion":"2025-06-18",
            "capabilities":{},
            "clientInfo":{"name":"daemon-test","version":"1"}
        }),
    );
    assert_eq!(response(&mut reader)["id"], "init");
    request(&mut stream, "tools", "tools/list", json!({}));
    let tools = response(&mut reader);
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "repo.read")
    );
    request(
        &mut stream,
        "read",
        "tools/call",
        json!({"name":"repo.read","arguments":{"path":"README.md"}}),
    );
    assert_eq!(
        response(&mut reader)["result"]["content"][0]["text"],
        "daemon fixture\n"
    );

    stop_daemon_v1(workspace.path()).unwrap();
    assert!(matches!(
        connect_mcp_v1(workspace.path()),
        Err(GatewayServiceError::Draining)
    ));
    request(&mut stream, "draining-tools", "tools/list", json!({}));
    assert_eq!(response(&mut reader)["id"], "draining-tools");
    stream.shutdown(std::net::Shutdown::Both).unwrap();
    drop(reader);
    drop(stream);
    server.join().unwrap();
    assert!(!socket.exists());
}

#[test]
fn production_binary_daemon_and_stdio_proxy_complete_a_real_mcp_session() {
    let workspace = workspace();
    let fixture = TempDir::new().unwrap();
    fs::create_dir(fixture.path().join("home")).unwrap();
    let mut daemon = cli(workspace.path(), fixture.path());
    let mut daemon = daemon
        .args([
            "mcp",
            "daemon",
            "serve",
            "--workspace",
            workspace.path().to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        let output = cli(workspace.path(), fixture.path())
            .args([
                "mcp",
                "daemon",
                "status",
                "--workspace",
                workspace.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        if output.status.success() {
            break serde_json::from_slice::<Value>(&output.stdout).unwrap();
        }
        assert!(Instant::now() < deadline, "daemon did not become ready");
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status["status"], "ready");
    assert!(matches!(
        status["peerAuthentication"].as_str(),
        Some("getpeereid_euid" | "so_peercred_euid")
    ));

    let mut proxy = cli(workspace.path(), fixture.path());
    let mut proxy = proxy
        .args([
            "mcp",
            "connect",
            "--workspace",
            workspace.path().to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut proxy_input = proxy.stdin.take().unwrap();
    let mut proxy_output = BufReader::new(proxy.stdout.take().unwrap());
    request(
        &mut proxy_input,
        "init",
        "initialize",
        json!({
            "protocolVersion":"2025-06-18",
            "capabilities":{},
            "clientInfo":{"name":"binary-daemon-test","version":"1"}
        }),
    );
    assert_eq!(response(&mut proxy_output)["id"], "init");
    request(
        &mut proxy_input,
        "read",
        "tools/call",
        json!({"name":"repo.read","arguments":{"path":"README.md"}}),
    );
    assert_eq!(
        response(&mut proxy_output)["result"]["content"][0]["text"],
        "daemon fixture\n"
    );

    let stopped = cli(workspace.path(), fixture.path())
        .args([
            "mcp",
            "daemon",
            "stop",
            "--workspace",
            workspace.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(stopped.status.success(), "{:?}", stopped.stderr);
    assert_eq!(
        serde_json::from_slice::<Value>(&stopped.stdout).unwrap()["status"],
        "stopping"
    );
    drop(proxy_input);
    assert!(wait_for_exit(&mut proxy).success());
    assert!(wait_for_exit(&mut daemon).success());
    let mut daemon_stderr = String::new();
    daemon
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut daemon_stderr)
        .unwrap();
    assert_eq!(
        daemon_stderr,
        "Again MCP daemon is experimental; socket peers are restricted to the current uid.\n"
    );
}

#[test]
fn production_daemon_reclaims_only_lock_proven_crash_stale_socket() {
    let workspace = workspace();
    let fixture = TempDir::new().unwrap();
    fs::create_dir(fixture.path().join("home")).unwrap();
    let spawn = || {
        cli(workspace.path(), fixture.path())
            .args([
                "mcp",
                "daemon",
                "serve",
                "--workspace",
                workspace.path().to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let ready = || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = cli(workspace.path(), fixture.path())
                .args([
                    "mcp",
                    "daemon",
                    "status",
                    "--workspace",
                    workspace.path().to_str().unwrap(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            if status.success() {
                break;
            }
            assert!(Instant::now() < deadline, "daemon did not become ready");
            thread::sleep(Duration::from_millis(20));
        }
    };

    let mut crashed = spawn();
    ready();
    crashed.kill().unwrap();
    assert!(!crashed.wait().unwrap().success());

    let mut replacement = spawn();
    ready();
    assert!(
        cli(workspace.path(), fixture.path())
            .args([
                "mcp",
                "daemon",
                "stop",
                "--workspace",
                workspace.path().to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(wait_for_exit(&mut replacement).success());
}

#[test]
fn twenty_simultaneous_connectors_elect_one_automatic_daemon() {
    let workspace = workspace();
    let fixture = TempDir::new().unwrap();
    fs::create_dir(fixture.path().join("home")).unwrap();
    let workspace_path = workspace.path().to_owned();
    let fixture_path = fixture.path().to_owned();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(21));
    let mut connectors = Vec::new();
    for _ in 0..20 {
        let workspace_path = workspace_path.clone();
        let fixture_path = fixture_path.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        connectors.push(thread::spawn(move || {
            barrier.wait();
            cli(&workspace_path, &fixture_path)
                .args([
                    "mcp",
                    "connect",
                    "--workspace",
                    workspace_path.to_str().unwrap(),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .unwrap()
        }));
    }
    barrier.wait();
    for connector in connectors {
        let output = connector.join().unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
    }

    let status = cli(&workspace_path, &fixture_path)
        .args([
            "mcp",
            "daemon",
            "status",
            "--workspace",
            workspace_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(status.status.success(), "{:?}", status.stderr);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["status"], "ready");
    assert_eq!(status["protocolVersion"], "2025-06-18");
    assert_eq!(status["idleTimeoutSeconds"], 600);

    assert!(
        cli(&workspace_path, &fixture_path)
            .args([
                "mcp",
                "daemon",
                "stop",
                "--workspace",
                workspace_path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}
