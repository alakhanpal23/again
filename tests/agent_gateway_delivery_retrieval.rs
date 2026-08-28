use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

struct Session {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}

impl Session {
    fn start(workspace: &std::path::Path, root: &std::path::Path) -> Self {
        let home = root.join("home");
        let state = root.join("state");
        let temporary = root.join("tmp");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&temporary).unwrap();
        for directory in [&home, &state, &temporary] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_again"))
            .args([
                "mcp",
                "serve",
                "--workspace",
                workspace.to_str().unwrap(),
                "--authorization-scope",
                "delivery-retrieval-e2e",
            ])
            .current_dir(workspace)
            .env_clear()
            .env("HOME", &home)
            .env("AGAIN_HOME", &state)
            .env("TMPDIR", &temporary)
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input: Some(input),
            output,
        }
    }

    fn send(&mut self, value: Value) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &value).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        if self.output.read_line(&mut line).unwrap() == 0 {
            let status = self.child.wait().unwrap();
            let mut stderr = String::new();
            self.child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("MCP server closed early ({status}): {stderr}");
        }
        serde_json::from_str(&line).unwrap()
    }

    fn request(&mut self, id: &str, method: &str, params: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        let response = self.read();
        assert_eq!(response["id"], id);
        response
    }

    fn close(mut self) {
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let mut stderr = String::new();
                self.child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                assert!(status.success(), "server failed: {stderr}");
                assert_eq!(
                    stderr,
                    "Again MCP gateway is experimental; only bounded built-in repository reads are reuse-eligible.\n"
                );
                return;
            }
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                let _ = self.child.wait();
                panic!("MCP server did not exit after EOF");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn initialize(session: &mut Session) {
    let response = session.request(
        "initialize",
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "experimental": {
                    "again": {"deliveryReceipts": {"schemaVersion": 2}}
                }
            },
            "clientInfo": {"name": "again-e2e", "version": "1"}
        }),
    );
    assert_eq!(
        response["result"]["capabilities"]["experimental"]["again"]["deliveryReceipts"]["schemaVersion"],
        2
    );
    session.send(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));
}

fn call_and_acknowledge(session: &mut Session, suffix: &str) -> (Value, Value) {
    let response = session.request(
        &format!("call-{suffix}"),
        "tools/call",
        json!({"name": "repo.read", "arguments": {"path": "README.md"}}),
    );
    let challenge = session.read();
    assert_eq!(
        challenge["method"],
        "notifications/again/delivery-challenge"
    );
    let acknowledgement = session.request(
        &format!("ack-{suffix}"),
        "again/delivery/ack",
        challenge["params"]["challenge"].clone(),
    );
    assert_eq!(acknowledgement["result"]["status"], "confirmed");
    (
        response["result"].clone(),
        acknowledgement["result"]["retrievalGrant"].clone(),
    )
}

#[test]
fn production_binary_retrieval_is_response_bound_one_use_and_compaction_safe() {
    let fixture = TempDir::new().unwrap();
    let workspace = fixture.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("README.md"), b"delivery fixture\n").unwrap();
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

    let mut session = Session::start(&workspace, fixture.path());
    initialize(&mut session);

    let (full, grant) = call_and_acknowledge(&mut session, "one-use");
    let retrieved = session.request("retrieve", "again/result/retrieve", grant.clone());
    assert_eq!(retrieved["result"]["schemaVersion"], 2);
    assert_eq!(retrieved["result"]["presentation"], "fullToolResult");
    assert_eq!(
        retrieved["result"]["gatewayResultId"],
        full["_meta"]["again"]["resultId"]
    );
    assert_eq!(
        retrieved["result"]["toolResult"]["content"],
        full["content"]
    );
    assert_eq!(
        retrieved["result"]["toolResult"]["structuredContent"],
        full["structuredContent"]
    );
    let replay = session.request("replay", "again/result/retrieve", grant);
    assert_eq!(
        replay["error"]["data"]["reason"],
        "acknowledgement_replayed"
    );

    let (_, compacted_grant) = call_and_acknowledge(&mut session, "compaction");
    session.send(json!({
        "jsonrpc": "2.0",
        "method": "notifications/again/context-compacted",
        "params": {"compactionGeneration": 1}
    }));
    let compacted = session.request("compacted", "again/result/retrieve", compacted_grant);
    assert!(
        matches!(
            compacted["error"]["data"]["reason"].as_str(),
            Some("delivery_authority_retired" | "invalid_delivery_binding")
        ),
        "{compacted}"
    );

    session.close();
}
