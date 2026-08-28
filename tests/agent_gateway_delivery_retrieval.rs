use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use again::store::Store;
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

fn call_full_result(session: &mut Session, suffix: &str) -> Value {
    session.request(
        &format!("call-{suffix}"),
        "tools/call",
        json!({"name": "repo.read", "arguments": {"path": "README.md"}}),
    )["result"]
        .clone()
}

#[test]
fn production_binary_unknown_recipient_has_no_delivery_or_retrieval_authority() {
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

    let full = call_full_result(&mut session, "full");
    assert_eq!(full["content"][0]["text"], "delivery fixture\n");

    let acknowledgement = session.request("ack", "again/delivery/ack", json!({}));
    assert_eq!(
        acknowledgement["error"]["data"]["reason"],
        "unsupported_recipient_authority"
    );
    let retrieval = session.request("retrieve", "again/result/retrieve", json!({}));
    assert_eq!(
        retrieval["error"]["data"]["reason"],
        "unsupported_recipient_authority"
    );
    session.send(json!({
        "jsonrpc": "2.0",
        "method": "notifications/again/context-compacted",
        "params": {"compactionGeneration": 1}
    }));
    let after_compaction = call_full_result(&mut session, "after-compaction");
    assert_eq!(after_compaction["content"], full["content"]);

    session.close();
    let stats = Store::open(fixture.path().join("state"))
        .unwrap()
        .gateway_stats()
        .unwrap();
    assert_eq!(stats.compact_deliveries, 0);
    assert_eq!(stats.delivery_confirmed_bytes_omitted, 0);
    assert_eq!(stats.estimated_tokens_avoided, 0);
    assert_eq!(stats.confirmed_tokens_avoided, 0);
}
