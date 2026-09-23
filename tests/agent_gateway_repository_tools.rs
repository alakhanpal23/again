use std::fs;
use std::path::Path;
use std::process::Command;

use again::agent_gateway_runtime::ExperimentalMcpGatewayV1;
use again::mcp_gateway::{
    AuthorizationScopeId, EphemeralSecrets, GatewayRequestContext, LogicalCallId, McpGateway,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn process(gateway: &McpGateway, logical_id: &str, request: Value) -> Value {
    let context = GatewayRequestContext::new(
        AuthorizationScopeId::new("repository-tools-test").unwrap(),
        LogicalCallId::new(logical_id).unwrap(),
    );
    let bytes = serde_json::to_vec(&request).unwrap();
    serde_json::from_slice(
        &gateway
            .process_bytes(&bytes, &context, EphemeralSecrets::default())
            .expect("JSON-RPC response"),
    )
    .expect("valid response JSON")
}

fn call(gateway: &McpGateway, sequence: u64, name: &str, arguments: Value) -> Value {
    process(
        gateway,
        &format!("call-{sequence}"),
        json!({
            "jsonrpc": "2.0",
            "id": sequence,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }),
    )
}

fn initialize(gateway: &McpGateway) {
    let response = process(
        gateway,
        "initialize",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "repository-tools-test", "version": "1" }
            }
        }),
    );
    assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
}

fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn git(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["-c", "commit.gpgsign=false"])
        .args(arguments)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn repository_refusals_are_actionable_without_echoing_sensitive_paths() {
    let workspace = TempDir::new().unwrap();
    write(workspace.path(), "visible.txt", "public\n");
    let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
    initialize(server.gateway());

    let secret_path = "customer-secrets/private-token.txt";
    let response = call(
        server.gateway(),
        2,
        "repo.read",
        json!({ "path": secret_path }),
    );
    assert_eq!(response["error"]["code"], -32_602);
    assert_eq!(
        response["error"]["data"]["reason"],
        "invalid_repository_arguments"
    );
    assert!(
        response["error"]["data"]["hint"]
            .as_str()
            .unwrap()
            .contains("tools/list")
    );
    assert!(!response.to_string().contains(secret_path));
    assert!(!format!("{response:?}").contains("private-token"));
}

#[test]
fn repository_primitives_are_product_routed_deterministic_and_exactly_reusable() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path(),
        "src/lib.rs",
        "pub fn target() -> usize { 7 }\npub fn caller() { let _ = target(); }\n",
    );
    write(workspace.path(), "src/empty.py", "print('stable')\n");
    write(
        workspace.path(),
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );
    write(workspace.path(), "docs/notes.txt", "irrelevant\n");
    git(workspace.path(), &["init", "-q"]);
    git(
        workspace.path(),
        &["config", "user.name", "Repository Tool Tests"],
    );
    git(
        workspace.path(),
        &["config", "user.email", "repository-tools@example.invalid"],
    );
    git(workspace.path(), &["add", "--all"]);
    git(workspace.path(), &["commit", "-q", "-m", "initial"]);

    let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
    initialize(server.gateway());

    let listed = process(
        server.gateway(),
        "list-tools",
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "context.cancel",
            "context.delta",
            "context.publish",
            "context.retrieve",
            "git.blame",
            "git.diff",
            "git.log",
            "git.show",
            "git.status",
            "repo.glob",
            "repo.list",
            "repo.manifest",
            "repo.read",
            "repo.references",
            "repo.search",
            "repo.stat",
            "repo.tree",
            "task.claim",
            "task.inspect",
            "task.list",
            "task.start",
            "task.transition",
        ]
    );

    let read = call(
        server.gateway(),
        10,
        "repo.read",
        json!({ "path": "src/lib.rs" }),
    );
    assert!(
        read["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("target")
    );

    let search = call(
        server.gateway(),
        11,
        "repo.search",
        json!({ "pattern": "target", "path": "src" }),
    );
    assert_eq!(
        search["result"]["structuredContent"]["matches"][0]["path"],
        "src/lib.rs"
    );
    assert_eq!(
        search["result"]["structuredContent"]["matches"][0]["line"],
        1
    );

    let directory = call(server.gateway(), 12, "repo.list", json!({ "path": "src" }));
    assert_eq!(
        directory["result"]["structuredContent"]["entries"][0]["path"],
        "src/empty.py"
    );

    let tree = call(server.gateway(), 13, "repo.tree", json!({ "path": "." }));
    let tree_paths = tree["result"]["structuredContent"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(tree_paths.contains(&"src/lib.rs"));

    let stat = call(
        server.gateway(),
        14,
        "repo.stat",
        json!({ "path": "src/lib.rs" }),
    );
    assert_eq!(stat["result"]["structuredContent"]["kind"], "file");
    assert_eq!(stat["result"]["structuredContent"]["exists"], true);

    let glob = call(
        server.gateway(),
        15,
        "repo.glob",
        json!({ "pattern": "**/*.rs", "path": "." }),
    );
    assert_eq!(
        glob["result"]["structuredContent"]["paths"],
        json!(["src/lib.rs"])
    );

    let references = call(
        server.gateway(),
        16,
        "repo.references",
        json!({ "symbol": "target", "path": "src" }),
    );
    assert_eq!(
        references["result"]["structuredContent"]["references"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        references["result"]["structuredContent"]["references"][1]["line"],
        2
    );

    let manifests = call(server.gateway(), 17, "repo.manifest", json!({}));
    assert_eq!(
        manifests["result"]["structuredContent"]["manifests"][0]["path"],
        "Cargo.toml"
    );

    let clean_status = call(server.gateway(), 18, "git.status", json!({ "path": "." }));
    assert_eq!(
        clean_status["result"]["structuredContent"]["entries"],
        json!([]),
        "{clean_status}"
    );
    let before_config_change = server.stats().unwrap();
    git(workspace.path(), &["config", "diff.algorithm", "histogram"]);
    let configured_status = call(server.gateway(), 181, "git.status", json!({ "path": "." }));
    assert_eq!(
        configured_status["result"]["structuredContent"]["entries"],
        json!([]),
        "{configured_status}"
    );
    let after_config_change = server.stats().unwrap();
    assert_eq!(
        after_config_change.executed,
        before_config_change.executed + 1,
        "a repository-control mutation must execute instead of reusing: before={before_config_change:?} after={after_config_change:?}"
    );
    assert_eq!(
        after_config_change.exact_hits, before_config_change.exact_hits,
        "a repository-control mutation must not count as an exact hit: before={before_config_change:?} after={after_config_change:?}"
    );
    let log = call(server.gateway(), 19, "git.log", json!({ "maxResults": 10 }));
    assert_eq!(
        log["result"]["structuredContent"]["commits"][0]["subject"],
        "initial"
    );

    let negative = call(
        server.gateway(),
        20,
        "repo.search",
        json!({ "pattern": "not_present", "path": "src" }),
    );
    assert!(
        negative["result"]["structuredContent"]["matches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let warm = call(
        server.gateway(),
        21,
        "repo.search",
        json!({ "pattern": "not_present", "path": "src" }),
    );
    assert_eq!(negative["result"], warm["result"]);

    write(
        workspace.path(),
        "docs/notes.txt",
        "changed but outside src\n",
    );
    let irrelevant = call(
        server.gateway(),
        22,
        "repo.search",
        json!({ "pattern": "not_present", "path": "src" }),
    );
    assert_eq!(negative["result"], irrelevant["result"]);

    write(workspace.path(), "src/new.rs", "fn not_present() {}\n");
    let invalidated = call(
        server.gateway(),
        23,
        "repo.search",
        json!({ "pattern": "not_present", "path": "src" }),
    );
    assert_eq!(
        invalidated["result"]["structuredContent"]["matches"][0]["path"],
        "src/new.rs"
    );

    write(
        workspace.path(),
        "src/lib.rs",
        "pub fn target() -> usize { 8 }\npub fn caller() { let _ = target(); }\n",
    );
    let dirty_status = call(server.gateway(), 24, "git.status", json!({ "path": "src" }));
    let dirty_paths = dirty_status["result"]["structuredContent"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(dirty_paths, vec!["src/lib.rs", "src/new.rs"]);

    let diff = call(
        server.gateway(),
        25,
        "git.diff",
        json!({ "path": "src/lib.rs" }),
    );
    assert!(
        diff["result"]["structuredContent"]["patch"]
            .as_str()
            .unwrap()
            .contains("usize { 8 }")
    );
    let warm_diff = call(
        server.gateway(),
        26,
        "git.diff",
        json!({ "path": "src/lib.rs" }),
    );
    assert_eq!(diff["result"], warm_diff["result"]);

    let shown = call(
        server.gateway(),
        27,
        "git.show",
        json!({ "path": "src/lib.rs" }),
    );
    assert!(
        shown["result"]["structuredContent"]["output"]
            .as_str()
            .unwrap()
            .contains("usize { 7 }")
    );
    let blame = call(
        server.gateway(),
        28,
        "git.blame",
        json!({ "path": "src/lib.rs", "startLine": 1, "endLine": 1 }),
    );
    assert_eq!(
        blame["result"]["structuredContent"]["lines"][0]["path"],
        "src/lib.rs"
    );
    assert_eq!(blame["result"]["structuredContent"]["lines"][0]["line"], 1);

    let unstaged_index = call(
        server.gateway(),
        29,
        "git.diff",
        json!({ "path": "src/lib.rs", "staged": true, "revision": "HEAD" }),
    );
    assert_eq!(unstaged_index["result"]["structuredContent"]["patch"], "");
    git(workspace.path(), &["add", "src/lib.rs"]);
    let staged = call(
        server.gateway(),
        30,
        "git.diff",
        json!({ "path": "src/lib.rs", "staged": true, "revision": "HEAD" }),
    );
    assert!(
        staged["result"]["structuredContent"]["patch"]
            .as_str()
            .unwrap()
            .contains("usize { 8 }")
    );

    let staged_status = call(server.gateway(), 31, "git.status", json!({ "path": "src" }));
    assert!(
        staged_status["result"]["structuredContent"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "src/lib.rs")
    );
    git(workspace.path(), &["mv", "src/lib.rs", "src/moved.rs"]);
    let renamed = call(server.gateway(), 32, "git.status", json!({ "path": "src" }));
    assert!(
        renamed["result"]["structuredContent"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "src/moved.rs")
    );
    fs::remove_file(workspace.path().join("src/empty.py")).unwrap();
    let deleted = call(server.gateway(), 33, "git.status", json!({ "path": "src" }));
    assert!(
        deleted["result"]["structuredContent"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "src/empty.py")
    );

    let stats = server.stats().unwrap();
    // Standalone repo.search now executes directly because its source proof
    // costs more than this bounded provider scan. The Git diff retry remains
    // exact; another Git retry may conservatively execute on hosts where Git
    // changes an observed index/executable binding while answering it.
    assert!((1..=2).contains(&stats.exact_hits), "{stats:?}");
    assert_eq!(stats.executed + stats.exact_hits, 25, "{stats:?}");
}

#[test]
fn external_git_inputs_execute_without_reuse() {
    let workspace = TempDir::new().unwrap();
    write(workspace.path(), "tracked", "tracked\n");
    git(workspace.path(), &["init", "-q"]);
    git(
        workspace.path(),
        &["config", "user.name", "Repository Tool Tests"],
    );
    git(
        workspace.path(),
        &["config", "user.email", "repository-tools@example.invalid"],
    );
    git(workspace.path(), &["add", "tracked"]);
    git(workspace.path(), &["commit", "-q", "-m", "initial"]);
    write(workspace.path(), "ignored.txt", "untracked\n");
    let external_root = TempDir::new().unwrap();
    let external = external_root.path().join("external-ignore");
    fs::write(&external, b"ignored.txt\n").unwrap();
    git(
        workspace.path(),
        &["config", "core.excludesFile", external.to_str().unwrap()],
    );

    let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
    initialize(server.gateway());
    let ignored = call(server.gateway(), 10, "git.status", json!({ "path": "." }));
    assert_eq!(
        ignored["result"]["structuredContent"]["entries"],
        json!([]),
        "{ignored}"
    );

    fs::write(&external, b"").unwrap();
    let visible = call(server.gateway(), 11, "git.status", json!({ "path": "." }));
    assert_eq!(
        visible["result"]["structuredContent"]["entries"][0]["path"], "ignored.txt",
        "{visible}"
    );
    let stats = server.stats().unwrap();
    assert_eq!(stats.exact_hits, 0, "external Git inputs must never hit");
}

#[test]
fn nested_git_state_executes_without_reuse() {
    let workspace = TempDir::new().unwrap();
    git(workspace.path(), &["init", "-q"]);
    git(
        workspace.path(),
        &["config", "user.name", "Repository Tool Tests"],
    );
    git(
        workspace.path(),
        &["config", "user.email", "repository-tools@example.invalid"],
    );

    let nested = workspace.path().join("dep");
    fs::create_dir(&nested).unwrap();
    git(&nested, &["init", "-q"]);
    git(&nested, &["config", "user.name", "Nested Tool Tests"]);
    git(
        &nested,
        &["config", "user.email", "nested-tools@example.invalid"],
    );
    write(&nested, "file", "unchanged\n");
    git(&nested, &["add", "file"]);
    git(&nested, &["commit", "-q", "-m", "nested-one"]);

    let modules = workspace.path().join(".git/modules");
    fs::create_dir_all(&modules).unwrap();
    fs::rename(nested.join(".git"), modules.join("dep")).unwrap();
    write(&nested, ".git", "gitdir: ../.git/modules/dep\n");
    git(workspace.path(), &["add", "dep"]);
    git(workspace.path(), &["commit", "-q", "-m", "parent"]);

    let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
    initialize(server.gateway());
    let clean = call(server.gateway(), 20, "git.status", json!({ "path": "." }));
    assert_eq!(
        clean["result"]["structuredContent"]["entries"],
        json!([]),
        "{clean}"
    );

    git(
        &nested,
        &["commit", "-q", "--allow-empty", "-m", "nested-two"],
    );
    let changed = call(server.gateway(), 21, "git.status", json!({ "path": "." }));
    assert_eq!(
        changed["result"]["structuredContent"]["entries"][0]["path"], "dep",
        "{changed}"
    );
    let stats = server.stats().unwrap();
    assert_eq!(stats.exact_hits, 0, "nested Git state must never hit");
}

#[test]
fn repository_configured_filters_never_execute() {
    let workspace = TempDir::new().unwrap();
    write(workspace.path(), "input.txt", "one\n");
    git(workspace.path(), &["init", "-q"]);
    git(
        workspace.path(),
        &["config", "user.name", "Repository Tool Tests"],
    );
    git(
        workspace.path(),
        &["config", "user.email", "repository-tools@example.invalid"],
    );
    git(workspace.path(), &["add", "input.txt"]);
    git(workspace.path(), &["commit", "-q", "-m", "initial"]);

    let marker_root = TempDir::new().unwrap();
    let marker = marker_root.path().join("filter-ran");
    let command = format!("touch '{}'", marker.display());
    git(workspace.path(), &["config", "filter.evil.clean", &command]);
    write(workspace.path(), ".gitattributes", "*.txt filter=evil\n");
    write(workspace.path(), "input.txt", "two\n");

    let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
    initialize(server.gateway());
    let response = call(server.gateway(), 30, "git.diff", json!({ "path": "." }));
    assert!(response.get("error").is_some(), "{response}");
    assert!(
        !marker.exists(),
        "the sanitized read-only Git provider executed a configured filter"
    );
}

#[test]
fn externally_configured_git_worktree_is_refused() {
    let workspace = TempDir::new().unwrap();
    write(workspace.path(), "tracked", "tracked\n");
    git(workspace.path(), &["init", "-q"]);
    git(
        workspace.path(),
        &["config", "user.name", "Repository Tool Tests"],
    );
    git(
        workspace.path(),
        &["config", "user.email", "repository-tools@example.invalid"],
    );
    git(workspace.path(), &["add", "tracked"]);
    git(workspace.path(), &["commit", "-q", "-m", "initial"]);

    let external = TempDir::new().unwrap();
    write(external.path(), "outside", "must not be observed\n");
    git(
        workspace.path(),
        &["config", "core.worktree", external.path().to_str().unwrap()],
    );
    let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
    initialize(server.gateway());
    let response = call(server.gateway(), 40, "git.status", json!({ "path": "." }));
    assert!(response.get("error").is_some(), "{response}");
    assert!(
        !response.to_string().contains("outside"),
        "external worktree content leaked into the response: {response}"
    );
}
