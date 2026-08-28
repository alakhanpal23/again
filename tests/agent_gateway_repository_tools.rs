use std::fs;
use std::path::Path;

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

fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
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

    let server = ExperimentalMcpGatewayV1::build(workspace.path()).unwrap();
    let initialize = process(
        server.gateway(),
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
    assert_eq!(initialize["result"]["protocolVersion"], "2025-06-18");

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
            "repo.glob",
            "repo.list",
            "repo.manifest",
            "repo.read",
            "repo.references",
            "repo.search",
            "repo.stat",
            "repo.tree",
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

    let stats = server.stats().unwrap();
    assert_eq!(stats.executed, 10);
    assert_eq!(stats.exact_hits, 2);
}
