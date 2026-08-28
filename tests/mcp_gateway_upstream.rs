#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use again::mcp_gateway::{
    AuthorizationScopeId, EffectClass, EphemeralSecret, EphemeralSecrets, GatewayLimits,
    GatewayRequestContext, LogicalCallId, McpGateway, ProviderDescriptor, ProviderRegistration,
    StdioMcpProviderConfigV1, StdioMcpProviderV1,
};
use serde_json::{Value, json};

fn fixture_program() -> PathBuf {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp_upstream/provider.py");
    let mut permissions = fs::metadata(&fixture).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fixture, permissions).unwrap();
    fs::canonicalize(fixture).unwrap()
}

fn limits() -> GatewayLimits {
    GatewayLimits {
        max_message_bytes: 64 * 1024,
        max_result_bytes: 64 * 1024,
        max_text_bytes: 32 * 1024,
        ..GatewayLimits::default()
    }
}

fn provider_config(mode: &str, timeout: Duration, workdir: &Path) -> StdioMcpProviderConfigV1 {
    StdioMcpProviderConfigV1::new(
        ProviderDescriptor {
            id: "upstream".to_owned(),
            implementation: "local-mcp-fixture".to_owned(),
            version: "1".to_owned(),
            endpoint_identity: "fixture-before-binding".to_owned(),
        },
        fixture_program(),
        workdir,
        limits(),
        timeout,
    )
    .unwrap()
    .with_environment("PATH", "/usr/local/bin:/usr/bin:/bin")
    .unwrap()
    .with_environment("FIXTURE_MODE", mode)
    .unwrap()
}

fn gateway(
    mode: &str,
    timeout: Duration,
    workdir: &Path,
    configure: impl FnOnce(StdioMcpProviderConfigV1) -> StdioMcpProviderConfigV1,
    discovery_secrets: EphemeralSecrets<'_>,
) -> McpGateway {
    let provider = Arc::new(
        StdioMcpProviderV1::new(configure(provider_config(mode, timeout, workdir))).unwrap(),
    );
    McpGateway::new_with_discovery_secrets(
        vec![ProviderRegistration::untrusted(provider)],
        limits(),
        discovery_secrets,
    )
    .unwrap()
}

fn context(call: &str) -> GatewayRequestContext {
    GatewayRequestContext::new(
        AuthorizationScopeId::new("scope:upstream-test").unwrap(),
        LogicalCallId::new(call).unwrap(),
    )
}

fn wait_for_descendant_pid(path: &Path) -> i32 {
    for _ in 0..200 {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                if pid > 0 {
                    return pid;
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("upstream attempt did not publish a valid descendant identity");
}

fn invoke(gateway: &McpGateway, request: Value, secrets: EphemeralSecrets<'_>) -> Value {
    serde_json::from_slice(
        &gateway
            .process_bytes(
                &serde_json::to_vec(&request).unwrap(),
                &context("logical:upstream"),
                secrets,
            )
            .expect("response"),
    )
    .unwrap()
}

fn initialize(gateway: &McpGateway) {
    let response = invoke(
        gateway,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1" }
            }
        }),
        EphemeralSecrets::empty(),
    );
    assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
}

fn call(gateway: &McpGateway, secrets: EphemeralSecrets<'_>) -> Value {
    invoke(
        gateway,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "upstream.echo", "arguments": { "value": "hello" } }
        }),
        secrets,
    )
}

#[test]
fn real_stdio_discovery_call_notifications_and_unknown_policy_are_bounded() {
    let temporary = tempfile::tempdir().unwrap();
    let gateway = gateway(
        "notifications",
        Duration::from_secs(3),
        temporary.path(),
        |config| config,
        EphemeralSecrets::empty(),
    );
    initialize(&gateway);
    let listed = invoke(
        &gateway,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }),
        EphemeralSecrets::empty(),
    );
    assert_eq!(listed["result"]["tools"][0]["name"], "upstream.echo");
    assert_eq!(
        listed["result"]["tools"][0]["_meta"]["again.dev/effectClass"],
        "unknown"
    );
    assert_eq!(
        listed["result"]["tools"][0]["_meta"]["again.dev/reuseDisposition"],
        "bypass_reuse"
    );
    let response = call(&gateway, EphemeralSecrets::empty());
    assert_eq!(response["result"]["structuredContent"]["value"], "hello");
    assert_eq!(
        response["result"]["structuredContent"]["credentialPresent"],
        false
    );
}

#[test]
fn local_policy_not_forged_annotations_controls_reuse_disposition() {
    let temporary = tempfile::tempdir().unwrap();
    let unknown = gateway(
        "normal",
        Duration::from_secs(3),
        temporary.path(),
        |config| config,
        EphemeralSecrets::empty(),
    );
    initialize(&unknown);
    let unknown_list = invoke(
        &unknown,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        EphemeralSecrets::empty(),
    );
    assert_eq!(
        unknown_list["result"]["tools"][0]["_meta"]["again.dev/effectClass"],
        "unknown"
    );

    let read = gateway(
        "normal",
        Duration::from_secs(3),
        temporary.path(),
        |config| {
            config
                .with_tool_effect("echo", EffectClass::ReadOnly)
                .unwrap()
        },
        EphemeralSecrets::empty(),
    );
    initialize(&read);
    let read_list = invoke(
        &read,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        EphemeralSecrets::empty(),
    );
    assert_eq!(
        read_list["result"]["tools"][0]["_meta"]["again.dev/effectClass"],
        "read_only"
    );
}

#[test]
fn credentials_are_borrowed_per_invocation_and_missing_values_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let discovery_entries = [EphemeralSecret {
        name: "token",
        value: b"discovery-secret",
    }];
    let gateway = gateway(
        "normal",
        Duration::from_secs(3),
        temporary.path(),
        |config| {
            config
                .with_secret_environment("token", "FIXTURE_TOKEN")
                .unwrap()
        },
        EphemeralSecrets::new(&discovery_entries),
    );
    initialize(&gateway);
    let missing = call(&gateway, EphemeralSecrets::empty());
    assert_eq!(missing["error"]["code"], -32603);
    assert!(!missing.to_string().contains("discovery-secret"));

    let invocation_entries = [EphemeralSecret {
        name: "token",
        value: b"invocation-secret",
    }];
    let present = call(&gateway, EphemeralSecrets::new(&invocation_entries));
    assert_eq!(
        present["result"]["structuredContent"]["credentialPresent"],
        true
    );
    assert!(!present.to_string().contains("invocation-secret"));
}

#[test]
fn malformed_wrong_id_crash_and_oversized_upstreams_fail_safely() {
    for mode in [
        "malformed",
        "wrong_id",
        "crash",
        "oversized",
        "notification_flood",
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let gateway = gateway(
            mode,
            Duration::from_secs(2),
            temporary.path(),
            |config| config,
            EphemeralSecrets::empty(),
        );
        initialize(&gateway);
        let response = call(&gateway, EphemeralSecrets::empty());
        assert!(response.get("error").is_some(), "mode {mode}: {response}");
        assert!(response.get("result").is_none());
    }
}

#[test]
fn timeout_kills_and_reaps_the_complete_upstream_process_group() {
    let temporary = tempfile::tempdir().unwrap();
    let pid_file = temporary.path().join("descendant.pid");
    let gateway = gateway(
        "hang_descendant",
        Duration::from_millis(250),
        temporary.path(),
        |config| {
            config
                .with_environment("PID_FILE", pid_file.to_string_lossy())
                .unwrap()
        },
        EphemeralSecrets::empty(),
    );
    initialize(&gateway);
    let started = Instant::now();
    let response = call(&gateway, EphemeralSecrets::empty());
    assert!(response.get("error").is_some());
    assert!(started.elapsed() < Duration::from_secs(3));
    let descendant = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    for _ in 0..100 {
        let alive = unsafe { libc::kill(descendant, 0) } == 0;
        if !alive {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("descendant process {descendant} survived upstream cleanup");
}

#[test]
fn gateway_cancellation_reaches_the_exact_attempt_and_reaps_descendants() {
    let temporary = tempfile::tempdir().unwrap();
    let pid_file = temporary.path().join("cancel-descendant.pid");
    let gateway = Arc::new(gateway(
        "hang_descendant",
        Duration::from_secs(10),
        temporary.path(),
        |config| {
            config
                .with_environment("PID_FILE", pid_file.to_string_lossy())
                .unwrap()
        },
        EphemeralSecrets::empty(),
    ));
    initialize(&gateway);
    let worker_gateway = Arc::clone(&gateway);
    let worker = thread::spawn(move || call(&worker_gateway, EphemeralSecrets::empty()));
    // File creation precedes the fixture's PID write. Waiting for existence
    // alone races an empty regular file on Linux and does not prove that the
    // descendant identity is ready for the subsequent cleanup assertion.
    let descendant = wait_for_descendant_pid(&pid_file);
    let cancellation = gateway.process_bytes(
        &serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "requestId": 2 }
        }))
        .unwrap(),
        &context("logical:cancel"),
        EphemeralSecrets::empty(),
    );
    assert!(cancellation.is_none());
    let response = worker.join().unwrap();
    assert_eq!(response["error"]["code"], -32800);
    for _ in 0..100 {
        if unsafe { libc::kill(descendant, 0) } != 0 {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("cancelled descendant process {descendant} survived cleanup");
}

#[test]
fn executable_drift_after_discovery_refuses_execution() {
    let temporary = tempfile::tempdir().unwrap();
    let copied_fixture = temporary.path().join("mutable-provider.py");
    fs::copy(fixture_program(), &copied_fixture).unwrap();
    let mut permissions = fs::metadata(&copied_fixture).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&copied_fixture, permissions).unwrap();
    let config = StdioMcpProviderConfigV1::new(
        ProviderDescriptor {
            id: "drift".to_owned(),
            implementation: "mutable-local-fixture".to_owned(),
            version: "1".to_owned(),
            endpoint_identity: "before-binding".to_owned(),
        },
        fs::canonicalize(&copied_fixture).unwrap(),
        temporary.path(),
        limits(),
        Duration::from_secs(3),
    )
    .unwrap()
    .with_environment("PATH", "/usr/local/bin:/usr/bin:/bin")
    .unwrap();
    let gateway = McpGateway::new(
        vec![ProviderRegistration::untrusted(Arc::new(
            StdioMcpProviderV1::new(config).unwrap(),
        ))],
        limits(),
    )
    .unwrap();
    initialize(&gateway);
    fs::write(&copied_fixture, b"#!/bin/sh\nexit 0\n").unwrap();
    let response = invoke(
        &gateway,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "drift.echo", "arguments": {} }
        }),
        EphemeralSecrets::empty(),
    );
    assert_eq!(response["error"]["code"], -32603);
    assert!(response.get("result").is_none());
}

#[test]
fn repeated_real_upstream_calls_have_zero_failures_and_report_proxy_latency() {
    let temporary = tempfile::tempdir().unwrap();
    let gateway = gateway(
        "normal",
        Duration::from_secs(3),
        temporary.path(),
        |config| config,
        EphemeralSecrets::empty(),
    );
    initialize(&gateway);
    let samples = 20_u32;
    let started = Instant::now();
    for _ in 0..samples {
        assert!(
            call(&gateway, EphemeralSecrets::empty())
                .get("result")
                .is_some()
        );
    }
    let elapsed = started.elapsed();
    eprintln!(
        "again_mcp_upstream_benchmark samples={samples} total_us={} mean_us={} failures=0",
        elapsed.as_micros(),
        elapsed.as_micros() / u128::from(samples)
    );
}
