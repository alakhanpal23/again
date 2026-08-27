#[path = "../src/agent_gateway/protocol.rs"]
pub mod agent_gateway_protocol;
mod agent_gateway {
    pub use crate::agent_gateway_protocol as protocol;
}
#[path = "../src/mcp_gateway.rs"]
mod mcp_gateway;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader, Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use mcp_gateway::{
    AuthorizationScopeId, CapturedToolResult, EffectClass, EphemeralSecret, EphemeralSecrets,
    Freshness, FreshnessMetadata, GatewayAuditEvent, GatewayAuditSink, GatewayInputError,
    GatewayLimits, GatewayRequestContext, LogicalCallId, McpError, McpErrorCode, McpGateway,
    ProviderCall, ProviderCancellation, ProviderDescriptor, ProviderError, ProviderRegistration,
    ProviderTool, ReuseDispositionV1, SideEffectClassification, StructuredResultCapture,
    ToolCancellation, ToolDiscovery, ToolExecution,
};
use serde_json::{Value, json};

#[derive(Default)]
struct BlockState {
    started: Mutex<bool>,
    changed: Condvar,
    cancelled: AtomicBool,
}

struct FakeProvider {
    descriptor: ProviderDescriptor,
    tools: Vec<ProviderTool>,
    effects: BTreeMap<String, EffectClass>,
    result: Mutex<Result<Value, ProviderError>>,
    calls: Mutex<Vec<ProviderCall>>,
    cancellations: Mutex<Vec<ProviderCancellation>>,
    block: Option<Arc<BlockState>>,
    panics: bool,
    freshness_panics: bool,
    capture_panics: bool,
    cancellation_panics: bool,
    observed_secret: Mutex<Option<Vec<u8>>>,
    freshness: Freshness,
}

impl FakeProvider {
    fn new(id: &str, tools: Vec<ProviderTool>) -> Self {
        Self {
            descriptor: ProviderDescriptor {
                id: id.into(),
                implementation: format!("fake-{id}"),
                version: "1.0.0".into(),
                endpoint_identity: format!("test://{id}"),
            },
            tools,
            effects: BTreeMap::new(),
            result: Mutex::new(Ok(json!({ "content": [] }))),
            calls: Mutex::new(Vec::new()),
            cancellations: Mutex::new(Vec::new()),
            block: None,
            panics: false,
            freshness_panics: false,
            capture_panics: false,
            cancellation_panics: false,
            observed_secret: Mutex::new(None),
            freshness: Freshness {
                revision: "fake-revision-7".into(),
                observed_at_unix_ms: Some(123_456),
            },
        }
    }

    fn with_effect(mut self, tool: &str, effect: EffectClass) -> Self {
        self.effects.insert(tool.into(), effect);
        self
    }

    fn with_result(self, result: Result<Value, ProviderError>) -> Self {
        *self.result.lock().unwrap() = result;
        self
    }

    fn blocking(mut self, state: Arc<BlockState>) -> Self {
        self.block = Some(state);
        self
    }

    fn panicking(mut self) -> Self {
        self.panics = true;
        self
    }

    fn panicking_freshness(mut self) -> Self {
        self.freshness_panics = true;
        self
    }

    fn panicking_capture(mut self) -> Self {
        self.capture_panics = true;
        self
    }

    fn panicking_cancellation(mut self) -> Self {
        self.cancellation_panics = true;
        self
    }

    fn with_freshness(mut self, revision: &str) -> Self {
        self.freshness.revision = revision.into();
        self
    }
}

impl ToolDiscovery for FakeProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        Ok(self.tools.clone())
    }
}

impl ToolExecution for FakeProvider {
    fn execute(
        &self,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        self.calls.lock().unwrap().push(call);
        assert!(!self.panics, "injected provider panic");
        if let Some(secret) = secrets.get("token") {
            *self.observed_secret.lock().unwrap() = Some(secret.to_vec());
        }
        if let Some(block) = &self.block {
            let mut started = block.started.lock().unwrap();
            *started = true;
            block.changed.notify_all();
            while !block.cancelled.load(Ordering::Acquire) {
                started = block.changed.wait(started).unwrap();
            }
        }
        self.result.lock().unwrap().clone()
    }
}

impl ToolCancellation for FakeProvider {
    fn cancel(&self, cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        self.cancellations.lock().unwrap().push(cancellation);
        if let Some(block) = &self.block {
            let _started = block.started.lock().unwrap();
            block.cancelled.store(true, Ordering::Release);
            block.changed.notify_all();
        }
        assert!(!self.cancellation_panics, "injected cancellation panic");
        Ok(())
    }
}

impl FreshnessMetadata for FakeProvider {
    fn freshness(&self) -> Freshness {
        assert!(!self.freshness_panics, "injected freshness panic");
        self.freshness.clone()
    }
}

impl SideEffectClassification for FakeProvider {
    fn classify_effect(&self, upstream_tool_name: &str) -> EffectClass {
        self.effects
            .get(upstream_tool_name)
            .copied()
            .unwrap_or(EffectClass::ReadOnly)
    }
}

impl StructuredResultCapture for FakeProvider {
    fn capture_result(&self, result: Value) -> Result<CapturedToolResult, ProviderError> {
        assert!(!self.capture_panics, "injected capture panic");
        Ok(CapturedToolResult::exact(result))
    }
}

#[derive(Default)]
struct AttemptState {
    started: BTreeSet<u64>,
    cancelled: BTreeSet<u64>,
    completed: BTreeSet<u64>,
}

struct AttemptProvider {
    calls: Mutex<Vec<ProviderCall>>,
    cancellations: Mutex<Vec<ProviderCancellation>>,
    state: Mutex<AttemptState>,
    changed: Condvar,
    blocking: AtomicBool,
}

impl AttemptProvider {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            cancellations: Mutex::new(Vec::new()),
            state: Mutex::new(AttemptState::default()),
            changed: Condvar::new(),
            blocking: AtomicBool::new(true),
        }
    }

    fn wait_for_started(&self, count: usize) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| {
                state.started.len() < count
            })
            .unwrap();
        assert!(!timeout.timed_out(), "provider did not start {count} calls");
        assert!(state.started.len() >= count);
    }

    fn wait_for_cancellations(&self, count: usize) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| {
                state.cancelled.len() < count
            })
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "provider did not receive {count} cancellations"
        );
        assert!(state.cancelled.len() >= count);
    }

    fn stop_blocking(&self) {
        self.blocking.store(false, Ordering::Release);
        self.changed.notify_all();
    }
}

impl ToolDiscovery for AttemptProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "attempts".into(),
            implementation: "attempt-gate".into(),
            version: "1.0.0".into(),
            endpoint_identity: "test://attempt-gate".into(),
        }
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        Ok(vec![tool("fast"), tool("wait")])
    }
}

impl ToolExecution for AttemptProvider {
    fn execute(
        &self,
        call: ProviderCall,
        _secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        let physical = call.physical_attempt_id.get();
        let fast = call.upstream_tool_name == "fast";
        self.calls.lock().unwrap().push(call);
        let mut state = self.state.lock().unwrap();
        state.started.insert(physical);
        self.changed.notify_all();
        while !fast && self.blocking.load(Ordering::Acquire) && !state.cancelled.contains(&physical)
        {
            state = self.changed.wait(state).unwrap();
        }
        state.completed.insert(physical);
        self.changed.notify_all();
        Ok(json!({ "content": [] }))
    }
}

impl ToolCancellation for AttemptProvider {
    fn cancel(&self, cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        let physical = cancellation.physical_attempt_id.get();
        self.cancellations.lock().unwrap().push(cancellation);
        self.state.lock().unwrap().cancelled.insert(physical);
        self.changed.notify_all();
        Ok(())
    }
}

impl FreshnessMetadata for AttemptProvider {
    fn freshness(&self) -> Freshness {
        Freshness {
            revision: "attempt-revision".into(),
            observed_at_unix_ms: Some(321),
        }
    }
}

impl SideEffectClassification for AttemptProvider {
    fn classify_effect(&self, _upstream_tool_name: &str) -> EffectClass {
        EffectClass::ReadOnly
    }
}

impl StructuredResultCapture for AttemptProvider {
    fn capture_result(&self, result: Value) -> Result<CapturedToolResult, ProviderError> {
        Ok(CapturedToolResult::exact(result))
    }
}

struct ChannelReader {
    receiver: mpsc::Receiver<Vec<u8>>,
    current: Cursor<Vec<u8>>,
}

impl ChannelReader {
    fn new(receiver: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            receiver,
            current: Cursor::new(Vec::new()),
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            let read = self.current.read(output)?;
            if read != 0 {
                return Ok(read);
            }
            match self.receiver.recv() {
                Ok(bytes) => self.current = Cursor::new(bytes),
                Err(_) => return Ok(0),
            }
        }
    }
}

struct LineWriter {
    pending: Vec<u8>,
    lines: mpsc::Sender<Vec<u8>>,
}

impl Write for LineWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        for byte in input {
            if *byte == b'\n' {
                let line = std::mem::take(&mut self.pending);
                self.lines
                    .send(line)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test receiver"))?;
            } else {
                self.pending.push(*byte);
            }
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct WriterGateState {
    entered: bool,
    released: bool,
}

struct BlockingWriter {
    gate: Arc<(Mutex<WriterGateState>, Condvar)>,
    bytes: Vec<u8>,
}

impl Write for BlockingWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let (state, changed) = &*self.gate;
        let mut state = state.lock().unwrap();
        state.entered = true;
        changed.notify_all();
        while !state.released {
            state = changed.wait(state).unwrap();
        }
        drop(state);
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected writer failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct MemoryAudit {
    events: Mutex<Vec<GatewayAuditEvent>>,
}

impl GatewayAuditSink for MemoryAudit {
    fn record(&self, event: GatewayAuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn tool(name: &str) -> ProviderTool {
    ProviderTool::new(
        name,
        json!({
            "type": "object",
            "properties": { "value": { "type": "string" } }
        }),
    )
}

fn context(logical: &str) -> GatewayRequestContext {
    GatewayRequestContext::new(
        AuthorizationScopeId::new("scope:test").unwrap(),
        LogicalCallId::new(logical).unwrap(),
    )
}

fn decode(bytes: Option<Vec<u8>>) -> Value {
    serde_json::from_slice(&bytes.expect("JSON-RPC response")).unwrap()
}

fn invoke(gateway: &McpGateway, request: Value, context: &GatewayRequestContext) -> Value {
    decode(gateway.process_bytes(
        &serde_json::to_vec(&request).unwrap(),
        context,
        EphemeralSecrets::empty(),
    ))
}

fn encoded_line(value: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn cancel_string_id(gateway: &McpGateway, request_id: &str) {
    let response = gateway.process_bytes(
        &serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "requestId": request_id }
        }))
        .unwrap(),
        &context("logical:test-cancellation"),
        EphemeralSecrets::empty(),
    );
    assert!(response.is_none());
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
        &context("logical:init"),
    );
    assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
}

fn gateway(provider: Arc<FakeProvider>) -> McpGateway {
    McpGateway::new(
        vec![ProviderRegistration::untrusted(provider)],
        GatewayLimits::default(),
    )
    .unwrap()
}

fn attempt_gateway(provider: Arc<AttemptProvider>) -> McpGateway {
    McpGateway::new(
        vec![ProviderRegistration::untrusted(provider)],
        GatewayLimits::default(),
    )
    .unwrap()
}

#[test]
fn initialize_and_tools_list_are_deterministic() {
    let zeta = Arc::new(FakeProvider::new(
        "zeta",
        vec![tool("second"), tool("first")],
    ));
    let alpha = Arc::new(FakeProvider::new("alpha", vec![tool("z"), tool("a")]));
    let gateway = McpGateway::new(
        vec![
            ProviderRegistration::untrusted(zeta),
            ProviderRegistration::untrusted(alpha),
        ],
        GatewayLimits::default(),
    )
    .unwrap();

    initialize(&gateway);
    let request = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let first = invoke(&gateway, request.clone(), &context("logical:list-1"));
    let second = invoke(&gateway, request, &context("logical:list-2"));
    assert_eq!(first, second);
    let names = first["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, ["alpha.a", "alpha.z", "zeta.first", "zeta.second"]);
}

#[test]
fn initialized_notification_cannot_bypass_the_initialize_handshake() {
    let gateway = McpGateway::new(Vec::new(), GatewayLimits::default()).unwrap();
    assert!(
        gateway
            .process_bytes(
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                &context("logical:premature-notification"),
                EphemeralSecrets::empty(),
            )
            .is_none()
    );
    let denied = invoke(
        &gateway,
        json!({ "jsonrpc":"2.0", "id":2, "method":"tools/list" }),
        &context("logical:list-before-initialize"),
    );
    assert_eq!(denied["error"]["code"], -32_020);
    initialize(&gateway);
}

#[test]
fn namespacing_handles_upstream_name_collisions() {
    let gateway = McpGateway::new(
        vec![
            ProviderRegistration::untrusted(Arc::new(FakeProvider::new(
                "one",
                vec![tool("lookup")],
            ))),
            ProviderRegistration::untrusted(Arc::new(FakeProvider::new(
                "two",
                vec![tool("lookup")],
            ))),
        ],
        GatewayLimits::default(),
    )
    .unwrap();
    initialize(&gateway);
    let listed = invoke(
        &gateway,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        &context("logical:list"),
    );
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, ["one.lookup", "two.lookup"]);
}

#[test]
fn tools_call_forwards_exact_arguments_and_structured_result() {
    let exact_result = json!({
        "content": [
            { "type": "text", "text": "human" },
            { "type": "image", "data": "AAEC", "mimeType": "image/png" },
            { "type": "audio", "data": "AwQF", "mimeType": "audio/wav" },
            {
                "type": "resource",
                "resource": { "uri": "memory://r", "text": "resource text" }
            }
        ],
        "structuredContent": { "nested": [1, true, null, { "x": "y" }] },
        "isError": false,
        "_meta": { "provider.example/cache": { "hit": true } }
    });
    let provider = Arc::new(
        FakeProvider::new("fake", vec![tool("echo")]).with_result(Ok(exact_result.clone())),
    );
    let gateway = gateway(Arc::clone(&provider));
    initialize(&gateway);
    let arguments = json!({ "value": "sensitive", "nested": { "n": 7 } });
    let response = invoke(
        &gateway,
        json!({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": { "name": "fake.echo", "arguments": arguments }
        }),
        &context("logical:call-1"),
    );
    assert_eq!(response["result"], exact_result);
    let calls = provider.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].upstream_tool_name, "echo");
    assert_eq!(calls[0].namespaced_tool_name, "fake.echo");
    assert_eq!(calls[0].arguments, arguments);
    assert_eq!(calls[0].authorization_scope.as_str(), "scope:test");
}

#[test]
fn canonical_translation_is_deterministic_complete_redacted_and_non_authoritative() {
    let provider = Arc::new(FakeProvider::new("fake", vec![tool("echo")]));
    let gateway = gateway(Arc::clone(&provider));
    initialize(&gateway);
    for (id, arguments) in [
        (
            2,
            serde_json::from_str::<Value>(r#"{"b":2,"a":1}"#).unwrap(),
        ),
        (
            3,
            serde_json::from_str::<Value>(r#"{"a":1,"b":2}"#).unwrap(),
        ),
    ] {
        let response = invoke(
            &gateway,
            json!({
                "jsonrpc":"2.0", "id":id, "method":"tools/call",
                "params":{"name":"fake.echo","arguments":arguments}
            }),
            &context("logical:canonical"),
        );
        assert!(response.get("result").is_some());
    }
    let calls = provider.calls.lock().unwrap();
    let first = &calls[0].translation;
    let second = &calls[1].translation;
    assert_eq!(first.schema_version(), 1);
    assert_eq!(first.provider_identity(), calls[0].provider_identity);
    assert_eq!(first.namespaced_tool_name(), "fake.echo");
    assert_eq!(first.upstream_tool_name(), "echo");
    assert_eq!(first.authorization_scope_identity(), "scope:test");
    assert_eq!(first.freshness().revision, "fake-revision-7");
    assert_eq!(first.canonical_arguments(), br#"{"a":1,"b":2}"#);
    assert_eq!(first.canonical_digest(), second.canonical_digest());
    assert_eq!(first.tool_schema_identity().len(), 64);
    assert!(!first.permits_reuse());
    assert!(!format!("{:?}", calls[0]).contains("\"a\":1"));

    let captured = CapturedToolResult::exact(json!({ "secret": "result-payload" }));
    assert!(!format!("{captured:?}").contains("result-payload"));
    let error = McpError {
        code: -1,
        message: "secret-message".into(),
        data: Some(json!({ "secret": "error-payload" })),
    };
    let diagnostic = format!("{error:?}");
    assert!(!diagnostic.contains("secret-message"));
    assert!(!diagnostic.contains("error-payload"));
}

fn translation_digest_for(
    provider: FakeProvider,
    authorization_scope: &str,
    arguments: Value,
) -> [u8; 32] {
    let provider = Arc::new(provider);
    let gateway = gateway(Arc::clone(&provider));
    initialize(&gateway);
    let call_context = GatewayRequestContext::new(
        AuthorizationScopeId::new(authorization_scope).unwrap(),
        LogicalCallId::new("logical:binding-check").unwrap(),
    );
    let response = invoke(
        &gateway,
        json!({
            "jsonrpc":"2.0", "id":77, "method":"tools/call",
            "params":{"name":"fake.echo","arguments":arguments}
        }),
        &call_context,
    );
    assert!(response.get("result").is_some());
    *provider.calls.lock().unwrap()[0]
        .translation
        .canonical_digest()
}

#[test]
fn canonical_translation_digest_binds_every_declared_identity_dimension() {
    let baseline = translation_digest_for(
        FakeProvider::new("fake", vec![tool("echo")]),
        "scope:one",
        json!({ "value": 1 }),
    );

    let mut changed_provider = FakeProvider::new("fake", vec![tool("echo")]);
    changed_provider.descriptor.version = "2.0.0".into();
    let changed_provider =
        translation_digest_for(changed_provider, "scope:one", json!({ "value": 1 }));

    let changed_schema = translation_digest_for(
        FakeProvider::new(
            "fake",
            vec![ProviderTool::new(
                "echo",
                json!({ "type":"object", "properties": { "other": { "type":"number" } } }),
            )],
        ),
        "scope:one",
        json!({ "value": 1 }),
    );
    let changed_scope = translation_digest_for(
        FakeProvider::new("fake", vec![tool("echo")]),
        "scope:two",
        json!({ "value": 1 }),
    );
    let changed_freshness = translation_digest_for(
        FakeProvider::new("fake", vec![tool("echo")]).with_freshness("revision-8"),
        "scope:one",
        json!({ "value": 1 }),
    );
    let changed_arguments = translation_digest_for(
        FakeProvider::new("fake", vec![tool("echo")]),
        "scope:one",
        json!({ "value": 2 }),
    );

    for changed in [
        changed_provider,
        changed_schema,
        changed_scope,
        changed_freshness,
        changed_arguments,
    ] {
        assert_ne!(baseline, changed);
    }
}

#[test]
fn provider_error_is_forwarded_exactly() {
    let upstream = McpError {
        code: -31_777,
        message: "provider-specific".into(),
        data: Some(json!({ "opaque": [3, 2, 1] })),
    };
    let provider = Arc::new(
        FakeProvider::new("fake", vec![tool("fail")])
            .with_result(Err(ProviderError(upstream.clone()))),
    );
    let gateway = gateway(provider);
    initialize(&gateway);
    let response = invoke(
        &gateway,
        json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": { "name": "fake.fail", "arguments": {} }
        }),
        &context("logical:error"),
    );
    assert_eq!(response["error"], serde_json::to_value(upstream).unwrap());
}

#[test]
fn oversized_or_deep_provider_errors_become_payload_free_limit_refusals() {
    let mut deep_data = json!({ "must_not_escape": true });
    for _ in 0..GatewayLimits::default().max_result_depth {
        deep_data = json!({ "nested": deep_data });
    }
    for upstream in [
        McpError {
            code: -31_778,
            message: "x".repeat(GatewayLimits::default().max_metadata_bytes + 1),
            data: Some(json!({ "must_not_escape": "message-case" })),
        },
        McpError {
            code: -31_779,
            message: "bounded".into(),
            data: Some(deep_data.clone()),
        },
    ] {
        let provider = Arc::new(
            FakeProvider::new("fake", vec![tool("fail")]).with_result(Err(ProviderError(upstream))),
        );
        let gateway = McpGateway::new(
            vec![ProviderRegistration::untrusted(provider)],
            GatewayLimits::default(),
        )
        .unwrap();
        initialize(&gateway);
        let response = invoke(
            &gateway,
            json!({
                "jsonrpc":"2.0", "id":9, "method":"tools/call",
                "params":{"name":"fake.fail","arguments":{}}
            }),
            &context("logical:bounded-error"),
        );
        assert_eq!(
            response["error"]["code"],
            McpErrorCode::LimitExceeded as i64
        );
        assert!(response["error"].get("data").is_none());
        assert!(!response.to_string().contains("must_not_escape"));
    }
}

#[test]
fn malformed_oversized_deep_node_heavy_and_duplicate_input_are_rejected() {
    let limits = GatewayLimits {
        max_message_bytes: 512,
        max_json_nodes: 32,
        max_argument_depth: 4,
        max_argument_nodes: 8,
        ..GatewayLimits::default()
    };
    let gateway = McpGateway::new(Vec::new(), limits).unwrap();

    assert!(matches!(
        gateway.parse_message(br#"{"jsonrpc":"2.0",]"#),
        Err(GatewayInputError::MalformedJson)
    ));
    assert!(matches!(
        gateway.parse_message(&vec![b'x'; 513]),
        Err(GatewayInputError::MessageTooLarge { .. })
    ));
    assert_eq!(
        gateway.parse_message(br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#),
        Err(GatewayInputError::DuplicateKey)
    );

    initialize(&gateway);
    let deep = invoke(
        &gateway,
        json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "missing.tool", "arguments": { "a": { "b": { "c": { "d": {} } } } } }
        }),
        &context("logical:deep"),
    );
    assert_eq!(deep["error"]["code"], -32_021);

    let nodes = invoke(
        &gateway,
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "missing.tool", "arguments": { "values": [1,2,3,4,5,6,7,8,9] } }
        }),
        &context("logical:nodes"),
    );
    assert_eq!(nodes["error"]["code"], -32_021);
}

#[test]
fn parser_enforces_global_depth_nodes_and_nested_duplicate_keys_during_decode() {
    let limits = GatewayLimits {
        max_json_depth: 3,
        max_json_nodes: 5,
        ..GatewayLimits::default()
    };
    let gateway = McpGateway::new(Vec::new(), limits).unwrap();
    assert_eq!(gateway.parse_message(br#"[[[]]]"#).unwrap(), json!([[[]]]));
    assert!(matches!(
        gateway.parse_message(br#"[[[[]]]]"#),
        Err(GatewayInputError::DepthLimit {
            limit: 3,
            actual: 4
        })
    ));
    assert!(matches!(
        gateway.parse_message(br#"[0,1,2,3,4]"#),
        Err(GatewayInputError::NodeLimit { limit: 5 })
    ));
    let duplicate = gateway
        .parse_message(br#"{"outer":{"payload-secret":1,"payload-secret":2}}"#)
        .unwrap_err();
    assert_eq!(duplicate, GatewayInputError::DuplicateKey);
    assert!(!format!("{duplicate:?}").contains("payload-secret"));
}

#[test]
fn cancellation_propagates_to_the_matching_physical_attempt() {
    let block = Arc::new(BlockState::default());
    let cancelled = McpError {
        code: McpErrorCode::RequestCancelled as i64,
        message: "cancelled upstream".into(),
        data: Some(json!({ "provider": "fake" })),
    };
    let provider = Arc::new(
        FakeProvider::new("fake", vec![tool("wait")])
            .with_result(Err(ProviderError(cancelled.clone())))
            .blocking(Arc::clone(&block)),
    );
    let gateway = Arc::new(gateway(Arc::clone(&provider)));
    initialize(&gateway);

    let calling_gateway = Arc::clone(&gateway);
    let call_thread = thread::spawn(move || {
        invoke(
            &calling_gateway,
            json!({
                "jsonrpc": "2.0", "id": "in-flight", "method": "tools/call",
                "params": { "name": "fake.wait", "arguments": {} }
            }),
            &context("logical:wait"),
        )
    });

    let mut started = block.started.lock().unwrap();
    while !*started {
        started = block.changed.wait(started).unwrap();
    }
    drop(started);

    let duplicate = invoke(
        &gateway,
        json!({
            "jsonrpc": "2.0", "id": "in-flight", "method": "tools/call",
            "params": { "name": "fake.wait", "arguments": {} }
        }),
        &context("logical:duplicate-id"),
    );
    assert_eq!(duplicate["error"]["code"], -32_600);

    let wrong_scope = GatewayRequestContext::new(
        AuthorizationScopeId::new("scope:other").unwrap(),
        LogicalCallId::new("logical:wrong-scope-cancel").unwrap(),
    );
    assert!(
        gateway
            .process_bytes(
                br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"in-flight"}}"#,
                &wrong_scope,
                EphemeralSecrets::empty(),
            )
            .is_none()
    );
    assert!(provider.cancellations.lock().unwrap().is_empty());

    let notification = gateway.process_bytes(
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"in-flight","reason":"unused secret reason"}}"#,
        &context("logical:cancel-notification"),
        EphemeralSecrets::empty(),
    );
    assert!(notification.is_none());

    let response = call_thread.join().unwrap();
    assert_eq!(response["error"], serde_json::to_value(cancelled).unwrap());
    let calls = provider.calls.lock().unwrap();
    let cancellations = provider.cancellations.lock().unwrap();
    assert_eq!(cancellations.len(), 1);
    assert_eq!(cancellations[0].logical_call_id, calls[0].logical_call_id);
    assert_eq!(
        cancellations[0].physical_attempt_id,
        calls[0].physical_attempt_id
    );
}

#[test]
fn audit_records_are_secret_free_and_credentials_are_ephemeral() {
    let secret = "do-not-log-argument-or-result";
    let credential = b"credential-do-not-log";
    let provider = Arc::new(
        FakeProvider::new("fake", vec![tool("echo")]).with_result(Ok(json!({
            "content": [{ "type": "text", "text": secret }]
        }))),
    );
    let audit = Arc::new(MemoryAudit::default());
    let gateway = gateway(Arc::clone(&provider)).with_audit_sink(audit.clone());
    initialize(&gateway);
    let entries = [EphemeralSecret {
        name: "token",
        value: credential,
    }];
    let response = decode(
        gateway.process_bytes(
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "fake.echo", "arguments": { "value": secret } }
            }))
            .unwrap(),
            &context("logical:secret"),
            EphemeralSecrets::new(&entries),
        ),
    );
    assert_eq!(response["result"]["content"][0]["text"], secret);
    assert_eq!(
        provider.observed_secret.lock().unwrap().as_deref(),
        Some(credential.as_slice())
    );
    let encoded_audit = serde_json::to_string(&*audit.events.lock().unwrap()).unwrap();
    assert!(!encoded_audit.contains(secret));
    assert!(!encoded_audit.contains("credential-do-not-log"));
}

#[test]
fn non_read_only_tools_transparently_bypass_reuse_and_reach_the_provider() {
    let provider = Arc::new(
        FakeProvider::new(
            "fake",
            vec![
                tool("read"),
                tool("mutate"),
                tool("external"),
                tool("privileged"),
                tool("unknown"),
            ],
        )
        .with_effect("mutate", EffectClass::Mutating)
        .with_effect("external", EffectClass::ExternalSideEffect)
        .with_effect("privileged", EffectClass::Privileged)
        .with_effect("unknown", EffectClass::Unknown),
    );
    let gateway = gateway(Arc::clone(&provider));
    initialize(&gateway);

    for (id, name, logical) in [
        (2, "fake.read", "logical:read"),
        (3, "fake.mutate", "logical:mutate"),
        (4, "fake.external", "logical:external"),
        (5, "fake.privileged", "logical:privileged"),
        (6, "fake.unknown", "logical:unknown"),
    ] {
        let response = invoke(
            &gateway,
            json!({
                "jsonrpc":"2.0", "id":id, "method":"tools/call",
                "params":{"name":name,"arguments":{}}
            }),
            &context(logical),
        );
        assert!(response.get("result").is_some());
    }
    let calls = provider.calls.lock().unwrap();
    assert_eq!(
        calls[0].translation.disposition(),
        ReuseDispositionV1::EligibleForStateEvaluation
    );
    for call in &calls[1..] {
        assert_eq!(
            call.translation.disposition(),
            ReuseDispositionV1::BypassReuse
        );
        assert!(!call.translation.permits_reuse());
    }
}

#[test]
fn annotations_cannot_make_unknown_or_mutating_tools_replayable() {
    let mut annotated = tool("annotated");
    annotated.annotations = Some(json!({
        "readOnlyHint": true,
        "destructiveHint": false,
        "openWorldHint": false
    }));
    let untrusted_provider = Arc::new(
        FakeProvider::new("untrusted", vec![annotated.clone()])
            .with_effect("annotated", EffectClass::Unknown),
    );
    let trusted_provider = Arc::new(
        FakeProvider::new("trusted", vec![annotated.clone()])
            .with_effect("annotated", EffectClass::Unknown),
    );
    let mutating_provider = Arc::new(
        FakeProvider::new("mutating", vec![annotated])
            .with_effect("annotated", EffectClass::Mutating),
    );
    let gateway = McpGateway::new(
        vec![
            ProviderRegistration::untrusted(untrusted_provider),
            ProviderRegistration::trusted_annotations(trusted_provider),
            ProviderRegistration::trusted_annotations(mutating_provider),
        ],
        GatewayLimits::default(),
    )
    .unwrap();
    initialize(&gateway);
    let listed = invoke(
        &gateway,
        json!({ "jsonrpc":"2.0", "id":2, "method":"tools/list" }),
        &context("logical:list-annotations"),
    );
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools[0]["name"], "mutating.annotated");
    assert_eq!(tools[0]["_meta"]["again.dev/effectClass"], "mutating");
    assert_eq!(tools[1]["name"], "trusted.annotated");
    assert_eq!(tools[1]["_meta"]["again.dev/effectClass"], "unknown");
    assert_eq!(tools[2]["name"], "untrusted.annotated");
    assert_eq!(tools[2]["_meta"]["again.dev/effectClass"], "unknown");
    for tool in tools {
        assert_eq!(tool["_meta"]["again.dev/reuseDisposition"], "bypass_reuse");
    }
}

fn identities_for(provider: FakeProvider) -> (String, String) {
    let gateway = gateway(Arc::new(provider));
    initialize(&gateway);
    let listed = invoke(
        &gateway,
        json!({ "jsonrpc":"2.0", "id":2, "method":"tools/list" }),
        &context("logical:identity"),
    );
    let meta = &listed["result"]["tools"][0]["_meta"];
    (
        meta["again.dev/providerIdentity"].as_str().unwrap().into(),
        meta["again.dev/toolSchemaIdentity"]
            .as_str()
            .unwrap()
            .into(),
    )
}

#[test]
fn provider_and_tool_schema_identities_are_stable_and_separate() {
    let first = identities_for(FakeProvider::new("stable", vec![tool("echo")]));
    let second = identities_for(FakeProvider::new("stable", vec![tool("echo")]));
    assert_eq!(first, second);
    assert_eq!(first.0.len(), 64);
    assert_eq!(first.1.len(), 64);

    let changed_schema = ProviderTool::new(
        "echo",
        json!({ "type":"object", "properties": { "changed": { "type":"boolean" } } }),
    );
    let changed = identities_for(FakeProvider::new("stable", vec![changed_schema]));
    assert_eq!(first.0, changed.0);
    assert_ne!(first.1, changed.1);
}

#[test]
fn one_logical_call_can_have_distinct_physical_retry_ids() {
    let provider = Arc::new(FakeProvider::new("fake", vec![tool("echo")]));
    let gateway = gateway(Arc::clone(&provider));
    initialize(&gateway);
    let shared_context = context("logical:stable-across-retry");
    for id in [11, 12] {
        let response = invoke(
            &gateway,
            json!({
                "jsonrpc":"2.0", "id":id, "method":"tools/call",
                "params":{"name":"fake.echo","arguments":{}}
            }),
            &shared_context,
        );
        assert!(response.get("result").is_some());
    }
    let calls = provider.calls.lock().unwrap();
    assert_eq!(calls[0].logical_call_id, calls[1].logical_call_id);
    assert_eq!(
        calls[0].logical_call_id.as_str(),
        "logical:stable-across-retry"
    );
    assert_ne!(calls[0].physical_attempt_id, calls[1].physical_attempt_id);
}

#[test]
fn bounded_content_and_metadata_are_enforced_without_truncation() {
    let limits = GatewayLimits {
        max_text_bytes: 4,
        max_binary_base64_bytes: 8,
        max_metadata_bytes: 32,
        ..GatewayLimits::default()
    };
    let provider = Arc::new(
        FakeProvider::new("fake", vec![tool("large")]).with_result(Ok(json!({
            "content": [{ "type":"text", "text":"12345" }]
        }))),
    );
    let gateway = McpGateway::new(vec![ProviderRegistration::untrusted(provider)], limits).unwrap();
    initialize(&gateway);
    let response = invoke(
        &gateway,
        json!({
            "jsonrpc":"2.0", "id":2, "method":"tools/call",
            "params":{"name":"fake.large","arguments":{}}
        }),
        &context("logical:large-result"),
    );
    assert_eq!(response["error"]["code"], -32_021);
    assert_eq!(response["error"]["data"]["violation"], "bytes");
}

#[test]
fn stdio_is_newline_delimited_and_recovers_after_an_oversized_frame() {
    let limits = GatewayLimits {
        max_message_bytes: 160,
        ..GatewayLimits::default()
    };
    let gateway = McpGateway::new(Vec::new(), limits).unwrap();
    assert_eq!(gateway.limits().max_message_bytes, 160);
    let oversized = "x".repeat(161);
    let input = format!("{oversized}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}}\n");
    let mut reader = BufReader::new(Cursor::new(input.into_bytes()));
    let mut output = Vec::new();
    gateway
        .serve_stdio(
            &mut reader,
            &mut output,
            &AuthorizationScopeId::new("scope:stdio").unwrap(),
            EphemeralSecrets::empty(),
        )
        .unwrap();
    let responses = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], -32_021);
    assert_eq!(responses[1]["result"], json!({}));
}

#[test]
fn stdio_reads_cancellation_while_the_provider_call_is_running() {
    let block = Arc::new(BlockState::default());
    let cancelled = McpError {
        code: McpErrorCode::RequestCancelled as i64,
        message: "cancelled upstream".into(),
        data: None,
    };
    let provider = Arc::new(
        FakeProvider::new("fake", vec![tool("wait")])
            .with_result(Err(ProviderError(cancelled.clone())))
            .blocking(Arc::clone(&block)),
    );
    let gateway = gateway(Arc::clone(&provider));
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"stdio-test\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":\"running\",\"method\":\"tools/call\",\"params\":{\"name\":\"fake.wait\",\"arguments\":{}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":\"running\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n"
    );
    let mut reader = BufReader::new(Cursor::new(input.as_bytes()));
    let mut output = Vec::new();
    gateway
        .serve_stdio(
            &mut reader,
            &mut output,
            &AuthorizationScopeId::new("scope:stdio-cancel").unwrap(),
            EphemeralSecrets::empty(),
        )
        .unwrap();

    let responses = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 3);
    let running = responses
        .iter()
        .find(|response| response["id"] == "running")
        .unwrap();
    assert_eq!(running["error"], serde_json::to_value(cancelled).unwrap());
    assert!(
        responses
            .iter()
            .any(|response| response["id"] == 2 && response["result"] == json!({}))
    );
    let calls = provider.calls.lock().unwrap();
    let cancellations = provider.cancellations.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(cancellations.len(), 1);
    assert_eq!(
        calls[0].physical_attempt_id,
        cancellations[0].physical_attempt_id
    );
}

#[test]
fn provider_panics_before_capture_during_execution_and_during_capture_are_contained() {
    let providers = [
        FakeProvider::new("fake", vec![tool("panic")]).panicking_freshness(),
        FakeProvider::new("fake", vec![tool("panic")]).panicking(),
        FakeProvider::new("fake", vec![tool("panic")]).panicking_capture(),
    ];
    for provider in providers {
        let gateway = gateway(Arc::new(provider));
        initialize(&gateway);
        for logical in ["logical:panic-1", "logical:panic-2"] {
            let response = invoke(
                &gateway,
                json!({
                    "jsonrpc": "2.0", "id": "same", "method": "tools/call",
                    "params": { "name": "fake.panic", "arguments": {} }
                }),
                &context(logical),
            );
            assert_eq!(response["id"], "same");
            assert_eq!(
                response["error"]["code"],
                McpErrorCode::InternalError as i64
            );
            assert_eq!(response["error"]["message"], "upstream provider failed");
            assert!(response["error"].get("data").is_none());
        }
    }
}

#[test]
fn stdio_contains_provider_panic_as_payload_free_internal_error() {
    let provider = Arc::new(FakeProvider::new("fake", vec![tool("panic")]).panicking());
    let gateway = gateway(provider);
    initialize(&gateway);
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":\"panic\",\"method\":\"tools/call\",\"params\":{\"name\":\"fake.panic\",\"arguments\":{}}}\n";
    let mut reader = BufReader::new(Cursor::new(input));
    let mut output = Vec::new();
    gateway
        .serve_stdio(
            &mut reader,
            &mut output,
            &AuthorizationScopeId::new("scope:stdio-panic").unwrap(),
            EphemeralSecrets::empty(),
        )
        .unwrap();

    let response: Value = serde_json::from_slice(output.strip_suffix(b"\n").unwrap()).unwrap();
    assert_eq!(response["id"], "panic");
    assert_eq!(
        response["error"]["code"],
        McpErrorCode::InternalError as i64
    );
    assert_eq!(response["error"]["message"], "upstream provider failed");
    assert!(response["error"].get("data").is_none());
}

#[test]
fn stdio_eof_cancels_the_exact_active_attempt_and_drains_the_response() {
    let provider = Arc::new(AttemptProvider::new());
    let gateway = Arc::new(attempt_gateway(Arc::clone(&provider)));
    initialize(&gateway);
    let (input_sender, input_receiver) = mpsc::channel();
    let (line_sender, line_receiver) = mpsc::channel();
    let serving_gateway = Arc::clone(&gateway);
    let server = thread::spawn(move || {
        let mut reader = BufReader::new(ChannelReader::new(input_receiver));
        let mut writer = LineWriter {
            pending: Vec::new(),
            lines: line_sender,
        };
        serving_gateway.serve_stdio(
            &mut reader,
            &mut writer,
            &AuthorizationScopeId::new("scope:stdio-eof").unwrap(),
            EphemeralSecrets::empty(),
        )
    });

    input_sender
        .send(encoded_line(json!({
            "jsonrpc":"2.0", "id":"active", "method":"tools/call",
            "params":{"name":"attempts.wait","arguments":{}}
        })))
        .unwrap();
    provider.wait_for_started(1);
    drop(input_sender);
    provider.wait_for_cancellations(1);
    server.join().unwrap().unwrap();

    let response: Value =
        serde_json::from_slice(&line_receiver.recv_timeout(Duration::from_secs(2)).unwrap())
            .unwrap();
    assert_eq!(response["id"], "active");
    assert_eq!(
        response["error"]["code"],
        McpErrorCode::RequestCancelled as i64
    );
    assert!(line_receiver.try_recv().is_err());
    let calls = provider.calls.lock().unwrap();
    let cancellations = provider.cancellations.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(cancellations.len(), 1);
    assert_eq!(
        calls[0].physical_attempt_id,
        cancellations[0].physical_attempt_id
    );
}

#[test]
fn writer_failure_cancels_active_work_and_rejects_later_frames() {
    let provider = Arc::new(AttemptProvider::new());
    let gateway = Arc::new(attempt_gateway(Arc::clone(&provider)));
    initialize(&gateway);
    let (input_sender, input_receiver) = mpsc::channel();
    let serving_gateway = Arc::clone(&gateway);
    let server = thread::spawn(move || {
        let mut reader = BufReader::new(ChannelReader::new(input_receiver));
        let mut writer = FailingWriter;
        serving_gateway.serve_stdio(
            &mut reader,
            &mut writer,
            &AuthorizationScopeId::new("scope:stdio-writer-failure").unwrap(),
            EphemeralSecrets::empty(),
        )
    });

    input_sender
        .send(encoded_line(json!({
            "jsonrpc":"2.0", "id":"waiting", "method":"tools/call",
            "params":{"name":"attempts.wait","arguments":{}}
        })))
        .unwrap();
    provider.wait_for_started(1);
    input_sender
        .send(encoded_line(json!({
            "jsonrpc":"2.0", "id":"trigger", "method":"tools/call",
            "params":{"name":"attempts.fast","arguments":{}}
        })))
        .unwrap();
    provider.wait_for_started(2);
    provider.wait_for_cancellations(1);

    input_sender
        .send(encoded_line(json!({
            "jsonrpc":"2.0", "id":"must-not-run", "method":"tools/call",
            "params":{"name":"attempts.fast","arguments":{}}
        })))
        .unwrap();
    drop(input_sender);
    let error = server.join().unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(provider.calls.lock().unwrap().len(), 2);
    assert_eq!(provider.state.lock().unwrap().started.len(), 2);
}

#[test]
fn stdio_saturation_refuses_the_seventeenth_provider_execution() {
    let provider = Arc::new(AttemptProvider::new());
    let gateway = Arc::new(attempt_gateway(Arc::clone(&provider)));
    initialize(&gateway);
    let mut input = Vec::new();
    for id in 0..17 {
        input.extend(encoded_line(json!({
            "jsonrpc":"2.0", "id":id, "method":"tools/call",
            "params":{"name":"attempts.wait","arguments":{}}
        })));
    }
    let gate = Arc::new((Mutex::new(WriterGateState::default()), Condvar::new()));
    let server_gate = Arc::clone(&gate);
    let serving_gateway = Arc::clone(&gateway);
    let server = thread::spawn(move || {
        let mut reader = BufReader::new(Cursor::new(input));
        let mut writer = BlockingWriter {
            gate: server_gate,
            bytes: Vec::new(),
        };
        serving_gateway.serve_stdio(
            &mut reader,
            &mut writer,
            &AuthorizationScopeId::new("scope:stdio-saturation").unwrap(),
            EphemeralSecrets::empty(),
        )
    });

    provider.wait_for_started(16);
    let (state, changed) = &*gate;
    let state = state.lock().unwrap();
    let (mut state, timeout) = changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| !state.entered)
        .unwrap();
    assert!(!timeout.timed_out(), "writer never observed a response");
    assert_eq!(provider.calls.lock().unwrap().len(), 16);
    state.released = true;
    changed.notify_all();
    drop(state);

    server.join().unwrap().unwrap();
    provider.wait_for_cancellations(16);
    assert_eq!(provider.calls.lock().unwrap().len(), 16);
}

#[test]
fn completed_cancellation_does_not_poison_a_reused_request_id() {
    let provider = Arc::new(AttemptProvider::new());
    let gateway = Arc::new(attempt_gateway(Arc::clone(&provider)));
    initialize(&gateway);
    let first_gateway = Arc::clone(&gateway);
    let first = thread::spawn(move || {
        invoke(
            &first_gateway,
            json!({
                "jsonrpc":"2.0", "id":"reused", "method":"tools/call",
                "params":{"name":"attempts.wait","arguments":{}}
            }),
            &context("logical:first-attempt"),
        )
    });
    provider.wait_for_started(1);
    cancel_string_id(&gateway, "reused");
    let first = first.join().unwrap();
    assert_eq!(
        first["error"]["code"],
        McpErrorCode::RequestCancelled as i64
    );

    let second_gateway = Arc::clone(&gateway);
    let second = thread::spawn(move || {
        invoke(
            &second_gateway,
            json!({
                "jsonrpc":"2.0", "id":"reused", "method":"tools/call",
                "params":{"name":"attempts.wait","arguments":{}}
            }),
            &context("logical:second-attempt"),
        )
    });
    provider.wait_for_started(2);
    provider.stop_blocking();
    assert!(second.join().unwrap().get("result").is_some());

    let calls = provider.calls.lock().unwrap();
    let cancellations = provider.cancellations.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(cancellations.len(), 1);
    assert_eq!(
        cancellations[0].physical_attempt_id,
        calls[0].physical_attempt_id
    );
    assert_ne!(calls[0].physical_attempt_id, calls[1].physical_attempt_id);
}

#[test]
fn provider_cancellation_panic_is_contained_and_active_id_is_released() {
    let block = Arc::new(BlockState::default());
    let provider = Arc::new(
        FakeProvider::new("fake", vec![tool("wait")])
            .blocking(Arc::clone(&block))
            .panicking_cancellation(),
    );
    let gateway = Arc::new(gateway(Arc::clone(&provider)));
    initialize(&gateway);
    let calling_gateway = Arc::clone(&gateway);
    let call = thread::spawn(move || {
        invoke(
            &calling_gateway,
            json!({
                "jsonrpc":"2.0", "id":"panic-cancel", "method":"tools/call",
                "params":{"name":"fake.wait","arguments":{}}
            }),
            &context("logical:panic-cancel"),
        )
    });
    let mut started = block.started.lock().unwrap();
    while !*started {
        started = block.changed.wait(started).unwrap();
    }
    drop(started);
    cancel_string_id(&gateway, "panic-cancel");
    let response = call.join().unwrap();
    assert_eq!(
        response["error"]["code"],
        McpErrorCode::RequestCancelled as i64
    );

    let retried = invoke(
        &gateway,
        json!({
            "jsonrpc":"2.0", "id":"panic-cancel", "method":"tools/call",
            "params":{"name":"fake.wait","arguments":{}}
        }),
        &context("logical:after-panic-cancel"),
    );
    assert!(retried.get("result").is_some());
}

#[test]
fn multiple_requests_can_execute_simultaneously() {
    let provider = Arc::new(FakeProvider::new("fake", vec![tool("echo")]));
    let gateway = Arc::new(gateway(Arc::clone(&provider)));
    initialize(&gateway);
    let workers = (0..16)
        .map(|id| {
            let gateway = Arc::clone(&gateway);
            thread::spawn(move || {
                let response = invoke(
                    &gateway,
                    json!({
                        "jsonrpc":"2.0", "id":id, "method":"tools/call",
                        "params":{"name":"fake.echo","arguments":{"value":id.to_string()}}
                    }),
                    &context(&format!("logical:parallel-{id}")),
                );
                assert!(response.get("result").is_some());
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
    let calls = provider.calls.lock().unwrap();
    assert_eq!(calls.len(), 16);
    let physical_ids = calls
        .iter()
        .map(|call| call.physical_attempt_id.get())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(physical_ids.len(), 16);
}
