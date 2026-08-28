use std::any::Any;
use std::collections::BTreeSet;
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[allow(dead_code)]
#[path = "../src/agent_gateway/context.rs"]
mod context;
#[allow(dead_code)]
#[path = "../src/agent_gateway/protocol.rs"]
mod protocol;

mod agent_gateway {
    pub(crate) use crate::context;
    pub(crate) use crate::protocol;
}

#[allow(dead_code)]
#[path = "../src/agent_gateway_runtime/context_compiler.rs"]
pub(crate) mod context_compiler;

#[allow(dead_code)]
#[path = "../src/mcp_gateway.rs"]
mod mcp_gateway;

use context::{
    CompletedReasoningObservationV1, ReasoningBriefInputV1, ReasoningFactScopeV1, ReasoningFactV1,
    ReasoningRecipientV1, ReasoningRetrievalIdentityV1, ReasoningScopeV1,
    ReasoningSourceReferenceV1,
};
use mcp_gateway::{
    AuthenticatedStdioRecipientV1, AuthorizationScopeId, CapturedToolResult, ConfirmedDeliveryV1,
    DeliveryConfirmationSink, EffectClass, EphemeralSecrets, Freshness, FreshnessMetadata,
    GatewayLimits, McpGateway, OpaqueReasoningAcknowledgmentV1, PreparedReasoningContextV1,
    ProviderCall, ProviderCancellation, ProviderDescriptor, ProviderError, ProviderRegistration,
    ProviderTool, ReasoningContextCandidateV1, ReasoningDeliveryCompletionV1,
    ReasoningTransportPresentationV1, ReasoningTransportRecipientV1, ReasoningTransportScopeV1,
    RetrievalGrantV2, SideEffectClassification, StructuredResultCapture, ToolCancellation,
    ToolDiscovery, ToolExecution, UpstreamProvider, authorization_scope_digest_v1,
};
use serde_json::{Value, json};

fn digest(label: &str) -> String {
    blake3::hash(label.as_bytes()).to_hex().to_string()
}

fn reasoning_input(scope: &AuthorizationScopeId) -> ReasoningBriefInputV1 {
    let scope = ReasoningScopeV1::new(
        "task-01",
        "repository-01",
        "workspace-01",
        &digest("state-01"),
        &digest("dependencies-01"),
        &authorization_scope_digest_v1(scope),
    )
    .unwrap();
    let recipient = ReasoningRecipientV1::new(
        "pending-agent",
        "pending-session",
        "pending-turn",
        &digest("pending-connection"),
        0,
        1,
    )
    .unwrap();
    let source = ReasoningSourceReferenceV1::new(
        &"a".repeat(64),
        &digest("result-source"),
        scope.repository_id(),
        scope.workspace_id(),
        scope.state_digest(),
        scope.dependency_digest(),
        scope.authorization_scope_digest(),
        "src/lib.rs:1",
    )
    .unwrap();
    let mut input = ReasoningBriefInputV1::empty(scope, recipient);
    input.known_facts.push(
        ReasoningFactV1::new(
            "fact-01",
            "repository-observation",
            &"verified repository observation remains current ".repeat(12),
            &digest("fact-value"),
            ReasoningFactScopeV1::RepositoryWide,
            None,
            vec![source.clone()],
        )
        .unwrap(),
    );
    input.completed_observations.push(
        CompletedReasoningObservationV1::new(
            "observation-01",
            "the exact full result remains available through binding-checked retrieval",
            31,
            ReasoningRetrievalIdentityV1::new(&"a".repeat(64), &digest("result-source"), 4096)
                .unwrap(),
            vec![source],
        )
        .unwrap(),
    );
    input
}

struct TestReasoningContextV1 {
    input: ReasoningBriefInputV1,
}

impl ReasoningContextCandidateV1 for TestReasoningContextV1 {
    fn scope(&self) -> ReasoningTransportScopeV1 {
        ReasoningTransportScopeV1 {
            task_id: self.input.scope.task_id().to_owned(),
            repository_id: self.input.scope.repository_id().to_owned(),
            workspace_id: self.input.scope.workspace_id().to_owned(),
            state_digest: self.input.scope.state_digest().to_owned(),
            dependency_digest: self.input.scope.dependency_digest().to_owned(),
            authorization_scope_digest: self.input.scope.authorization_scope_digest().to_owned(),
        }
    }

    fn compile(
        mut self: Box<Self>,
        recipient: &ReasoningTransportRecipientV1,
        acknowledgment: Option<&(dyn Any + Send + Sync)>,
    ) -> Result<PreparedReasoningContextV1, ()> {
        let recipient = ReasoningRecipientV1::new(
            &recipient.agent_id,
            &recipient.session_id,
            &recipient.turn_id,
            &recipient.connection_generation,
            recipient.compaction_generation,
            recipient.lifecycle_generation,
        )
        .map_err(|_| ())?;
        self.input.recipient = recipient.clone();
        let acknowledgment = acknowledgment.and_then(|value| {
            value.downcast_ref::<context_compiler::ReasoningDeliveryAcknowledgmentV1>()
        });
        let compiled = context_compiler::compile_reasoning_brief_v1(
            &self.input,
            context_compiler::ReasoningBriefPresentationRequestV1::PreferCompact { acknowledgment },
        )
        .map_err(|_| ())?;
        let brief = serde_json::from_slice(compiled.bytes()).map_err(|_| ())?;
        let metrics = serde_json::to_value(compiled.metrics()).map_err(|_| ())?;
        let (presentation, completion) = match compiled.presentation() {
            context_compiler::ReasoningBriefPresentationV1::Full => (
                ReasoningTransportPresentationV1::Full,
                Some(Box::new(TestReasoningCompletionV1 {
                    recipient,
                    compiled,
                }) as Box<dyn ReasoningDeliveryCompletionV1>),
            ),
            context_compiler::ReasoningBriefPresentationV1::CompactReference => {
                (ReasoningTransportPresentationV1::CompactReference, None)
            }
        };
        Ok(PreparedReasoningContextV1 {
            presentation,
            brief,
            metrics,
            completion,
        })
    }
}

struct TestReasoningCompletionV1 {
    recipient: ReasoningRecipientV1,
    compiled: context_compiler::CompiledReasoningBriefV1,
}

impl ReasoningDeliveryCompletionV1 for TestReasoningCompletionV1 {
    fn complete(self: Box<Self>) -> Result<OpaqueReasoningAcknowledgmentV1, ()> {
        let acknowledgment = context_compiler::complete_reasoning_brief_delivery_v1(
            &self.recipient,
            &self.compiled,
            self.compiled.bytes(),
            true,
            true,
            true,
        )
        .map_err(|_| ())?;
        Ok(Arc::new(acknowledgment))
    }
}

struct ReasoningProvider {
    input: ReasoningBriefInputV1,
}

impl ToolDiscovery for ReasoningProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "fixture".to_owned(),
            implementation: "fixture.reasoning-provider.v1".to_owned(),
            version: "1".to_owned(),
            endpoint_identity: "local-fixture".to_owned(),
        }
    }

    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError> {
        Ok(vec![ProviderTool::new(
            "observe",
            json!({"type": "object", "additionalProperties": false}),
        )])
    }
}

impl FreshnessMetadata for ReasoningProvider {
    fn freshness(&self) -> Freshness {
        Freshness {
            revision: "fixture-state-v1".to_owned(),
            observed_at_unix_ms: None,
        }
    }
}

impl SideEffectClassification for ReasoningProvider {
    fn classify_effect(&self, _upstream_tool_name: &str) -> EffectClass {
        EffectClass::ReadOnly
    }
}

impl ToolExecution for ReasoningProvider {
    fn execute(
        &self,
        _call: ProviderCall,
        _secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError> {
        Ok(json!({
            "content": [{"type": "text", "text": "full exact result"}],
            "structuredContent": {"status": "verified"}
        }))
    }
}

impl StructuredResultCapture for ReasoningProvider {
    fn capture_result(&self, result: Value) -> Result<CapturedToolResult, ProviderError> {
        Ok(CapturedToolResult::exact_with_delivery_and_reasoning(
            result,
            "a".repeat(64),
            "a".repeat(64),
            protocol::DeliveryStreamsV1::new(0, &"b".repeat(64), 4096, &"c".repeat(64), 0).unwrap(),
            Some(Box::new(TestReasoningContextV1 {
                input: self.input.clone(),
            })),
        ))
    }
}

impl ToolCancellation for ReasoningProvider {
    fn cancel(&self, _cancellation: ProviderCancellation) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[derive(Default)]
struct ResponseGate {
    ids: Mutex<BTreeSet<i64>>,
    changed: Condvar,
}

impl ResponseGate {
    fn observe(&self, id: i64) {
        self.ids
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(id);
        self.changed.notify_all();
    }

    fn wait(&self, id: i64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut ids = self.ids.lock().unwrap_or_else(|poison| poison.into_inner());
        while !ids.contains(&id) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for response {id}");
            let (next, timeout) = self.changed.wait_timeout(ids, remaining).unwrap();
            ids = next;
            assert!(!timeout.timed_out(), "timed out waiting for response {id}");
        }
    }
}

#[derive(Clone)]
enum ReaderGate {
    None,
    Response(i64),
    Flag(Arc<AtomicBool>),
}

struct GatedReader {
    frames: Vec<(ReaderGate, Vec<u8>)>,
    frame: usize,
    offset: usize,
    eof_gate: ReaderGate,
    responses: Arc<ResponseGate>,
}

impl GatedReader {
    fn new(
        frames: Vec<(ReaderGate, Value)>,
        eof_gate: ReaderGate,
        responses: Arc<ResponseGate>,
    ) -> Self {
        Self {
            frames: frames
                .into_iter()
                .map(|(gate, value)| {
                    let mut bytes = serde_json::to_vec(&value).unwrap();
                    bytes.push(b'\n');
                    (gate, bytes)
                })
                .collect(),
            frame: 0,
            offset: 0,
            eof_gate,
            responses,
        }
    }

    fn wait_for(&self, gate: &ReaderGate) {
        match gate {
            ReaderGate::None => {}
            ReaderGate::Response(id) => self.responses.wait(*id),
            ReaderGate::Flag(flag) => {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !flag.load(Ordering::Acquire) {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for writer failure"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
}

impl BufRead for GatedReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.frame < self.frames.len() && self.offset == self.frames[self.frame].1.len() {
            self.frame += 1;
            self.offset = 0;
        }
        if self.frame == self.frames.len() {
            self.wait_for(&self.eof_gate);
            return Ok(&[]);
        }
        if self.offset == 0 {
            let gate = self.frames[self.frame].0.clone();
            self.wait_for(&gate);
        }
        Ok(&self.frames[self.frame].1[self.offset..])
    }

    fn consume(&mut self, amount: usize) {
        self.offset = self.offset.saturating_add(amount);
    }
}

impl Read for GatedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let copied = available.len().min(output.len());
        output[..copied].copy_from_slice(&available[..copied]);
        self.consume(copied);
        Ok(copied)
    }
}

struct RecordingWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    parsed: usize,
    responses: Arc<ResponseGate>,
}

impl RecordingWriter {
    fn new(bytes: Arc<Mutex<Vec<u8>>>, responses: Arc<ResponseGate>) -> Self {
        Self {
            bytes,
            parsed: 0,
            responses,
        }
    }
}

impl Write for RecordingWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.bytes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let bytes = self
            .bytes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        while let Some(relative) = bytes[self.parsed..].iter().position(|byte| *byte == b'\n') {
            let end = self.parsed + relative;
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes[self.parsed..end])
                && let Some(id) = value.get("id").and_then(Value::as_i64)
            {
                self.responses.observe(id);
            }
            self.parsed = end + 1;
        }
        Ok(())
    }
}

struct PartialWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    response_objects: usize,
    parsed: usize,
    responses: Arc<ResponseGate>,
    failed: Arc<AtomicBool>,
}

impl Write for PartialWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.first() == Some(&b'{') {
            self.response_objects += 1;
        }
        if self.response_objects >= 2 {
            let partial = input.len().max(2) / 2;
            self.bytes
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .extend_from_slice(&input[..partial]);
            self.failed.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected partial response write",
            ));
        }
        self.bytes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let bytes = self
            .bytes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        while let Some(relative) = bytes[self.parsed..].iter().position(|byte| *byte == b'\n') {
            let end = self.parsed + relative;
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes[self.parsed..end])
                && let Some(id) = value.get("id").and_then(Value::as_i64)
            {
                self.responses.observe(id);
            }
            self.parsed = end + 1;
        }
        Ok(())
    }
}

fn initialize(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "reasoning-test", "version": "1"}
        }
    })
}

fn call(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "fixture.observe", "arguments": {}}
    })
}

fn responses(bytes: &Arc<Mutex<Vec<u8>>>) -> Vec<Value> {
    bytes
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect()
}

fn response(responses: &[Value], id: i64) -> &Value {
    responses
        .iter()
        .find(|response| response.get("id").and_then(Value::as_i64) == Some(id))
        .unwrap()
}

fn presentation(response: &Value) -> &str {
    response["result"]["_meta"]["again"]["reasoningContext"]["presentation"]
        .as_str()
        .unwrap()
}

fn gateway(scope: &AuthorizationScopeId) -> McpGateway {
    let provider: Arc<dyn UpstreamProvider> = Arc::new(ReasoningProvider {
        input: reasoning_input(scope),
    });
    McpGateway::new(
        vec![ProviderRegistration::trusted_annotations(provider)],
        GatewayLimits::default(),
    )
    .unwrap()
}

struct ExplicitReceiptSink;

impl DeliveryConfirmationSink for ExplicitReceiptSink {
    fn confirm_delivery_and_issue_retrieval(
        &self,
        delivery: &ConfirmedDeliveryV1,
    ) -> Result<RetrievalGrantV2, protocol::DeliveryAuthorityRefusalV1> {
        Ok(RetrievalGrantV2::from_store(
            "reasoning-test-grant".to_owned(),
            "reasoning-test-token".to_owned(),
            delivery.gateway_result_id().to_owned(),
            9_999_999_999_999,
        ))
    }
}

#[test]
fn write_and_flush_without_client_acknowledgment_never_compacts_reasoning() {
    let scope = AuthorizationScopeId::new("reasoning-scope").unwrap();
    let gateway = gateway(&scope);
    let confirmations = gateway.reasoning_confirmation_counter_for_test_v1();
    let gate = Arc::new(ResponseGate::default());
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let frames = vec![
        (ReaderGate::None, initialize(0)),
        (ReaderGate::Response(0), call(1)),
        (ReaderGate::Response(1), call(2)),
        (
            ReaderGate::Response(2),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/again/context-compacted",
                "params": {"compactionGeneration": 1}
            }),
        ),
        (ReaderGate::None, call(3)),
        (
            ReaderGate::Response(3),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 999, "reason": "cancel context"}
            }),
        ),
        (ReaderGate::None, call(4)),
    ];
    let mut reader = GatedReader::new(frames, ReaderGate::Response(4), Arc::clone(&gate));
    let mut writer = RecordingWriter::new(Arc::clone(&bytes), gate);
    let recipient =
        AuthenticatedStdioRecipientV1::issue_for_test("agent", "session", "turn", 0).unwrap();
    gateway
        .serve_stdio_for_authenticated_recipient_v1(
            &mut reader,
            &mut writer,
            &scope,
            EphemeralSecrets::default(),
            recipient,
        )
        .unwrap();

    let output = responses(&bytes);
    assert_eq!(presentation(response(&output, 1)), "full");
    assert_eq!(presentation(response(&output, 2)), "full");
    assert_eq!(presentation(response(&output, 3)), "full");
    assert_eq!(presentation(response(&output, 4)), "full");
    assert_eq!(
        response(&output, 1)["result"]["_meta"]["again"]["reasoningContext"]["metrics"]["confirmed_tokens_avoided"],
        0
    );
    assert_eq!(
        response(&output, 2)["result"]["_meta"]["again"]["reasoningContext"]["metrics"]["confirmed_tokens_avoided"],
        0
    );
    assert_eq!(
        response(&output, 2)["result"]["_meta"]["again"]["reasoningContext"]["brief"]["full_result_retrieval"]
            [0]["result_id"],
        "a".repeat(64)
    );
    assert_eq!(
        response(&output, 4)["result"]["content"][0]["text"],
        "full exact result"
    );
    assert_eq!(gateway.reasoning_acknowledgment_count_for_test_v1(), 0);
    assert_eq!(confirmations.load(Ordering::Acquire), 0);

    for (id, session, turn) in [(5, "session", "turn"), (6, "session-2", "turn-2")] {
        let gate = Arc::new(ResponseGate::default());
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut reader = GatedReader::new(
            vec![(ReaderGate::None, call(id))],
            ReaderGate::Response(id),
            Arc::clone(&gate),
        );
        let mut writer = RecordingWriter::new(Arc::clone(&bytes), gate);
        let recipient =
            AuthenticatedStdioRecipientV1::issue_for_test("agent", session, turn, 0).unwrap();
        gateway
            .serve_stdio_for_authenticated_recipient_v1(
                &mut reader,
                &mut writer,
                &scope,
                EphemeralSecrets::default(),
                recipient,
            )
            .unwrap();
        assert_eq!(presentation(response(&responses(&bytes), id)), "full");
    }
}

#[cfg(unix)]
#[test]
fn explicit_response_bound_acknowledgment_enables_exact_recipient_compaction() {
    fn send(stream: &mut UnixStream, value: &Value) {
        serde_json::to_writer(&mut *stream, value).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    fn read(reader: &mut BufReader<UnixStream>) -> Value {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        serde_json::from_str(&line).unwrap()
    }

    let scope = AuthorizationScopeId::new("reasoning-explicit-ack-scope").unwrap();
    let gateway =
        Arc::new(gateway(&scope).with_delivery_confirmation_sink(Arc::new(ExplicitReceiptSink)));
    let confirmations = gateway.reasoning_confirmation_counter_for_test_v1();
    let (mut client, server) = UnixStream::pair().unwrap();
    let mut client_reader = BufReader::new(client.try_clone().unwrap());
    let serving = Arc::clone(&gateway);
    let serving_scope = scope.clone();
    let server_thread = std::thread::spawn(move || {
        let mut writer = server;
        let mut reader = BufReader::new(writer.try_clone().unwrap());
        let recipient =
            AuthenticatedStdioRecipientV1::issue_for_test("agent", "session", "turn", 0).unwrap();
        serving
            .serve_stdio_for_authenticated_recipient_v1(
                &mut reader,
                &mut writer,
                &serving_scope,
                EphemeralSecrets::default(),
                recipient,
            )
            .unwrap();
    });

    send(
        &mut client,
        &json!({
            "jsonrpc":"2.0","id":"init","method":"initialize",
            "params":{
                "protocolVersion":"2025-06-18",
                "capabilities":{"experimental":{"again":{"deliveryReceipts":{"schemaVersion":2}}}},
                "clientInfo":{"name":"reasoning-explicit-ack","version":"1"}
            }
        }),
    );
    assert_eq!(read(&mut client_reader)["id"], "init");
    send(&mut client, &call(1));
    let first = read(&mut client_reader);
    assert_eq!(presentation(&first), "full");
    let challenge = read(&mut client_reader);
    assert_eq!(
        challenge["method"],
        "notifications/again/delivery-challenge"
    );
    send(
        &mut client,
        &json!({
            "jsonrpc":"2.0","id":"ack","method":"again/delivery/ack",
            "params":challenge["params"]["challenge"].clone()
        }),
    );
    assert_eq!(read(&mut client_reader)["result"]["status"], "confirmed");
    assert_eq!(confirmations.load(Ordering::Acquire), 1);

    send(&mut client, &call(2));
    let compact = read(&mut client_reader);
    assert_eq!(presentation(&compact), "compact_reference");
    assert!(
        compact["result"]["_meta"]["again"]["reasoningContext"]["metrics"]
            ["confirmed_tokens_avoided"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        read(&mut client_reader)["method"],
        "notifications/again/delivery-challenge"
    );
    drop(client_reader);
    drop(client);
    server_thread.join().unwrap();
}

#[test]
fn partial_response_write_issues_no_reasoning_acknowledgment_or_savings() {
    let scope = AuthorizationScopeId::new("partial-scope").unwrap();
    let gateway = gateway(&scope);
    let confirmations = gateway.reasoning_confirmation_counter_for_test_v1();
    let gate = Arc::new(ResponseGate::default());
    let failed = Arc::new(AtomicBool::new(false));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let mut reader = GatedReader::new(
        vec![
            (ReaderGate::None, initialize(0)),
            (ReaderGate::Response(0), call(1)),
        ],
        ReaderGate::Flag(Arc::clone(&failed)),
        Arc::clone(&gate),
    );
    let mut writer = PartialWriter {
        bytes,
        response_objects: 0,
        parsed: 0,
        responses: gate,
        failed,
    };
    let recipient =
        AuthenticatedStdioRecipientV1::issue_for_test("agent", "session", "turn", 0).unwrap();
    assert!(
        gateway
            .serve_stdio_for_authenticated_recipient_v1(
                &mut reader,
                &mut writer,
                &scope,
                EphemeralSecrets::default(),
                recipient,
            )
            .is_err()
    );
    assert_eq!(confirmations.load(Ordering::Acquire), 0);
    assert_eq!(gateway.reasoning_acknowledgment_count_for_test_v1(), 0);
}
