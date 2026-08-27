//! Bounded MCP 2025-06-18 stdio gateway and upstream provider boundary.
//!
//! The gateway owns protocol validation, stable namespacing, conservative
//! replay classification, cancellation routing, and result bounds.  It does
//! not persist credentials, approve sensitive calls, invoke an AI model, or
//! perform local command execution.

use std::cell::Cell;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value, json};
use thiserror::Error;

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
pub const GATEWAY_NAME: &str = "again-mcp-gateway";
pub const GATEWAY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// All parser and provider-output bounds are explicit and independently
/// configurable.  Defaults are deliberately finite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayLimits {
    pub max_message_bytes: usize,
    pub max_json_depth: usize,
    pub max_json_nodes: usize,
    pub max_argument_bytes: usize,
    pub max_argument_depth: usize,
    pub max_argument_nodes: usize,
    pub max_schema_bytes: usize,
    pub max_tools: usize,
    pub max_tool_list_bytes: usize,
    pub max_result_bytes: usize,
    pub max_result_depth: usize,
    pub max_result_nodes: usize,
    pub max_content_items: usize,
    pub max_text_bytes: usize,
    pub max_binary_base64_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_metadata_depth: usize,
    pub max_metadata_nodes: usize,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 1_048_576,
            max_json_depth: 48,
            max_json_nodes: 50_000,
            max_argument_bytes: 262_144,
            max_argument_depth: 24,
            max_argument_nodes: 10_000,
            max_schema_bytes: 262_144,
            max_tools: 1_024,
            max_tool_list_bytes: 8_388_608,
            max_result_bytes: 8_388_608,
            max_result_depth: 48,
            max_result_nodes: 50_000,
            max_content_items: 128,
            max_text_bytes: 1_048_576,
            max_binary_base64_bytes: 5_592_408,
            max_metadata_bytes: 65_536,
            max_metadata_depth: 12,
            max_metadata_nodes: 2_048,
        }
    }
}

#[derive(Clone, Eq, Error, PartialEq)]
pub enum GatewayInputError {
    #[error("JSON-RPC frame is {actual} bytes; limit is {limit}")]
    MessageTooLarge { limit: usize, actual: usize },
    #[error("malformed JSON")]
    MalformedJson,
    #[error("duplicate JSON object key")]
    DuplicateKey,
    #[error("JSON depth {actual} exceeds limit {limit}")]
    DepthLimit { limit: usize, actual: usize },
    #[error("JSON node count exceeds limit {limit}")]
    NodeLimit { limit: usize },
    #[error("invalid JSON-RPC request: {message}")]
    InvalidRequest { message: String },
}

impl fmt::Debug for GatewayInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum McpErrorCode {
    ParseError = -32_700,
    InvalidRequest = -32_600,
    MethodNotFound = -32_601,
    InvalidParams = -32_602,
    InternalError = -32_603,
    NotInitialized = -32_020,
    LimitExceeded = -32_021,
    RequestCancelled = -32_800,
}

/// JSON-RPC/MCP error object.  Provider errors use this same type and are
/// forwarded without code, message, or data rewriting.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl fmt::Debug for McpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpError")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .field("data", &self.data.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl McpError {
    #[must_use]
    pub fn typed(code: McpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as i64,
            message: message.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError(pub McpError);

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "upstream MCP error {}", self.0.code)
    }
}

impl std::error::Error for ProviderError {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthorizationScopeId(String);

impl AuthorizationScopeId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_boundary_identifier("authorization scope", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LogicalCallId(String);

impl LogicalCallId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        validate_boundary_identifier("logical call", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PhysicalAttemptId(u64);

impl PhysicalAttemptId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("invalid {kind} identifier")]
pub struct IdentifierError {
    kind: &'static str,
}

fn validate_boundary_identifier(kind: &'static str, value: &str) -> Result<(), IdentifierError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(IdentifierError { kind })
    }
}

/// A borrowed secret entry.  Secret values deliberately implement neither
/// `Debug` nor serialization.
#[derive(Clone, Copy)]
pub struct EphemeralSecret<'a> {
    pub name: &'a str,
    pub value: &'a [u8],
}

/// Credentials are borrowed for one provider invocation and are never stored
/// by the gateway or included in [`ProviderCall`].
#[derive(Clone, Copy, Default)]
pub struct EphemeralSecrets<'a> {
    entries: &'a [EphemeralSecret<'a>],
}

impl<'a> EphemeralSecrets<'a> {
    #[must_use]
    pub const fn new(entries: &'a [EphemeralSecret<'a>]) -> Self {
        Self { entries }
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self { entries: &[] }
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRequestContext {
    pub authorization_scope: AuthorizationScopeId,
    pub logical_call_id: LogicalCallId,
}

impl GatewayRequestContext {
    #[must_use]
    pub fn new(authorization_scope: AuthorizationScopeId, logical_call_id: LogicalCallId) -> Self {
        Self {
            authorization_scope,
            logical_call_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDescriptor {
    pub id: String,
    pub implementation: String,
    pub version: String,
    /// Stable endpoint/configuration identity.  It must not contain credentials.
    pub endpoint_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    pub revision: String,
    pub observed_at_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    ReadOnly,
    Mutating,
    ExternalSideEffect,
    Privileged,
    Unknown,
}

impl EffectClass {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Mutating => "mutating",
            Self::ExternalSideEffect => "external_side_effect",
            Self::Privileged => "privileged",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn reuse_disposition(self) -> ReuseDispositionV1 {
        if matches!(self, Self::ReadOnly) {
            ReuseDispositionV1::EligibleForStateEvaluation
        } else {
            ReuseDispositionV1::BypassReuse
        }
    }
}

/// Routing-only reuse disposition. Eligibility requests later state
/// evaluation; it is never evidence that a result may be reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseDispositionV1 {
    EligibleForStateEvaluation,
    BypassReuse,
}

impl ReuseDispositionV1 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::EligibleForStateEvaluation => "eligible_for_state_evaluation",
            Self::BypassReuse => "bypass_reuse",
        }
    }
}

/// Upstream tool definition before stable gateway namespacing.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderTool {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub annotations: Option<Value>,
    pub meta: Option<Value>,
}

impl ProviderTool {
    #[must_use]
    pub fn new(name: impl Into<String>, input_schema: Value) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: None,
            input_schema,
            output_schema: None,
            annotations: None,
            meta: None,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct CapturedToolResult {
    exact: Value,
}

impl fmt::Debug for CapturedToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapturedToolResult(<redacted>)")
    }
}

impl CapturedToolResult {
    #[must_use]
    pub fn exact(value: Value) -> Self {
        Self { exact: value }
    }

    #[must_use]
    pub fn into_exact(self) -> Value {
        self.exact
    }
}

/// Canonical, explicitly non-authoritative translation of one MCP tool call.
/// It is complete enough for a later core-lane mapping, but cannot itself
/// grant reuse.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayToolCallTranslationV1 {
    schema_version: u16,
    provider_identity: String,
    tool_schema_identity: String,
    namespaced_tool_name: String,
    upstream_tool_name: String,
    authorization_scope_identity: String,
    freshness: Freshness,
    disposition: ReuseDispositionV1,
    canonical_arguments: Vec<u8>,
    canonical_digest: [u8; 32],
}

impl fmt::Debug for GatewayToolCallTranslationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayToolCallTranslationV1")
            .field("schema_version", &self.schema_version)
            .field("disposition", &self.disposition)
            .field("canonical_digest", &self.canonical_digest)
            .field("canonical_arguments", &"<redacted>")
            .finish()
    }
}

impl GatewayToolCallTranslationV1 {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn provider_identity(&self) -> &str {
        &self.provider_identity
    }

    #[must_use]
    pub fn tool_schema_identity(&self) -> &str {
        &self.tool_schema_identity
    }

    #[must_use]
    pub fn namespaced_tool_name(&self) -> &str {
        &self.namespaced_tool_name
    }

    #[must_use]
    pub fn upstream_tool_name(&self) -> &str {
        &self.upstream_tool_name
    }

    #[must_use]
    pub fn authorization_scope_identity(&self) -> &str {
        &self.authorization_scope_identity
    }

    #[must_use]
    pub const fn freshness(&self) -> &Freshness {
        &self.freshness
    }

    #[must_use]
    pub const fn disposition(&self) -> ReuseDispositionV1 {
        self.disposition
    }

    #[must_use]
    pub fn canonical_arguments(&self) -> &[u8] {
        &self.canonical_arguments
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }

    /// This translation is an input to later authority evaluation, never an
    /// authority result.
    #[must_use]
    pub const fn permits_reuse(&self) -> bool {
        false
    }
}

#[derive(Clone, PartialEq)]
pub struct ProviderCall {
    pub logical_call_id: LogicalCallId,
    pub physical_attempt_id: PhysicalAttemptId,
    pub authorization_scope: AuthorizationScopeId,
    pub provider_identity: String,
    pub upstream_tool_name: String,
    pub namespaced_tool_name: String,
    pub arguments: Value,
    pub freshness: Freshness,
    pub effect: EffectClass,
    pub translation: GatewayToolCallTranslationV1,
}

impl fmt::Debug for ProviderCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCall")
            .field("logical_call_id", &self.logical_call_id)
            .field("physical_attempt_id", &self.physical_attempt_id)
            .field("provider_identity", &self.provider_identity)
            .field("upstream_tool_name", &self.upstream_tool_name)
            .field("namespaced_tool_name", &self.namespaced_tool_name)
            .field("arguments", &"<redacted>")
            .field("effect", &self.effect)
            .field("translation", &self.translation)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCancellation {
    pub logical_call_id: LogicalCallId,
    pub physical_attempt_id: PhysicalAttemptId,
}

pub trait ToolDiscovery: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    fn discover_tools(&self) -> Result<Vec<ProviderTool>, ProviderError>;
}

pub trait ToolExecution: Send + Sync {
    fn execute(
        &self,
        call: ProviderCall,
        secrets: EphemeralSecrets<'_>,
    ) -> Result<Value, ProviderError>;
}

pub trait ToolCancellation: Send + Sync {
    fn cancel(&self, cancellation: ProviderCancellation) -> Result<(), ProviderError>;
}

pub trait FreshnessMetadata: Send + Sync {
    fn freshness(&self) -> Freshness;
}

pub trait SideEffectClassification: Send + Sync {
    fn classify_effect(&self, upstream_tool_name: &str) -> EffectClass;
}

pub trait StructuredResultCapture: Send + Sync {
    fn capture_result(&self, result: Value) -> Result<CapturedToolResult, ProviderError>;
}

pub trait UpstreamProvider:
    ToolDiscovery
    + ToolExecution
    + ToolCancellation
    + FreshnessMetadata
    + SideEffectClassification
    + StructuredResultCapture
{
}

impl<T> UpstreamProvider for T where
    T: ToolDiscovery
        + ToolExecution
        + ToolCancellation
        + FreshnessMetadata
        + SideEffectClassification
        + StructuredResultCapture
{
}

#[derive(Clone)]
pub struct ProviderRegistration {
    provider: Arc<dyn UpstreamProvider>,
    annotations_trusted: bool,
}

impl ProviderRegistration {
    #[must_use]
    pub fn untrusted(provider: Arc<dyn UpstreamProvider>) -> Self {
        Self {
            provider,
            annotations_trusted: false,
        }
    }

    #[must_use]
    pub fn trusted_annotations(provider: Arc<dyn UpstreamProvider>) -> Self {
        Self {
            provider,
            annotations_trusted: true,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayBuildError {
    #[error("invalid provider id `{provider_id}`")]
    InvalidProviderId { provider_id: String },
    #[error("provider id `{provider_id}` is registered more than once")]
    DuplicateProvider { provider_id: String },
    #[error("provider `{provider_id}` discovery failed: {source}")]
    Discovery {
        provider_id: String,
        source: ProviderError,
    },
    #[error("invalid tool `{tool_name}` from provider `{provider_id}`: {reason}")]
    InvalidTool {
        provider_id: String,
        tool_name: String,
        reason: String,
    },
    #[error("namespaced tool collision: `{namespaced_name}`")]
    ToolCollision { namespaced_name: String },
    #[error("provider catalog exceeds gateway limits: {reason}")]
    CatalogLimit { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    ProviderError,
    Rejected,
    CancelRequested,
}

/// Secret-free audit metadata.  Raw arguments, raw results, error data,
/// credentials, and cancellation reasons are never fields in this record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAuditEvent {
    pub logical_call_id: String,
    pub physical_attempt_id: Option<u64>,
    pub authorization_scope: String,
    pub provider_identity: Option<String>,
    pub tool_schema_identity: Option<String>,
    pub effect: Option<EffectClass>,
    pub outcome: AuditOutcome,
}

pub trait GatewayAuditSink: Send + Sync {
    fn record(&self, event: GatewayAuditEvent);
}

#[derive(Default)]
pub struct NoopAuditSink;

impl GatewayAuditSink for NoopAuditSink {
    fn record(&self, _event: GatewayAuditEvent) {}
}

#[derive(Clone)]
struct ToolRoute {
    provider: Arc<dyn UpstreamProvider>,
    provider_identity: String,
    definition: ProviderTool,
    namespaced_name: String,
    schema_identity: String,
    annotations_trusted: bool,
    effect: EffectClass,
}

#[derive(Clone)]
struct ActiveCall {
    provider: Arc<dyn UpstreamProvider>,
    cancellation: ProviderCancellation,
    authorization_scope: AuthorizationScopeId,
    provider_identity: String,
    schema_identity: String,
    effect: EffectClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum JsonRpcId {
    Number(i64),
    String(String),
}

impl JsonRpcId {
    fn from_value(value: &Value) -> Result<Self, GatewayInputError> {
        match value {
            Value::String(value) if value.len() <= 128 => Ok(Self::String(value.clone())),
            Value::Number(value) => {
                value
                    .as_i64()
                    .map(Self::Number)
                    .ok_or_else(|| GatewayInputError::InvalidRequest {
                        message: "request id must be an integer representable as i64".into(),
                    })
            }
            _ => Err(GatewayInputError::InvalidRequest {
                message: "request id must be a string or integer".into(),
            }),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Number(value) => Value::Number((*value).into()),
            Self::String(value) => Value::String(value.clone()),
        }
    }
}

pub struct McpGateway {
    limits: GatewayLimits,
    routes: BTreeMap<String, ToolRoute>,
    listed_tools: Vec<Value>,
    initialized: AtomicBool,
    next_physical_attempt: AtomicU64,
    next_stdio_logical_call: AtomicU64,
    active: Mutex<BTreeMap<JsonRpcId, ActiveCall>>,
    audit: Arc<dyn GatewayAuditSink>,
}

impl McpGateway {
    pub fn new(
        registrations: Vec<ProviderRegistration>,
        limits: GatewayLimits,
    ) -> Result<Self, GatewayBuildError> {
        let mut provider_ids = BTreeSet::new();
        let mut routes = BTreeMap::new();

        for registration in registrations {
            let descriptor = registration.provider.descriptor();
            validate_provider_id(&descriptor.id)?;
            if !provider_ids.insert(descriptor.id.clone()) {
                return Err(GatewayBuildError::DuplicateProvider {
                    provider_id: descriptor.id,
                });
            }
            validate_provider_descriptor(&descriptor)?;
            let provider_identity = provider_identity(&descriptor);
            let tools = registration.provider.discover_tools().map_err(|source| {
                GatewayBuildError::Discovery {
                    provider_id: descriptor.id.clone(),
                    source,
                }
            })?;
            let mut upstream_names = BTreeSet::new();
            for definition in tools {
                validate_tool(&descriptor.id, &definition, limits)?;
                if !upstream_names.insert(definition.name.clone()) {
                    return Err(GatewayBuildError::InvalidTool {
                        provider_id: descriptor.id.clone(),
                        tool_name: definition.name,
                        reason: "duplicate upstream tool name".into(),
                    });
                }
                let namespaced_name = namespace_tool_name(&descriptor.id, &definition.name)?;
                let schema_identity = tool_schema_identity(&definition);
                let declared_effect = registration
                    .provider
                    .classify_effect(definition.name.as_str());
                let effect = effective_effect(
                    declared_effect,
                    definition.annotations.as_ref(),
                    registration.annotations_trusted,
                );
                let route = ToolRoute {
                    provider: Arc::clone(&registration.provider),
                    provider_identity: provider_identity.clone(),
                    definition,
                    namespaced_name: namespaced_name.clone(),
                    schema_identity,
                    annotations_trusted: registration.annotations_trusted,
                    effect,
                };
                if routes.insert(namespaced_name.clone(), route).is_some() {
                    return Err(GatewayBuildError::ToolCollision { namespaced_name });
                }
                if routes.len() > limits.max_tools {
                    return Err(GatewayBuildError::CatalogLimit {
                        reason: "tool count".into(),
                    });
                }
            }
        }

        let listed_tools = routes.values().map(tool_list_value).collect::<Vec<_>>();
        validate_value_bounds(
            &json!({ "tools": listed_tools }),
            limits.max_result_depth,
            limits.max_result_nodes,
            limits.max_tool_list_bytes,
        )
        .map_err(|violation| GatewayBuildError::CatalogLimit {
            reason: violation.wire_name().into(),
        })?;

        Ok(Self {
            limits,
            routes,
            listed_tools,
            initialized: AtomicBool::new(false),
            next_physical_attempt: AtomicU64::new(1),
            next_stdio_logical_call: AtomicU64::new(1),
            active: Mutex::new(BTreeMap::new()),
            audit: Arc::new(NoopAuditSink),
        })
    }

    #[must_use]
    pub fn with_audit_sink(mut self, audit: Arc<dyn GatewayAuditSink>) -> Self {
        self.audit = audit;
        self
    }

    #[must_use]
    pub const fn limits(&self) -> GatewayLimits {
        self.limits
    }

    /// Parse one JSON-RPC frame, rejecting duplicate keys before constructing a
    /// request value.
    pub fn parse_message(&self, input: &[u8]) -> Result<Value, GatewayInputError> {
        parse_bounded_json(input, self.limits)
    }

    /// Process one newline-free stdio frame.  Framing/parser failures become
    /// typed JSON-RPC error responses with a null id.
    #[must_use]
    pub fn process_bytes(
        &self,
        input: &[u8],
        context: &GatewayRequestContext,
        secrets: EphemeralSecrets<'_>,
    ) -> Option<Vec<u8>> {
        let response = match self.parse_message(input) {
            Ok(message) => self.handle_message(message, context, secrets),
            Err(error) => Some(error_response(Value::Null, input_error_to_mcp(&error))),
        };
        response.map(|value| {
            serde_json::to_vec(&value).expect("JSON-RPC response values are always serializable")
        })
    }

    /// Serve newline-delimited MCP frames without ever buffering more than the
    /// configured frame limit. Sensitive calls are never approved by this loop;
    /// mutating, external, privileged, and unknown tools are forwarded without
    /// reuse and remain subject to the upstream provider's own authorization.
    pub fn serve_stdio<R: BufRead, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        authorization_scope: &AuthorizationScopeId,
        secrets: EphemeralSecrets<'_>,
    ) -> io::Result<()> {
        while let Some(frame) = read_bounded_frame(reader, self.limits.max_message_bytes)? {
            let logical_number = self.next_stdio_logical_call.fetch_add(1, Ordering::Relaxed);
            let context = GatewayRequestContext::new(
                authorization_scope.clone(),
                LogicalCallId::new(format!("stdio:{logical_number}"))
                    .expect("generated logical call ids are valid"),
            );
            let response = match frame {
                Ok(bytes) => self.process_bytes(&bytes, &context, secrets),
                Err(error) => Some(
                    serde_json::to_vec(&error_response(Value::Null, input_error_to_mcp(&error)))
                        .expect("JSON-RPC error values are serializable"),
                ),
            };
            if let Some(response) = response {
                writer.write_all(&response)?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
        }
        Ok(())
    }

    fn handle_message(
        &self,
        message: Value,
        context: &GatewayRequestContext,
        secrets: EphemeralSecrets<'_>,
    ) -> Option<Value> {
        let request = match ParsedRequest::from_value(message) {
            Ok(request) => request,
            Err(error) => return Some(error_response(Value::Null, input_error_to_mcp(&error))),
        };
        let response_id = request.id.as_ref().map_or(Value::Null, JsonRpcId::to_value);

        match request.method.as_str() {
            "initialize" if request.id.is_some() => {
                Some(self.initialize(response_id, request.params))
            }
            "notifications/initialized" if request.id.is_none() => None,
            "ping" if request.id.is_some() => Some(success_response(response_id, json!({}))),
            "tools/list" if request.id.is_some() => {
                Some(self.list_tools(response_id, request.params))
            }
            "tools/call" if request.id.is_some() => self.call_tool(
                response_id,
                request.id.expect("checked request id"),
                request.params,
                context,
                secrets,
            ),
            "notifications/cancelled" if request.id.is_none() => {
                self.cancel(request.params, context);
                None
            }
            _ if request.id.is_none() => None,
            _ => Some(error_response(
                response_id,
                McpError::typed(McpErrorCode::MethodNotFound, "method not found"),
            )),
        }
    }

    fn initialize(&self, id: Value, params: Option<Value>) -> Value {
        if let Err(error) = validate_initialize_params(params.as_ref()) {
            return error_response(id, error);
        }
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return error_response(
                id,
                McpError::typed(
                    McpErrorCode::InvalidRequest,
                    "gateway is already initialized",
                ),
            );
        }
        success_response(
            id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": GATEWAY_NAME, "version": GATEWAY_VERSION }
            }),
        )
    }

    fn list_tools(&self, id: Value, params: Option<Value>) -> Value {
        if !self.initialized.load(Ordering::Acquire) {
            return error_response(
                id,
                McpError::typed(McpErrorCode::NotInitialized, "gateway is not initialized"),
            );
        }
        if let Some(params) = params {
            let Some(object) = params.as_object() else {
                return error_response(
                    id,
                    McpError::typed(McpErrorCode::InvalidParams, "params must be an object"),
                );
            };
            if object.get("cursor").is_some_and(|cursor| !cursor.is_null()) {
                return error_response(
                    id,
                    McpError::typed(McpErrorCode::InvalidParams, "pagination is not supported"),
                );
            }
        }
        success_response(id, json!({ "tools": self.listed_tools }))
    }

    fn call_tool(
        &self,
        response_id: Value,
        request_id: JsonRpcId,
        params: Option<Value>,
        context: &GatewayRequestContext,
        secrets: EphemeralSecrets<'_>,
    ) -> Option<Value> {
        if !self.initialized.load(Ordering::Acquire) {
            return Some(error_response(
                response_id,
                McpError::typed(McpErrorCode::NotInitialized, "gateway is not initialized"),
            ));
        }
        let (name, arguments) = match parse_tool_call_params(params, self.limits) {
            Ok(call) => call,
            Err(error) => return Some(error_response(response_id, error)),
        };
        let Some(route) = self.routes.get(&name).cloned() else {
            return Some(error_response(
                response_id,
                McpError::typed(McpErrorCode::InvalidParams, "unknown tool"),
            ));
        };
        let freshness = route.provider.freshness();
        if let Err(error) = validate_freshness(&freshness, self.limits) {
            self.audit.record(GatewayAuditEvent {
                logical_call_id: context.logical_call_id.0.clone(),
                physical_attempt_id: None,
                authorization_scope: context.authorization_scope.0.clone(),
                provider_identity: Some(route.provider_identity.clone()),
                tool_schema_identity: Some(route.schema_identity.clone()),
                effect: Some(route.effect),
                outcome: AuditOutcome::Rejected,
            });
            return Some(error_response(response_id, error));
        }
        let physical_attempt_id =
            PhysicalAttemptId(self.next_physical_attempt.fetch_add(1, Ordering::Relaxed));
        let cancellation = ProviderCancellation {
            logical_call_id: context.logical_call_id.clone(),
            physical_attempt_id,
        };
        let active_call = ActiveCall {
            provider: Arc::clone(&route.provider),
            cancellation: cancellation.clone(),
            authorization_scope: context.authorization_scope.clone(),
            provider_identity: route.provider_identity.clone(),
            schema_identity: route.schema_identity.clone(),
            effect: route.effect,
        };
        {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            match active.entry(request_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(active_call);
                }
                Entry::Occupied(_) => {
                    return Some(error_response(
                        response_id,
                        McpError::typed(
                            McpErrorCode::InvalidRequest,
                            "request id is already in flight",
                        ),
                    ));
                }
            }
        }

        let translation = translate_tool_call_v1(&route, &arguments, context, &freshness);
        let call = ProviderCall {
            logical_call_id: context.logical_call_id.clone(),
            physical_attempt_id,
            authorization_scope: context.authorization_scope.clone(),
            provider_identity: route.provider_identity.clone(),
            upstream_tool_name: route.definition.name.clone(),
            namespaced_tool_name: route.namespaced_name.clone(),
            arguments,
            freshness,
            effect: route.effect,
            translation,
        };
        let upstream = route
            .provider
            .execute(call, secrets)
            .and_then(|result| route.provider.capture_result(result));
        self.active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&request_id);

        match upstream {
            Ok(captured) => {
                let exact = captured.into_exact();
                if let Err(error) = validate_tool_result(&exact, self.limits) {
                    self.record_call_audit(
                        context,
                        &route,
                        physical_attempt_id,
                        AuditOutcome::Rejected,
                    );
                    return Some(error_response(response_id, error));
                }
                self.record_call_audit(
                    context,
                    &route,
                    physical_attempt_id,
                    AuditOutcome::Succeeded,
                );
                Some(success_response(response_id, exact))
            }
            Err(error) => {
                let (outcome, forwarded) = if validate_provider_error(&error.0, self.limits) {
                    (AuditOutcome::ProviderError, error.0)
                } else {
                    (
                        AuditOutcome::Rejected,
                        McpError::typed(
                            McpErrorCode::LimitExceeded,
                            "upstream provider error exceeded gateway limits",
                        ),
                    )
                };
                self.record_call_audit(context, &route, physical_attempt_id, outcome);
                Some(error_response(response_id, forwarded))
            }
        }
    }

    fn cancel(&self, params: Option<Value>, context: &GatewayRequestContext) {
        let Some(request_id) = parse_cancellation_id(params) else {
            return;
        };
        let active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&request_id)
            .cloned();
        let Some(active) = active else {
            return;
        };
        if active.authorization_scope != context.authorization_scope {
            return;
        }
        let _ = active.provider.cancel(active.cancellation.clone());
        self.audit.record(GatewayAuditEvent {
            logical_call_id: active.cancellation.logical_call_id.0,
            physical_attempt_id: Some(active.cancellation.physical_attempt_id.0),
            authorization_scope: active.authorization_scope.0,
            provider_identity: Some(active.provider_identity),
            tool_schema_identity: Some(active.schema_identity),
            effect: Some(active.effect),
            outcome: AuditOutcome::CancelRequested,
        });
    }

    fn record_call_audit(
        &self,
        context: &GatewayRequestContext,
        route: &ToolRoute,
        physical_attempt_id: PhysicalAttemptId,
        outcome: AuditOutcome,
    ) {
        self.audit.record(GatewayAuditEvent {
            logical_call_id: context.logical_call_id.0.clone(),
            physical_attempt_id: Some(physical_attempt_id.0),
            authorization_scope: context.authorization_scope.0.clone(),
            provider_identity: Some(route.provider_identity.clone()),
            tool_schema_identity: Some(route.schema_identity.clone()),
            effect: Some(route.effect),
            outcome,
        });
    }
}

struct ParsedRequest {
    id: Option<JsonRpcId>,
    method: String,
    params: Option<Value>,
}

impl ParsedRequest {
    fn from_value(value: Value) -> Result<Self, GatewayInputError> {
        let object = value
            .as_object()
            .ok_or_else(|| GatewayInputError::InvalidRequest {
                message: "request must be a JSON object".into(),
            })?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(GatewayInputError::InvalidRequest {
                message: "jsonrpc must equal \"2.0\"".into(),
            });
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .filter(|method| !method.is_empty() && method.len() <= 128)
            .ok_or_else(|| GatewayInputError::InvalidRequest {
                message: "method must be a non-empty bounded string".into(),
            })?
            .to_owned();
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
        {
            return Err(GatewayInputError::InvalidRequest {
                message: "unknown top-level JSON-RPC field".into(),
            });
        }
        let id = object.get("id").map(JsonRpcId::from_value).transpose()?;
        Ok(Self {
            id,
            method,
            params: object.get("params").cloned(),
        })
    }
}

fn validate_initialize_params(params: Option<&Value>) -> Result<(), McpError> {
    let object = params.and_then(Value::as_object).ok_or_else(|| {
        McpError::typed(
            McpErrorCode::InvalidParams,
            "initialize params must be an object",
        )
    })?;
    if object
        .get("protocolVersion")
        .and_then(Value::as_str)
        .is_none()
        || object
            .get("capabilities")
            .and_then(Value::as_object)
            .is_none()
        || object
            .get("clientInfo")
            .and_then(Value::as_object)
            .is_none()
    {
        return Err(McpError::typed(
            McpErrorCode::InvalidParams,
            "initialize requires protocolVersion, capabilities, and clientInfo",
        ));
    }
    Ok(())
}

fn parse_tool_call_params(
    params: Option<Value>,
    limits: GatewayLimits,
) -> Result<(String, Value), McpError> {
    let object = params
        .and_then(|params| params.as_object().cloned())
        .ok_or_else(|| {
            McpError::typed(
                McpErrorCode::InvalidParams,
                "tool call params must be an object",
            )
        })?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "arguments" | "_meta"))
    {
        return Err(McpError::typed(
            McpErrorCode::InvalidParams,
            "unknown tool call parameter",
        ));
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && name.len() <= 128)
        .ok_or_else(|| McpError::typed(McpErrorCode::InvalidParams, "invalid tool name"))?
        .to_owned();
    let arguments = object
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !arguments.is_object() {
        return Err(McpError::typed(
            McpErrorCode::InvalidParams,
            "tool arguments must be an object",
        ));
    }
    validate_value_bounds(
        &arguments,
        limits.max_argument_depth,
        limits.max_argument_nodes,
        limits.max_argument_bytes,
    )
    .map_err(|violation| limit_error("tool arguments", violation))?;
    if let Some(metadata) = object.get("_meta") {
        validate_metadata(metadata, limits)?;
    }
    Ok((name, arguments))
}

fn parse_cancellation_id(params: Option<Value>) -> Option<JsonRpcId> {
    let params = params?.as_object()?.get("requestId")?.clone();
    JsonRpcId::from_value(&params).ok()
}

fn success_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, error: McpError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

fn input_error_to_mcp(error: &GatewayInputError) -> McpError {
    match error {
        GatewayInputError::MalformedJson | GatewayInputError::DuplicateKey => {
            McpError::typed(McpErrorCode::ParseError, "invalid JSON")
        }
        GatewayInputError::MessageTooLarge { .. }
        | GatewayInputError::DepthLimit { .. }
        | GatewayInputError::NodeLimit { .. } => {
            McpError::typed(McpErrorCode::LimitExceeded, "JSON input limit exceeded")
        }
        GatewayInputError::InvalidRequest { .. } => {
            McpError::typed(McpErrorCode::InvalidRequest, "invalid JSON-RPC request")
        }
    }
}

fn limit_error(subject: &str, violation: ValueBoundViolation) -> McpError {
    McpError::typed(
        McpErrorCode::LimitExceeded,
        format!("{subject} limit exceeded"),
    )
    .with_data(json!({ "violation": violation.wire_name() }))
}

fn validate_provider_id(provider_id: &str) -> Result<(), GatewayBuildError> {
    let valid = !provider_id.is_empty()
        && provider_id.len() <= 48
        && provider_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(GatewayBuildError::InvalidProviderId {
            provider_id: provider_id.into(),
        })
    }
}

fn validate_provider_descriptor(descriptor: &ProviderDescriptor) -> Result<(), GatewayBuildError> {
    let bounded = !descriptor.implementation.is_empty()
        && descriptor.implementation.len() <= 128
        && !descriptor.version.is_empty()
        && descriptor.version.len() <= 64
        && !descriptor.endpoint_identity.is_empty()
        && descriptor.endpoint_identity.len() <= 512;
    if bounded {
        Ok(())
    } else {
        Err(GatewayBuildError::InvalidProviderId {
            provider_id: descriptor.id.clone(),
        })
    }
}

fn validate_tool(
    provider_id: &str,
    tool: &ProviderTool,
    limits: GatewayLimits,
) -> Result<(), GatewayBuildError> {
    let valid_name = !tool.name.is_empty()
        && tool.name.len() <= 96
        && tool
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if !valid_name {
        return Err(invalid_tool(
            provider_id,
            &tool.name,
            "invalid MCP tool name",
        ));
    }
    if tool
        .title
        .as_ref()
        .is_some_and(|title| title.len() > limits.max_metadata_bytes)
        || tool
            .description
            .as_ref()
            .is_some_and(|description| description.len() > limits.max_metadata_bytes)
    {
        return Err(invalid_tool(
            provider_id,
            &tool.name,
            "title or description exceeds metadata limit",
        ));
    }
    validate_schema(&tool.input_schema, limits)
        .map_err(|reason| invalid_tool(provider_id, &tool.name, reason))?;
    if let Some(output_schema) = &tool.output_schema {
        validate_schema(output_schema, limits)
            .map_err(|reason| invalid_tool(provider_id, &tool.name, reason))?;
    }
    for metadata in [tool.annotations.as_ref(), tool.meta.as_ref()]
        .into_iter()
        .flatten()
    {
        validate_value_bounds(
            metadata,
            limits.max_metadata_depth,
            limits.max_metadata_nodes,
            limits.max_metadata_bytes,
        )
        .map_err(|_| invalid_tool(provider_id, &tool.name, "metadata exceeds limits"))?;
    }
    Ok(())
}

fn validate_schema(schema: &Value, limits: GatewayLimits) -> Result<(), &'static str> {
    if schema
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        != Some("object")
    {
        return Err("tool schema root type must be object");
    }
    validate_value_bounds(
        schema,
        limits.max_argument_depth,
        limits.max_argument_nodes,
        limits.max_schema_bytes,
    )
    .map_err(|_| "tool schema exceeds limits")
}

fn invalid_tool(
    provider_id: &str,
    tool_name: &str,
    reason: impl Into<String>,
) -> GatewayBuildError {
    GatewayBuildError::InvalidTool {
        provider_id: provider_id.into(),
        tool_name: tool_name.into(),
        reason: reason.into(),
    }
}

fn namespace_tool_name(
    provider_id: &str,
    upstream_name: &str,
) -> Result<String, GatewayBuildError> {
    let namespaced = format!("{provider_id}.{upstream_name}");
    if namespaced.len() > 128 {
        Err(invalid_tool(
            provider_id,
            upstream_name,
            "namespaced tool name exceeds 128 bytes",
        ))
    } else {
        Ok(namespaced)
    }
}

fn provider_identity(descriptor: &ProviderDescriptor) -> String {
    let canonical = canonical_json_bytes(
        &serde_json::to_value(descriptor).expect("provider descriptor is serializable"),
    );
    tagged_blake3("again.mcp.provider.v1", &canonical)
}

fn tool_schema_identity(tool: &ProviderTool) -> String {
    let identity = json!({
        "name": tool.name,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
    });
    tagged_blake3("again.mcp.tool-schema.v1", &canonical_json_bytes(&identity))
}

fn translate_tool_call_v1(
    route: &ToolRoute,
    arguments: &Value,
    context: &GatewayRequestContext,
    freshness: &Freshness,
) -> GatewayToolCallTranslationV1 {
    const TRANSLATION_SCHEMA_VERSION_V1: u16 = 1;
    let disposition = route.effect.reuse_disposition();
    let canonical_arguments = canonical_json_bytes(arguments);
    let canonical_record = json!({
        "schemaVersion": TRANSLATION_SCHEMA_VERSION_V1,
        "providerIdentity": route.provider_identity,
        "toolSchemaIdentity": route.schema_identity,
        "namespacedToolName": route.namespaced_name,
        "upstreamToolName": route.definition.name,
        "authorizationScopeIdentity": context.authorization_scope.as_str(),
        "freshness": freshness,
        "reuseDisposition": disposition,
        "arguments": arguments,
    });
    let canonical_record = canonical_json_bytes(&canonical_record);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.mcp.gateway-tool-call-translation.v1");
    hasher.update(&[0]);
    hasher.update(&canonical_record);
    GatewayToolCallTranslationV1 {
        schema_version: TRANSLATION_SCHEMA_VERSION_V1,
        provider_identity: route.provider_identity.clone(),
        tool_schema_identity: route.schema_identity.clone(),
        namespaced_tool_name: route.namespaced_name.clone(),
        upstream_tool_name: route.definition.name.clone(),
        authorization_scope_identity: context.authorization_scope.0.clone(),
        freshness: freshness.clone(),
        disposition,
        canonical_arguments,
        canonical_digest: *hasher.finalize().as_bytes(),
    }
}

fn tagged_blake3(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            Value::Object(object) => {
                let mut keys = object.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                let mut sorted = Map::new();
                for key in keys {
                    sorted.insert(key.clone(), canonical(&object[key]));
                }
                Value::Object(sorted)
            }
            scalar => scalar.clone(),
        }
    }
    serde_json::to_vec(&canonical(value)).expect("JSON values are serializable")
}

fn effective_effect(
    declared: EffectClass,
    annotations: Option<&Value>,
    annotations_trusted: bool,
) -> EffectClass {
    if declared != EffectClass::Unknown || !annotations_trusted {
        return declared;
    }
    let Some(annotations) = annotations.and_then(Value::as_object) else {
        return EffectClass::Unknown;
    };
    if annotations.get("readOnlyHint").and_then(Value::as_bool) == Some(true) {
        EffectClass::ReadOnly
    } else if annotations.get("openWorldHint").and_then(Value::as_bool) == Some(true) {
        EffectClass::ExternalSideEffect
    } else {
        EffectClass::Mutating
    }
}

fn validate_freshness(freshness: &Freshness, limits: GatewayLimits) -> Result<(), McpError> {
    if freshness.revision.is_empty() {
        return Err(McpError::typed(
            McpErrorCode::InternalError,
            "provider freshness revision must not be empty",
        ));
    }
    if freshness.revision.len() > limits.max_metadata_bytes {
        return Err(limit_error(
            "provider freshness metadata",
            ValueBoundViolation::Bytes,
        ));
    }
    Ok(())
}

fn validate_provider_error(error: &McpError, limits: GatewayLimits) -> bool {
    if error.message.len() > limits.max_metadata_bytes {
        return false;
    }
    if let Some(data) = &error.data
        && validate_value_bounds(
            data,
            limits.max_result_depth,
            limits.max_result_nodes,
            limits.max_result_bytes,
        )
        .is_err()
    {
        return false;
    }
    let Ok(value) = serde_json::to_value(error) else {
        return false;
    };
    validate_value_bounds(
        &value,
        limits.max_result_depth,
        limits.max_result_nodes,
        limits.max_result_bytes,
    )
    .is_ok()
}

fn tool_list_value(route: &ToolRoute) -> Value {
    let mut tool = Map::new();
    tool.insert("name".into(), Value::String(route.namespaced_name.clone()));
    if let Some(title) = &route.definition.title {
        tool.insert("title".into(), Value::String(title.clone()));
    }
    if let Some(description) = &route.definition.description {
        tool.insert("description".into(), Value::String(description.clone()));
    }
    tool.insert("inputSchema".into(), route.definition.input_schema.clone());
    if let Some(output_schema) = &route.definition.output_schema {
        tool.insert("outputSchema".into(), output_schema.clone());
    }
    if let Some(annotations) = &route.definition.annotations {
        tool.insert("annotations".into(), annotations.clone());
    }
    let mut meta = route
        .definition
        .meta
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    meta.insert(
        "again.dev/providerIdentity".into(),
        Value::String(route.provider_identity.clone()),
    );
    meta.insert(
        "again.dev/toolSchemaIdentity".into(),
        Value::String(route.schema_identity.clone()),
    );
    meta.insert(
        "again.dev/annotationsTrusted".into(),
        Value::Bool(route.annotations_trusted),
    );
    meta.insert(
        "again.dev/effectClass".into(),
        Value::String(route.effect.wire_name().into()),
    );
    meta.insert(
        "again.dev/reuseDisposition".into(),
        Value::String(route.effect.reuse_disposition().wire_name().into()),
    );
    tool.insert("_meta".into(), Value::Object(meta));
    Value::Object(tool)
}

fn validate_tool_result(result: &Value, limits: GatewayLimits) -> Result<(), McpError> {
    validate_value_bounds(
        result,
        limits.max_result_depth,
        limits.max_result_nodes,
        limits.max_result_bytes,
    )
    .map_err(|violation| limit_error("tool result", violation))?;
    let object = result.as_object().ok_or_else(|| {
        McpError::typed(
            McpErrorCode::InternalError,
            "upstream tool result must be an object",
        )
    })?;
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            McpError::typed(
                McpErrorCode::InternalError,
                "upstream tool result must contain a content array",
            )
        })?;
    if content.len() > limits.max_content_items {
        return Err(limit_error(
            "tool result content",
            ValueBoundViolation::Nodes,
        ));
    }
    if object
        .get("structuredContent")
        .is_some_and(|structured| !structured.is_object())
    {
        return Err(McpError::typed(
            McpErrorCode::InternalError,
            "structuredContent must be an object",
        ));
    }
    for item in content {
        validate_content_item(item, limits)?;
    }
    for metadata in [object.get("_meta")].into_iter().flatten() {
        validate_metadata(metadata, limits)?;
    }
    Ok(())
}

fn validate_content_item(item: &Value, limits: GatewayLimits) -> Result<(), McpError> {
    let object = item.as_object().ok_or_else(|| {
        McpError::typed(
            McpErrorCode::InternalError,
            "tool content item must be an object",
        )
    })?;
    for metadata in [object.get("annotations"), object.get("_meta")]
        .into_iter()
        .flatten()
    {
        validate_metadata(metadata, limits)?;
    }
    match object.get("type").and_then(Value::as_str) {
        Some("text") => validate_bounded_string(object, "text", limits.max_text_bytes),
        Some("image" | "audio") => {
            validate_bounded_string(object, "data", limits.max_binary_base64_bytes)?;
            validate_bounded_string(object, "mimeType", limits.max_metadata_bytes)
        }
        Some("resource_link") => {
            for field in ["uri", "name"] {
                validate_bounded_string(object, field, limits.max_metadata_bytes)?;
            }
            for field in ["title", "description", "mimeType"] {
                validate_optional_bounded_string(object, field, limits.max_metadata_bytes)?;
            }
            Ok(())
        }
        Some("resource") => validate_embedded_resource(object, limits),
        _ => Err(McpError::typed(
            McpErrorCode::InternalError,
            "unsupported upstream content type",
        )),
    }
}

fn validate_embedded_resource(
    content: &Map<String, Value>,
    limits: GatewayLimits,
) -> Result<(), McpError> {
    let resource = content
        .get("resource")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            McpError::typed(
                McpErrorCode::InternalError,
                "embedded resource must contain a resource object",
            )
        })?;
    validate_bounded_string(resource, "uri", limits.max_metadata_bytes)?;
    validate_optional_bounded_string(resource, "mimeType", limits.max_metadata_bytes)?;
    if let Some(metadata) = resource.get("_meta") {
        validate_metadata(metadata, limits)?;
    }
    match (resource.get("text"), resource.get("blob")) {
        (Some(_), None) => validate_bounded_string(resource, "text", limits.max_text_bytes),
        (None, Some(_)) => {
            validate_bounded_string(resource, "blob", limits.max_binary_base64_bytes)
        }
        _ => Err(McpError::typed(
            McpErrorCode::InternalError,
            "embedded resource must contain exactly one of text or blob",
        )),
    }
}

fn validate_metadata(metadata: &Value, limits: GatewayLimits) -> Result<(), McpError> {
    validate_value_bounds(
        metadata,
        limits.max_metadata_depth,
        limits.max_metadata_nodes,
        limits.max_metadata_bytes,
    )
    .map_err(|violation| limit_error("content metadata", violation))
}

fn validate_bounded_string(
    object: &Map<String, Value>,
    field: &str,
    limit: usize,
) -> Result<(), McpError> {
    let value = object.get(field).and_then(Value::as_str).ok_or_else(|| {
        McpError::typed(
            McpErrorCode::InternalError,
            format!("upstream content field `{field}` must be a string"),
        )
    })?;
    if value.len() > limit {
        Err(limit_error(field, ValueBoundViolation::Bytes))
    } else {
        Ok(())
    }
}

fn validate_optional_bounded_string(
    object: &Map<String, Value>,
    field: &str,
    limit: usize,
) -> Result<(), McpError> {
    match object.get(field) {
        None => Ok(()),
        Some(Value::String(value)) if value.len() <= limit => Ok(()),
        Some(Value::String(_)) => Err(limit_error(field, ValueBoundViolation::Bytes)),
        Some(_) => Err(McpError::typed(
            McpErrorCode::InternalError,
            format!("upstream content field `{field}` must be a string"),
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueBoundViolation {
    Depth,
    Nodes,
    Bytes,
}

impl ValueBoundViolation {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Depth => "depth",
            Self::Nodes => "nodes",
            Self::Bytes => "bytes",
        }
    }
}

fn validate_value_bounds(
    value: &Value,
    max_depth: usize,
    max_nodes: usize,
    max_bytes: usize,
) -> Result<(), ValueBoundViolation> {
    let mut stack = vec![(value, 1_usize)];
    let mut nodes = 0_usize;
    let mut string_bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        if depth > max_depth {
            return Err(ValueBoundViolation::Depth);
        }
        nodes = nodes.checked_add(1).ok_or(ValueBoundViolation::Nodes)?;
        if nodes > max_nodes {
            return Err(ValueBoundViolation::Nodes);
        }
        match value {
            Value::String(value) => {
                string_bytes = string_bytes
                    .checked_add(value.len())
                    .ok_or(ValueBoundViolation::Bytes)?;
            }
            Value::Array(values) => {
                let remaining = max_nodes.saturating_sub(nodes).saturating_sub(stack.len());
                if values.len() > remaining {
                    return Err(ValueBoundViolation::Nodes);
                }
                stack
                    .try_reserve(values.len())
                    .map_err(|_| ValueBoundViolation::Nodes)?;
                for value in values {
                    stack.push((value, depth + 1));
                }
            }
            Value::Object(object) => {
                let remaining = max_nodes.saturating_sub(nodes).saturating_sub(stack.len());
                if object.len() > remaining {
                    return Err(ValueBoundViolation::Nodes);
                }
                stack
                    .try_reserve(object.len())
                    .map_err(|_| ValueBoundViolation::Nodes)?;
                for (key, value) in object {
                    string_bytes = string_bytes
                        .checked_add(key.len())
                        .ok_or(ValueBoundViolation::Bytes)?;
                    stack.push((value, depth + 1));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        if string_bytes > max_bytes {
            return Err(ValueBoundViolation::Bytes);
        }
    }
    let encoded = serde_json::to_vec(value).map_err(|_| ValueBoundViolation::Bytes)?;
    if encoded.len() > max_bytes {
        Err(ValueBoundViolation::Bytes)
    } else {
        Ok(())
    }
}

fn parse_bounded_json(input: &[u8], limits: GatewayLimits) -> Result<Value, GatewayInputError> {
    if input.len() > limits.max_message_bytes {
        return Err(GatewayInputError::MessageTooLarge {
            limit: limits.max_message_bytes,
            actual: input.len(),
        });
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let budget = ParseBudgetV1 {
        nodes: Cell::new(0),
        max_nodes: limits.max_json_nodes,
        max_depth: limits.max_json_depth,
    };
    let value = UniqueValueSeed {
        budget: &budget,
        depth: 1,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| {
        let message = error.to_string();
        if message.starts_with("__again_duplicate_key__") {
            GatewayInputError::DuplicateKey
        } else if let Some(actual) = message
            .strip_prefix("__again_depth__")
            .and_then(|rest| rest.split(':').next())
            .and_then(|actual| actual.parse().ok())
        {
            GatewayInputError::DepthLimit {
                limit: limits.max_json_depth,
                actual,
            }
        } else if message.starts_with("__again_nodes__") {
            GatewayInputError::NodeLimit {
                limit: limits.max_json_nodes,
            }
        } else {
            GatewayInputError::MalformedJson
        }
    })?;
    deserializer
        .end()
        .map_err(|_| GatewayInputError::MalformedJson)?;
    validate_value_bounds(
        &value,
        limits.max_json_depth,
        limits.max_json_nodes,
        limits.max_message_bytes,
    )
    .map_err(|violation| match violation {
        ValueBoundViolation::Depth => GatewayInputError::DepthLimit {
            limit: limits.max_json_depth,
            actual: limits.max_json_depth.saturating_add(1),
        },
        ValueBoundViolation::Nodes => GatewayInputError::NodeLimit {
            limit: limits.max_json_nodes,
        },
        ValueBoundViolation::Bytes => GatewayInputError::MessageTooLarge {
            limit: limits.max_message_bytes,
            actual: input.len(),
        },
    })?;
    Ok(value)
}

struct ParseBudgetV1 {
    nodes: Cell<usize>,
    max_nodes: usize,
    max_depth: usize,
}

impl ParseBudgetV1 {
    fn observe<E: de::Error>(&self, depth: usize) -> Result<(), E> {
        if depth > self.max_depth {
            return Err(E::custom(format!("__again_depth__{depth}:")));
        }
        let nodes = self
            .nodes
            .get()
            .checked_add(1)
            .ok_or_else(|| E::custom("__again_nodes__"))?;
        if nodes > self.max_nodes {
            return Err(E::custom("__again_nodes__"));
        }
        self.nodes.set(nodes);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct UniqueValueSeed<'a> {
    budget: &'a ParseBudgetV1,
    depth: usize,
}

impl UniqueValueSeed<'_> {
    fn child(self) -> Self {
        Self {
            budget: self.budget,
            depth: self.depth.saturating_add(1),
        }
    }
}

impl<'de> DeserializeSeed<'de> for UniqueValueSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.budget.observe::<D::Error>(self.depth)?;
        deserializer.deserialize_any(UniqueValueVisitor { seed: self })
    }
}

struct UniqueValueVisitor<'a> {
    seed: UniqueValueSeed<'a>,
}

impl<'de> Visitor<'de> for UniqueValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.into()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.seed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1024));
        while let Some(value) = sequence.next_element_seed(self.seed.child())? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("__again_duplicate_key__"));
            }
            let value = object.next_value_seed(self.seed.child())?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Option<Result<Vec<u8>, GatewayInputError>>> {
    let mut frame = Vec::with_capacity(limit.min(8192));
    let mut actual = 0_usize;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if actual == 0 {
                return Ok(None);
            }
            return if oversized {
                Ok(Some(Err(GatewayInputError::MessageTooLarge {
                    limit,
                    actual,
                })))
            } else {
                Ok(Some(Ok(frame)))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let payload_len = newline.unwrap_or(available.len());
        actual = actual.saturating_add(payload_len);
        if actual > limit {
            oversized = true;
        } else if !oversized {
            frame.extend_from_slice(&available[..payload_len]);
        }
        reader.consume(consumed);
        if newline.is_some() {
            if frame.last() == Some(&b'\r') {
                frame.pop();
                actual = actual.saturating_sub(1);
            }
            return if oversized {
                Ok(Some(Err(GatewayInputError::MessageTooLarge {
                    limit,
                    actual,
                })))
            } else {
                Ok(Some(Ok(frame)))
            };
        }
    }
}
