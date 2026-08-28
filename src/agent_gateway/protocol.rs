//! Versioned, bounded protocol values for the agent gateway.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Number, Value};
use thiserror::Error;

/// The only schema version accepted for a [`GatewayToolCallV1`].
pub const GATEWAY_TOOL_CALL_SCHEMA_VERSION: u16 = 1;
pub const GATEWAY_TOOL_CALL_SCHEMA: &str = "again.gateway-tool-call.v1";
/// Maximum raw and canonical byte length of a standalone arguments document.
pub const MAX_CANONICAL_JSON_BYTES: usize = 64 * 1024;
/// Maximum value nesting, counting the root as depth one.
pub const MAX_CANONICAL_JSON_DEPTH: usize = 32;
/// Maximum JSON values, counting every container and scalar.
pub const MAX_CANONICAL_JSON_NODES: usize = 4_096;
pub const MAX_CANONICAL_COLLECTION_MEMBERS: usize = 256;
pub const MAX_CANONICAL_STRING_BYTES: usize = 48 * 1024;
/// Maximum raw and canonical byte length of an owned gateway envelope.
pub const MAX_GATEWAY_TOOL_CALL_BYTES: usize = 80 * 1024;
/// The envelope permits the bounded arguments depth plus its fixed wrappers.
pub const MAX_GATEWAY_TOOL_CALL_DEPTH: usize = MAX_CANONICAL_JSON_DEPTH + 8;
/// The envelope permits the bounded arguments nodes plus its fixed fields.
pub const MAX_GATEWAY_TOOL_CALL_NODES: usize = MAX_CANONICAL_JSON_NODES + 128;
pub const DELIVERY_CHALLENGE_SCHEMA_VERSION: u16 = 1;
pub const DELIVERY_ACKNOWLEDGEMENT_SCHEMA_VERSION: u16 = 1;
pub const MAX_DELIVERY_IDENTIFIER_BYTES_V1: usize = 128;
pub const TOOL_POLICY_SCHEMA_VERSION_V1: u16 = 1;
pub const MAX_TOOL_POLICY_IDENTIFIER_BYTES_V1: usize = 128;
pub const MAX_TOOL_POLICY_DEPENDENCIES_V1: usize = 64;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"again.agent-gateway.request.v1\0";
const ADAPTER_DIGEST_DOMAIN: &[u8] = b"again.agent-gateway.adapter.v1\0";
const MAX_IDENTITY_BYTES_V1: usize = 256;
const MAX_DIGEST_ALGORITHM_BYTES_V1: usize = 32;
const MAX_DIGEST_VALUE_BYTES_V1: usize = 256;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CanonicalJsonError {
    #[error("input_too_large")]
    InputTooLarge,
    #[error("encoded_too_large")]
    EncodedTooLarge,
    #[error("depth_limit_exceeded")]
    DepthLimitExceeded,
    #[error("node_limit_exceeded")]
    NodeLimitExceeded,
    #[error("duplicate_key")]
    DuplicateKey,
    #[error("malformed_json")]
    Malformed,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum GatewayProtocolError {
    #[error("unsupported_schema_version")]
    UnsupportedSchemaVersion,
    #[error("invalid_field")]
    InvalidField,
    #[error("malformed_envelope")]
    MalformedEnvelope,
    #[error(transparent)]
    CanonicalJson(#[from] CanonicalJsonError),
}

/// Stable, payload-free refusal codes for the compact untrusted-input adapter.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum GatewayProtocolRefusalV1 {
    #[error("duplicate_key")]
    DuplicateKey,
    #[error("non_canonical")]
    NonCanonical,
    #[error("top_level_not_object")]
    TopLevelNotObject,
    #[error("missing_field")]
    MissingField,
    #[error("unknown_field")]
    UnknownField,
    #[error("invalid_schema")]
    InvalidSchema,
    #[error("invalid_field_type")]
    InvalidFieldType,
    #[error("arguments_not_object")]
    ArgumentsNotObject,
    #[error("invalid_effect")]
    InvalidEffect,
    #[error("invalid_identifier")]
    InvalidIdentifier,
    #[error("invalid_json")]
    InvalidJson,
    #[error("non_integral_number")]
    NonIntegralNumber,
    #[error("depth_exceeded")]
    DepthExceeded,
    #[error("collection_limit_exceeded")]
    CollectionLimitExceeded,
    #[error("node_limit_exceeded")]
    NodeLimitExceeded,
    #[error("string_limit_exceeded")]
    StringLimitExceeded,
    #[error("argument_too_large")]
    ArgumentTooLarge,
}

impl GatewayProtocolRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DuplicateKey => "duplicate_key",
            Self::NonCanonical => "non_canonical",
            Self::TopLevelNotObject => "top_level_not_object",
            Self::MissingField => "missing_field",
            Self::UnknownField => "unknown_field",
            Self::InvalidSchema => "invalid_schema",
            Self::InvalidFieldType => "invalid_field_type",
            Self::ArgumentsNotObject => "arguments_not_object",
            Self::InvalidEffect => "invalid_effect",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidJson => "invalid_json",
            Self::NonIntegralNumber => "non_integral_number",
            Self::DepthExceeded => "depth_exceeded",
            Self::CollectionLimitExceeded => "collection_limit_exceeded",
            Self::NodeLimitExceeded => "node_limit_exceeded",
            Self::StringLimitExceeded => "string_limit_exceeded",
            Self::ArgumentTooLarge => "argument_too_large",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalNumber(String);

impl CanonicalNumber {
    fn from_json_number(number: &Number) -> Result<Self, CanonicalJsonError> {
        if let Some(value) = number.as_i64() {
            return Ok(Self(value.to_string()));
        }
        if let Some(value) = number.as_u64() {
            return Ok(Self(value.to_string()));
        }
        let value = number
            .as_f64()
            .filter(|value| value.is_finite())
            .ok_or(CanonicalJsonError::Malformed)?;
        Ok(Self(canonical_f64(value)))
    }
}

fn canonical_f64(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    let mut encoded = Number::from_f64(value)
        .expect("finite f64 has a JSON number representation")
        .to_string();
    if encoded.ends_with(".0") {
        encoded.truncate(encoded.len() - 2);
    }
    encoded
}

impl Serialize for CanonicalNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0
            .parse::<Number>()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CanonicalNode {
    Null,
    Bool(bool),
    Number(CanonicalNumber),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Serialize for CanonicalNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

#[derive(Clone, Copy)]
struct JsonLimits {
    bytes: usize,
    depth: usize,
    nodes: usize,
}

const ARGUMENT_LIMITS: JsonLimits = JsonLimits {
    bytes: MAX_CANONICAL_JSON_BYTES,
    depth: MAX_CANONICAL_JSON_DEPTH,
    nodes: MAX_CANONICAL_JSON_NODES,
};

const ENVELOPE_LIMITS: JsonLimits = JsonLimits {
    bytes: MAX_GATEWAY_TOOL_CALL_BYTES,
    depth: MAX_GATEWAY_TOOL_CALL_DEPTH,
    nodes: MAX_GATEWAY_TOOL_CALL_NODES,
};

#[derive(Clone, Debug, PartialEq, Eq)]
enum ParseFailure {
    Depth,
    Nodes,
    Duplicate,
}

struct ParseState {
    limits: JsonLimits,
    nodes: usize,
    failure: Option<ParseFailure>,
}

impl ParseState {
    fn enter(&mut self, depth: usize) -> Result<(), &'static str> {
        if depth > self.limits.depth {
            self.failure = Some(ParseFailure::Depth);
            return Err("canonical JSON depth limit exceeded");
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.nodes {
            self.failure = Some(ParseFailure::Nodes);
            return Err("canonical JSON node limit exceeded");
        }
        Ok(())
    }
}

struct NodeSeed<'a> {
    state: &'a mut ParseState,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for NodeSeed<'_> {
    type Value = CanonicalNode;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.state.enter(self.depth).map_err(de::Error::custom)?;
        deserializer.deserialize_any(NodeVisitor {
            state: self.state,
            depth: self.depth,
        })
    }
}

struct NodeVisitor<'a> {
    state: &'a mut ParseState,
    depth: usize,
}

impl<'de> Visitor<'de> for NodeVisitor<'_> {
    type Value = CanonicalNode;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Number(CanonicalNumber(value.to_string())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(CanonicalNode::Number(CanonicalNumber(value.to_string())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !value.is_finite() {
            return Err(E::custom("non-finite JSON number"));
        }
        Ok(CanonicalNode::Number(CanonicalNumber(canonical_f64(value))))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(CanonicalNode::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(CanonicalNode::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1_024));
        while let Some(value) = sequence.next_element_seed(NodeSeed {
            state: &mut *self.state,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(CanonicalNode::Array(values))
    }

    fn visit_map<A>(self, mut source: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        let mut seen = BTreeSet::new();
        while let Some(key) = source.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                self.state.failure = Some(ParseFailure::Duplicate);
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = source.next_value_seed(NodeSeed {
                state: &mut *self.state,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(CanonicalNode::Object(values))
    }
}

fn parse_canonical(input: &[u8], limits: JsonLimits) -> Result<CanonicalNode, CanonicalJsonError> {
    if input.len() > limits.bytes {
        return Err(CanonicalJsonError::InputTooLarge);
    }
    let mut state = ParseState {
        limits,
        nodes: 0,
        failure: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let parsed = NodeSeed {
        state: &mut state,
        depth: 1,
    }
    .deserialize(&mut deserializer);
    let node = match parsed {
        Ok(node) => node,
        Err(_error) => {
            return Err(match state.failure {
                Some(ParseFailure::Depth) => CanonicalJsonError::DepthLimitExceeded,
                Some(ParseFailure::Nodes) => CanonicalJsonError::NodeLimitExceeded,
                Some(ParseFailure::Duplicate) => CanonicalJsonError::DuplicateKey,
                None => CanonicalJsonError::Malformed,
            });
        }
    };
    deserializer
        .end()
        .map_err(|_| CanonicalJsonError::Malformed)?;
    let encoded = encode_node(&node);
    if encoded.len() > limits.bytes {
        return Err(CanonicalJsonError::EncodedTooLarge);
    }
    Ok(node)
}

fn node_from_value(value: Value, limits: JsonLimits) -> Result<CanonicalNode, CanonicalJsonError> {
    fn convert(
        value: Value,
        depth: usize,
        nodes: &mut usize,
        limits: JsonLimits,
    ) -> Result<CanonicalNode, CanonicalJsonError> {
        if depth > limits.depth {
            return Err(CanonicalJsonError::DepthLimitExceeded);
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > limits.nodes {
            return Err(CanonicalJsonError::NodeLimitExceeded);
        }
        Ok(match value {
            Value::Null => CanonicalNode::Null,
            Value::Bool(value) => CanonicalNode::Bool(value),
            Value::Number(value) => {
                CanonicalNode::Number(CanonicalNumber::from_json_number(&value)?)
            }
            Value::String(value) => CanonicalNode::String(value),
            Value::Array(values) => CanonicalNode::Array(
                values
                    .into_iter()
                    .map(|value| convert(value, depth + 1, nodes, limits))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Object(values) => CanonicalNode::Object(
                values
                    .into_iter()
                    .map(|(key, value)| Ok((key, convert(value, depth + 1, nodes, limits)?)))
                    .collect::<Result<_, CanonicalJsonError>>()?,
            ),
        })
    }

    let mut nodes = 0;
    let node = convert(value, 1, &mut nodes, limits)?;
    let encoded = encode_node(&node);
    if encoded.len() > limits.bytes {
        return Err(CanonicalJsonError::EncodedTooLarge);
    }
    Ok(node)
}

fn encode_node(node: &CanonicalNode) -> Vec<u8> {
    fn write(node: &CanonicalNode, output: &mut Vec<u8>) {
        match node {
            CanonicalNode::Null => output.extend_from_slice(b"null"),
            CanonicalNode::Bool(true) => output.extend_from_slice(b"true"),
            CanonicalNode::Bool(false) => output.extend_from_slice(b"false"),
            CanonicalNode::Number(number) => output.extend_from_slice(number.0.as_bytes()),
            CanonicalNode::String(value) => {
                serde_json::to_writer(output, value).expect("writing a string to Vec cannot fail");
            }
            CanonicalNode::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(value, output);
                }
                output.push(b']');
            }
            CanonicalNode::Object(values) => {
                output.push(b'{');
                for (index, (key, value)) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)
                        .expect("writing an object key to Vec cannot fail");
                    output.push(b':');
                    write(value, output);
                }
                output.push(b'}');
            }
        }
    }

    let mut output = Vec::new();
    write(node, &mut output);
    output
}

/// Parsed structured arguments with canonical ordering and enforced bounds.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CanonicalArguments(CanonicalNode);

impl fmt::Debug for CanonicalArguments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalArguments(<redacted>)")
    }
}

impl CanonicalArguments {
    pub fn from_json_slice(input: &[u8]) -> Result<Self, CanonicalJsonError> {
        parse_canonical(input, ARGUMENT_LIMITS).map(Self)
    }

    pub fn from_json_str(input: &str) -> Result<Self, CanonicalJsonError> {
        Self::from_json_slice(input.as_bytes())
    }

    pub fn from_value(value: Value) -> Result<Self, CanonicalJsonError> {
        node_from_value(value, ARGUMENT_LIMITS).map(Self)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_node(&self.0)
    }

    pub fn canonical_json(&self) -> String {
        String::from_utf8(self.canonical_bytes()).expect("canonical JSON is always UTF-8")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentityV1 {
    pub id: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentityV1 {
    pub id: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentityV1 {
    pub id: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceIdentityV1 {
    pub workspace_id: String,
    pub cwd: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCallIdentityV1 {
    pub agent_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub call_id: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIdentityV1 {
    pub task_id: String,
    pub version: String,
}

/// Algorithm-qualified digest reference. The protocol does not dereference it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestReferenceV1 {
    pub algorithm: String,
    pub value: String,
}

impl DigestReferenceV1 {
    pub fn new(
        algorithm: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, GatewayProtocolError> {
        let digest = Self {
            algorithm: algorithm.into(),
            value: value.into(),
        };
        validate_digest(&digest, "digest algorithm", "digest value")?;
        Ok(digest)
    }

    #[allow(
        dead_code,
        reason = "standalone protocol consumers do not construct complete gateway calls"
    )]
    pub(crate) fn validate_bounded(&self) -> Result<(), GatewayProtocolError> {
        validate_digest(self, "digest algorithm", "digest value")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDigestReferenceV1 {
    pub schema_version: u16,
    pub repository: DigestReferenceV1,
    pub environment: DigestReferenceV1,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RepositoryEnvironmentStateV1 {
    Known { reference: StateDigestReferenceV1 },
    Unknown,
}

macro_rules! impl_redacted_debug {
    ($($type:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(concat!(stringify!($type), "(<redacted>)"))
                }
            }
        )+
    };
}

impl_redacted_debug!(
    ProviderIdentityV1,
    ModelIdentityV1,
    ToolIdentityV1,
    WorkspaceIdentityV1,
    AgentCallIdentityV1,
    TaskIdentityV1,
    DigestReferenceV1,
    StateDigestReferenceV1,
    RepositoryEnvironmentStateV1,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionClass {
    Preapproved,
    RequiresApproval,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    SnapshotRead,
    FreshnessBoundRead,
    DeterministicCompute,
    Mutation,
    ExternalSideEffect,
    Unknown,
}

/// Closed effect vocabulary accepted from an untrusted tool-call adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayEffectClassV1 {
    Pure,
    WorkspaceRead,
    ExternalRead,
    WorkspaceWrite,
    ExternalWrite,
    Privileged,
    Unknown,
}

/// Conservative capability classes understood by the universal MCP control
/// plane. These values describe policy; they do not themselves grant reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapabilityClassV1 {
    ExactStateBoundRead,
    DeterministicCommand,
    FreshnessBoundRead,
    NonReusableRead,
    Mutation,
    CredentialOperation,
    Communication,
    Deployment,
    Payment,
    Unknown,
}

impl ToolCapabilityClassV1 {
    pub const fn may_consider_reuse(self) -> bool {
        matches!(self, Self::ExactStateBoundRead | Self::DeterministicCommand)
    }

    pub const fn must_bypass_storage(self) -> bool {
        matches!(
            self,
            Self::Mutation
                | Self::CredentialOperation
                | Self::Communication
                | Self::Deployment
                | Self::Payment
                | Self::Unknown
        )
    }
}

/// State inputs which a reusable tool observation claims to cover. A binding
/// is content addressed; names identify scope but never serve as authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDependencyKindV1 {
    RepositoryPath,
    RepositoryTree,
    GitState,
    Executable,
    Toolchain,
    Environment,
    Configuration,
    Lockfile,
    ExternalResource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToolDependencyBindingV1 {
    kind: ToolDependencyKindV1,
    name: String,
    digest: DigestReferenceV1,
}

impl ToolDependencyBindingV1 {
    pub fn new(
        kind: ToolDependencyKindV1,
        name: impl Into<String>,
        digest: DigestReferenceV1,
    ) -> Result<Self, ToolPolicyRefusalV1> {
        let binding = Self {
            kind,
            name: name.into(),
            digest,
        };
        validate_tool_policy_identifier_v1(&binding.name)?;
        binding
            .digest
            .validate_bounded()
            .map_err(|_| ToolPolicyRefusalV1::InvalidDependency)?;
        Ok(binding)
    }

    pub const fn kind(&self) -> ToolDependencyKindV1 {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn digest(&self) -> &DigestReferenceV1 {
        &self.digest
    }
}

/// A dependency declaration is either explicitly empty or a non-empty,
/// duplicate-free set. An absent/incomplete declaration has no representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDependencySetV1 {
    ExplicitlyNone,
    Bound(Vec<ToolDependencyBindingV1>),
}

impl ToolDependencySetV1 {
    pub fn bound(dependencies: Vec<ToolDependencyBindingV1>) -> Result<Self, ToolPolicyRefusalV1> {
        if dependencies.is_empty() || dependencies.len() > MAX_TOOL_POLICY_DEPENDENCIES_V1 {
            return Err(ToolPolicyRefusalV1::InvalidDependency);
        }
        let mut identities = BTreeSet::new();
        for dependency in &dependencies {
            validate_tool_policy_identifier_v1(dependency.name())?;
            dependency
                .digest()
                .validate_bounded()
                .map_err(|_| ToolPolicyRefusalV1::InvalidDependency)?;
            if !identities.insert((dependency.kind(), dependency.name().to_owned())) {
                return Err(ToolPolicyRefusalV1::DuplicateDependency);
            }
        }
        Ok(Self::Bound(dependencies))
    }

    pub fn dependencies(&self) -> &[ToolDependencyBindingV1] {
        match self {
            Self::ExplicitlyNone => &[],
            Self::Bound(dependencies) => dependencies,
        }
    }
}

/// Identification of a deterministic external freshness validator. Merely
/// declaring a validator does not prove that it ran or authorize a cache hit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExternalFreshnessValidatorV1 {
    id: String,
    version: String,
    implementation_digest: DigestReferenceV1,
}

impl ExternalFreshnessValidatorV1 {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        implementation_digest: DigestReferenceV1,
    ) -> Result<Self, ToolPolicyRefusalV1> {
        let validator = Self {
            id: id.into(),
            version: version.into(),
            implementation_digest,
        };
        validate_tool_policy_identifier_v1(&validator.id)?;
        validate_tool_policy_identifier_v1(&validator.version)?;
        validator
            .implementation_digest
            .validate_bounded()
            .map_err(|_| ToolPolicyRefusalV1::InvalidFreshnessValidator)?;
        Ok(validator)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPolicyDispositionV1 {
    Allow,
    Deny,
}

/// Validated local policy for one provider tool. It is deliberately separate
/// from provider-supplied MCP annotations, which remain untrusted hints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UniversalToolPolicyV1 {
    schema_version: u16,
    policy_id: String,
    policy_version: String,
    capability: ToolCapabilityClassV1,
    dependencies: ToolDependencySetV1,
    freshness_validator: Option<ExternalFreshnessValidatorV1>,
    disposition: ToolPolicyDispositionV1,
}

impl UniversalToolPolicyV1 {
    pub fn new(
        schema_version: u16,
        policy_id: impl Into<String>,
        policy_version: impl Into<String>,
        capability: ToolCapabilityClassV1,
        dependencies: ToolDependencySetV1,
        freshness_validator: Option<ExternalFreshnessValidatorV1>,
        disposition: ToolPolicyDispositionV1,
    ) -> Result<Self, ToolPolicyRefusalV1> {
        if schema_version != TOOL_POLICY_SCHEMA_VERSION_V1 {
            return Err(ToolPolicyRefusalV1::UnsupportedSchema);
        }
        let policy = Self {
            schema_version,
            policy_id: policy_id.into(),
            policy_version: policy_version.into(),
            capability,
            dependencies,
            freshness_validator,
            disposition,
        };
        validate_tool_policy_identifier_v1(&policy.policy_id)?;
        validate_tool_policy_identifier_v1(&policy.policy_version)?;
        if policy.capability == ToolCapabilityClassV1::ExactStateBoundRead
            && policy.dependencies.dependencies().is_empty()
        {
            return Err(ToolPolicyRefusalV1::IncompleteDependencies);
        }
        if policy.freshness_validator.is_some()
            && policy.capability != ToolCapabilityClassV1::FreshnessBoundRead
        {
            return Err(ToolPolicyRefusalV1::UnexpectedFreshnessValidator);
        }
        Ok(policy)
    }

    pub const fn capability(&self) -> ToolCapabilityClassV1 {
        self.capability
    }

    pub const fn disposition(&self) -> ToolPolicyDispositionV1 {
        self.disposition
    }

    pub fn dependencies(&self) -> &ToolDependencySetV1 {
        &self.dependencies
    }

    pub fn freshness_validator(&self) -> Option<&ExternalFreshnessValidatorV1> {
        self.freshness_validator.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ToolPolicyRefusalV1 {
    #[error("unsupported_schema")]
    UnsupportedSchema,
    #[error("invalid_identifier")]
    InvalidIdentifier,
    #[error("invalid_dependency")]
    InvalidDependency,
    #[error("duplicate_dependency")]
    DuplicateDependency,
    #[error("incomplete_dependencies")]
    IncompleteDependencies,
    #[error("invalid_freshness_validator")]
    InvalidFreshnessValidator,
    #[error("unexpected_freshness_validator")]
    UnexpectedFreshnessValidator,
}

fn validate_tool_policy_identifier_v1(value: &str) -> Result<(), ToolPolicyRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_TOOL_POLICY_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ToolPolicyRefusalV1::InvalidIdentifier);
    }
    Ok(())
}

impl GatewayEffectClassV1 {
    pub const ALL: [Self; 7] = [
        Self::Pure,
        Self::WorkspaceRead,
        Self::ExternalRead,
        Self::WorkspaceWrite,
        Self::ExternalWrite,
        Self::Privileged,
        Self::Unknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pure => "pure",
            Self::WorkspaceRead => "workspace_read",
            Self::ExternalRead => "external_read",
            Self::WorkspaceWrite => "workspace_write",
            Self::ExternalWrite => "external_write",
            Self::Privileged => "privileged",
            Self::Unknown => "unknown",
        }
    }

    pub const fn supports_deterministic_validation(self) -> bool {
        matches!(self, Self::Pure | Self::WorkspaceRead)
    }

    pub const fn requires_fresh_execution(self) -> bool {
        matches!(
            self,
            Self::ExternalRead | Self::WorkspaceWrite | Self::ExternalWrite | Self::Privileged
        )
    }

    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessRequirementV1 {
    Snapshot,
    MaxAgeMillis(u64),
    RequireRevalidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationMode {
    Exact,
    DeterministicExcerpt,
    CompactReference,
    FullRetrievalRequired,
}

/// Payload-free outcomes for recipient-bound delivery authority. These are
/// deliberately distinct from reuse and execution decisions.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryAuthorityRefusalV1 {
    #[error("unsupported_recipient_authority")]
    UnsupportedRecipientAuthority,
    #[error("invalid_delivery_binding")]
    InvalidBinding,
    #[error("malformed_acknowledgement")]
    MalformedAcknowledgement,
    #[error("wrong_connection")]
    WrongConnection,
    #[error("wrong_authorization_scope")]
    WrongAuthorizationScope,
    #[error("wrong_recipient")]
    WrongRecipient,
    #[error("wrong_turn")]
    WrongTurn,
    #[error("wrong_call")]
    WrongCall,
    #[error("wrong_result")]
    WrongResult,
    #[error("wrong_streams")]
    WrongStreams,
    #[error("stale_compaction_generation")]
    StaleCompactionGeneration,
    #[error("acknowledgement_replayed")]
    AcknowledgementReplayed,
    #[error("delivery_authority_retired")]
    Retired,
    #[error("delivery_challenge_capacity")]
    ChallengeCapacity,
}

impl DeliveryAuthorityRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedRecipientAuthority => "unsupported_recipient_authority",
            Self::InvalidBinding => "invalid_delivery_binding",
            Self::MalformedAcknowledgement => "malformed_acknowledgement",
            Self::WrongConnection => "wrong_connection",
            Self::WrongAuthorizationScope => "wrong_authorization_scope",
            Self::WrongRecipient => "wrong_recipient",
            Self::WrongTurn => "wrong_turn",
            Self::WrongCall => "wrong_call",
            Self::WrongResult => "wrong_result",
            Self::WrongStreams => "wrong_streams",
            Self::StaleCompactionGeneration => "stale_compaction_generation",
            Self::AcknowledgementReplayed => "acknowledgement_replayed",
            Self::Retired => "delivery_authority_retired",
            Self::ChallengeCapacity => "delivery_challenge_capacity",
        }
    }
}

/// Complete exact-result status and stream identity acknowledged by a
/// recipient. Digests are bounded lowercase BLAKE3 hex strings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryStreamsV1 {
    exact_status: i32,
    stdout_digest: String,
    stdout_bytes: u64,
    stderr_digest: String,
    stderr_bytes: u64,
}

impl DeliveryStreamsV1 {
    pub fn new(
        exact_status: i32,
        stdout_digest: &str,
        stdout_bytes: u64,
        stderr_digest: &str,
        stderr_bytes: u64,
    ) -> Result<Self, DeliveryAuthorityRefusalV1> {
        for digest in [stdout_digest, stderr_digest] {
            validate_delivery_digest_v1(digest)?;
        }
        Ok(Self {
            exact_status,
            stdout_digest: stdout_digest.to_owned(),
            stdout_bytes,
            stderr_digest: stderr_digest.to_owned(),
            stderr_bytes,
        })
    }

    pub const fn exact_status(&self) -> i32 {
        self.exact_status
    }

    pub fn stdout_digest(&self) -> &str {
        &self.stdout_digest
    }

    pub const fn stdout_bytes(&self) -> u64 {
        self.stdout_bytes
    }

    pub fn stderr_digest(&self) -> &str {
        &self.stderr_digest
    }

    pub const fn stderr_bytes(&self) -> u64 {
        self.stderr_bytes
    }

    pub(crate) fn validate(&self) -> Result<(), DeliveryAuthorityRefusalV1> {
        validate_delivery_digest_v1(&self.stdout_digest)?;
        validate_delivery_digest_v1(&self.stderr_digest)
    }
}

/// All non-secret fields to which a delivery challenge and its one-use
/// acknowledgment are bound.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryBindingV1 {
    authorization_scope_digest: String,
    connection_digest: String,
    agent_id: String,
    session_id: String,
    turn_id: String,
    call_digest: String,
    result_digest: String,
    streams: DeliveryStreamsV1,
    compaction_generation: u64,
}

impl DeliveryBindingV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        authorization_scope_digest: String,
        connection_digest: String,
        agent_id: String,
        session_id: String,
        turn_id: String,
        call_digest: String,
        result_digest: String,
        streams: DeliveryStreamsV1,
        compaction_generation: u64,
    ) -> Result<Self, DeliveryAuthorityRefusalV1> {
        for digest in [
            &authorization_scope_digest,
            &connection_digest,
            &call_digest,
            &result_digest,
        ] {
            validate_delivery_digest_v1(digest)?;
        }
        for identity in [&agent_id, &session_id, &turn_id] {
            validate_delivery_identifier_v1(identity)?;
        }
        streams.validate()?;
        Ok(Self {
            authorization_scope_digest,
            connection_digest,
            agent_id,
            session_id,
            turn_id,
            call_digest,
            result_digest,
            streams,
            compaction_generation,
        })
    }

    pub fn authorization_scope_digest(&self) -> &str {
        &self.authorization_scope_digest
    }

    pub fn connection_digest(&self) -> &str {
        &self.connection_digest
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub fn call_digest(&self) -> &str {
        &self.call_digest
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub const fn streams(&self) -> &DeliveryStreamsV1 {
        &self.streams
    }

    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }
}

/// Wire challenge. The acknowledgment token is not bearer authority: it is
/// accepted only on the issuing live connection and only once.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryChallengeV1 {
    schema_version: u16,
    challenge_id: String,
    acknowledgement_token: String,
    binding: DeliveryBindingV1,
}

impl DeliveryChallengeV1 {
    pub(crate) fn issue(
        challenge_id: String,
        acknowledgement_token: String,
        binding: DeliveryBindingV1,
    ) -> Result<Self, DeliveryAuthorityRefusalV1> {
        validate_delivery_identifier_v1(&challenge_id)?;
        validate_delivery_digest_v1(&acknowledgement_token)?;
        Ok(Self {
            schema_version: DELIVERY_CHALLENGE_SCHEMA_VERSION,
            challenge_id,
            acknowledgement_token,
            binding,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub fn acknowledgement_token(&self) -> &str {
        &self.acknowledgement_token
    }

    pub const fn binding(&self) -> &DeliveryBindingV1 {
        &self.binding
    }
}

/// Strict acknowledgment of every challenge binding field. Echoing a result
/// ID or digest alone is intentionally insufficient.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryAcknowledgementV1 {
    schema_version: u16,
    challenge_id: String,
    acknowledgement_token: String,
    binding: DeliveryBindingV1,
}

impl DeliveryAcknowledgementV1 {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub fn acknowledgement_token(&self) -> &str {
        &self.acknowledgement_token
    }

    pub const fn binding(&self) -> &DeliveryBindingV1 {
        &self.binding
    }

    pub(crate) fn validate(&self) -> Result<(), DeliveryAuthorityRefusalV1> {
        if self.schema_version != DELIVERY_ACKNOWLEDGEMENT_SCHEMA_VERSION {
            return Err(DeliveryAuthorityRefusalV1::MalformedAcknowledgement);
        }
        validate_delivery_identifier_v1(&self.challenge_id)?;
        validate_delivery_digest_v1(&self.acknowledgement_token)?;
        self.binding.streams.validate()
    }
}

impl_redacted_debug!(
    DeliveryStreamsV1,
    DeliveryBindingV1,
    DeliveryChallengeV1,
    DeliveryAcknowledgementV1,
);

fn validate_delivery_digest_v1(value: &str) -> Result<(), DeliveryAuthorityRefusalV1> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DeliveryAuthorityRefusalV1::InvalidBinding);
    }
    Ok(())
}

fn validate_delivery_identifier_v1(value: &str) -> Result<(), DeliveryAuthorityRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_DELIVERY_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(DeliveryAuthorityRefusalV1::InvalidBinding);
    }
    Ok(())
}

/// Construction input for a validated [`GatewayToolCallV1`].
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayToolCallInputV1 {
    pub schema_version: u16,
    pub provider: ProviderIdentityV1,
    pub model: ModelIdentityV1,
    pub tool: ToolIdentityV1,
    pub arguments: CanonicalArguments,
    pub workspace: WorkspaceIdentityV1,
    pub call: AgentCallIdentityV1,
    pub task: Option<TaskIdentityV1>,
    pub state: RepositoryEnvironmentStateV1,
    pub permission_class: PermissionClass,
    pub effect_class: EffectClass,
    pub freshness: FreshnessRequirementV1,
    pub presentation: PresentationMode,
}

/// Canonical, immutable, bounded gateway request envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayToolCallV1 {
    schema_version: u16,
    provider: ProviderIdentityV1,
    model: ModelIdentityV1,
    tool: ToolIdentityV1,
    arguments: CanonicalArguments,
    workspace: WorkspaceIdentityV1,
    call: AgentCallIdentityV1,
    task: Option<TaskIdentityV1>,
    state: RepositoryEnvironmentStateV1,
    permission_class: PermissionClass,
    effect_class: EffectClass,
    freshness: FreshnessRequirementV1,
    presentation: PresentationMode,
    canonical_argument_bytes: Vec<u8>,
    canonical_bytes: Vec<u8>,
}

impl Serialize for GatewayToolCallV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = GatewayToolCallSerializeV1 {
            schema_version: self.schema_version,
            provider: &self.provider,
            model: &self.model,
            tool: &self.tool,
            arguments: &self.arguments,
            workspace: &self.workspace,
            call: &self.call,
            task: self.task.as_ref(),
            state: &self.state,
            permission_class: self.permission_class,
            effect_class: self.effect_class,
            freshness: self.freshness,
            presentation: self.presentation,
        };
        let value = serde_json::to_value(wire).map_err(serde::ser::Error::custom)?;
        let node = node_from_value(value, ENVELOPE_LIMITS).map_err(serde::ser::Error::custom)?;
        node.serialize(serializer)
    }
}

#[derive(Serialize)]
struct GatewayToolCallSerializeV1<'a> {
    schema_version: u16,
    provider: &'a ProviderIdentityV1,
    model: &'a ModelIdentityV1,
    tool: &'a ToolIdentityV1,
    arguments: &'a CanonicalArguments,
    workspace: &'a WorkspaceIdentityV1,
    call: &'a AgentCallIdentityV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<&'a TaskIdentityV1>,
    state: &'a RepositoryEnvironmentStateV1,
    permission_class: PermissionClass,
    effect_class: EffectClass,
    freshness: FreshnessRequirementV1,
    presentation: PresentationMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayToolCallWireV1 {
    schema_version: u16,
    provider: ProviderIdentityV1,
    model: ModelIdentityV1,
    tool: ToolIdentityV1,
    arguments: Value,
    workspace: WorkspaceIdentityV1,
    call: AgentCallIdentityV1,
    task: Option<TaskIdentityV1>,
    state: RepositoryEnvironmentStateV1,
    permission_class: PermissionClass,
    effect_class: EffectClass,
    freshness: FreshnessRequirementV1,
    presentation: PresentationMode,
}

impl GatewayToolCallV1 {
    /// Construct the complete canonical gateway envelope.
    pub fn from_input(input: GatewayToolCallInputV1) -> Result<Self, GatewayProtocolError> {
        validate_input(&input)?;
        let canonical_argument_bytes = input.arguments.canonical_bytes();
        let mut call = Self {
            schema_version: input.schema_version,
            provider: input.provider,
            model: input.model,
            tool: input.tool,
            arguments: input.arguments,
            workspace: input.workspace,
            call: input.call,
            task: input.task,
            state: input.state,
            permission_class: input.permission_class,
            effect_class: input.effect_class,
            freshness: input.freshness,
            presentation: input.presentation,
            canonical_argument_bytes,
            canonical_bytes: Vec::new(),
        };
        call.canonical_bytes = canonicalize_serializable(&call, ENVELOPE_LIMITS)?;
        Ok(call)
    }

    /// Parse an owned gateway envelope, rejecting duplicate keys at any depth.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, GatewayProtocolError> {
        let node = parse_canonical(input, ENVELOPE_LIMITS)?;
        let canonical = encode_node(&node);
        let wire: GatewayToolCallWireV1 = serde_json::from_slice(&canonical)
            .map_err(|_| GatewayProtocolError::MalformedEnvelope)?;
        Self::from_input(GatewayToolCallInputV1 {
            schema_version: wire.schema_version,
            provider: wire.provider,
            model: wire.model,
            tool: wire.tool,
            arguments: CanonicalArguments::from_value(wire.arguments)?,
            workspace: wire.workspace,
            call: wire.call,
            task: wire.task,
            state: wire.state,
            permission_class: wire.permission_class,
            effect_class: wire.effect_class,
            freshness: wire.freshness,
            presentation: wire.presentation,
        })
    }

    pub fn from_json_str(input: &str) -> Result<Self, GatewayProtocolError> {
        Self::from_json_slice(input.as_bytes())
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn provider(&self) -> &ProviderIdentityV1 {
        &self.provider
    }

    pub fn model(&self) -> &ModelIdentityV1 {
        &self.model
    }

    pub fn tool(&self) -> &str {
        &self.tool.id
    }

    pub fn tool_identity(&self) -> &ToolIdentityV1 {
        &self.tool
    }

    pub fn arguments(&self) -> &CanonicalArguments {
        &self.arguments
    }

    pub fn workspace(&self) -> &WorkspaceIdentityV1 {
        &self.workspace
    }

    pub fn call_identity(&self) -> &AgentCallIdentityV1 {
        &self.call
    }

    pub fn call_id(&self) -> &str {
        &self.call.call_id
    }

    pub fn task(&self) -> Option<&TaskIdentityV1> {
        self.task.as_ref()
    }

    pub fn state(&self) -> &RepositoryEnvironmentStateV1 {
        &self.state
    }

    pub fn permission_class(&self) -> PermissionClass {
        self.permission_class
    }

    pub fn effect_class(&self) -> EffectClass {
        self.effect_class
    }

    pub fn freshness(&self) -> FreshnessRequirementV1 {
        self.freshness
    }

    pub fn presentation(&self) -> PresentationMode {
        self.presentation
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn canonical_argument_bytes(&self) -> &[u8] {
        &self.canonical_argument_bytes
    }

    pub fn request_digest(&self) -> RequestDigestV1 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REQUEST_DIGEST_DOMAIN);
        hasher.update(&(self.canonical_bytes.len() as u64).to_be_bytes());
        hasher.update(&self.canonical_bytes);
        RequestDigestV1(hasher.finalize().to_hex().to_string())
    }

    pub fn digest(&self) -> [u8; 32] {
        *domain_digest(REQUEST_DIGEST_DOMAIN, &self.canonical_bytes).as_bytes()
    }
}

/// Compact untrusted-boundary call. It is deliberately a different type from
/// the complete [`GatewayToolCallV1`] so each type has one wire schema, one
/// canonical byte string, and one digest domain.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayAdapterToolCallV1 {
    call_id: String,
    tool: String,
    effect: GatewayEffectClassV1,
    arguments: CanonicalArguments,
    canonical_argument_bytes: Vec<u8>,
    canonical_bytes: Vec<u8>,
}

impl GatewayAdapterToolCallV1 {
    pub fn new(
        call_id: &str,
        tool: &str,
        effect: GatewayEffectClassV1,
        arguments: &[u8],
    ) -> Result<Self, GatewayProtocolRefusalV1> {
        if !valid_identifier(call_id, false) || !valid_identifier(tool, true) {
            return Err(GatewayProtocolRefusalV1::InvalidIdentifier);
        }
        let arguments = strict_adapter_arguments(arguments)?;
        let canonical_argument_bytes = arguments.canonical_bytes();
        let canonical_bytes = compact_envelope_bytes(call_id, tool, effect, arguments.0.clone());
        Ok(Self {
            call_id: call_id.to_owned(),
            tool: tool.to_owned(),
            effect,
            arguments,
            canonical_argument_bytes,
            canonical_bytes,
        })
    }

    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, GatewayProtocolRefusalV1> {
        let parsed = parse_canonical(input, ENVELOPE_LIMITS).map_err(map_canonical_refusal)?;
        if encode_node(&parsed) != input {
            return Err(GatewayProtocolRefusalV1::NonCanonical);
        }
        let value: Value =
            serde_json::from_slice(input).map_err(|_| GatewayProtocolRefusalV1::InvalidJson)?;
        let Value::Object(object) = value else {
            return Err(GatewayProtocolRefusalV1::TopLevelNotObject);
        };
        const FIELDS: [&str; 5] = ["arguments", "call_id", "effect", "schema", "tool"];
        if object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err(GatewayProtocolRefusalV1::UnknownField);
        }
        if FIELDS.iter().any(|field| !object.contains_key(*field)) {
            return Err(GatewayProtocolRefusalV1::MissingField);
        }
        let schema = object
            .get("schema")
            .and_then(Value::as_str)
            .ok_or(GatewayProtocolRefusalV1::InvalidFieldType)?;
        if schema != GATEWAY_TOOL_CALL_SCHEMA {
            return Err(GatewayProtocolRefusalV1::InvalidSchema);
        }
        let call_id = object
            .get("call_id")
            .and_then(Value::as_str)
            .ok_or(GatewayProtocolRefusalV1::InvalidFieldType)?;
        let tool = object
            .get("tool")
            .and_then(Value::as_str)
            .ok_or(GatewayProtocolRefusalV1::InvalidFieldType)?;
        let effect_name = object
            .get("effect")
            .and_then(Value::as_str)
            .ok_or(GatewayProtocolRefusalV1::InvalidFieldType)?;
        let effect = GatewayEffectClassV1::parse(effect_name)
            .ok_or(GatewayProtocolRefusalV1::InvalidEffect)?;
        let arguments = object
            .get("arguments")
            .ok_or(GatewayProtocolRefusalV1::MissingField)?;
        if !arguments.is_object() {
            return Err(GatewayProtocolRefusalV1::ArgumentsNotObject);
        }
        let argument_bytes =
            serde_json::to_vec(arguments).map_err(|_| GatewayProtocolRefusalV1::InvalidJson)?;
        let call = Self::new(call_id, tool, effect, &argument_bytes)?;
        if call.canonical_bytes != input {
            return Err(GatewayProtocolRefusalV1::NonCanonical);
        }
        Ok(call)
    }

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub const fn effect(&self) -> GatewayEffectClassV1 {
        self.effect
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn canonical_argument_bytes(&self) -> &[u8] {
        &self.canonical_argument_bytes
    }

    pub fn digest(&self) -> [u8; 32] {
        *domain_digest(ADAPTER_DIGEST_DOMAIN, &self.canonical_bytes).as_bytes()
    }
}

impl fmt::Debug for GatewayAdapterToolCallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayAdapterToolCallV1")
            .field("digest", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for GatewayToolCallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayToolCallV1")
            .field("request_digest", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn strict_adapter_arguments(input: &[u8]) -> Result<CanonicalArguments, GatewayProtocolRefusalV1> {
    let arguments = CanonicalArguments::from_json_slice(input).map_err(map_canonical_refusal)?;
    let value: Value =
        serde_json::from_slice(input).map_err(|_| GatewayProtocolRefusalV1::InvalidJson)?;
    if !value.is_object() {
        return Err(GatewayProtocolRefusalV1::ArgumentsNotObject);
    }

    fn inspect(value: &Value) -> Result<(), GatewayProtocolRefusalV1> {
        match value {
            Value::Null | Value::Bool(_) => Ok(()),
            Value::Number(number) if number.is_i64() || number.is_u64() => Ok(()),
            Value::Number(_) => Err(GatewayProtocolRefusalV1::NonIntegralNumber),
            Value::String(value) if value.len() <= MAX_CANONICAL_STRING_BYTES => Ok(()),
            Value::String(_) => Err(GatewayProtocolRefusalV1::StringLimitExceeded),
            Value::Array(values) => {
                if values.len() > MAX_CANONICAL_COLLECTION_MEMBERS {
                    return Err(GatewayProtocolRefusalV1::CollectionLimitExceeded);
                }
                values.iter().try_for_each(inspect)
            }
            Value::Object(values) => {
                if values.len() > MAX_CANONICAL_COLLECTION_MEMBERS {
                    return Err(GatewayProtocolRefusalV1::CollectionLimitExceeded);
                }
                for (key, value) in values {
                    if key.len() > MAX_CANONICAL_STRING_BYTES {
                        return Err(GatewayProtocolRefusalV1::StringLimitExceeded);
                    }
                    inspect(value)?;
                }
                Ok(())
            }
        }
    }

    inspect(&value)?;
    Ok(arguments)
}

fn map_canonical_refusal(error: CanonicalJsonError) -> GatewayProtocolRefusalV1 {
    match error {
        CanonicalJsonError::InputTooLarge | CanonicalJsonError::EncodedTooLarge => {
            GatewayProtocolRefusalV1::ArgumentTooLarge
        }
        CanonicalJsonError::DepthLimitExceeded => GatewayProtocolRefusalV1::DepthExceeded,
        CanonicalJsonError::NodeLimitExceeded => GatewayProtocolRefusalV1::NodeLimitExceeded,
        CanonicalJsonError::DuplicateKey => GatewayProtocolRefusalV1::DuplicateKey,
        CanonicalJsonError::Malformed => GatewayProtocolRefusalV1::InvalidJson,
    }
}

fn valid_identifier(value: &str, tool: bool) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b':')
                || (tool && byte == b'/')
        })
}

fn compact_envelope_bytes(
    call_id: &str,
    tool: &str,
    effect: GatewayEffectClassV1,
    arguments: CanonicalNode,
) -> Vec<u8> {
    let values = BTreeMap::from([
        ("arguments".to_owned(), arguments),
        (
            "call_id".to_owned(),
            CanonicalNode::String(call_id.to_owned()),
        ),
        (
            "effect".to_owned(),
            CanonicalNode::String(effect.as_str().to_owned()),
        ),
        (
            "schema".to_owned(),
            CanonicalNode::String(GATEWAY_TOOL_CALL_SCHEMA.to_owned()),
        ),
        ("tool".to_owned(), CanonicalNode::String(tool.to_owned())),
    ]);
    encode_node(&CanonicalNode::Object(values))
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize()
}

/// Domain-locked digest of the complete canonical request envelope.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RequestDigestV1(String);

impl fmt::Debug for RequestDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestDigestV1(<redacted>)")
    }
}

impl RequestDigestV1 {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn canonicalize_serializable<T: Serialize>(
    value: &T,
    limits: JsonLimits,
) -> Result<Vec<u8>, CanonicalJsonError> {
    let value = serde_json::to_value(value).map_err(|_| CanonicalJsonError::Malformed)?;
    let node = node_from_value(value, limits)?;
    Ok(encode_node(&node))
}

fn validate_input(input: &GatewayToolCallInputV1) -> Result<(), GatewayProtocolError> {
    if input.schema_version != GATEWAY_TOOL_CALL_SCHEMA_VERSION {
        return Err(GatewayProtocolError::UnsupportedSchemaVersion);
    }
    validate_identity(&input.provider.id, "provider id")?;
    validate_identity(&input.provider.version, "provider version")?;
    validate_identity(&input.model.id, "model id")?;
    validate_identity(&input.model.version, "model version")?;
    validate_identity(&input.tool.id, "tool id")?;
    validate_identity(&input.tool.version, "tool version")?;
    validate_identity(&input.workspace.workspace_id, "workspace id")?;
    validate_identity(&input.workspace.cwd, "cwd")?;
    validate_identity(&input.call.agent_id, "agent id")?;
    validate_identity(&input.call.session_id, "session id")?;
    validate_identity(&input.call.turn_id, "turn id")?;
    validate_identity(&input.call.call_id, "call id")?;
    if let Some(task) = &input.task {
        validate_identity(&task.task_id, "task id")?;
        validate_identity(&task.version, "task version")?;
    }
    if let RepositoryEnvironmentStateV1::Known { reference } = &input.state {
        if reference.schema_version != GATEWAY_TOOL_CALL_SCHEMA_VERSION {
            return Err(GatewayProtocolError::UnsupportedSchemaVersion);
        }
        validate_digest(
            &reference.repository,
            "repository digest algorithm",
            "repository digest value",
        )?;
        validate_digest(
            &reference.environment,
            "environment digest algorithm",
            "environment digest value",
        )?;
    }
    Ok(())
}

fn validate_digest(
    digest: &DigestReferenceV1,
    _algorithm_field: &'static str,
    _value_field: &'static str,
) -> Result<(), GatewayProtocolError> {
    if digest.algorithm.is_empty()
        || digest.algorithm.len() > MAX_DIGEST_ALGORITHM_BYTES_V1
        || !digest
            .algorithm
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || digest.value.is_empty()
        || digest.value.len() > MAX_DIGEST_VALUE_BYTES_V1
        || !digest.value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(GatewayProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_identity(value: &str, _field: &'static str) -> Result<(), GatewayProtocolError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(GatewayProtocolError::InvalidField);
    }
    Ok(())
}
