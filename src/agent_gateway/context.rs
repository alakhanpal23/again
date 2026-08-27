//! Pure selection rules for presenting an already-selected exact result.

use serde::{Deserialize, Serialize};

use super::protocol::{DigestReferenceV1, GatewayToolCallV1, PresentationMode};

/// Delivery-receipt schema version.
pub const DELIVERY_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const MAX_PRESENTATION_STREAM_BYTES: usize = 64 * 1024 * 1024;

/// The exact conversational context into which bytes were delivered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentContextIdentityV1 {
    pub agent_id: String,
    pub session_id: String,
    pub turn_id: String,
    /// Generation token changed by the owner whenever context is compacted.
    pub compaction_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentationContextV1 {
    session_id: String,
    turn_id: String,
    agent_id: Option<String>,
    environment_id: String,
    cwd_identity: [u8; 32],
    tty: bool,
    output_ceiling: u64,
}

impl PresentationContextV1 {
    pub fn new(
        session_id: &str,
        turn_id: &str,
        agent_id: Option<&str>,
        environment_id: &str,
        cwd_identity: [u8; 32],
        tty: bool,
        output_ceiling: u64,
    ) -> Result<Self, PresentationRefusalV1> {
        if !valid_context_identifier(session_id)
            || !valid_context_identifier(turn_id)
            || !valid_context_identifier(environment_id)
            || agent_id.is_some_and(|agent| !valid_context_identifier(agent))
        {
            return Err(PresentationRefusalV1::InvalidIdentifier);
        }
        Ok(Self {
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            agent_id: agent_id.map(str::to_owned),
            environment_id: environment_id.to_owned(),
            cwd_identity,
            tty,
            output_ceiling,
        })
    }

    pub fn output_ceiling(&self) -> u64 {
        self.output_ceiling
    }

    fn compact_identity(&self) -> AgentContextIdentityV1 {
        AgentContextIdentityV1 {
            agent_id: self
                .agent_id
                .as_deref()
                .unwrap_or("unattributed")
                .to_owned(),
            session_id: self.session_id.clone(),
            turn_id: self.turn_id.clone(),
            compaction_generation: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationRefusalV1 {
    InvalidIdentifier,
    InvalidDeliveryCount,
    StreamBoundExceeded,
}

impl PresentationRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidDeliveryCount => "invalid_delivery_count",
            Self::StreamBoundExceeded => "stream_bound_exceeded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayResultIdentityV1 {
    exit_code: i32,
    stdout_bytes: u64,
    stderr_bytes: u64,
    digest: [u8; 32],
}

impl GatewayResultIdentityV1 {
    pub fn from_streams(
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<Self, PresentationRefusalV1> {
        if stdout.len() > MAX_PRESENTATION_STREAM_BYTES
            || stderr.len() > MAX_PRESENTATION_STREAM_BYTES
        {
            return Err(PresentationRefusalV1::StreamBoundExceeded);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"again.agent-gateway.result.v1\0");
        hasher.update(&exit_code.to_be_bytes());
        put_stream(&mut hasher, stdout);
        put_stream(&mut hasher, stderr);
        Ok(Self {
            exit_code,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            digest: *hasher.finalize().as_bytes(),
        })
    }

    fn digest_reference(self) -> DigestReferenceV1 {
        DigestReferenceV1 {
            algorithm: "blake3".to_owned(),
            value: self
                .digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailedDeliveryV1 {
    context: PresentationContextV1Wire,
    call_digest: [u8; 32],
    result: GatewayResultIdentityV1,
    stdout_delivered: u64,
    stderr_delivered: u64,
    status_delivered: bool,
    completion_confirmed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PresentationContextV1Wire {
    session_id: String,
    turn_id: String,
    agent_id: Option<String>,
    environment_id: String,
    cwd_identity: [u8; 32],
    tty: bool,
    output_ceiling: u64,
}

impl From<&PresentationContextV1> for PresentationContextV1Wire {
    fn from(context: &PresentationContextV1) -> Self {
        Self {
            session_id: context.session_id.clone(),
            turn_id: context.turn_id.clone(),
            agent_id: context.agent_id.clone(),
            environment_id: context.environment_id.clone(),
            cwd_identity: context.cwd_identity,
            tty: context.tty,
            output_ceiling: context.output_ceiling,
        }
    }
}

impl PartialEq<PresentationContextV1> for PresentationContextV1Wire {
    fn eq(&self, other: &PresentationContextV1) -> bool {
        self.session_id == other.session_id
            && self.turn_id == other.turn_id
            && self.agent_id == other.agent_id
            && self.environment_id == other.environment_id
            && self.cwd_identity == other.cwd_identity
            && self.tty == other.tty
            && self.output_ceiling == other.output_ceiling
    }
}

impl AgentContextIdentityV1 {
    pub fn after_compaction(&self) -> Self {
        let mut compacted = self.clone();
        compacted.compaction_generation = compacted.compaction_generation.wrapping_add(1);
        compacted
    }
}

/// Evidence that the exact result bytes reached one exact agent context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReceiptV1 {
    schema_version: u16,
    context: AgentContextIdentityV1,
    exact_result: DigestReferenceV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detailed: Option<DetailedDeliveryV1>,
}

impl DeliveryReceiptV1 {
    pub fn for_exact_delivery(
        context: AgentContextIdentityV1,
        exact_result: DigestReferenceV1,
    ) -> Self {
        Self {
            schema_version: DELIVERY_RECEIPT_SCHEMA_VERSION,
            context,
            exact_result,
            detailed: None,
        }
    }

    pub fn new(
        context: &PresentationContextV1,
        call: &GatewayToolCallV1,
        result: GatewayResultIdentityV1,
        stdout_delivered: u64,
        stderr_delivered: u64,
        status_delivered: bool,
        completion_confirmed: bool,
    ) -> Result<Self, PresentationRefusalV1> {
        if stdout_delivered > result.stdout_bytes || stderr_delivered > result.stderr_bytes {
            return Err(PresentationRefusalV1::InvalidDeliveryCount);
        }
        Ok(Self {
            schema_version: DELIVERY_RECEIPT_SCHEMA_VERSION,
            context: context.compact_identity(),
            exact_result: result.digest_reference(),
            detailed: Some(DetailedDeliveryV1 {
                context: context.into(),
                call_digest: call.digest(),
                result,
                stdout_delivered,
                stderr_delivered,
                status_delivered,
                completion_confirmed,
            }),
        })
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn context(&self) -> &AgentContextIdentityV1 {
        &self.context
    }

    pub fn exact_result(&self) -> &DigestReferenceV1 {
        &self.exact_result
    }

    pub fn authorizes_compact_reference(
        &self,
        context: &AgentContextIdentityV1,
        exact_result: &DigestReferenceV1,
    ) -> bool {
        self.schema_version == DELIVERY_RECEIPT_SCHEMA_VERSION
            && self.context == *context
            && self.exact_result == *exact_result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationDecisionV1 {
    FullResult,
    ExactPriorDeliveryReference,
}

impl PresentationDecisionV1 {
    pub const fn grants_reuse(self) -> bool {
        false
    }
}

pub fn decide_presentation_v1(
    context: &PresentationContextV1,
    call: &GatewayToolCallV1,
    result: GatewayResultIdentityV1,
    receipt: Option<&DeliveryReceiptV1>,
) -> PresentationDecisionV1 {
    let Some(delivery) = receipt.and_then(|receipt| receipt.detailed.as_ref()) else {
        return PresentationDecisionV1::FullResult;
    };
    if delivery.context == *context
        && delivery.call_digest == call.digest()
        && delivery.result == result
        && delivery.stdout_delivered == result.stdout_bytes
        && delivery.stderr_delivered == result.stderr_bytes
        && delivery.status_delivered
        && delivery.completion_confirmed
    {
        PresentationDecisionV1::ExactPriorDeliveryReference
    } else {
        PresentationDecisionV1::FullResult
    }
}

/// Resolve a requested presentation without fetching or rendering any bytes.
///
/// Compact references fail closed to full retrieval unless the caller supplies
/// an exact-delivery receipt for this result and this un-compacted context.
pub fn select_presentation(
    requested: PresentationMode,
    context: &AgentContextIdentityV1,
    exact_result: &DigestReferenceV1,
    receipt: Option<&DeliveryReceiptV1>,
) -> PresentationMode {
    if requested != PresentationMode::CompactReference {
        return requested;
    }
    match receipt {
        Some(receipt) if receipt.authorizes_compact_reference(context, exact_result) => {
            PresentationMode::CompactReference
        }
        _ => PresentationMode::FullRetrievalRequired,
    }
}

fn valid_context_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn put_stream(hasher: &mut blake3::Hasher, stream: &[u8]) {
    hasher.update(&(stream.len() as u64).to_be_bytes());
    hasher.update(stream);
}
