//! Pure selection rules for presenting an already-selected exact result.

use std::fmt;

use serde::Serialize;

use super::protocol::{DigestReferenceV1, GatewayToolCallV1, PresentationMode};

pub const DELIVERY_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const MAX_PRESENTATION_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTEXT_IDENTIFIER_BYTES_V1: usize = 128;

/// Exact conversational context. Fields are private so deserialization or a
/// struct literal cannot manufacture a context that bypasses validation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentContextIdentityV1 {
    agent_id: String,
    session_id: String,
    turn_id: String,
    compaction_generation: u64,
}

impl fmt::Debug for AgentContextIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentContextIdentityV1(<redacted>)")
    }
}

impl AgentContextIdentityV1 {
    pub fn new(
        agent_id: &str,
        session_id: &str,
        turn_id: &str,
        compaction_generation: u64,
    ) -> Result<Self, PresentationRefusalV1> {
        for value in [agent_id, session_id, turn_id] {
            validate_context_identifier(value)?;
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            compaction_generation,
        })
    }

    pub fn after_compaction(&self) -> Result<Self, PresentationRefusalV1> {
        let generation = self
            .compaction_generation
            .checked_add(1)
            .ok_or(PresentationRefusalV1::CompactionGenerationExhausted)?;
        Self::new(&self.agent_id, &self.session_id, &self.turn_id, generation)
    }

    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PresentationContextV1 {
    session_id: String,
    turn_id: String,
    agent_id: Option<String>,
    environment_id: String,
    cwd_identity: [u8; 32],
    tty: bool,
    output_ceiling: u64,
    compaction_generation: u64,
}

impl fmt::Debug for PresentationContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PresentationContextV1(<redacted>)")
    }
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
        Self::new_at_generation(
            session_id,
            turn_id,
            agent_id,
            environment_id,
            cwd_identity,
            tty,
            output_ceiling,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_at_generation(
        session_id: &str,
        turn_id: &str,
        agent_id: Option<&str>,
        environment_id: &str,
        cwd_identity: [u8; 32],
        tty: bool,
        output_ceiling: u64,
        compaction_generation: u64,
    ) -> Result<Self, PresentationRefusalV1> {
        for value in [session_id, turn_id, environment_id] {
            validate_context_identifier(value)?;
        }
        if let Some(agent_id) = agent_id {
            validate_context_identifier(agent_id)?;
        }
        Ok(Self {
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            agent_id: agent_id.map(str::to_owned),
            environment_id: environment_id.to_owned(),
            cwd_identity,
            tty,
            output_ceiling,
            compaction_generation,
        })
    }

    pub fn after_compaction(&self) -> Result<Self, PresentationRefusalV1> {
        let generation = self
            .compaction_generation
            .checked_add(1)
            .ok_or(PresentationRefusalV1::CompactionGenerationExhausted)?;
        Self::new_at_generation(
            &self.session_id,
            &self.turn_id,
            self.agent_id.as_deref(),
            &self.environment_id,
            self.cwd_identity,
            self.tty,
            self.output_ceiling,
            generation,
        )
    }

    pub const fn output_ceiling(&self) -> u64 {
        self.output_ceiling
    }

    #[allow(dead_code)]
    fn compact_identity(&self) -> AgentContextIdentityV1 {
        AgentContextIdentityV1 {
            agent_id: self
                .agent_id
                .as_deref()
                .unwrap_or("unattributed")
                .to_owned(),
            session_id: self.session_id.clone(),
            turn_id: self.turn_id.clone(),
            compaction_generation: self.compaction_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationRefusalV1 {
    InvalidIdentifier,
    InvalidDeliveryCount,
    StreamBoundExceeded,
    IncompleteDelivery,
    CompactionGenerationExhausted,
}

impl PresentationRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidDeliveryCount => "invalid_delivery_count",
            Self::StreamBoundExceeded => "stream_bound_exceeded",
            Self::IncompleteDelivery => "incomplete_delivery",
            Self::CompactionGenerationExhausted => "compaction_generation_exhausted",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayResultIdentityV1 {
    exit_code: i32,
    stdout_bytes: u64,
    stderr_bytes: u64,
    digest: [u8; 32],
}

impl fmt::Debug for GatewayResultIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayResultIdentityV1(<redacted>)")
    }
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

    #[allow(dead_code)]
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

#[derive(Clone, PartialEq, Eq, Serialize)]
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

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PresentationContextV1Wire {
    session_id: String,
    turn_id: String,
    agent_id: Option<String>,
    environment_id: String,
    cwd_identity: [u8; 32],
    tty: bool,
    output_ceiling: u64,
    compaction_generation: u64,
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
            compaction_generation: context.compaction_generation,
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
            && self.compaction_generation == other.compaction_generation
    }
}

/// Presenter-issued evidence. It is serializable for display/storage but has
/// no `Deserialize` implementation and no public constructor.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReceiptV1 {
    schema_version: u16,
    context: AgentContextIdentityV1,
    exact_result: DigestReferenceV1,
    detailed: DetailedDeliveryV1,
}

impl fmt::Debug for DeliveryReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeliveryReceiptV1(<redacted>)")
    }
}

impl DeliveryReceiptV1 {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn context(&self) -> &AgentContextIdentityV1 {
        &self.context
    }

    pub const fn exact_result(&self) -> &DigestReferenceV1 {
        &self.exact_result
    }

    fn authorizes_compact_reference(
        &self,
        context: &AgentContextIdentityV1,
        exact_result: &DigestReferenceV1,
    ) -> bool {
        self.schema_version == DELIVERY_RECEIPT_SCHEMA_VERSION
            && self.context == *context
            && self.exact_result == *exact_result
            && self.detailed.stdout_delivered == self.detailed.result.stdout_bytes
            && self.detailed.stderr_delivered == self.detailed.result.stderr_bytes
            && self.detailed.status_delivered
            && self.detailed.completion_confirmed
    }
}

/// Narrow crate-private presenter completion boundary. Callers cannot mint a
/// receipt until exact stream counts, status delivery, and completion all hold.
#[allow(dead_code)]
pub(crate) fn presenter_complete_exact_delivery_v1(
    context: &PresentationContextV1,
    call: &GatewayToolCallV1,
    result: GatewayResultIdentityV1,
    stdout_delivered: u64,
    stderr_delivered: u64,
    status_delivered: bool,
    completion_confirmed: bool,
) -> Result<DeliveryReceiptV1, PresentationRefusalV1> {
    if stdout_delivered > result.stdout_bytes || stderr_delivered > result.stderr_bytes {
        return Err(PresentationRefusalV1::InvalidDeliveryCount);
    }
    if stdout_delivered != result.stdout_bytes
        || stderr_delivered != result.stderr_bytes
        || !status_delivered
        || !completion_confirmed
    {
        return Err(PresentationRefusalV1::IncompleteDelivery);
    }
    Ok(DeliveryReceiptV1 {
        schema_version: DELIVERY_RECEIPT_SCHEMA_VERSION,
        context: context.compact_identity(),
        exact_result: result.digest_reference(),
        detailed: DetailedDeliveryV1 {
            context: context.into(),
            call_digest: call.digest(),
            result,
            stdout_delivered,
            stderr_delivered,
            status_delivered,
            completion_confirmed,
        },
    })
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
    let Some(delivery) = receipt.map(|receipt| &receipt.detailed) else {
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

fn validate_context_identifier(value: &str) -> Result<(), PresentationRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_CONTEXT_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(PresentationRefusalV1::InvalidIdentifier);
    }
    Ok(())
}

fn put_stream(hasher: &mut blake3::Hasher, stream: &[u8]) {
    hasher.update(&(stream.len() as u64).to_be_bytes());
    hasher.update(stream);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_gateway::protocol::{
        AgentCallIdentityV1, CanonicalArguments, EffectClass, FreshnessRequirementV1,
        GatewayToolCallInputV1, ModelIdentityV1, PermissionClass, ProviderIdentityV1,
        RepositoryEnvironmentStateV1, ToolIdentityV1, WorkspaceIdentityV1,
    };

    fn call() -> GatewayToolCallV1 {
        GatewayToolCallV1::from_input(GatewayToolCallInputV1 {
            schema_version: 1,
            provider: ProviderIdentityV1 {
                id: "provider".to_owned(),
                version: "1".to_owned(),
            },
            model: ModelIdentityV1 {
                id: "model".to_owned(),
                version: "1".to_owned(),
            },
            tool: ToolIdentityV1 {
                id: "tool".to_owned(),
                version: "1".to_owned(),
            },
            arguments: CanonicalArguments::from_json_str("{}").unwrap(),
            workspace: WorkspaceIdentityV1 {
                workspace_id: "workspace".to_owned(),
                cwd: ".".to_owned(),
            },
            call: AgentCallIdentityV1 {
                agent_id: "agent".to_owned(),
                session_id: "session".to_owned(),
                turn_id: "turn".to_owned(),
                call_id: "call".to_owned(),
            },
            task: None,
            state: RepositoryEnvironmentStateV1::Unknown,
            permission_class: PermissionClass::Preapproved,
            effect_class: EffectClass::SnapshotRead,
            freshness: FreshnessRequirementV1::Snapshot,
            presentation: PresentationMode::Exact,
        })
        .unwrap()
    }

    #[test]
    fn both_presentation_apis_refuse_after_compaction() {
        let context = PresentationContextV1::new(
            "session",
            "turn",
            Some("agent"),
            "local",
            [1; 32],
            false,
            4096,
        )
        .unwrap();
        let call = call();
        let result = GatewayResultIdentityV1::from_streams(0, b"out", b"err").unwrap();
        let receipt =
            presenter_complete_exact_delivery_v1(&context, &call, result, 3, 3, true, true)
                .unwrap();
        let compacted = context.after_compaction().unwrap();
        assert_eq!(
            decide_presentation_v1(&compacted, &call, result, Some(&receipt)),
            PresentationDecisionV1::FullResult
        );
        let compact_identity = compacted.compact_identity();
        assert_eq!(
            select_presentation(
                PresentationMode::CompactReference,
                &compact_identity,
                receipt.exact_result(),
                Some(&receipt)
            ),
            PresentationMode::FullRetrievalRequired
        );
    }

    #[test]
    fn presenter_refuses_every_incomplete_delivery_shape() {
        let context =
            PresentationContextV1::new("session", "turn", None, "local", [0; 32], false, 4096)
                .unwrap();
        let call = call();
        let result = GatewayResultIdentityV1::from_streams(0, b"out", b"err").unwrap();
        for arguments in [
            (2, 3, true, true),
            (3, 2, true, true),
            (3, 3, false, true),
            (3, 3, true, false),
        ] {
            assert_eq!(
                presenter_complete_exact_delivery_v1(
                    &context,
                    &call,
                    result,
                    arguments.0,
                    arguments.1,
                    arguments.2,
                    arguments.3,
                ),
                Err(PresentationRefusalV1::IncompleteDelivery)
            );
        }
    }

    #[test]
    fn compaction_generation_overflow_fails_closed() {
        let identity = AgentContextIdentityV1::new("agent", "session", "turn", u64::MAX).unwrap();
        assert_eq!(
            identity.after_compaction(),
            Err(PresentationRefusalV1::CompactionGenerationExhausted)
        );
    }
}
