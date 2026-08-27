//! Pure, bounded context presentation for one content-addressed result.
//!
//! This module does not select results, execute tools, or grant reuse. The
//! compact form requires opaque evidence from the exact-delivery presenter.

use std::fmt;

const RESULT_DIGEST_DOMAIN_V1: &[u8] = b"again.agent-context.result.v1\0";
const REFERENCE_PREFIX_V1: &str = "again-result-v1:blake3:";
const MAX_CONTEXT_IDENTIFIER_BYTES_V1: usize = 128;
pub const MAX_CONTEXT_RESULT_BYTES_V1: usize = 8 * 1024 * 1024;
pub const MAX_CONTEXT_EXCERPT_BYTES_V1: usize = 64 * 1024;

/// Stable, payload-free compiler refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextCompilerRefusalV1 {
    Identifier,
    ResultBound,
    ExcerptRange,
    ExcerptBound,
    DeliveryIncomplete,
    DeliveryAuthority,
    GenerationOverflow,
}

impl ContextCompilerRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Identifier => "invalid_identifier",
            Self::ResultBound => "result_bound_exceeded",
            Self::ExcerptRange => "invalid_excerpt_range",
            Self::ExcerptBound => "excerpt_bound_exceeded",
            Self::DeliveryIncomplete => "delivery_incomplete",
            Self::DeliveryAuthority => "delivery_authority_mismatch",
            Self::GenerationOverflow => "compaction_generation_exhausted",
        }
    }
}

/// The exact context identity against which compact delivery is authorized.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextIdentityV1 {
    agent_id: String,
    session_id: String,
    turn_id: String,
    compaction_generation: u64,
}

impl fmt::Debug for ContextIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContextIdentityV1(<redacted>)")
    }
}

impl ContextIdentityV1 {
    pub fn new(
        agent_id: &str,
        session_id: &str,
        turn_id: &str,
        compaction_generation: u64,
    ) -> Result<Self, ContextCompilerRefusalV1> {
        for value in [agent_id, session_id, turn_id] {
            validate_identifier_v1(value)?;
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: turn_id.to_owned(),
            compaction_generation,
        })
    }

    pub fn after_compaction(&self) -> Result<Self, ContextCompilerRefusalV1> {
        let next = self
            .compaction_generation
            .checked_add(1)
            .ok_or(ContextCompilerRefusalV1::GenerationOverflow)?;
        Self::new(&self.agent_id, &self.session_id, &self.turn_id, next)
    }

    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }
}

/// Immutable bounded source bytes and their content identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextResultV1 {
    identity: FullRetrievalIdentityV1,
    bytes: Vec<u8>,
}

impl fmt::Debug for ContextResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContextResultV1(<redacted>)")
    }
}

impl ContextResultV1 {
    pub fn new(result_id: &str, bytes: &[u8]) -> Result<Self, ContextCompilerRefusalV1> {
        validate_identifier_v1(result_id)?;
        if bytes.len() > MAX_CONTEXT_RESULT_BYTES_V1 {
            return Err(ContextCompilerRefusalV1::ResultBound);
        }
        let digest = digest_result_v1(bytes);
        Ok(Self {
            identity: FullRetrievalIdentityV1 {
                result_id: result_id.to_owned(),
                digest,
                total_bytes: bytes.len() as u64,
            },
            bytes: bytes.to_vec(),
        })
    }

    pub const fn identity(&self) -> &FullRetrievalIdentityV1 {
        &self.identity
    }
}

/// Identity retained by every presentation so the full result remains
/// retrievable without interpreting presented bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct FullRetrievalIdentityV1 {
    result_id: String,
    digest: [u8; 32],
    total_bytes: u64,
}

impl fmt::Debug for FullRetrievalIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FullRetrievalIdentityV1(<redacted>)")
    }
}

impl FullRetrievalIdentityV1 {
    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// Opaque presenter-issued proof of exact byte delivery into one context.
/// It is deliberately non-serializable and has no public constructor.
pub struct ExactDeliveryAuthorityV1 {
    context: ContextIdentityV1,
    result: FullRetrievalIdentityV1,
}

impl fmt::Debug for ExactDeliveryAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactDeliveryAuthorityV1(<redacted>)")
    }
}

/// Crate-local presenter completion boundary. Product composition must invoke
/// this only after the supplied bytes reached the named context and status is
/// complete; byte equality is rechecked here before authority is issued.
#[allow(dead_code)]
pub(crate) fn complete_exact_delivery_v1(
    context: &ContextIdentityV1,
    result: &ContextResultV1,
    delivered_bytes: &[u8],
    status_delivered: bool,
    completion_confirmed: bool,
) -> Result<ExactDeliveryAuthorityV1, ContextCompilerRefusalV1> {
    if delivered_bytes != result.bytes || !status_delivered || !completion_confirmed {
        return Err(ContextCompilerRefusalV1::DeliveryIncomplete);
    }
    Ok(ExactDeliveryAuthorityV1 {
        context: context.clone(),
        result: result.identity.clone(),
    })
}

#[derive(Clone, Copy, Debug)]
pub enum ContextPresentationRequestV1<'a> {
    ExactFull,
    DeterministicExcerpt {
        start: u64,
        max_bytes: u64,
    },
    CompactContentAddressed {
        authority: &'a ExactDeliveryAuthorityV1,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteOffsetsV1 {
    start: u64,
    end_exclusive: u64,
}

impl ByteOffsetsV1 {
    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end_exclusive(self) -> u64 {
        self.end_exclusive
    }
}

#[derive(Clone, PartialEq, Eq)]
enum PresentedContentV1 {
    Exact(Vec<u8>),
    Excerpt {
        bytes: Vec<u8>,
        offsets: ByteOffsetsV1,
    },
    CompactReference(Vec<u8>),
}

/// One deterministic presentation. Every variant retains the same full
/// retrieval identity and reports source bytes omitted plus a deterministic
/// payload/reference-only token estimate.
#[derive(Clone, PartialEq, Eq)]
pub struct CompiledContextPresentationV1 {
    identity: FullRetrievalIdentityV1,
    content: PresentedContentV1,
    source_bytes_omitted: u64,
    estimated_tokens: u64,
}

impl fmt::Debug for CompiledContextPresentationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompiledContextPresentationV1(<redacted>)")
    }
}

impl CompiledContextPresentationV1 {
    pub const fn identity(&self) -> &FullRetrievalIdentityV1 {
        &self.identity
    }

    pub fn exact_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            PresentedContentV1::Exact(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn excerpt(&self) -> Option<(&[u8], ByteOffsetsV1)> {
        match &self.content {
            PresentedContentV1::Excerpt { bytes, offsets } => Some((bytes, *offsets)),
            _ => None,
        }
    }

    pub fn compact_reference_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            PresentedContentV1::CompactReference(reference) => Some(reference),
            _ => None,
        }
    }

    pub const fn source_bytes_omitted(&self) -> u64 {
        self.source_bytes_omitted
    }

    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }

    pub const fn grants_reuse(&self) -> bool {
        false
    }

    pub const fn grants_execution(&self) -> bool {
        false
    }
}

pub fn compile_context_presentation_v1(
    context: &ContextIdentityV1,
    result: &ContextResultV1,
    request: ContextPresentationRequestV1<'_>,
) -> Result<CompiledContextPresentationV1, ContextCompilerRefusalV1> {
    let (content, included_source_bytes, presented_bytes) = match request {
        ContextPresentationRequestV1::ExactFull => {
            let bytes = result.bytes.clone();
            let length = bytes.len() as u64;
            (PresentedContentV1::Exact(bytes), length, length)
        }
        ContextPresentationRequestV1::DeterministicExcerpt { start, max_bytes } => {
            if max_bytes == 0 || max_bytes > MAX_CONTEXT_EXCERPT_BYTES_V1 as u64 {
                return Err(ContextCompilerRefusalV1::ExcerptBound);
            }
            if start > result.identity.total_bytes {
                return Err(ContextCompilerRefusalV1::ExcerptRange);
            }
            let end = start
                .checked_add(max_bytes)
                .unwrap_or(u64::MAX)
                .min(result.identity.total_bytes);
            let start_usize =
                usize::try_from(start).map_err(|_| ContextCompilerRefusalV1::ExcerptRange)?;
            let end_usize =
                usize::try_from(end).map_err(|_| ContextCompilerRefusalV1::ExcerptRange)?;
            let bytes = result.bytes[start_usize..end_usize].to_vec();
            let length = bytes.len() as u64;
            (
                PresentedContentV1::Excerpt {
                    bytes,
                    offsets: ByteOffsetsV1 {
                        start,
                        end_exclusive: end,
                    },
                },
                length,
                length,
            )
        }
        ContextPresentationRequestV1::CompactContentAddressed { authority } => {
            if authority.context != *context || authority.result != result.identity {
                return Err(ContextCompilerRefusalV1::DeliveryAuthority);
            }
            let reference = compact_reference_v1(&result.identity);
            let length = reference.len() as u64;
            (PresentedContentV1::CompactReference(reference), 0, length)
        }
    };
    let source_bytes_omitted = result
        .identity
        .total_bytes
        .checked_sub(included_source_bytes)
        .expect("included bytes never exceed the bounded result");
    Ok(CompiledContextPresentationV1 {
        identity: result.identity.clone(),
        content,
        source_bytes_omitted,
        estimated_tokens: token_estimate_v1(presented_bytes),
    })
}

fn validate_identifier_v1(value: &str) -> Result<(), ContextCompilerRefusalV1> {
    if value.is_empty()
        || value.len() > MAX_CONTEXT_IDENTIFIER_BYTES_V1
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ContextCompilerRefusalV1::Identifier);
    }
    Ok(())
}

fn digest_result_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESULT_DIGEST_DOMAIN_V1);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn compact_reference_v1(identity: &FullRetrievalIdentityV1) -> Vec<u8> {
    let mut reference = Vec::with_capacity(REFERENCE_PREFIX_V1.len() + 64 + 1 + 20);
    reference.extend_from_slice(REFERENCE_PREFIX_V1.as_bytes());
    for byte in identity.digest {
        reference.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    reference.push(b':');
    reference.extend_from_slice(identity.total_bytes.to_string().as_bytes());
    reference
}

const fn token_estimate_v1(presented_bytes: u64) -> u64 {
    presented_bytes.div_ceil(4)
}
