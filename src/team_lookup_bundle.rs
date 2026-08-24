//! Strict, allocation-free parser for the team lookup-bundle v1 wire format.
//!
//! The container is only framing. Its fields remain untrusted until the caller
//! verifies the root-signed trust bundle, producer-signed manifest, ciphertext
//! digests and sizes, AEAD tags, request/runtime bindings, and local sharing
//! policy. Parsing deliberately returns borrowed slices so malformed length
//! fields cannot trigger attacker-controlled allocations.

use std::fmt;

use thiserror::Error;

use crate::remote::{MAX_BLOB_BYTES, MAX_MANIFEST_BYTES, MAX_TRUST_BUNDLE_BYTES};

pub const TEAM_LOOKUP_BUNDLE_CONTENT_TYPE: &str = "application/vnd.again.lookup-bundle-v1";
pub const TEAM_LOOKUP_BUNDLE_MAGIC: [u8; 8] = *b"AGNBNDL1";
pub const TEAM_LOOKUP_BUNDLE_HEADER_BYTES: usize = 32;
pub const TEAM_LOOKUP_BUNDLE_SCHEMA_VERSION: u16 = 1;

const VERSION_OFFSET: usize = 8;
const FLAGS_OFFSET: usize = 10;
const TRUST_LENGTH_OFFSET: usize = 12;
const MANIFEST_LENGTH_OFFSET: usize = 16;
const STDOUT_LENGTH_OFFSET: usize = 20;
const STDERR_LENGTH_OFFSET: usize = 24;
const RESERVED_OFFSET: usize = 28;

/// Borrowed untrusted fields from one structurally valid lookup bundle.
///
/// `Debug` intentionally reports lengths only; response bytes can contain
/// encrypted repository output and signed operator metadata.
#[derive(PartialEq, Eq)]
pub struct UntrustedTeamLookupBundleV1<'a> {
    initial_trust_json: &'a [u8],
    manifest_json: &'a [u8],
    stdout_ciphertext: &'a [u8],
    stderr_ciphertext: &'a [u8],
}

impl UntrustedTeamLookupBundleV1<'_> {
    pub fn initial_trust_json(&self) -> &[u8] {
        self.initial_trust_json
    }

    pub fn manifest_json(&self) -> &[u8] {
        self.manifest_json
    }

    pub fn stdout_ciphertext(&self) -> &[u8] {
        self.stdout_ciphertext
    }

    pub fn stderr_ciphertext(&self) -> &[u8] {
        self.stderr_ciphertext
    }
}

impl fmt::Debug for UntrustedTeamLookupBundleV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UntrustedTeamLookupBundleV1")
            .field("initial_trust_json_bytes", &self.initial_trust_json.len())
            .field("manifest_json_bytes", &self.manifest_json.len())
            .field("stdout_ciphertext_bytes", &self.stdout_ciphertext.len())
            .field("stderr_ciphertext_bytes", &self.stderr_ciphertext.len())
            .finish()
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TeamLookupBundleWireError {
    #[error("lookup bundle exceeds the configured cumulative response budget")]
    ResponseBudgetExceeded,
    #[error("lookup bundle is shorter than its fixed header")]
    HeaderTruncated,
    #[error("lookup bundle magic is invalid")]
    InvalidMagic,
    #[error("lookup bundle schema version is unsupported")]
    UnsupportedVersion,
    #[error("lookup bundle flags are unsupported")]
    UnsupportedFlags,
    #[error("lookup bundle reserved header field is non-zero")]
    NonZeroReserved,
    #[error("lookup bundle initial trust field is empty")]
    EmptyTrustBundle,
    #[error("lookup bundle encrypted manifest field is empty")]
    EmptyManifest,
    #[error("lookup bundle initial trust field exceeds its limit")]
    TrustBundleTooLarge,
    #[error("lookup bundle encrypted manifest field exceeds its limit")]
    ManifestTooLarge,
    #[error("lookup bundle stdout ciphertext exceeds its limit")]
    StdoutCiphertextTooLarge,
    #[error("lookup bundle stderr ciphertext exceeds its limit")]
    StderrCiphertextTooLarge,
    #[error("lookup bundle declared length overflows this platform")]
    LengthOverflow,
    #[error("lookup bundle body is shorter than its declared fields")]
    PayloadTruncated,
    #[error("lookup bundle has trailing bytes after its declared fields")]
    TrailingBytes,
}

/// Incrementally validate lookup-bundle framing while an HTTP body arrives.
///
/// This validator never retains caller bytes or allocates from declared wire
/// lengths. Once the fixed header is complete it validates every field limit
/// and computes the one exact permitted body length. A transport can therefore
/// reject an impossible declaration before buffering its payload and reject a
/// trailing byte in the chunk that contains it.
#[derive(Debug, Clone)]
pub(crate) struct TeamLookupBundleStreamValidator {
    header: [u8; TEAM_LOOKUP_BUNDLE_HEADER_BYTES],
    header_bytes: usize,
    received_bytes: usize,
    expected_bytes: Option<usize>,
    max_response_bytes: u64,
}

impl TeamLookupBundleStreamValidator {
    pub(crate) fn new(max_response_bytes: u64) -> Self {
        Self {
            header: [0; TEAM_LOOKUP_BUNDLE_HEADER_BYTES],
            header_bytes: 0,
            received_bytes: 0,
            expected_bytes: None,
            max_response_bytes,
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), TeamLookupBundleWireError> {
        let next_received = self
            .received_bytes
            .checked_add(chunk.len())
            .ok_or(TeamLookupBundleWireError::LengthOverflow)?;
        if next_received as u64 > self.max_response_bytes {
            return Err(TeamLookupBundleWireError::ResponseBudgetExceeded);
        }

        if self.header_bytes < TEAM_LOOKUP_BUNDLE_HEADER_BYTES {
            let header_remaining = TEAM_LOOKUP_BUNDLE_HEADER_BYTES - self.header_bytes;
            let copied = header_remaining.min(chunk.len());
            self.header[self.header_bytes..self.header_bytes + copied]
                .copy_from_slice(&chunk[..copied]);
            self.header_bytes += copied;
            if self.header_bytes == TEAM_LOOKUP_BUNDLE_HEADER_BYTES {
                self.expected_bytes = Some(validate_header(&self.header, self.max_response_bytes)?);
            }
        }

        if self
            .expected_bytes
            .is_some_and(|expected| next_received > expected)
        {
            return Err(TeamLookupBundleWireError::TrailingBytes);
        }
        self.received_bytes = next_received;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), TeamLookupBundleWireError> {
        if self.header_bytes < TEAM_LOOKUP_BUNDLE_HEADER_BYTES {
            return Err(TeamLookupBundleWireError::HeaderTruncated);
        }
        let expected = self
            .expected_bytes
            .ok_or(TeamLookupBundleWireError::HeaderTruncated)?;
        match self.received_bytes.cmp(&expected) {
            std::cmp::Ordering::Less => Err(TeamLookupBundleWireError::PayloadTruncated),
            std::cmp::Ordering::Greater => Err(TeamLookupBundleWireError::TrailingBytes),
            std::cmp::Ordering::Equal => Ok(()),
        }
    }
}

/// Parse one complete v1 body without allocating from wire-controlled lengths.
pub fn parse_team_lookup_bundle_v1(
    body: &[u8],
    max_response_bytes: u64,
) -> Result<UntrustedTeamLookupBundleV1<'_>, TeamLookupBundleWireError> {
    let mut validator = TeamLookupBundleStreamValidator::new(max_response_bytes);
    validator.push(body)?;
    validator.finish()?;
    let expected_length = validate_header(body, max_response_bytes)?;

    let trust_length = read_u32(body, TRUST_LENGTH_OFFSET) as usize;
    let manifest_length = read_u32(body, MANIFEST_LENGTH_OFFSET) as usize;
    let stdout_length = read_u32(body, STDOUT_LENGTH_OFFSET) as usize;

    let trust_start = TEAM_LOOKUP_BUNDLE_HEADER_BYTES;
    let manifest_start = trust_start + trust_length;
    let stdout_start = manifest_start + manifest_length;
    let stderr_start = stdout_start + stdout_length;

    Ok(UntrustedTeamLookupBundleV1 {
        initial_trust_json: &body[trust_start..manifest_start],
        manifest_json: &body[manifest_start..stdout_start],
        stdout_ciphertext: &body[stdout_start..stderr_start],
        stderr_ciphertext: &body[stderr_start..expected_length],
    })
}

fn validate_header(
    header: &[u8],
    max_response_bytes: u64,
) -> Result<usize, TeamLookupBundleWireError> {
    if header.len() < TEAM_LOOKUP_BUNDLE_HEADER_BYTES {
        return Err(TeamLookupBundleWireError::HeaderTruncated);
    }
    if header[..TEAM_LOOKUP_BUNDLE_MAGIC.len()] != TEAM_LOOKUP_BUNDLE_MAGIC {
        return Err(TeamLookupBundleWireError::InvalidMagic);
    }
    if read_u16(header, VERSION_OFFSET) != TEAM_LOOKUP_BUNDLE_SCHEMA_VERSION {
        return Err(TeamLookupBundleWireError::UnsupportedVersion);
    }
    if read_u16(header, FLAGS_OFFSET) != 0 {
        return Err(TeamLookupBundleWireError::UnsupportedFlags);
    }
    if read_u32(header, RESERVED_OFFSET) != 0 {
        return Err(TeamLookupBundleWireError::NonZeroReserved);
    }

    let trust_length = read_u32(header, TRUST_LENGTH_OFFSET) as usize;
    let manifest_length = read_u32(header, MANIFEST_LENGTH_OFFSET) as usize;
    let stdout_length = read_u32(header, STDOUT_LENGTH_OFFSET) as usize;
    let stderr_length = read_u32(header, STDERR_LENGTH_OFFSET) as usize;

    if trust_length == 0 {
        return Err(TeamLookupBundleWireError::EmptyTrustBundle);
    }
    if manifest_length == 0 {
        return Err(TeamLookupBundleWireError::EmptyManifest);
    }
    if trust_length > MAX_TRUST_BUNDLE_BYTES {
        return Err(TeamLookupBundleWireError::TrustBundleTooLarge);
    }
    if manifest_length > MAX_MANIFEST_BYTES {
        return Err(TeamLookupBundleWireError::ManifestTooLarge);
    }
    if stdout_length > MAX_BLOB_BYTES {
        return Err(TeamLookupBundleWireError::StdoutCiphertextTooLarge);
    }
    if stderr_length > MAX_BLOB_BYTES {
        return Err(TeamLookupBundleWireError::StderrCiphertextTooLarge);
    }

    let expected_length = [trust_length, manifest_length, stdout_length, stderr_length]
        .into_iter()
        .try_fold(TEAM_LOOKUP_BUNDLE_HEADER_BYTES, |total, length| {
            total.checked_add(length)
        })
        .ok_or(TeamLookupBundleWireError::LengthOverflow)?;
    if expected_length as u64 > max_response_bytes {
        return Err(TeamLookupBundleWireError::ResponseBudgetExceeded);
    }
    Ok(expected_length)
}

fn read_u16(body: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([body[offset], body[offset + 1]])
}

fn read_u32(body: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        body[offset],
        body[offset + 1],
        body[offset + 2],
        body[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: u64 = 40 * 1024 * 1024;

    #[derive(serde::Deserialize)]
    struct RetainedWireFixture {
        schema: String,
        initial_trust_hex: String,
        manifest_hex: String,
        stdout_ciphertext_hex: String,
        stderr_ciphertext_hex: String,
        expected_wire_hex: String,
    }

    fn decode_fixture_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "fixture hex must have even length");
        (0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16)
                    .expect("retained fixture must contain lower-case hex")
            })
            .collect()
    }

    fn body(trust: &[u8], manifest: &[u8], stdout: &[u8], stderr: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; TEAM_LOOKUP_BUNDLE_HEADER_BYTES];
        bytes[..8].copy_from_slice(&TEAM_LOOKUP_BUNDLE_MAGIC);
        bytes[VERSION_OFFSET..VERSION_OFFSET + 2]
            .copy_from_slice(&TEAM_LOOKUP_BUNDLE_SCHEMA_VERSION.to_be_bytes());
        bytes[TRUST_LENGTH_OFFSET..TRUST_LENGTH_OFFSET + 4]
            .copy_from_slice(&(trust.len() as u32).to_be_bytes());
        bytes[MANIFEST_LENGTH_OFFSET..MANIFEST_LENGTH_OFFSET + 4]
            .copy_from_slice(&(manifest.len() as u32).to_be_bytes());
        bytes[STDOUT_LENGTH_OFFSET..STDOUT_LENGTH_OFFSET + 4]
            .copy_from_slice(&(stdout.len() as u32).to_be_bytes());
        bytes[STDERR_LENGTH_OFFSET..STDERR_LENGTH_OFFSET + 4]
            .copy_from_slice(&(stderr.len() as u32).to_be_bytes());
        bytes.extend_from_slice(trust);
        bytes.extend_from_slice(manifest);
        bytes.extend_from_slice(stdout);
        bytes.extend_from_slice(stderr);
        bytes
    }

    #[test]
    fn retained_typescript_encoder_vector_parses_byte_for_byte() {
        let fixture: RetainedWireFixture = serde_json::from_str(include_str!(
            "../service/test/fixtures/lookup-bundle-v1-wire.json"
        ))
        .unwrap();
        assert_eq!(fixture.schema, "again.lookup-bundle-v1-wire-fixture.v1");

        let wire = decode_fixture_hex(&fixture.expected_wire_hex);
        let parsed = parse_team_lookup_bundle_v1(&wire, BUDGET).unwrap();
        assert_eq!(
            parsed.initial_trust_json(),
            decode_fixture_hex(&fixture.initial_trust_hex)
        );
        assert_eq!(
            parsed.manifest_json(),
            decode_fixture_hex(&fixture.manifest_hex)
        );
        assert_eq!(
            parsed.stdout_ciphertext(),
            decode_fixture_hex(&fixture.stdout_ciphertext_hex)
        );
        assert_eq!(
            parsed.stderr_ciphertext(),
            decode_fixture_hex(&fixture.stderr_ciphertext_hex)
        );
    }

    #[test]
    fn parses_exact_borrowed_fields_and_redacts_debug_bytes() {
        let bytes = body(b"trust-secret", b"manifest", b"stdout", b"stderr");
        let parsed = parse_team_lookup_bundle_v1(&bytes, BUDGET).unwrap();
        assert_eq!(parsed.initial_trust_json(), b"trust-secret");
        assert_eq!(parsed.manifest_json(), b"manifest");
        assert_eq!(parsed.stdout_ciphertext(), b"stdout");
        assert_eq!(parsed.stderr_ciphertext(), b"stderr");
        let debug = format!("{parsed:?}");
        assert!(debug.contains("initial_trust_json_bytes: 12"));
        assert!(!debug.contains("trust-secret"));
    }

    #[test]
    fn every_truncation_of_valid_body_is_rejected_without_panic() {
        let bytes = body(b"trust", b"manifest", b"stdout", b"stderr");
        for end in 0..bytes.len() {
            assert!(parse_team_lookup_bundle_v1(&bytes[..end], BUDGET).is_err());
        }
        assert!(parse_team_lookup_bundle_v1(&bytes, BUDGET).is_ok());
    }

    #[test]
    fn rejects_trailing_bytes_and_response_budget_overrun() {
        let mut bytes = body(b"trust", b"manifest", b"stdout", b"stderr");
        bytes.push(0);
        assert_eq!(
            parse_team_lookup_bundle_v1(&bytes, BUDGET),
            Err(TeamLookupBundleWireError::TrailingBytes)
        );
        assert_eq!(
            parse_team_lookup_bundle_v1(&bytes, bytes.len() as u64 - 1),
            Err(TeamLookupBundleWireError::ResponseBudgetExceeded)
        );
    }

    #[test]
    fn rejects_magic_version_flags_reserved_and_empty_required_json() {
        let valid = body(b"trust", b"manifest", b"", b"");
        let cases = [
            (0, 0xff, TeamLookupBundleWireError::InvalidMagic),
            (
                VERSION_OFFSET + 1,
                2,
                TeamLookupBundleWireError::UnsupportedVersion,
            ),
            (
                FLAGS_OFFSET + 1,
                1,
                TeamLookupBundleWireError::UnsupportedFlags,
            ),
            (
                RESERVED_OFFSET + 3,
                1,
                TeamLookupBundleWireError::NonZeroReserved,
            ),
        ];
        for (offset, replacement, expected) in cases {
            let mut malformed = valid.clone();
            malformed[offset] = replacement;
            assert_eq!(
                parse_team_lookup_bundle_v1(&malformed, BUDGET),
                Err(expected)
            );
        }

        let mut empty_trust = valid.clone();
        empty_trust[TRUST_LENGTH_OFFSET..TRUST_LENGTH_OFFSET + 4]
            .copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            parse_team_lookup_bundle_v1(&empty_trust, BUDGET),
            Err(TeamLookupBundleWireError::EmptyTrustBundle)
        );

        let mut empty_manifest = valid;
        empty_manifest[MANIFEST_LENGTH_OFFSET..MANIFEST_LENGTH_OFFSET + 4]
            .copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            parse_team_lookup_bundle_v1(&empty_manifest, BUDGET),
            Err(TeamLookupBundleWireError::EmptyManifest)
        );
    }

    #[test]
    fn rejects_each_field_over_its_individual_limit_before_slicing() {
        let cases = [
            (
                TRUST_LENGTH_OFFSET,
                MAX_TRUST_BUNDLE_BYTES as u32 + 1,
                TeamLookupBundleWireError::TrustBundleTooLarge,
            ),
            (
                MANIFEST_LENGTH_OFFSET,
                MAX_MANIFEST_BYTES as u32 + 1,
                TeamLookupBundleWireError::ManifestTooLarge,
            ),
            (
                STDOUT_LENGTH_OFFSET,
                MAX_BLOB_BYTES as u32 + 1,
                TeamLookupBundleWireError::StdoutCiphertextTooLarge,
            ),
            (
                STDERR_LENGTH_OFFSET,
                MAX_BLOB_BYTES as u32 + 1,
                TeamLookupBundleWireError::StderrCiphertextTooLarge,
            ),
        ];
        for (offset, length, expected) in cases {
            let mut malformed = body(b"trust", b"manifest", b"", b"");
            malformed[offset..offset + 4].copy_from_slice(&length.to_be_bytes());
            assert_eq!(
                parse_team_lookup_bundle_v1(&malformed, BUDGET),
                Err(expected)
            );
        }
    }

    #[test]
    fn distinguishes_declared_truncation_from_trailing_data() {
        let mut truncated = body(b"trust", b"manifest", b"stdout", b"stderr");
        let declared = 7_u32;
        truncated[STDERR_LENGTH_OFFSET..STDERR_LENGTH_OFFSET + 4]
            .copy_from_slice(&declared.to_be_bytes());
        assert_eq!(
            parse_team_lookup_bundle_v1(&truncated, BUDGET),
            Err(TeamLookupBundleWireError::PayloadTruncated)
        );

        let mut trailing = truncated;
        trailing[STDERR_LENGTH_OFFSET..STDERR_LENGTH_OFFSET + 4]
            .copy_from_slice(&5_u32.to_be_bytes());
        assert_eq!(
            parse_team_lookup_bundle_v1(&trailing, BUDGET),
            Err(TeamLookupBundleWireError::TrailingBytes)
        );
    }

    #[test]
    fn declared_payload_can_exceed_budget_even_when_received_prefix_does_not() {
        let mut malformed = body(b"trust", b"manifest", b"", b"");
        malformed[STDOUT_LENGTH_OFFSET..STDOUT_LENGTH_OFFSET + 4]
            .copy_from_slice(&(1024_u32).to_be_bytes());
        assert_eq!(
            parse_team_lookup_bundle_v1(&malformed, malformed.len() as u64),
            Err(TeamLookupBundleWireError::ResponseBudgetExceeded)
        );
    }

    #[test]
    fn incremental_validator_accepts_every_chunk_boundary() {
        let bytes = body(b"trust", b"manifest", b"stdout", b"stderr");
        for chunk_size in 1..=bytes.len() + 1 {
            let mut validator = TeamLookupBundleStreamValidator::new(BUDGET);
            for chunk in bytes.chunks(chunk_size) {
                validator.push(chunk).unwrap();
            }
            validator.finish().unwrap();
        }
    }

    #[test]
    fn incremental_validator_rejects_impossible_header_before_payload() {
        let mut bytes = body(b"trust", b"manifest", b"", b"");
        bytes[STDOUT_LENGTH_OFFSET..STDOUT_LENGTH_OFFSET + 4]
            .copy_from_slice(&(MAX_BLOB_BYTES as u32 + 1).to_be_bytes());
        let mut validator = TeamLookupBundleStreamValidator::new(BUDGET);
        assert_eq!(
            validator.push(&bytes[..TEAM_LOOKUP_BUNDLE_HEADER_BYTES]),
            Err(TeamLookupBundleWireError::StdoutCiphertextTooLarge)
        );
    }

    #[test]
    fn incremental_validator_distinguishes_truncation_and_first_trailing_byte() {
        let bytes = body(b"trust", b"manifest", b"stdout", b"stderr");
        let mut truncated = TeamLookupBundleStreamValidator::new(BUDGET);
        truncated.push(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(
            truncated.finish(),
            Err(TeamLookupBundleWireError::PayloadTruncated)
        );

        let mut trailing = TeamLookupBundleStreamValidator::new(BUDGET);
        trailing.push(&bytes).unwrap();
        assert_eq!(
            trailing.push(&[0]),
            Err(TeamLookupBundleWireError::TrailingBytes)
        );
    }
}
