//! Strict local configuration, credential, and trust-checkpoint admission.
//!
//! Shared-cache configuration is inert until a caller explicitly loads a
//! profile from an absolute canonical path. Profile, token, and existing
//! checkpoint files must be current-user-owned, single-link regular files with
//! exact mode `0600`; reads use `O_NOFOLLOW | O_CLOEXEC` and recheck file
//! identity after bounded reads. Ancestors must be real directories owned by
//! the current user or root and must not be writable by untrusted users.
//!
//! Checkpoint replacement is an owned `0600` same-directory stage, file fsync,
//! atomic rename, and directory fsync. The on-disk checkpoint is validated as
//! an ancestor of the replacement first, preventing a stale process from
//! overwriting newer accepted trust state.
//!
//! This protects against accidental corruption and other unprivileged users.
//! A same-user or root attacker can replace or roll back both the profile and
//! checkpoint and therefore remains outside the file-based threat boundary.
//! Stronger deployments need an external witness or platform monotonic state.

use std::fmt;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{Ordering, compiler_fence};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(unix)]
use uuid::Uuid;
use zeroize::Zeroize;

use crate::privacy::{RepositorySharingPolicy, SharingPolicyError};
use crate::team_crypto::{CryptoError, Ed25519Signer};
use crate::team_manifest_v2::{REPOSITORY_ENCRYPTION_KEY_BYTES, RepositoryEncryptionKeyV1};
use crate::trust_bundle::{
    ExpectedTrustBundle, PinnedRootKey, TrustBundleError, TrustCheckpointV1, TrustEpochTracker,
};

pub const TEAM_PROFILE_SCHEMA_VERSION: u16 = 1;
pub const TEAM_PROFILE_NAMESPACE: &str = "again.team-profile.v1";
pub const MAX_TEAM_PROFILE_BYTES: usize = 64 * 1024;
pub const MAX_READ_TOKEN_BYTES: usize = 256;
pub const MAX_WRITE_TOKEN_BYTES: usize = 256;
pub const MAX_REPOSITORY_KEY_BYTES: usize = 1_024;
pub const MAX_PRODUCER_SIGNING_KEY_BYTES: usize = 2_048;
pub const MAX_SHARING_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_TRUST_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_LOOKUP_REQUESTS: u8 = 8;
pub const MIN_LEGACY_V2_LOOKUP_REQUESTS: u8 = 5;
pub const MIN_BUNDLE_V1_LOOKUP_REQUESTS: u8 = 2;
pub const MAX_LOOKUP_RESPONSE_BYTES: u64 = 40 * 1024 * 1024;
pub const MAX_LOOKUP_TIMEOUT_MS: u64 = 30_000;
pub const MAX_PUBLISH_REQUESTS: u8 = 8;
pub const MIN_PUBLISH_REQUESTS: u8 = 4;
pub const MAX_PUBLISH_TRANSFER_BYTES: u64 = 40 * 1024 * 1024;
pub const MAX_PUBLISH_TIMEOUT_MS: u64 = 30_000;
#[cfg(unix)]
const CHECKPOINT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const CHECKPOINT_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

const ED25519_PUBLIC_KEY_HEX_BYTES: usize = 64;
const REPOSITORY_KEY_SCHEMA_VERSION: u16 = 1;
const REPOSITORY_KEY_NAMESPACE: &str = "again.repository-encryption-key.v1";
const PRODUCER_SIGNING_KEY_SCHEMA_VERSION: u16 = 1;
const PRODUCER_SIGNING_KEY_NAMESPACE: &str = "again.producer-signing-key.v1";
const SHARING_POLICY_SCHEMA_VERSION: u16 = 1;
const SHARING_POLICY_NAMESPACE: &str = "again.repository-sharing-policy.v1";
const ED25519_SECRET_KEY_BYTES: usize = 32;

/// Exact remote lookup protocol selected by a strict team profile.
///
/// There is intentionally no default and callers must not downgrade between
/// variants after admission. A profile therefore pins both the wire contract
/// and the request-count safety budget used for one lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamLookupProtocolV1 {
    LegacyV2,
    BundleV1,
}

impl TeamLookupProtocolV1 {
    const fn minimum_requests(self) -> u8 {
        match self {
            Self::LegacyV2 => MIN_LEGACY_V2_LOOKUP_REQUESTS,
            Self::BundleV1 => MIN_BUNDLE_V1_LOOKUP_REQUESTS,
        }
    }
}

/// A hard upper bound for one future remote lookup attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeamLookupBudgetV1 {
    max_requests: u8,
    max_response_bytes: u64,
    total_timeout_ms: u64,
}

impl TeamLookupBudgetV1 {
    pub fn max_requests(self) -> u8 {
        self.max_requests
    }

    pub fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }

    pub fn total_timeout_ms(self) -> u64 {
        self.total_timeout_ms
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        max_requests: u8,
        max_response_bytes: u64,
        total_timeout_ms: u64,
    ) -> Self {
        assert!((1..=MAX_LOOKUP_REQUESTS).contains(&max_requests));
        assert!((1..=MAX_LOOKUP_RESPONSE_BYTES).contains(&max_response_bytes));
        assert!((1..=MAX_LOOKUP_TIMEOUT_MS).contains(&total_timeout_ms));
        Self {
            max_requests,
            max_response_bytes,
            total_timeout_ms,
        }
    }
}

/// One cumulative publication budget. Trust download bytes and encrypted
/// upload bodies share the same transfer ceiling and wall-clock deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeamPublishBudgetV1 {
    max_requests: u8,
    max_transfer_bytes: u64,
    total_timeout_ms: u64,
}

impl TeamPublishBudgetV1 {
    pub fn max_requests(self) -> u8 {
        self.max_requests
    }

    pub fn max_transfer_bytes(self) -> u64 {
        self.max_transfer_bytes
    }

    pub fn total_timeout_ms(self) -> u64 {
        self.total_timeout_ms
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        max_requests: u8,
        max_transfer_bytes: u64,
        total_timeout_ms: u64,
    ) -> Self {
        assert!((1..=MAX_PUBLISH_REQUESTS).contains(&max_requests));
        assert!((1..=MAX_PUBLISH_TRANSFER_BYTES).contains(&max_transfer_bytes));
        assert!((1..=MAX_PUBLISH_TIMEOUT_MS).contains(&total_timeout_ms));
        Self {
            max_requests,
            max_transfer_bytes,
            total_timeout_ms,
        }
    }
}

/// Non-secret producer configuration admitted from the strict team profile.
#[derive(Debug)]
pub(crate) struct TeamPublisherConfigV1 {
    write_token_file: PathBuf,
    producer_signing_key_file: PathBuf,
    publish_budget: TeamPublishBudgetV1,
}

impl TeamPublisherConfigV1 {
    pub(crate) fn write_token_file(&self) -> &Path {
        &self.write_token_file
    }

    pub(crate) fn producer_signing_key_file(&self) -> &Path {
        &self.producer_signing_key_file
    }

    pub(crate) fn publish_budget(&self) -> TeamPublishBudgetV1 {
        self.publish_budget
    }
}

/// Validated, non-secret team profile.
///
/// This type has no deserializer: it can only be constructed by the strict
/// owned-file loader in this module.
#[derive(Debug)]
pub struct TeamProfileV1 {
    endpoint_origin: String,
    tenant_id: String,
    repository_id: String,
    generation_id: String,
    pinned_root: PinnedRootKey,
    read_token_file: PathBuf,
    repository_key_file: PathBuf,
    sharing_policy_file: PathBuf,
    checkpoint_file: PathBuf,
    runtime_attestation_checkpoint_file: PathBuf,
    lookup_protocol: TeamLookupProtocolV1,
    lookup_budget: TeamLookupBudgetV1,
    publisher: Option<TeamPublisherConfigV1>,
}

impl TeamProfileV1 {
    pub fn endpoint_origin(&self) -> &str {
        &self.endpoint_origin
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    /// Random repository incarnation returned by the service when the
    /// repository was created. Reusing a human-readable repository id must
    /// never reuse this value.
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    pub fn pinned_root(&self) -> &PinnedRootKey {
        &self.pinned_root
    }

    pub fn read_token_file(&self) -> &Path {
        &self.read_token_file
    }

    pub fn checkpoint_file(&self) -> &Path {
        &self.checkpoint_file
    }

    /// Owner-private checkpoint for the exact host/runtime audit used by the
    /// team execution boundary. This is deliberately distinct from the remote
    /// trust-epoch checkpoint: neither rollback domain can substitute for the
    /// other.
    pub(crate) fn runtime_attestation_checkpoint_file(&self) -> &Path {
        &self.runtime_attestation_checkpoint_file
    }

    pub fn repository_key_file(&self) -> &Path {
        &self.repository_key_file
    }

    pub fn sharing_policy_file(&self) -> &Path {
        &self.sharing_policy_file
    }

    pub fn lookup_budget(&self) -> TeamLookupBudgetV1 {
        self.lookup_budget
    }

    /// Return the exact lookup wire protocol pinned by this profile.
    pub fn lookup_protocol(&self) -> TeamLookupProtocolV1 {
        self.lookup_protocol
    }

    pub(crate) fn publisher(&self) -> Option<&TeamPublisherConfigV1> {
        self.publisher.as_ref()
    }

    pub fn expected_trust_bundle(&self) -> ExpectedTrustBundle<'_> {
        ExpectedTrustBundle {
            tenant_id: &self.tenant_id,
            repository_id: &self.repository_id,
            generation_id: &self.generation_id,
            endpoint_origin: &self.endpoint_origin,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct TeamProfileWireV1 {
    schema_version: u16,
    namespace: String,
    endpoint_origin: String,
    tenant_id: String,
    repository_id: String,
    generation_id: String,
    pinned_root_key_id: String,
    pinned_root_public_key_hex: String,
    read_token_file: String,
    repository_key_file: String,
    sharing_policy_file: String,
    checkpoint_file: String,
    runtime_attestation_checkpoint_file: String,
    lookup_protocol: TeamLookupProtocolV1,
    lookup_budget: TeamLookupBudgetWireV1,
    #[serde(default)]
    publisher: Option<TeamPublisherWireV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct TeamLookupBudgetWireV1 {
    max_requests: u8,
    max_response_bytes: u64,
    total_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct TeamPublisherWireV1 {
    write_token_file: String,
    producer_signing_key_file: String,
    publish_budget: TeamPublishBudgetWireV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct TeamPublishBudgetWireV1 {
    max_requests: u8,
    max_transfer_bytes: u64,
    total_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct SharingPolicyWireV1 {
    schema_version: u16,
    namespace: String,
    version: String,
    include_prefixes: Vec<String>,
    exclude_prefixes: Vec<String>,
    max_output_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RepositoryKeyWireV1 {
    schema_version: u16,
    namespace: String,
    key_id: String,
    key_hex: SecretString,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct ProducerSigningKeyWireV1 {
    schema_version: u16,
    namespace: String,
    key_id: String,
    producer_id: String,
    secret_key_hex: SecretString,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct SecretString(String);

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret bearer token. It is deliberately neither `Clone` nor serializable.
pub(crate) struct ReadToken {
    bytes: Vec<u8>,
}

/// Independently provisioned write bearer. It cannot be substituted where a
/// read credential is required, cloned, serialized, or printed.
pub(crate) struct WriteToken {
    bytes: Vec<u8>,
}

/// Loaded producer signing credential. Debug reveals only public identity;
/// the underlying secret-key object remains non-cloneable and zeroizes its
/// scalar material on drop through `ed25519-dalek`.
pub(crate) struct ProducerSigningCredentialV1 {
    signer: Ed25519Signer,
}

impl ProducerSigningCredentialV1 {
    pub(crate) fn signer(&self) -> &Ed25519Signer {
        &self.signer
    }
}

impl fmt::Debug for ProducerSigningCredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerSigningCredentialV1")
            .field("key_id", &self.signer.key_id())
            .field("producer_id", &self.signer.producer_id())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl WriteToken {
    pub(crate) fn expose(&self) -> &str {
        // SAFETY: construction accepts strict ASCII only and Drop cannot run
        // while this shared borrow is live.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }

    fn wipe(&mut self) {
        wipe_secret_bytes(&mut self.bytes);
    }
}

impl fmt::Debug for WriteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WriteToken(<redacted>)")
    }
}

impl Drop for WriteToken {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl ReadToken {
    /// The only access to bearer bytes; kept crate-private for the eventual
    /// authenticated client constructor.
    pub(crate) fn expose(&self) -> &str {
        // SAFETY: construction rejects non-ASCII bytes and mutation is limited
        // to Drop (when no safe references can coexist).
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }

    fn wipe(&mut self) {
        wipe_secret_bytes(&mut self.bytes);
    }
}

impl fmt::Debug for ReadToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadToken(<redacted>)")
    }
}

impl Drop for ReadToken {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Debug, Error)]
pub enum TeamConfigError {
    #[error("{label} path must be absolute and canonical: {path}")]
    NonCanonicalPath { label: &'static str, path: PathBuf },
    #[error("{label} path has an invalid or untrusted ancestor: {path}")]
    UntrustedAncestor { label: &'static str, path: PathBuf },
    #[error(
        "{label} must be a current-user-owned single-link regular file with exact mode 0600: {path}"
    )]
    UnsafeFile { label: &'static str, path: PathBuf },
    #[error("{label} changed while it was being read: {path}")]
    FileChanged { label: &'static str, path: PathBuf },
    #[error("{label} exceeds its {limit}-byte limit")]
    FileTooLarge { label: &'static str, limit: usize },
    #[error("I/O failed while accessing {label}: {source}")]
    Io {
        label: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("team profiles are not supported on this platform")]
    UnsupportedPlatform,
    #[error("team profile JSON is invalid")]
    InvalidProfileJson(#[source] serde_json::Error),
    #[error("unknown team-profile schema version or namespace")]
    UnknownProfileVersion,
    #[error("invalid team-profile field: {0}")]
    InvalidProfileField(&'static str),
    #[error("all team-profile files must use distinct paths")]
    AliasedProfileFiles,
    #[error("{label} must be external to the active workspace: {path}")]
    WorkspaceStateOverlap { label: &'static str, path: PathBuf },
    #[error("team profile does not contain producer publication configuration")]
    MissingPublisherConfig,
    #[error("read token does not match the strict ag1 token format")]
    InvalidReadToken,
    #[error("write token does not match the strict ag1 token format")]
    InvalidWriteToken,
    #[error("repository encryption-key JSON is invalid")]
    InvalidRepositoryKeyJson(#[source] serde_json::Error),
    #[error("unknown repository encryption-key schema version or namespace")]
    UnknownRepositoryKeyVersion,
    #[error("repository encryption-key material must be exactly 32 lower-case hex bytes")]
    InvalidRepositoryKeyMaterial,
    #[error("repository sharing-policy JSON is invalid")]
    InvalidSharingPolicyJson(#[source] serde_json::Error),
    #[error("unknown repository sharing-policy schema version or namespace")]
    UnknownSharingPolicyVersion,
    #[error("repository sharing policy is invalid: {0}")]
    InvalidSharingPolicy(#[from] SharingPolicyError),
    #[error("producer signing-key JSON is invalid")]
    InvalidProducerSigningKeyJson(#[source] serde_json::Error),
    #[error("unknown producer signing-key schema version or namespace")]
    UnknownProducerSigningKeyVersion,
    #[error("producer signing-key material must be exactly 32 lower-case hex bytes")]
    InvalidProducerSigningKeyMaterial,
    #[error("producer signing-key metadata or key material is invalid: {0}")]
    InvalidProducerSigningKey(#[from] CryptoError),
    #[error("trust checkpoint JSON is invalid")]
    InvalidCheckpointJson(#[source] serde_json::Error),
    #[error("trust checkpoint has no accepted bundle state to persist")]
    EmptyCheckpoint,
    #[error("trust checkpoint lock remained busy past its bounded deadline")]
    CheckpointLockTimeout,
    #[error("trust checkpoint validation failed: {0}")]
    Trust(#[from] TrustBundleError),
}

/// Load and validate one strict v1 profile from an owned private file.
pub fn load_team_profile(path: &Path) -> Result<TeamProfileV1, TeamConfigError> {
    let profile_path = require_absolute_path(path, "team profile")?;
    let bytes = read_owned_file(&profile_path, "team profile", MAX_TEAM_PROFILE_BYTES)?;
    let wire: TeamProfileWireV1 =
        serde_json::from_slice(&bytes).map_err(TeamConfigError::InvalidProfileJson)?;
    if wire.schema_version != TEAM_PROFILE_SCHEMA_VERSION
        || wire.namespace != TEAM_PROFILE_NAMESPACE
    {
        return Err(TeamConfigError::UnknownProfileVersion);
    }
    validate_namespace(&wire.tenant_id, "tenant_id")?;
    validate_namespace(&wire.repository_id, "repository_id")?;
    validate_generation_id(&wire.generation_id)?;
    validate_canonical_https_origin(&wire.endpoint_origin)?;
    let root_public_key = decode_lower_hex_public_key(&wire.pinned_root_public_key_hex)?;
    let pinned_root = PinnedRootKey::from_public_key(&wire.pinned_root_key_id, &root_public_key)?;
    let read_token_file = parse_absolute_path(&wire.read_token_file, "read_token_file")?;
    let repository_key_file =
        parse_absolute_path(&wire.repository_key_file, "repository_key_file")?;
    let sharing_policy_file =
        parse_absolute_path(&wire.sharing_policy_file, "sharing_policy_file")?;
    let checkpoint_file = parse_absolute_path(&wire.checkpoint_file, "checkpoint_file")?;
    let runtime_attestation_checkpoint_file = parse_absolute_path(
        &wire.runtime_attestation_checkpoint_file,
        "runtime_attestation_checkpoint_file",
    )?;
    validate_existing_owned_binding(&read_token_file, "read token")?;
    validate_existing_owned_binding(&repository_key_file, "repository encryption key")?;
    validate_existing_owned_binding(&sharing_policy_file, "repository sharing policy")?;
    validate_checkpoint_target(&checkpoint_file)?;
    validate_checkpoint_target(&runtime_attestation_checkpoint_file)?;
    let publisher = match wire.publisher {
        Some(publisher) => {
            let write_token_file =
                parse_absolute_path(&publisher.write_token_file, "publisher.write_token_file")?;
            let producer_signing_key_file = parse_absolute_path(
                &publisher.producer_signing_key_file,
                "publisher.producer_signing_key_file",
            )?;
            validate_existing_owned_binding(&write_token_file, "write token")?;
            validate_existing_owned_binding(&producer_signing_key_file, "producer signing key")?;
            Some(TeamPublisherConfigV1 {
                write_token_file,
                producer_signing_key_file,
                publish_budget: validate_publish_budget(publisher.publish_budget)?,
            })
        }
        None => None,
    };
    let mut paths = vec![
        &profile_path,
        &read_token_file,
        &repository_key_file,
        &sharing_policy_file,
        &checkpoint_file,
        &runtime_attestation_checkpoint_file,
    ];
    if let Some(publisher) = &publisher {
        paths.push(&publisher.write_token_file);
        paths.push(&publisher.producer_signing_key_file);
    }
    if paths
        .iter()
        .enumerate()
        .any(|(index, path)| paths[index + 1..].contains(path))
    {
        return Err(TeamConfigError::AliasedProfileFiles);
    }
    let lookup_protocol = wire.lookup_protocol;
    let lookup_budget = validate_lookup_budget(lookup_protocol, wire.lookup_budget)?;
    Ok(TeamProfileV1 {
        endpoint_origin: wire.endpoint_origin,
        tenant_id: wire.tenant_id,
        repository_id: wire.repository_id,
        generation_id: wire.generation_id,
        pinned_root,
        read_token_file,
        repository_key_file,
        sharing_policy_file,
        checkpoint_file,
        runtime_attestation_checkpoint_file,
        lookup_protocol,
        lookup_budget,
        publisher,
    })
}

/// Load the repository sharing policy bound to a strict team profile.
///
/// The policy file is independently admitted as a canonical, owner-only,
/// single-link file and decoded with a bounded, deny-unknown schema. Pull and
/// publication callers must compare its digest with the sealed request before
/// any network mutation or plaintext release.
pub fn load_sharing_policy(
    profile: &TeamProfileV1,
) -> Result<RepositorySharingPolicy, TeamConfigError> {
    let bytes = read_owned_file(
        &profile.sharing_policy_file,
        "repository sharing policy",
        MAX_SHARING_POLICY_BYTES,
    )?;
    let wire: SharingPolicyWireV1 =
        serde_json::from_slice(&bytes).map_err(TeamConfigError::InvalidSharingPolicyJson)?;
    if wire.schema_version != SHARING_POLICY_SCHEMA_VERSION
        || wire.namespace != SHARING_POLICY_NAMESPACE
    {
        return Err(TeamConfigError::UnknownSharingPolicyVersion);
    }
    RepositorySharingPolicy::new(
        wire.version,
        wire.include_prefixes
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        wire.exclude_prefixes
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        wire.max_output_bytes,
    )
    .map_err(TeamConfigError::from)
}

/// Reject every profile-controlled state or credential path inside the active
/// repository. Team checkpoint writes and secret reads must not mutate or
/// source data from the request being fingerprinted.
pub(crate) fn validate_profile_state_external_to_workspace(
    profile_path: &Path,
    profile: &TeamProfileV1,
    workspace: &Path,
) -> Result<(), TeamConfigError> {
    let workspace = fs::canonicalize(workspace).map_err(|source| TeamConfigError::Io {
        label: "active workspace",
        source,
    })?;
    let mut paths = vec![
        ("team profile", profile_path),
        ("read token", profile.read_token_file.as_path()),
        (
            "repository encryption key",
            profile.repository_key_file.as_path(),
        ),
        (
            "repository sharing policy",
            profile.sharing_policy_file.as_path(),
        ),
        ("trust checkpoint", profile.checkpoint_file.as_path()),
        (
            "runtime attestation checkpoint",
            profile.runtime_attestation_checkpoint_file.as_path(),
        ),
    ];
    if let Some(publisher) = &profile.publisher {
        paths.push(("write token", publisher.write_token_file.as_path()));
        paths.push((
            "producer signing key",
            publisher.producer_signing_key_file.as_path(),
        ));
    }
    for (label, path) in paths {
        if path == workspace || path.starts_with(&workspace) || workspace.starts_with(path) {
            return Err(TeamConfigError::WorkspaceStateOverlap {
                label,
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Load the independently provisioned repository decryption key from a strict
/// owned file. The returned key is non-cloneable, non-serializable, redacted
/// in `Debug`, and zeroizes its 32-byte key buffer on drop.
pub(crate) fn load_repository_key(
    profile: &TeamProfileV1,
) -> Result<RepositoryEncryptionKeyV1, TeamConfigError> {
    let mut bytes = read_owned_file(
        &profile.repository_key_file,
        "repository encryption key",
        MAX_REPOSITORY_KEY_BYTES,
    )?;
    let wire: RepositoryKeyWireV1 = match serde_json::from_slice(&bytes) {
        Ok(wire) => wire,
        Err(error) => {
            wipe_secret_bytes(&mut bytes);
            return Err(TeamConfigError::InvalidRepositoryKeyJson(error));
        }
    };
    wipe_secret_bytes(&mut bytes);
    if wire.schema_version != REPOSITORY_KEY_SCHEMA_VERSION
        || wire.namespace != REPOSITORY_KEY_NAMESPACE
    {
        return Err(TeamConfigError::UnknownRepositoryKeyVersion);
    }
    validate_identifier(&wire.key_id, "repository_key.key_id")?;
    let key_bytes = decode_lower_hex_repository_key(&wire.key_hex.0)?;
    Ok(
        RepositoryEncryptionKeyV1::from_bytes(wire.key_id, key_bytes)
            .expect("repository key id passed the identical identifier validator"),
    )
}

/// Load a strict read token. The returned secret is never cloneable,
/// serializable, or printable and its owned byte buffer is wiped on Drop.
pub(crate) fn load_read_token(profile: &TeamProfileV1) -> Result<ReadToken, TeamConfigError> {
    let mut bytes = read_owned_file(&profile.read_token_file, "read token", MAX_READ_TOKEN_BYTES)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if !is_strict_ag1_token(&bytes) {
        wipe_secret_bytes(&mut bytes);
        return Err(TeamConfigError::InvalidReadToken);
    }
    Ok(ReadToken { bytes })
}

/// Require producer configuration and load its independently provisioned
/// write credential from a strict private file.
pub(crate) fn load_write_token(profile: &TeamProfileV1) -> Result<WriteToken, TeamConfigError> {
    let publisher = profile
        .publisher()
        .ok_or(TeamConfigError::MissingPublisherConfig)?;
    let mut bytes = read_owned_file(
        publisher.write_token_file(),
        "write token",
        MAX_WRITE_TOKEN_BYTES,
    )?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if !is_strict_ag1_token(&bytes) {
        wipe_secret_bytes(&mut bytes);
        return Err(TeamConfigError::InvalidWriteToken);
    }
    Ok(WriteToken { bytes })
}

/// Load a non-cloneable Ed25519 producer key from a strict private file. The
/// decoded raw key is wiped immediately after `Ed25519Signer` takes its own
/// zeroizing key representation.
pub(crate) fn load_producer_signer(
    profile: &TeamProfileV1,
) -> Result<ProducerSigningCredentialV1, TeamConfigError> {
    let publisher = profile
        .publisher()
        .ok_or(TeamConfigError::MissingPublisherConfig)?;
    let mut bytes = read_owned_file(
        publisher.producer_signing_key_file(),
        "producer signing key",
        MAX_PRODUCER_SIGNING_KEY_BYTES,
    )?;
    let wire: ProducerSigningKeyWireV1 = match serde_json::from_slice(&bytes) {
        Ok(wire) => wire,
        Err(error) => {
            wipe_secret_bytes(&mut bytes);
            return Err(TeamConfigError::InvalidProducerSigningKeyJson(error));
        }
    };
    wipe_secret_bytes(&mut bytes);
    if wire.schema_version != PRODUCER_SIGNING_KEY_SCHEMA_VERSION
        || wire.namespace != PRODUCER_SIGNING_KEY_NAMESPACE
    {
        return Err(TeamConfigError::UnknownProducerSigningKeyVersion);
    }
    validate_identifier(&wire.key_id, "producer_signing_key.key_id")?;
    validate_identifier(&wire.producer_id, "producer_signing_key.producer_id")?;
    let mut secret_key = decode_lower_hex_signing_key(&wire.secret_key_hex.0)?;
    let signer = Ed25519Signer::from_secret_key(&wire.key_id, &wire.producer_id, &secret_key);
    secret_key.zeroize();
    signer
        .map(|signer| ProducerSigningCredentialV1 { signer })
        .map_err(TeamConfigError::from)
}

fn wipe_secret_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, uniquely borrowed initialized byte.
        // Volatile writes plus the compiler fence prevent the wipe from being
        // optimized away as dead storage.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Restore durable anti-rollback state. A missing checkpoint is first use;
/// every other read or validation failure is fail-closed.
pub fn load_trust_tracker(profile: &TeamProfileV1) -> Result<TrustEpochTracker, TeamConfigError> {
    let Some(checkpoint) = read_checkpoint_if_present(profile)? else {
        return Ok(TrustEpochTracker::new());
    };
    let mut tracker = TrustEpochTracker::new();
    tracker.restore_checkpoint(
        checkpoint,
        profile.expected_trust_bundle(),
        profile.pinned_root(),
    )?;
    Ok(tracker)
}

/// Persist complete trust history without allowing a stale process to replace
/// a newer on-disk checkpoint.
pub fn persist_trust_checkpoint(
    profile: &TeamProfileV1,
    tracker: &TrustEpochTracker,
) -> Result<(), TeamConfigError> {
    let checkpoint = tracker
        .export_checkpoint(profile.expected_trust_bundle(), profile.pinned_root())?
        .ok_or(TeamConfigError::EmptyCheckpoint)?;

    // Serialize read/compare/replace across local processes. Without this
    // lock, a stale writer could read epoch N, race a writer of N+1, then
    // atomically replace N+1 with N despite both individual writes being
    // crash-safe.
    let _checkpoint_lock = acquire_checkpoint_lock(profile)?;
    if let Some(existing) = read_checkpoint_if_present(profile)? {
        let mut monotonic = TrustEpochTracker::new();
        monotonic.restore_checkpoint(
            existing,
            profile.expected_trust_bundle(),
            profile.pinned_root(),
        )?;
        monotonic.restore_checkpoint(
            checkpoint.clone(),
            profile.expected_trust_bundle(),
            profile.pinned_root(),
        )?;
    }

    let encoded =
        serde_json::to_vec(&checkpoint).map_err(TeamConfigError::InvalidCheckpointJson)?;
    if encoded.len() > MAX_TRUST_CHECKPOINT_BYTES {
        return Err(TeamConfigError::FileTooLarge {
            label: "trust checkpoint",
            limit: MAX_TRUST_CHECKPOINT_BYTES,
        });
    }
    atomic_write_checkpoint(profile, &encoded)?;

    let committed = read_checkpoint_if_present(profile)?.ok_or(TeamConfigError::FileChanged {
        label: "trust checkpoint",
        path: profile.checkpoint_file.clone(),
    })?;
    if committed != checkpoint {
        return Err(TeamConfigError::FileChanged {
            label: "trust checkpoint",
            path: profile.checkpoint_file.clone(),
        });
    }
    Ok(())
}

fn read_checkpoint_if_present(
    profile: &TeamProfileV1,
) -> Result<Option<TrustCheckpointV1>, TeamConfigError> {
    match fs::symlink_metadata(&profile.checkpoint_file) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(TeamConfigError::Io {
                label: "trust checkpoint",
                source,
            });
        }
    }
    let bytes = read_owned_file(
        &profile.checkpoint_file,
        "trust checkpoint",
        MAX_TRUST_CHECKPOINT_BYTES,
    )?;
    let checkpoint =
        serde_json::from_slice(&bytes).map_err(TeamConfigError::InvalidCheckpointJson)?;
    Ok(Some(checkpoint))
}

fn validate_lookup_budget(
    protocol: TeamLookupProtocolV1,
    wire: TeamLookupBudgetWireV1,
) -> Result<TeamLookupBudgetV1, TeamConfigError> {
    if !(protocol.minimum_requests()..=MAX_LOOKUP_REQUESTS).contains(&wire.max_requests) {
        return Err(TeamConfigError::InvalidProfileField(
            "lookup_budget.max_requests",
        ));
    }
    if !(1..=MAX_LOOKUP_RESPONSE_BYTES).contains(&wire.max_response_bytes) {
        return Err(TeamConfigError::InvalidProfileField(
            "lookup_budget.max_response_bytes",
        ));
    }
    if !(1..=MAX_LOOKUP_TIMEOUT_MS).contains(&wire.total_timeout_ms) {
        return Err(TeamConfigError::InvalidProfileField(
            "lookup_budget.total_timeout_ms",
        ));
    }
    Ok(TeamLookupBudgetV1 {
        max_requests: wire.max_requests,
        max_response_bytes: wire.max_response_bytes,
        total_timeout_ms: wire.total_timeout_ms,
    })
}

fn validate_publish_budget(
    wire: TeamPublishBudgetWireV1,
) -> Result<TeamPublishBudgetV1, TeamConfigError> {
    if !(MIN_PUBLISH_REQUESTS..=MAX_PUBLISH_REQUESTS).contains(&wire.max_requests) {
        return Err(TeamConfigError::InvalidProfileField(
            "publisher.publish_budget.max_requests",
        ));
    }
    if !(1..=MAX_PUBLISH_TRANSFER_BYTES).contains(&wire.max_transfer_bytes) {
        return Err(TeamConfigError::InvalidProfileField(
            "publisher.publish_budget.max_transfer_bytes",
        ));
    }
    if !(1..=MAX_PUBLISH_TIMEOUT_MS).contains(&wire.total_timeout_ms) {
        return Err(TeamConfigError::InvalidProfileField(
            "publisher.publish_budget.total_timeout_ms",
        ));
    }
    Ok(TeamPublishBudgetV1 {
        max_requests: wire.max_requests,
        max_transfer_bytes: wire.max_transfer_bytes,
        total_timeout_ms: wire.total_timeout_ms,
    })
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), TeamConfigError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        Err(TeamConfigError::InvalidProfileField(field))
    } else {
        Ok(())
    }
}

fn validate_namespace(value: &str, field: &'static str) -> Result<(), TeamConfigError> {
    let mut bytes = value.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !valid_first
        || value.len() > 128
        || !bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(TeamConfigError::InvalidProfileField(field));
    }
    Ok(())
}

fn validate_generation_id(value: &str) -> Result<(), TeamConfigError> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(TeamConfigError::InvalidProfileField("generation_id"));
    }
    Ok(())
}

fn validate_canonical_https_origin(value: &str) -> Result<(), TeamConfigError> {
    if value.len() > 2_048 || !value.is_ascii() {
        return Err(TeamConfigError::InvalidProfileField("endpoint_origin"));
    }
    let parsed = reqwest::Url::parse(value)
        .map_err(|_| TeamConfigError::InvalidProfileField("endpoint_origin"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != value
    {
        return Err(TeamConfigError::InvalidProfileField("endpoint_origin"));
    }
    Ok(())
}

fn decode_lower_hex_public_key(value: &str) -> Result<[u8; 32], TeamConfigError> {
    if value.len() != ED25519_PUBLIC_KEY_HEX_BYTES
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(TeamConfigError::InvalidProfileField(
            "pinned_root_public_key_hex",
        ));
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(value.as_bytes()[index * 2]) << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1]);
    }
    Ok(output)
}

fn decode_lower_hex_repository_key(
    value: &str,
) -> Result<[u8; REPOSITORY_ENCRYPTION_KEY_BYTES], TeamConfigError> {
    if value.len() != REPOSITORY_ENCRYPTION_KEY_BYTES * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(TeamConfigError::InvalidRepositoryKeyMaterial);
    }
    let mut output = [0u8; REPOSITORY_ENCRYPTION_KEY_BYTES];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(value.as_bytes()[index * 2]) << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1]);
    }
    Ok(output)
}

fn decode_lower_hex_signing_key(
    value: &str,
) -> Result<[u8; ED25519_SECRET_KEY_BYTES], TeamConfigError> {
    if value.len() != ED25519_SECRET_KEY_BYTES * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(TeamConfigError::InvalidProducerSigningKeyMaterial);
    }
    let mut output = [0u8; ED25519_SECRET_KEY_BYTES];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(value.as_bytes()[index * 2]) << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1]);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("hex syntax was validated before decoding"),
    }
}

#[allow(dead_code)] // Used exclusively by the intentionally unwired token loader.
fn is_strict_ag1_token(value: &[u8]) -> bool {
    if !value.is_ascii() || value.contains(&b'\n') || value.contains(&b'\r') {
        return false;
    }
    let mut parts = value.split(|byte| *byte == b'.');
    let (Some(version), Some(token_id), Some(secret), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    version == b"ag1"
        && !token_id.is_empty()
        && token_id.len() <= 64
        && token_id.iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"_:-".contains(byte))
        })
        && (32..=128).contains(&secret.len())
        && secret
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn parse_absolute_path(value: &str, label: &'static str) -> Result<PathBuf, TeamConfigError> {
    if value.is_empty() || value.len() > 4_096 || value.contains('\0') {
        return Err(TeamConfigError::InvalidProfileField(label));
    }
    require_absolute_path(Path::new(value), label)
}

fn require_absolute_path(path: &Path, label: &'static str) -> Result<PathBuf, TeamConfigError> {
    if !path.is_absolute() {
        return Err(TeamConfigError::NonCanonicalPath {
            label,
            path: path.to_path_buf(),
        });
    }
    Ok(path.to_path_buf())
}

fn validate_existing_owned_binding(
    path: &Path,
    label: &'static str,
) -> Result<(), TeamConfigError> {
    validate_canonical_existing(path, label)?;
    validate_trusted_ancestors(path, label)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| TeamConfigError::Io { label, source })?;
    validate_private_file_metadata(path, &metadata, label)
}

fn validate_checkpoint_target(path: &Path) -> Result<(), TeamConfigError> {
    require_absolute_path(path, "checkpoint_file")?;
    let parent = path
        .parent()
        .ok_or(TeamConfigError::InvalidProfileField("checkpoint_file"))?;
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(TeamConfigError::InvalidProfileField("checkpoint_file"))?;
    let canonical_parent = fs::canonicalize(parent).map_err(|source| TeamConfigError::Io {
        label: "trust checkpoint parent",
        source,
    })?;
    if canonical_parent != parent || canonical_parent.join(file_name) != path {
        return Err(TeamConfigError::NonCanonicalPath {
            label: "trust checkpoint",
            path: path.to_path_buf(),
        });
    }
    validate_trusted_ancestors(path, "trust checkpoint")?;
    validate_private_checkpoint_parent(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_canonical_existing(path, "trust checkpoint")?;
            validate_private_file_metadata(path, &metadata, "trust checkpoint")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TeamConfigError::Io {
            label: "trust checkpoint",
            source,
        }),
    }
}

fn validate_canonical_existing(path: &Path, label: &'static str) -> Result<(), TeamConfigError> {
    require_absolute_path(path, label)?;
    let canonical =
        fs::canonicalize(path).map_err(|source| TeamConfigError::Io { label, source })?;
    if canonical != path {
        return Err(TeamConfigError::NonCanonicalPath {
            label,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_ancestors(path: &Path, label: &'static str) -> Result<(), TeamConfigError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and accesses no Rust memory.
    let current_uid = unsafe { libc::geteuid() };
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|source| TeamConfigError::Io { label, source })?;
        let owner_trusted = metadata.uid() == current_uid || metadata.uid() == 0;
        let mode = metadata.permissions().mode();
        let root_sticky_directory = metadata.uid() == 0 && mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !owner_trusted
            || (mode & 0o022 != 0 && !root_sticky_directory)
        {
            return Err(TeamConfigError::UntrustedAncestor {
                label,
                path: ancestor.to_path_buf(),
            });
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_ancestors(_path: &Path, _label: &'static str) -> Result<(), TeamConfigError> {
    Err(TeamConfigError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_private_checkpoint_parent(path: &Path) -> Result<(), TeamConfigError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).map_err(|source| TeamConfigError::Io {
        label: "trust checkpoint parent",
        source,
    })?;
    // SAFETY: `geteuid` has no preconditions and accesses no Rust memory.
    let current_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != current_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(TeamConfigError::UntrustedAncestor {
            label: "trust checkpoint",
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_checkpoint_parent(_path: &Path) -> Result<(), TeamConfigError> {
    Err(TeamConfigError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_private_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    label: &'static str,
) -> Result<(), TeamConfigError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and accesses no Rust memory.
    let current_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != current_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(TeamConfigError::UnsafeFile {
            label,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_metadata(
    _path: &Path,
    _metadata: &fs::Metadata,
    _label: &'static str,
) -> Result<(), TeamConfigError> {
    Err(TeamConfigError::UnsupportedPlatform)
}

#[cfg(unix)]
fn read_owned_file(
    path: &Path,
    label: &'static str,
    limit: usize,
) -> Result<Vec<u8>, TeamConfigError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    validate_canonical_existing(path, label)?;
    validate_trusted_ancestors(path, label)?;
    let before =
        fs::symlink_metadata(path).map_err(|source| TeamConfigError::Io { label, source })?;
    validate_private_file_metadata(path, &before, label)?;
    if before.len() > limit as u64 {
        return Err(TeamConfigError::FileTooLarge { label, limit });
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|source| TeamConfigError::Io { label, source })?;
    let opened = file
        .metadata()
        .map_err(|source| TeamConfigError::Io { label, source })?;
    validate_private_file_metadata(path, &opened, label)?;
    if !same_file_state(&before, &opened) {
        return Err(TeamConfigError::FileChanged {
            label,
            path: path.to_path_buf(),
        });
    }

    let mut bytes = Vec::with_capacity((opened.len() as usize).min(limit));
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| TeamConfigError::Io { label, source })?;
    if bytes.len() > limit {
        return Err(TeamConfigError::FileTooLarge { label, limit });
    }

    let after_open = file
        .metadata()
        .map_err(|source| TeamConfigError::Io { label, source })?;
    let after_path =
        fs::symlink_metadata(path).map_err(|source| TeamConfigError::Io { label, source })?;
    validate_private_file_metadata(path, &after_path, label)?;
    if !same_file_state(&opened, &after_open)
        || !same_file_state(&opened, &after_path)
        || after_open.dev() != after_path.dev()
        || after_open.ino() != after_path.ino()
    {
        return Err(TeamConfigError::FileChanged {
            label,
            path: path.to_path_buf(),
        });
    }
    validate_canonical_existing(path, label)?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_owned_file(
    _path: &Path,
    _label: &'static str,
    _limit: usize,
) -> Result<Vec<u8>, TeamConfigError> {
    Err(TeamConfigError::UnsupportedPlatform)
}

#[cfg(unix)]
fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.mode() == right.mode()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(unix)]
fn atomic_write_checkpoint(profile: &TeamProfileV1, bytes: &[u8]) -> Result<(), TeamConfigError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    validate_checkpoint_target(&profile.checkpoint_file)?;
    let parent = profile
        .checkpoint_file
        .parent()
        .ok_or(TeamConfigError::InvalidProfileField("checkpoint_file"))?;
    let stage = parent.join(format!(
        ".again-trust-checkpoint-{}.tmp",
        Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options.open(&stage).map_err(|source| TeamConfigError::Io {
            label: "trust checkpoint stage",
            source,
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| TeamConfigError::Io {
                label: "trust checkpoint stage",
                source,
            })?;
        let metadata = file.metadata().map_err(|source| TeamConfigError::Io {
            label: "trust checkpoint stage",
            source,
        })?;
        validate_private_file_metadata(&stage, &metadata, "trust checkpoint stage")?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|source| TeamConfigError::Io {
                label: "trust checkpoint stage",
                source,
            })?;
        drop(file);
        fs::rename(&stage, &profile.checkpoint_file).map_err(|source| TeamConfigError::Io {
            label: "trust checkpoint commit",
            source,
        })?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&stage);
    }
    result
}

#[cfg(unix)]
fn acquire_checkpoint_lock(profile: &TeamProfileV1) -> Result<File, TeamConfigError> {
    acquire_checkpoint_lock_with_timeout(profile, CHECKPOINT_LOCK_TIMEOUT)
}

#[cfg(unix)]
fn acquire_checkpoint_lock_with_timeout(
    profile: &TeamProfileV1,
    timeout: Duration,
) -> Result<File, TeamConfigError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = profile
        .checkpoint_file
        .parent()
        .ok_or(TeamConfigError::InvalidProfileField("checkpoint_file"))?;
    validate_private_checkpoint_parent(parent)?;
    let file_name = profile
        .checkpoint_file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(TeamConfigError::InvalidProfileField("checkpoint_file"))?;
    let lock_path = parent.join(format!(".{file_name}.lock"));

    let mut create = OpenOptions::new();
    create
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let (file, created) = match create.open(&lock_path) {
        Ok(file) => {
            // The requested mode contains no group/other bits, so a normal
            // umask cannot make the newly visible lock more permissive. Avoid
            // a post-create chmod: its ctime update races another local writer
            // performing the required identity-stability check.
            let metadata = file.metadata().map_err(|source| TeamConfigError::Io {
                label: "trust checkpoint lock",
                source,
            })?;
            validate_private_file_metadata(&lock_path, &metadata, "trust checkpoint lock")?;
            file.sync_all().map_err(|source| TeamConfigError::Io {
                label: "trust checkpoint lock",
                source,
            })?;
            (file, true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_canonical_existing(&lock_path, "trust checkpoint lock")?;
            validate_trusted_ancestors(&lock_path, "trust checkpoint lock")?;
            let before =
                fs::symlink_metadata(&lock_path).map_err(|source| TeamConfigError::Io {
                    label: "trust checkpoint lock",
                    source,
                })?;
            validate_private_file_metadata(&lock_path, &before, "trust checkpoint lock")?;
            let mut open = OpenOptions::new();
            open.read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let file = open
                .open(&lock_path)
                .map_err(|source| TeamConfigError::Io {
                    label: "trust checkpoint lock",
                    source,
                })?;
            let opened = file.metadata().map_err(|source| TeamConfigError::Io {
                label: "trust checkpoint lock",
                source,
            })?;
            validate_private_file_metadata(&lock_path, &opened, "trust checkpoint lock")?;
            if !same_file_state(&before, &opened) {
                return Err(TeamConfigError::FileChanged {
                    label: "trust checkpoint lock",
                    path: lock_path,
                });
            }
            (file, false)
        }
        Err(source) => {
            return Err(TeamConfigError::Io {
                label: "trust checkpoint lock",
                source,
            });
        }
    };

    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("the fixed checkpoint-lock timeout fits Instant");
    loop {
        // SAFETY: `file` owns a live file descriptor. `flock` retains no Rust
        // memory, and LOCK_NB ensures a wedged peer cannot block this thread
        // beyond the explicit monotonic deadline.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        let source = std::io::Error::last_os_error();
        match source.raw_os_error() {
            Some(code) if code == libc::EINTR => continue,
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(TeamConfigError::CheckpointLockTimeout);
                }
                thread::sleep(CHECKPOINT_LOCK_POLL_INTERVAL.min(remaining));
            }
            _ => {
                return Err(TeamConfigError::Io {
                    label: "trust checkpoint lock",
                    source,
                });
            }
        }
    }
    let opened = file.metadata().map_err(|source| TeamConfigError::Io {
        label: "trust checkpoint lock",
        source,
    })?;
    let final_path = fs::symlink_metadata(&lock_path).map_err(|source| TeamConfigError::Io {
        label: "trust checkpoint lock",
        source,
    })?;
    validate_private_file_metadata(&lock_path, &final_path, "trust checkpoint lock")?;
    if !same_file_state(&opened, &final_path) {
        return Err(TeamConfigError::FileChanged {
            label: "trust checkpoint lock",
            path: lock_path,
        });
    }
    if created {
        sync_directory(parent)?;
    }
    Ok(file)
}

#[cfg(not(unix))]
fn acquire_checkpoint_lock(_profile: &TeamProfileV1) -> Result<File, TeamConfigError> {
    Err(TeamConfigError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn atomic_write_checkpoint(_profile: &TeamProfileV1, _bytes: &[u8]) -> Result<(), TeamConfigError> {
    Err(TeamConfigError::UnsupportedPlatform)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), TeamConfigError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory = options.open(path).map_err(|source| TeamConfigError::Io {
        label: "trust checkpoint directory",
        source,
    })?;
    directory.sync_all().map_err(|source| TeamConfigError::Io {
        label: "trust checkpoint directory",
        source,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::team::Digest;
    use crate::trust_bundle::{
        ProducerKeyBindingV1, TRUST_BUNDLE_SCHEMA_VERSION, TrustBundleError, TrustBundleV1,
        verify_trust_bundle,
    };

    const TOKEN: &str = "ag1.reader.abcdefghijklmnopqrstuvwxyzABCDEF";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";

    struct Fixture {
        _temp: TempDir,
        profile_path: PathBuf,
        token_path: PathBuf,
        repository_key_path: PathBuf,
        sharing_policy_path: PathBuf,
        checkpoint_path: PathBuf,
        runtime_checkpoint_path: PathBuf,
        root_key: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TempDir::new().unwrap();
            let root = temp.path().canonicalize().unwrap();
            set_mode(&root, 0o700);
            let checkpoint_dir = root.join("checkpoint");
            fs::create_dir(&checkpoint_dir).unwrap();
            set_mode(&checkpoint_dir, 0o700);
            let profile_path = root.join("profile.json");
            let token_path = root.join("read.token");
            let repository_key_path = root.join("repository-key.json");
            let sharing_policy_path = root.join("sharing-policy.json");
            let checkpoint_path = checkpoint_dir.join("trust.json");
            let runtime_checkpoint_path = checkpoint_dir.join("runtime.json");
            write_private(&token_path, TOKEN.as_bytes());
            write_private(
                &repository_key_path,
                &serde_json::to_vec(&json!({
                    "schema_version": REPOSITORY_KEY_SCHEMA_VERSION,
                    "namespace": REPOSITORY_KEY_NAMESPACE,
                    "key_id": "repository-key-1",
                    "key_hex": "07".repeat(REPOSITORY_ENCRYPTION_KEY_BYTES),
                }))
                .unwrap(),
            );
            write_private(
                &sharing_policy_path,
                &serde_json::to_vec(&sharing_policy_json()).unwrap(),
            );
            let root_key = SigningKey::from_bytes(&[9; 32]);
            write_profile(
                &profile_path,
                &token_path,
                &repository_key_path,
                &sharing_policy_path,
                &checkpoint_path,
                &runtime_checkpoint_path,
                &root_key,
            );
            Self {
                _temp: temp,
                profile_path,
                token_path,
                repository_key_path,
                sharing_policy_path,
                checkpoint_path,
                runtime_checkpoint_path,
                root_key,
            }
        }

        fn profile(&self) -> TeamProfileV1 {
            load_team_profile(&self.profile_path).unwrap()
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        set_mode(path, 0o600);
    }

    fn public_key_hex(key: &SigningKey) -> String {
        key.verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn profile_json(
        token: &Path,
        repository_key: &Path,
        sharing_policy: &Path,
        checkpoint: &Path,
        runtime_checkpoint: &Path,
        root: &SigningKey,
        tenant: &str,
        repository: &str,
    ) -> Value {
        json!({
            "schema_version": TEAM_PROFILE_SCHEMA_VERSION,
            "namespace": TEAM_PROFILE_NAMESPACE,
            "endpoint_origin": "https://cache.example.test",
            "tenant_id": tenant,
            "repository_id": repository,
            "generation_id": GENERATION,
            "pinned_root_key_id": "root-key-1",
            "pinned_root_public_key_hex": public_key_hex(root),
            "read_token_file": token,
            "repository_key_file": repository_key,
            "sharing_policy_file": sharing_policy,
            "checkpoint_file": checkpoint,
            "runtime_attestation_checkpoint_file": runtime_checkpoint,
            "lookup_protocol": "legacy_v2",
            "lookup_budget": {
                "max_requests": 5,
                "max_response_bytes": 20 * 1024 * 1024,
                "total_timeout_ms": 15_000
            }
        })
    }

    fn sharing_policy_json() -> Value {
        json!({
            "schema_version": SHARING_POLICY_SCHEMA_VERSION,
            "namespace": SHARING_POLICY_NAMESPACE,
            "version": "sharing-v1",
            "include_prefixes": ["src"],
            "exclude_prefixes": ["target", ".env"],
            "max_output_bytes": 1024 * 1024,
        })
    }

    fn write_profile(
        path: &Path,
        token: &Path,
        repository_key: &Path,
        sharing_policy: &Path,
        checkpoint: &Path,
        runtime_checkpoint: &Path,
        root: &SigningKey,
    ) {
        write_private(
            path,
            &serde_json::to_vec(&profile_json(
                token,
                repository_key,
                sharing_policy,
                checkpoint,
                runtime_checkpoint,
                root,
                "tenant-a",
                "repo-a",
            ))
            .unwrap(),
        );
    }

    fn add_publisher(fixture: &Fixture) -> (PathBuf, PathBuf) {
        let root = fixture.profile_path.parent().unwrap();
        let write_token_path = root.join("write.token");
        let signing_key_path = root.join("producer-signing-key.json");
        write_private(
            &write_token_path,
            b"ag1.writer.0123456789abcdefghijklmnopqrstuvwxyzAB",
        );
        write_private(
            &signing_key_path,
            &serde_json::to_vec(&json!({
                "schema_version": PRODUCER_SIGNING_KEY_SCHEMA_VERSION,
                "namespace": PRODUCER_SIGNING_KEY_NAMESPACE,
                "key_id": "producer-key-1",
                "producer_id": "producer-a",
                "secret_key_hex": "2a".repeat(ED25519_SECRET_KEY_BYTES),
            }))
            .unwrap(),
        );
        let mut value: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        value["publisher"] = json!({
            "write_token_file": write_token_path,
            "producer_signing_key_file": signing_key_path,
            "publish_budget": {
                "max_requests": 4,
                "max_transfer_bytes": 20 * 1024 * 1024,
                "total_timeout_ms": 15_000,
            }
        });
        write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
        (write_token_path, signing_key_path)
    }

    fn digest(byte: u8) -> Digest {
        Digest::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn signed_bundle(fixture: &Fixture, epoch: u64) -> TrustBundleV1 {
        let producer = SigningKey::from_bytes(&[7; 32]);
        let mut bundle = TrustBundleV1 {
            schema_version: TRUST_BUNDLE_SCHEMA_VERSION,
            root_key_id: "root-key-1".into(),
            tenant_id: "tenant-a".into(),
            repository_id: "repo-a".into(),
            generation_id: GENERATION.into(),
            endpoint_origin: "https://cache.example.test".into(),
            epoch,
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 400,
            active_producer_keys: vec![ProducerKeyBindingV1 {
                key_id: "producer-key-1".into(),
                producer_id: "producer-a".into(),
                public_key: producer.verifying_key().to_bytes(),
            }],
            revoked_key_ids: vec!["old-key".into()],
            revoked_record_ids: vec!["old-record".into()],
            allowed_policy_digests: vec![digest(1)],
            allowed_execution_profile_digests: vec![digest(2)],
            allowed_platform_digests: vec![digest(3)],
            allowed_image_digests: vec![digest(4)],
            signature: Vec::new(),
        };
        bundle.signature = fixture
            .root_key
            .sign(&bundle.canonical_signing_bytes())
            .to_bytes()
            .to_vec();
        bundle
    }

    fn accept(fixture: &Fixture, profile: &TeamProfileV1, epoch: u64) -> TrustEpochTracker {
        let mut tracker = TrustEpochTracker::new();
        verify_trust_bundle(
            signed_bundle(fixture, epoch),
            profile.expected_trust_bundle(),
            profile.pinned_root(),
            120,
            &mut tracker,
        )
        .unwrap();
        tracker
    }

    #[test]
    fn strict_profile_and_token_roundtrip_redacts_secret() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        assert_eq!(profile.endpoint_origin(), "https://cache.example.test");
        assert_eq!(profile.tenant_id(), "tenant-a");
        assert_eq!(profile.repository_id(), "repo-a");
        assert_eq!(profile.generation_id(), GENERATION);
        assert_eq!(profile.lookup_protocol(), TeamLookupProtocolV1::LegacyV2);
        assert_eq!(profile.lookup_budget().max_requests(), 5);
        assert_eq!(profile.sharing_policy_file(), fixture.sharing_policy_path);
        assert_eq!(
            profile.runtime_attestation_checkpoint_file(),
            fixture.runtime_checkpoint_path
        );
        let sharing_policy = load_sharing_policy(&profile).unwrap();
        let expected_policy = RepositorySharingPolicy::new(
            "sharing-v1",
            vec![PathBuf::from("src")],
            vec![PathBuf::from("target"), PathBuf::from(".env")],
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(sharing_policy.version(), "sharing-v1");
        assert_eq!(sharing_policy.digest(), expected_policy.digest());
        let token = load_read_token(&profile).unwrap();
        assert_eq!(token.expose(), TOKEN);
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "ReadToken(<redacted>)");
        assert!(!rendered.contains(TOKEN));

        let repository_key = load_repository_key(&profile).unwrap();
        assert_eq!(repository_key.key_id(), "repository-key-1");
        let rendered = format!("{repository_key:?}");
        assert!(!rendered.contains(&"07".repeat(REPOSITORY_ENCRYPTION_KEY_BYTES)));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn profile_rejects_noncanonical_namespaces_and_repository_generations() {
        for generation in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789abcdef0123456789abcdeF",
            "g123456789abcdef0123456789abcdef",
        ] {
            let fixture = Fixture::new();
            let mut value: Value =
                serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
            value["generation_id"] = json!(generation);
            write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
            assert!(matches!(
                load_team_profile(&fixture.profile_path),
                Err(TeamConfigError::InvalidProfileField("generation_id"))
            ));
        }

        for (field, invalid) in [
            ("tenant_id", "-tenant"),
            ("repository_id", "repo/child"),
            ("repository_id", "répo"),
        ] {
            let fixture = Fixture::new();
            let mut value: Value =
                serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
            value[field] = json!(invalid);
            write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
            assert!(matches!(
                load_team_profile(&fixture.profile_path),
                Err(TeamConfigError::InvalidProfileField(actual)) if actual == field
            ));
        }
    }

    #[test]
    fn profile_and_all_controlled_state_must_be_external_to_workspace() {
        let fixture = Fixture::new();
        let root = fixture.profile_path.parent().unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        set_mode(&workspace, 0o700);

        let profile = fixture.profile();
        validate_profile_state_external_to_workspace(&fixture.profile_path, &profile, &workspace)
            .unwrap();

        let in_workspace_profile = workspace.join("profile.json");
        write_private(
            &in_workspace_profile,
            &fs::read(&fixture.profile_path).unwrap(),
        );
        let profile = load_team_profile(&in_workspace_profile).unwrap();
        assert!(matches!(
            validate_profile_state_external_to_workspace(
                &in_workspace_profile,
                &profile,
                &workspace,
            ),
            Err(TeamConfigError::WorkspaceStateOverlap {
                label: "team profile",
                ..
            })
        ));

        let mut profile_json: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        profile_json["runtime_attestation_checkpoint_file"] = json!(workspace.join("runtime.json"));
        write_private(
            &fixture.profile_path,
            &serde_json::to_vec(&profile_json).unwrap(),
        );
        let profile = load_team_profile(&fixture.profile_path).unwrap();
        assert!(matches!(
            validate_profile_state_external_to_workspace(
                &fixture.profile_path,
                &profile,
                &workspace,
            ),
            Err(TeamConfigError::WorkspaceStateOverlap {
                label: "runtime attestation checkpoint",
                ..
            })
        ));
    }

    #[test]
    fn sharing_policy_json_version_and_prefix_fail_closed_without_content_leaks() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        write_private(
            &fixture.sharing_policy_path,
            br#"{"version":"SENTINEL_POLICY_SECRET""#,
        );
        let error = load_sharing_policy(&profile).unwrap_err();
        assert!(matches!(
            &error,
            TeamConfigError::InvalidSharingPolicyJson(_)
        ));
        assert!(!error.to_string().contains("SENTINEL_POLICY_SECRET"));

        let fixture = Fixture::new();
        let profile = fixture.profile();
        let mut value = sharing_policy_json();
        value["schema_version"] = json!(SHARING_POLICY_SCHEMA_VERSION + 1);
        write_private(
            &fixture.sharing_policy_path,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(matches!(
            load_sharing_policy(&profile),
            Err(TeamConfigError::UnknownSharingPolicyVersion)
        ));

        let fixture = Fixture::new();
        let profile = fixture.profile();
        let mut value = sharing_policy_json();
        value["namespace"] = json!("again.repository-sharing-policy.v2");
        write_private(
            &fixture.sharing_policy_path,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(matches!(
            load_sharing_policy(&profile),
            Err(TeamConfigError::UnknownSharingPolicyVersion)
        ));

        let fixture = Fixture::new();
        let profile = fixture.profile();
        let mut value = sharing_policy_json();
        value["include_prefixes"] = json!(["../private"]);
        write_private(
            &fixture.sharing_policy_path,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(matches!(
            load_sharing_policy(&profile),
            Err(TeamConfigError::InvalidSharingPolicy(
                SharingPolicyError::InvalidPrefix { .. }
            ))
        ));

        let fixture = Fixture::new();
        let profile = fixture.profile();
        let mut value = sharing_policy_json();
        value["unexpected"] = json!(true);
        write_private(
            &fixture.sharing_policy_path,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(matches!(
            load_sharing_policy(&profile),
            Err(TeamConfigError::InvalidSharingPolicyJson(_))
        ));
    }

    #[test]
    fn sharing_policy_rejects_mode_links_and_profile_path_aliases() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        set_mode(&fixture.sharing_policy_path, 0o644);
        assert!(matches!(
            load_sharing_policy(&profile),
            Err(TeamConfigError::UnsafeFile { .. })
        ));

        let fixture = Fixture::new();
        let profile = fixture.profile();
        fs::remove_file(&fixture.sharing_policy_path).unwrap();
        symlink(&fixture.token_path, &fixture.sharing_policy_path).unwrap();
        assert!(matches!(
            load_sharing_policy(&profile),
            Err(TeamConfigError::NonCanonicalPath { .. })
        ));

        let fixture = Fixture::new();
        let profile = fixture.profile();
        let hardlink = fixture
            .sharing_policy_path
            .with_file_name("sharing-policy-hard.json");
        fs::hard_link(&fixture.sharing_policy_path, &hardlink).unwrap();
        assert!(matches!(
            load_sharing_policy(&profile),
            Err(TeamConfigError::UnsafeFile { .. })
        ));

        let fixture = Fixture::new();
        let mut profile_json: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        profile_json["sharing_policy_file"] = json!(fixture.token_path);
        write_private(
            &fixture.profile_path,
            &serde_json::to_vec(&profile_json).unwrap(),
        );
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::AliasedProfileFiles)
        ));
    }

    #[test]
    fn publisher_credentials_are_distinct_private_and_redacted() {
        let fixture = Fixture::new();
        let (write_token_path, signing_key_path) = add_publisher(&fixture);
        let profile = fixture.profile();
        let publisher = profile.publisher().unwrap();
        assert_eq!(publisher.write_token_file(), write_token_path);
        assert_eq!(publisher.producer_signing_key_file(), signing_key_path);
        assert_eq!(publisher.publish_budget().max_requests(), 4);

        let write_token = load_write_token(&profile).unwrap();
        let rendered = format!("{write_token:?}");
        assert_eq!(rendered, "WriteToken(<redacted>)");
        assert!(!rendered.contains(write_token.expose()));

        let credential = load_producer_signer(&profile).unwrap();
        let rendered = format!("{credential:?}");
        assert!(rendered.contains("producer-key-1"));
        assert!(rendered.contains("producer-a"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&"2a".repeat(ED25519_SECRET_KEY_BYTES)));

        set_mode(&write_token_path, 0o644);
        assert!(matches!(
            load_write_token(&profile),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
        set_mode(&write_token_path, 0o600);
        set_mode(&signing_key_path, 0o644);
        assert!(matches!(
            load_producer_signer(&profile),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
    }

    #[test]
    fn publisher_alias_corruption_and_secret_errors_fail_closed() {
        let fixture = Fixture::new();
        let (write_token_path, signing_key_path) = add_publisher(&fixture);
        let mut value: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        value["publisher"]["write_token_file"] = json!(fixture.token_path);
        write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::AliasedProfileFiles)
        ));

        value["publisher"]["write_token_file"] = json!(write_token_path);
        write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
        let profile = fixture.profile();
        write_private(&write_token_path, b"ag1.writer.SECRET_TOO_SHORT");
        let error = load_write_token(&profile).unwrap_err();
        let rendered = error.to_string();
        assert!(matches!(&error, TeamConfigError::InvalidWriteToken));
        assert!(!rendered.contains("SECRET_TOO_SHORT"));

        write_private(
            &signing_key_path,
            &serde_json::to_vec(&json!({
                "schema_version": PRODUCER_SIGNING_KEY_SCHEMA_VERSION,
                "namespace": PRODUCER_SIGNING_KEY_NAMESPACE,
                "key_id": "producer-key-1",
                "producer_id": "producer-a",
                "secret_key_hex": "AA".repeat(ED25519_SECRET_KEY_BYTES),
            }))
            .unwrap(),
        );
        let error = load_producer_signer(&profile).unwrap_err();
        assert!(matches!(
            &error,
            TeamConfigError::InvalidProducerSigningKeyMaterial
        ));
        assert!(
            !error
                .to_string()
                .contains(&"AA".repeat(ED25519_SECRET_KEY_BYTES))
        );
    }

    #[test]
    fn repository_key_is_strict_private_distinct_and_lower_hex() {
        let fixture = Fixture::new();
        let profile = fixture.profile();

        set_mode(&fixture.repository_key_path, 0o644);
        assert!(matches!(
            load_repository_key(&profile),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
        set_mode(&fixture.repository_key_path, 0o600);

        let mut invalid: Value =
            serde_json::from_slice(&fs::read(&fixture.repository_key_path).unwrap()).unwrap();
        invalid["key_hex"] = json!("AA".repeat(REPOSITORY_ENCRYPTION_KEY_BYTES));
        write_private(
            &fixture.repository_key_path,
            &serde_json::to_vec(&invalid).unwrap(),
        );
        assert!(matches!(
            load_repository_key(&profile),
            Err(TeamConfigError::InvalidRepositoryKeyMaterial)
        ));

        let fixture = Fixture::new();
        let mut profile_json: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        profile_json["repository_key_file"] = json!(fixture.token_path);
        write_private(
            &fixture.profile_path,
            &serde_json::to_vec(&profile_json).unwrap(),
        );
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::AliasedProfileFiles)
        ));
    }

    #[test]
    fn token_accepts_only_one_optional_final_lf_and_wipe_zeros_buffer() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        write_private(&fixture.token_path, format!("{TOKEN}\n").as_bytes());
        assert_eq!(load_read_token(&profile).unwrap().expose(), TOKEN);
        write_private(&fixture.token_path, format!("{TOKEN}\n\n").as_bytes());
        assert!(matches!(
            load_read_token(&profile),
            Err(TeamConfigError::InvalidReadToken)
        ));
        write_private(&fixture.token_path, TOKEN.as_bytes());
        let mut token = load_read_token(&profile).unwrap();
        token.wipe();
        assert!(token.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn profile_rejects_unknown_fields_oversize_and_unbounded_budget() {
        let fixture = Fixture::new();
        let mut value: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        value["unknown"] = json!(true);
        write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::InvalidProfileJson(_))
        ));

        write_private(
            &fixture.profile_path,
            &vec![b' '; MAX_TEAM_PROFILE_BYTES + 1],
        );
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::FileTooLarge { .. })
        ));

        write_profile(
            &fixture.profile_path,
            &fixture.token_path,
            &fixture.repository_key_path,
            &fixture.sharing_policy_path,
            &fixture.checkpoint_path,
            &fixture.runtime_checkpoint_path,
            &fixture.root_key,
        );
        let mut value: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        value["lookup_budget"]["max_requests"] = json!(MAX_LOOKUP_REQUESTS + 1);
        write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::InvalidProfileField(
                "lookup_budget.max_requests"
            ))
        ));

        write_profile(
            &fixture.profile_path,
            &fixture.token_path,
            &fixture.repository_key_path,
            &fixture.sharing_policy_path,
            &fixture.checkpoint_path,
            &fixture.runtime_checkpoint_path,
            &fixture.root_key,
        );
        let mut value: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        value["lookup_budget"]["max_requests"] = json!(MIN_LEGACY_V2_LOOKUP_REQUESTS - 1);
        write_private(&fixture.profile_path, &serde_json::to_vec(&value).unwrap());
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::InvalidProfileField(
                "lookup_budget.max_requests"
            ))
        ));
    }

    #[test]
    fn lookup_protocol_is_required_strict_and_sets_its_own_minimum_budget() {
        let fixture = Fixture::new();

        let mut missing: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        missing.as_object_mut().unwrap().remove("lookup_protocol");
        write_private(
            &fixture.profile_path,
            &serde_json::to_vec(&missing).unwrap(),
        );
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::InvalidProfileJson(_))
        ));

        write_profile(
            &fixture.profile_path,
            &fixture.token_path,
            &fixture.repository_key_path,
            &fixture.sharing_policy_path,
            &fixture.checkpoint_path,
            &fixture.runtime_checkpoint_path,
            &fixture.root_key,
        );
        let mut unknown: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        unknown["lookup_protocol"] = json!("automatic");
        write_private(
            &fixture.profile_path,
            &serde_json::to_vec(&unknown).unwrap(),
        );
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::InvalidProfileJson(_))
        ));

        write_profile(
            &fixture.profile_path,
            &fixture.token_path,
            &fixture.repository_key_path,
            &fixture.sharing_policy_path,
            &fixture.checkpoint_path,
            &fixture.runtime_checkpoint_path,
            &fixture.root_key,
        );
        let mut bundle: Value =
            serde_json::from_slice(&fs::read(&fixture.profile_path).unwrap()).unwrap();
        bundle["lookup_protocol"] = json!("bundle_v1");
        bundle["lookup_budget"]["max_requests"] = json!(MIN_BUNDLE_V1_LOOKUP_REQUESTS);
        write_private(&fixture.profile_path, &serde_json::to_vec(&bundle).unwrap());
        let profile = load_team_profile(&fixture.profile_path).unwrap();
        assert_eq!(profile.lookup_protocol(), TeamLookupProtocolV1::BundleV1);
        assert_eq!(
            profile.lookup_budget().max_requests(),
            MIN_BUNDLE_V1_LOOKUP_REQUESTS
        );

        bundle["lookup_budget"]["max_requests"] = json!(MIN_BUNDLE_V1_LOOKUP_REQUESTS - 1);
        write_private(&fixture.profile_path, &serde_json::to_vec(&bundle).unwrap());
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::InvalidProfileField(
                "lookup_budget.max_requests"
            ))
        ));
    }

    #[test]
    fn files_reject_wrong_mode_symlink_hardlink_and_noncanonical_path() {
        let fixture = Fixture::new();
        set_mode(&fixture.profile_path, 0o644);
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
        set_mode(&fixture.profile_path, 0o600);

        let symlink_path = fixture.profile_path.with_file_name("profile-link.json");
        symlink(&fixture.profile_path, &symlink_path).unwrap();
        assert!(load_team_profile(&symlink_path).is_err());

        let hardlink_path = fixture.profile_path.with_file_name("profile-hard.json");
        fs::hard_link(&fixture.profile_path, &hardlink_path).unwrap();
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
        fs::remove_file(hardlink_path).unwrap();

        let parent = fixture.profile_path.parent().unwrap();
        let noncanonical = parent.join("checkpoint").join("..").join("profile.json");
        assert!(matches!(
            load_team_profile(&noncanonical),
            Err(TeamConfigError::NonCanonicalPath { .. })
        ));
    }

    #[test]
    fn files_reject_untrusted_writable_ancestor_and_token_links() {
        let fixture = Fixture::new();
        let root = fixture.profile_path.parent().unwrap();
        set_mode(root, 0o777);
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::UntrustedAncestor { .. })
        ));
        set_mode(root, 0o700);

        let token_link = fixture.token_path.with_file_name("token-hard");
        fs::hard_link(&fixture.token_path, &token_link).unwrap();
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
        fs::remove_file(token_link).unwrap();
    }

    #[test]
    fn ownership_is_rejected_when_running_with_chown_authority() {
        // This branch is exercised in rootful CI/containers; an unprivileged
        // process cannot safely manufacture a differently owned fixture.
        // SAFETY: `geteuid` and `chown` have their documented C ABI and the
        // path is a live NUL-terminated CString owned for the call.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let fixture = Fixture::new();
        let c_path =
            std::ffi::CString::new(fixture.profile_path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(c_path.as_ptr(), 1, u32::MAX) }, 0);
        assert!(matches!(
            load_team_profile(&fixture.profile_path),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
    }

    #[test]
    fn checkpoint_atomic_roundtrip_restores_epoch_and_private_file() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        let tracker = accept(&fixture, &profile, 2);
        persist_trust_checkpoint(&profile, &tracker).unwrap();
        let metadata = fs::symlink_metadata(&fixture.checkpoint_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let restored = load_trust_tracker(&profile).unwrap();
        assert_eq!(
            restored.highest_accepted_epoch(
                profile.tenant_id(),
                profile.repository_id(),
                profile.generation_id(),
                profile.endpoint_origin()
            ),
            Some(2)
        );
        let entries = fs::read_dir(fixture.checkpoint_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&fixture.checkpoint_path.file_name().unwrap().to_os_string()));
        assert!(entries.iter().all(|name| {
            let name = name.to_string_lossy();
            !name.starts_with(".again-trust-checkpoint-") || name.ends_with(".lock")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_lock_contention_has_a_monotonic_deadline_and_recovers() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        let first = acquire_checkpoint_lock_with_timeout(&profile, Duration::from_secs(1)).unwrap();

        let started = Instant::now();
        assert!(matches!(
            acquire_checkpoint_lock_with_timeout(&profile, Duration::from_millis(30)),
            Err(TeamConfigError::CheckpointLockTimeout)
        ));
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(started.elapsed() < Duration::from_secs(1));

        drop(first);
        let recovered =
            acquire_checkpoint_lock_with_timeout(&profile, Duration::from_secs(1)).unwrap();
        drop(recovered);
    }

    #[test]
    fn checkpoint_reads_reject_wrong_mode_symlink_and_hardlink() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        let tracker = accept(&fixture, &profile, 1);
        persist_trust_checkpoint(&profile, &tracker).unwrap();

        set_mode(&fixture.checkpoint_path, 0o640);
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
        set_mode(&fixture.checkpoint_path, 0o600);

        let hardlink = fixture.checkpoint_path.with_file_name("trust-hard.json");
        fs::hard_link(&fixture.checkpoint_path, &hardlink).unwrap();
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::UnsafeFile { .. })
        ));
        fs::remove_file(hardlink).unwrap();

        fs::remove_file(&fixture.checkpoint_path).unwrap();
        symlink(&fixture.token_path, &fixture.checkpoint_path).unwrap();
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::NonCanonicalPath { .. })
        ));
    }

    #[test]
    fn restored_checkpoint_blocks_epoch_and_stale_writer_rollback() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        let newest = accept(&fixture, &profile, 2);
        persist_trust_checkpoint(&profile, &newest).unwrap();

        let mut restored = load_trust_tracker(&profile).unwrap();
        assert!(matches!(
            verify_trust_bundle(
                signed_bundle(&fixture, 1),
                profile.expected_trust_bundle(),
                profile.pinned_root(),
                120,
                &mut restored,
            ),
            Err(TrustBundleError::EpochRollback)
        ));

        let stale = accept(&fixture, &profile, 1);
        assert!(matches!(
            persist_trust_checkpoint(&profile, &stale),
            Err(TeamConfigError::Trust(TrustBundleError::EpochRollback))
        ));
        assert_eq!(
            load_trust_tracker(&profile)
                .unwrap()
                .highest_accepted_epoch(
                    profile.tenant_id(),
                    profile.repository_id(),
                    profile.generation_id(),
                    profile.endpoint_origin()
                ),
            Some(2)
        );
    }

    #[test]
    fn concurrent_stale_and_new_writers_finish_at_the_newest_epoch() {
        let fixture = Fixture::new();
        let stale_profile = fixture.profile();
        let newest_profile = fixture.profile();
        let stale = accept(&fixture, &stale_profile, 1);
        let newest = accept(&fixture, &newest_profile, 2);
        let barrier = Arc::new(Barrier::new(3));

        let stale_barrier = Arc::clone(&barrier);
        let stale_writer = thread::spawn(move || {
            stale_barrier.wait();
            persist_trust_checkpoint(&stale_profile, &stale)
        });
        let newest_barrier = Arc::clone(&barrier);
        let newest_writer = thread::spawn(move || {
            newest_barrier.wait();
            persist_trust_checkpoint(&newest_profile, &newest)
        });
        barrier.wait();

        let stale_result = stale_writer.join().unwrap();
        newest_writer.join().unwrap().unwrap();
        assert!(
            stale_result.is_ok()
                || matches!(
                    &stale_result,
                    Err(TeamConfigError::Trust(TrustBundleError::EpochRollback))
                ),
            "unexpected stale-writer result: {stale_result:?}"
        );

        let profile = fixture.profile();
        assert_eq!(
            load_trust_tracker(&profile)
                .unwrap()
                .highest_accepted_epoch(
                    profile.tenant_id(),
                    profile.repository_id(),
                    profile.generation_id(),
                    profile.endpoint_origin()
                ),
            Some(2)
        );
    }

    #[test]
    fn corrupt_cross_scope_unknown_and_oversize_checkpoints_fail_closed() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        write_private(&fixture.checkpoint_path, b"{");
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::InvalidCheckpointJson(_))
        ));

        fs::remove_file(&fixture.checkpoint_path).unwrap();
        let tracker = accept(&fixture, &profile, 1);
        persist_trust_checkpoint(&profile, &tracker).unwrap();
        let mut value: Value =
            serde_json::from_slice(&fs::read(&fixture.checkpoint_path).unwrap()).unwrap();
        value["repository_id"] = json!("repo-b");
        write_private(
            &fixture.checkpoint_path,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::Trust(
                TrustBundleError::CheckpointScopeMismatch
            ))
        ));

        value["repository_id"] = json!("repo-a");
        value["root_key_id"] = json!("root-key-2");
        write_private(
            &fixture.checkpoint_path,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::Trust(
                TrustBundleError::CheckpointRootMismatch
            ))
        ));

        value["root_key_id"] = json!("root-key-1");
        value["unknown"] = json!(true);
        write_private(
            &fixture.checkpoint_path,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::InvalidCheckpointJson(_))
        ));

        write_private(
            &fixture.checkpoint_path,
            &vec![b' '; MAX_TRUST_CHECKPOINT_BYTES + 1],
        );
        assert!(matches!(
            load_trust_tracker(&profile),
            Err(TeamConfigError::FileTooLarge { .. })
        ));
    }
}
