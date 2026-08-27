//! Local SQLite index and content-addressed output store.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent_gateway::protocol::{
    EffectClass, FreshnessRequirementV1, GatewayToolCallV1, RequestDigestV1,
};
use crate::fingerprint::{FileDigestCache, FileIdentity};

const SCHEMA_VERSION: i64 = 7;
const MAX_FILE_DIGEST_ROWS: i64 = 50_000;
const FILE_DIGEST_PRUNE_INTERVAL: u16 = 256;
const PENDING_CALL_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const EVENT_TTL_MS: i64 = 90 * 24 * 60 * 60 * 1_000;
const ORPHAN_ARTIFACT_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const CLEANUP_INTERVAL_MS: i64 = 60 * 60 * 1_000;
const CLEANUP_ROW_LIMIT: i64 = 512;
const CLEANUP_ARTIFACT_LIMIT: i64 = 256;
const MAX_LOCAL_BLOB_BYTES: usize = 16 * 1024 * 1024;
const GATEWAY_LEASE_TTL_MS: i64 = 30_000;
const GATEWAY_FRESHNESS_MAX_MS: i64 = 5 * 60_000;
const GATEWAY_MAX_DEPENDENCIES: usize = 64;
const GATEWAY_MAX_OWNER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupReport {
    pub pending_calls: u64,
    pub events: u64,
    pub gateway_events: u64,
    pub artifacts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCall {
    pub id: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub context_id: Option<String>,
    pub cwd: PathBuf,
    pub raw_command: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredResult {
    pub id: String,
    pub request_key: String,
    pub stdout_digest: String,
    pub stderr_digest: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub policy_version: String,
    pub proof_json: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventDisposition {
    Executed,
    ReplayedFull,
    ReplayedCompact,
    PassedThrough,
    BypassedNoStore,
    Quarantined,
}

impl EventDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::ReplayedFull => "replayed_full",
            Self::ReplayedCompact => "replayed_compact",
            Self::PassedThrough => "passed_through",
            Self::BypassedNoStore => "bypassed_no_store",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct StoreStats {
    pub executions: u64,
    pub full_replays: u64,
    pub compact_replays: u64,
    pub bypasses: u64,
    pub quarantines: u64,
    pub duplicate_bytes_omitted: u64,
    /// Sum of positive `(recorded execution duration - observed replay wall
    /// time)` estimates. Slower replays contribute zero, never negative time.
    pub estimated_execution_ms_saved: u64,
    pub requested: u64,
    pub executed: u64,
    pub exact_hits: u64,
    pub coverage_hits: u64,
    pub inflight_joins: u64,
    pub compact_deliveries: u64,
    pub estimated_tokens_avoided: u64,
    pub stale_or_divergent_quarantines: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayRefusalReason {
    InvalidCallKey,
    InvalidStateDigest,
    InvalidOwner,
    InvalidAgentContext,
    Quarantined,
    CallNotFound,
    LeaseNotFound,
    LeaseExpired,
    LeaseNotCurrent,
    OwnerMismatch,
    NotFollower,
    ResultNotFound,
    AlreadyTerminal,
    ExecutionNotStarted,
    BindingMismatch,
    FreshnessExpired,
}

impl GatewayRefusalReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCallKey => "invalid_call_key",
            Self::InvalidStateDigest => "invalid_state_digest",
            Self::InvalidOwner => "invalid_owner",
            Self::InvalidAgentContext => "invalid_agent_context",
            Self::Quarantined => "quarantined",
            Self::CallNotFound => "call_not_found",
            Self::LeaseNotFound => "lease_not_found",
            Self::LeaseExpired => "lease_expired",
            Self::LeaseNotCurrent => "lease_not_current",
            Self::OwnerMismatch => "owner_mismatch",
            Self::NotFollower => "not_follower",
            Self::ResultNotFound => "result_not_found",
            Self::AlreadyTerminal => "already_terminal",
            Self::ExecutionNotStarted => "execution_not_started",
            Self::BindingMismatch => "binding_mismatch",
            Self::FreshnessExpired => "freshness_expired",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayOperationDispositionV1 {
    ReplayEligibleRead,
    Mutation,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GatewayDependencyV1 {
    pub key_digest: String,
    pub value_digest: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GatewayFreshnessEvidenceV1 {
    pub snapshot_digest: String,
    pub observed_at_ms: i64,
    pub valid_until_ms: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GatewayCoordinatorInputV1 {
    pub request_digest: String,
    pub state_digest: String,
    pub policy_digest: String,
    pub operation: GatewayOperationDispositionV1,
    pub freshness: GatewayFreshnessEvidenceV1,
    pub dependencies: Vec<GatewayDependencyV1>,
}

/// Store-local proof that a complete, canonical gateway binding was admitted
/// as a replay-eligible read. Its fields are private and it deliberately does
/// not implement `Deserialize`; callers cannot turn a bool or string into
/// replay authority.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidatedGatewayReadV1 {
    input: GatewayCoordinatorInputV1,
    binding_digest: String,
}

impl ValidatedGatewayReadV1 {
    pub fn validate(input: GatewayCoordinatorInputV1) -> Result<Self> {
        validate_digest(&input.request_digest, "gateway request digest")?;
        validate_digest(&input.state_digest, "gateway state digest")?;
        validate_digest(&input.policy_digest, "gateway policy digest")?;
        validate_digest(
            &input.freshness.snapshot_digest,
            "gateway freshness snapshot digest",
        )?;
        if input.freshness.snapshot_digest != input.state_digest {
            bail!("gateway freshness evidence is not bound to the complete state digest");
        }
        if input.operation != GatewayOperationDispositionV1::ReplayEligibleRead {
            bail!("gateway operation is not an admitted replay-eligible read");
        }
        if input.dependencies.len() > GATEWAY_MAX_DEPENDENCIES {
            bail!("gateway dependency bound exceeded");
        }
        for dependency in &input.dependencies {
            validate_digest(&dependency.key_digest, "gateway dependency key digest")?;
            validate_digest(&dependency.value_digest, "gateway dependency value digest")?;
        }
        if input
            .dependencies
            .windows(2)
            .any(|pair| pair[0].key_digest >= pair[1].key_digest)
        {
            bail!("gateway dependencies must be strictly ordered by unique key digest");
        }
        if input.freshness.observed_at_ms < 0
            || input.freshness.valid_until_ms < input.freshness.observed_at_ms
            || input
                .freshness
                .valid_until_ms
                .saturating_sub(input.freshness.observed_at_ms)
                > GATEWAY_FRESHNESS_MAX_MS
        {
            bail!("gateway freshness evidence has an invalid bounded interval");
        }
        let binding_digest = gateway_binding_digest(&input);
        Ok(Self {
            input,
            binding_digest,
        })
    }

    pub fn request_digest(&self) -> &str {
        &self.input.request_digest
    }

    pub fn state_digest(&self) -> &str {
        &self.input.state_digest
    }

    pub fn policy_digest(&self) -> &str {
        &self.input.policy_digest
    }

    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFailureReason {
    ProviderUnavailable,
    Transport,
    Deadline,
    Cancelled,
    Protocol,
    Internal,
}

impl GatewayFailureReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Transport => "transport",
            Self::Deadline => "deadline",
            Self::Cancelled => "cancelled",
            Self::Protocol => "protocol",
            Self::Internal => "internal",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "provider_unavailable" => Self::ProviderUnavailable,
            "transport" => Self::Transport,
            "deadline" => Self::Deadline,
            "cancelled" => Self::Cancelled,
            "protocol" => Self::Protocol,
            "internal" => Self::Internal,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayCallAcquisition {
    Leader {
        call_id: String,
        lease_id: String,
        expires_at_ms: i64,
    },
    Follower {
        call_id: String,
        lease_id: String,
        leader_call_id: String,
        leader: String,
        expires_at_ms: i64,
    },
    Ready {
        call_id: String,
        gateway_result_id: String,
    },
    Refused {
        reason: GatewayRefusalReason,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayCallObservation {
    Inflight {
        leader_call_id: String,
        leader: String,
        expires_at_ms: i64,
        followers: u64,
    },
    Ready {
        gateway_result_id: String,
    },
    Failed {
        reason: GatewayFailureReason,
    },
    Quarantined {
        reason: String,
    },
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayExecutionStart {
    Started,
    AlreadyStarted,
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayHeartbeat {
    Extended { expires_at_ms: i64 },
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayCompletion {
    Completed {
        call_id: String,
        gateway_result_id: String,
    },
    AlreadyCompleted {
        call_id: String,
        gateway_result_id: String,
    },
    Quarantined {
        call_id: String,
        existing_gateway_result_id: String,
        conflicting_gateway_result_id: String,
    },
    Refused {
        reason: GatewayRefusalReason,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFailure {
    Failed { call_id: String },
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFollowerCancellation {
    Cancelled,
    AlreadyCancelled,
    Refused { reason: GatewayRefusalReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayAgentContext {
    pub session_id: String,
    pub turn_id: String,
    pub agent_id: String,
    pub compaction_epoch: u64,
}

impl GatewayAgentContext {
    pub fn new(
        session_id: impl Into<String>,
        turn_id: impl Into<String>,
        agent_id: impl Into<String>,
        compaction_epoch: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            turn_id: turn_id.into(),
            agent_id: agent_id.into(),
            compaction_epoch,
        }
    }

    fn is_valid(&self) -> bool {
        !self.session_id.is_empty() && !self.turn_id.is_empty() && !self.agent_id.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayPresentation {
    Full,
    Compact { estimated_tokens_avoided: u64 },
}

impl GatewayPresentation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Compact { .. } => "compact",
        }
    }

    fn estimated_tokens_avoided(self) -> u64 {
        match self {
            Self::Full => 0,
            Self::Compact {
                estimated_tokens_avoided,
            } => estimated_tokens_avoided,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct GatewayStats {
    pub requested: u64,
    pub executed: u64,
    pub exact_hits: u64,
    pub coverage_hits: u64,
    pub inflight_joins: u64,
    pub compact_deliveries: u64,
    pub estimated_tokens_avoided: u64,
    pub stale_or_divergent_quarantines: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayFullResultV1 {
    pub gateway_result_id: String,
    pub result: StoredResult,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub dependencies: Vec<GatewayDependencyV1>,
}

/// Store-transaction-issued, one-shot exact result authority. The private
/// fields, lack of `Clone` and lack of `Deserialize` prevent caller-created or
/// duplicated serve claims.
pub struct StoreExactResultProofV1 {
    used: std::cell::Cell<bool>,
    request_digest: RequestDigestV1,
    binding_digest: String,
    state_digest: String,
    policy_digest: String,
    dependency_digest: String,
    effect: EffectClass,
    freshness: FreshnessRequirementV1,
    lifecycle_generation: u64,
    observed_generation: u64,
    execution_started_ms: u64,
    observed_at_ms: u64,
    gateway_result_id: String,
    store_record_digest: String,
}

impl std::fmt::Debug for StoreExactResultProofV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoreExactResultProofV1(<redacted>)")
    }
}

impl StoreExactResultProofV1 {
    pub fn gateway_result_id(&self) -> &str {
        &self.gateway_result_id
    }

    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub(crate) fn authorizes_router_call_v1(&self, call: &GatewayToolCallV1) -> bool {
        !self.used.replace(true)
            && self.proof_invariants_hold_v1()
            && self.request_digest == call.request_digest()
            && self.effect == call.effect_class()
            && self.freshness == call.freshness()
            && freshness_requirement_holds_v1(
                self.freshness,
                self.execution_started_ms,
                self.observed_at_ms,
            )
    }

    fn proof_invariants_hold_v1(&self) -> bool {
        self.lifecycle_generation != 0
            && self.lifecycle_generation == self.observed_generation
            && self.execution_started_ms <= self.observed_at_ms
            && valid_digest_v1(&self.binding_digest)
            && valid_digest_v1(&self.state_digest)
            && valid_digest_v1(&self.policy_digest)
            && valid_digest_v1(&self.dependency_digest)
            && valid_digest_v1(&self.gateway_result_id)
            && valid_digest_v1(&self.store_record_digest)
    }
}

/// Store-transaction-issued, one-shot authority to join one actual active
/// lease generation. It never carries result serve authority.
pub struct StoreInflightJoinProofV1 {
    used: std::cell::Cell<bool>,
    request_digest: RequestDigestV1,
    binding_digest: String,
    state_digest: String,
    policy_digest: String,
    dependency_digest: String,
    effect: EffectClass,
    freshness: FreshnessRequirementV1,
    lifecycle_generation: u64,
    observed_generation: u64,
    execution_started_ms: u64,
    observed_at_ms: u64,
    lease_id: String,
    lease_record_digest: String,
}

impl std::fmt::Debug for StoreInflightJoinProofV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoreInflightJoinProofV1(<redacted>)")
    }
}

impl StoreInflightJoinProofV1 {
    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub(crate) fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub(crate) fn authorizes_router_call_v1(&self, call: &GatewayToolCallV1) -> bool {
        !self.used.replace(true)
            && self.lifecycle_generation != 0
            && self.lifecycle_generation == self.observed_generation
            && self.execution_started_ms <= self.observed_at_ms
            && valid_digest_v1(&self.binding_digest)
            && valid_digest_v1(&self.state_digest)
            && valid_digest_v1(&self.policy_digest)
            && valid_digest_v1(&self.dependency_digest)
            && valid_digest_v1(&self.lease_record_digest)
            && self.request_digest == call.request_digest()
            && self.effect == call.effect_class()
            && self.freshness == call.freshness()
            && freshness_requirement_holds_v1(
                self.freshness,
                self.execution_started_ms,
                self.observed_at_ms,
            )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayRouteProofUnavailableV1 {
    Missing,
    ExecutionNotStarted,
    BindingMismatch,
    Freshness,
    Quarantined,
}

pub enum GatewayRouteProofObservationV1 {
    Exact(StoreExactResultProofV1),
    Inflight(StoreInflightJoinProofV1),
    Unavailable(GatewayRouteProofUnavailableV1),
}

impl std::fmt::Debug for GatewayRouteProofObservationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Exact(_) => "exact",
            Self::Inflight(_) => "inflight",
            Self::Unavailable(_) => "unavailable",
        };
        formatter
            .debug_struct("GatewayRouteProofObservationV1")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

pub struct Store {
    root: PathBuf,
    blobs: PathBuf,
    conn: Connection,
    file_digest_writes_since_prune: u16,
}

impl Store {
    /// Resolve state for a repository-scoped execution.
    ///
    /// The default is a private, per-user, per-workspace directory below the
    /// operating system temporary directory. State must never live inside the
    /// observed workspace: creating or updating it could otherwise change the
    /// output of commands such as `ls -A .` and recursive `rg`.
    ///
    /// `AGAIN_HOME` selects one exact persistent store. It must be absolute and
    /// external to the workspace.
    pub fn root_for_workspace(workspace: &Path) -> Result<PathBuf> {
        let workspace = fs::canonicalize(workspace)
            .with_context(|| format!("resolve Again workspace {}", workspace.display()))?;
        if !workspace.is_dir() {
            bail!(
                "Again workspace is not a directory: {}",
                workspace.display()
            );
        }
        if let Some(path) = std::env::var_os("AGAIN_HOME") {
            let requested = PathBuf::from(path);
            if !requested.is_absolute() {
                bail!("AGAIN_HOME must be an absolute path outside the active workspace");
            }
            let root = prospective_store_root(&requested)?;
            validate_external_state_root(&workspace, &root)?;
            validate_trusted_state_ancestors(&root)?;
            return Ok(root);
        }
        default_workspace_state_root(&workspace, &std::env::temp_dir())
    }

    pub fn open_for_workspace(workspace: &Path) -> Result<Self> {
        Self::open_with_policy(Self::root_for_workspace(workspace)?)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_policy(root)
    }

    fn open_with_policy(root: impl AsRef<Path>) -> Result<Self> {
        let root = prepare_store_root(root.as_ref())?;
        let blobs = prepare_private_child_dir(&root, "blobs")?;
        create_self_ignoring_gitignore(&root)?;

        let database = root.join("again.sqlite");
        reject_unsafe_existing_file(&database, "Again database")?;
        reject_unsafe_existing_file(&root.join("again.sqlite-wal"), "Again WAL")?;
        reject_unsafe_existing_file(&root.join("again.sqlite-shm"), "Again SHM")?;
        ensure_private_database_file(&database)?;
        let conn = Connection::open(&database)
            .with_context(|| format!("open Again database {}", database.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;

        let mut store = Self {
            root,
            blobs,
            conn,
            file_digest_writes_since_prune: FILE_DIGEST_PRUNE_INTERVAL - 1,
        };
        store.migrate()?;
        store.verify_gateway_schema_v7()?;
        store.maybe_cleanup()?;
        set_private_file(&database)?;
        set_private_file(&store.root.join("again.sqlite-wal"))?;
        set_private_file(&store.root.join("again.sqlite-shm"))?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            bail!(
                "Again database schema {version} is newer than supported schema {SCHEMA_VERSION}"
            );
        }
        if version == 0 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE pending_calls (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    turn_id TEXT,
                    cwd TEXT NOT NULL,
                    raw_command TEXT NOT NULL,
                    argv_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL
                );
                CREATE TABLE results (
                    id TEXT PRIMARY KEY,
                    request_key TEXT NOT NULL UNIQUE,
                    stdout_digest TEXT NOT NULL,
                    stderr_digest TEXT NOT NULL,
                    stdout_bytes INTEGER NOT NULL,
                    stderr_bytes INTEGER NOT NULL,
                    exit_code INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    policy_version TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    quarantined INTEGER NOT NULL DEFAULT 0,
                    quarantine_reason TEXT,
                    created_ms INTEGER NOT NULL,
                    last_used_ms INTEGER NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE deliveries (
                    session_id TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    call_id TEXT,
                    result_id TEXT,
                    disposition TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL DEFAULT 0,
                    bytes_omitted INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL
                );
                CREATE INDEX events_created_idx ON events(created_ms);
                PRAGMA user_version = 1;
                COMMIT;
                "#,
            )?;
        }
        if version < 2 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE file_digests (
                    device BLOB NOT NULL CHECK(typeof(device) = 'blob' AND length(device) = 8),
                    inode BLOB NOT NULL CHECK(typeof(inode) = 'blob' AND length(inode) = 8),
                    mode INTEGER NOT NULL CHECK(mode >= 0),
                    uid INTEGER NOT NULL CHECK(uid >= 0),
                    gid INTEGER NOT NULL CHECK(gid >= 0),
                    size BLOB NOT NULL CHECK(typeof(size) = 'blob' AND length(size) = 8),
                    mtime_sec INTEGER NOT NULL,
                    mtime_nsec INTEGER NOT NULL CHECK(mtime_nsec >= 0 AND mtime_nsec < 1000000000),
                    ctime_sec INTEGER NOT NULL,
                    ctime_nsec INTEGER NOT NULL CHECK(ctime_nsec >= 0 AND ctime_nsec < 1000000000),
                    digest BLOB NOT NULL CHECK(typeof(digest) = 'blob' AND length(digest) = 32),
                    row_checksum BLOB NOT NULL CHECK(typeof(row_checksum) = 'blob' AND length(row_checksum) = 32),
                    last_used_ms INTEGER NOT NULL,
                    PRIMARY KEY (device, inode)
                ) WITHOUT ROWID;
                CREATE INDEX file_digests_lru_idx ON file_digests(last_used_ms);
                PRAGMA user_version = 2;
                COMMIT;
                "#,
            )?;
        }
        if version < 3 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE artifacts (
                    digest TEXT PRIMARY KEY CHECK(length(digest) = 64),
                    created_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE INDEX artifacts_created_idx ON artifacts(created_ms);
                CREATE INDEX pending_calls_created_idx ON pending_calls(created_ms);
                CREATE TABLE maintenance (
                    name TEXT PRIMARY KEY,
                    completed_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                PRAGMA user_version = 3;
                COMMIT;
                "#,
            )?;
        }
        if version < 4 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                ALTER TABLE pending_calls ADD COLUMN context_id TEXT;
                DELETE FROM pending_calls;
                DROP TABLE IF EXISTS deliveries;
                CREATE TABLE deliveries (
                    session_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, context_id, result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
                );
                PRAGMA user_version = 4;
                COMMIT;
                "#,
            )?;
        }
        if version < 5 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                -- Before schema v5, local full replays recorded the producer's
                -- gross duration rather than end-to-end net wall time saved.
                -- Team events were net estimates, but the shared column cannot
                -- distinguish the historical writers safely. Reset prior
                -- replay metrics instead of carrying an inflated claim forward.
                UPDATE events
                SET elapsed_ms = 0
                WHERE disposition IN ('replayed_full', 'replayed_compact');
                PRAGMA user_version = 5;
                COMMIT;
                "#,
            )?;
        }
        if version < 6 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE gateway_requests (
                    call_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                    state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
                    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
                    binding_digest TEXT NOT NULL CHECK(length(binding_digest) = 64),
                    freshness_valid_until_ms INTEGER NOT NULL,
                    owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 128),
                    role TEXT NOT NULL CHECK(role IN ('leader', 'follower', 'ready', 'refused')),
                    status TEXT NOT NULL CHECK(status IN ('inflight', 'waiting', 'ready', 'failed', 'cancelled', 'quarantined')),
                    joined_lease_id TEXT,
                    gateway_result_id TEXT,
                    reason TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL
                );
                CREATE INDEX gateway_requests_binding_idx
                    ON gateway_requests(binding_digest, created_ms);
                CREATE INDEX gateway_requests_lease_idx
                    ON gateway_requests(joined_lease_id, status);

                CREATE TABLE gateway_request_dependencies (
                    call_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 64),
                    dependency_key_digest TEXT NOT NULL CHECK(length(dependency_key_digest) = 64),
                    dependency_value_digest TEXT NOT NULL CHECK(length(dependency_value_digest) = 64),
                    PRIMARY KEY (call_id, ordinal),
                    UNIQUE (call_id, dependency_key_digest),
                    FOREIGN KEY (call_id) REFERENCES gateway_requests(call_id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE gateway_results (
                    gateway_result_id TEXT PRIMARY KEY CHECK(length(gateway_result_id) = 64),
                    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                    state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
                    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
                    binding_digest TEXT NOT NULL CHECK(length(binding_digest) = 64),
                    result_id TEXT NOT NULL,
                    stdout_digest TEXT NOT NULL CHECK(length(stdout_digest) = 64),
                    stderr_digest TEXT NOT NULL CHECK(length(stderr_digest) = 64),
                    stdout_bytes INTEGER NOT NULL CHECK(stdout_bytes >= 0),
                    stderr_bytes INTEGER NOT NULL CHECK(stderr_bytes >= 0),
                    exit_code INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0),
                    result_policy_version TEXT NOT NULL,
                    proof_digest TEXT NOT NULL CHECK(length(proof_digest) = 64),
                    lease_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ready', 'quarantined')),
                    quarantine_reason TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    UNIQUE (binding_digest, gateway_result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE RESTRICT
                );
                CREATE UNIQUE INDEX gateway_results_ready_idx
                    ON gateway_results(binding_digest) WHERE status = 'ready';
                CREATE INDEX gateway_results_result_idx ON gateway_results(result_id);

                CREATE TABLE result_dependencies (
                    gateway_result_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 64),
                    dependency_key_digest TEXT NOT NULL CHECK(length(dependency_key_digest) = 64),
                    dependency_value_digest TEXT NOT NULL CHECK(length(dependency_value_digest) = 64),
                    PRIMARY KEY (gateway_result_id, ordinal),
                    UNIQUE (gateway_result_id, dependency_key_digest),
                    FOREIGN KEY (gateway_result_id) REFERENCES gateway_results(gateway_result_id)
                        ON DELETE CASCADE
                ) WITHOUT ROWID;
                CREATE INDEX result_dependencies_digest_idx
                    ON result_dependencies(dependency_key_digest, dependency_value_digest);

                CREATE TABLE inflight_leases (
                    lease_id TEXT PRIMARY KEY,
                    call_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
                    state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
                    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
                    binding_digest TEXT NOT NULL CHECK(length(binding_digest) = 64),
                    freshness_valid_until_ms INTEGER NOT NULL,
                    owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 128),
                    status TEXT NOT NULL CHECK(status IN ('active', 'completed', 'failed', 'expired', 'quarantined')),
                    gateway_result_id TEXT,
                    reason TEXT,
                    acquired_ms INTEGER NOT NULL,
                    heartbeat_ms INTEGER NOT NULL,
                    expires_ms INTEGER NOT NULL,
                    execution_started_ms INTEGER,
                    completed_ms INTEGER,
                    FOREIGN KEY (call_id) REFERENCES gateway_requests(call_id) ON DELETE RESTRICT
                );
                CREATE UNIQUE INDEX inflight_leases_active_idx
                    ON inflight_leases(binding_digest) WHERE status = 'active';
                CREATE INDEX inflight_leases_expiry_idx
                    ON inflight_leases(status, expires_ms);

                CREATE TABLE gateway_deliveries (
                    session_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    compaction_epoch INTEGER NOT NULL CHECK(compaction_epoch >= 0),
                    gateway_result_id TEXT NOT NULL,
                    presentation TEXT NOT NULL,
                    estimated_tokens_avoided INTEGER NOT NULL DEFAULT 0,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (
                        session_id, turn_id, agent_id, compaction_epoch, gateway_result_id, presentation
                    ),
                    FOREIGN KEY (gateway_result_id) REFERENCES gateway_results(gateway_result_id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE gateway_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    call_id TEXT,
                    lease_id TEXT,
                    gateway_result_id TEXT,
                    event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 64),
                    reason TEXT,
                    estimated_tokens_avoided INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL
                );
                CREATE INDEX gateway_events_created_idx ON gateway_events(created_ms);
                CREATE INDEX gateway_events_type_idx ON gateway_events(event_type);
                PRAGMA user_version = 6;
                COMMIT;
                "#,
            )?;
        }
        if version < 7 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                ALTER TABLE inflight_leases
                    ADD COLUMN lifecycle_generation INTEGER NOT NULL DEFAULT 1
                    CHECK(lifecycle_generation > 0);
                UPDATE inflight_leases AS current
                SET lifecycle_generation = (
                    SELECT COUNT(*)
                    FROM inflight_leases AS prior
                    WHERE prior.binding_digest = current.binding_digest
                      AND (
                          prior.acquired_ms < current.acquired_ms
                          OR (
                              prior.acquired_ms = current.acquired_ms
                              AND prior.lease_id <= current.lease_id
                          )
                      )
                );
                CREATE UNIQUE INDEX inflight_leases_generation_idx
                    ON inflight_leases(binding_digest, lifecycle_generation);
                PRAGMA user_version = 7;
                COMMIT;
                "#,
            )?;
        }
        Ok(())
    }

    fn verify_gateway_schema_v7(&self) -> Result<()> {
        verify_gateway_schema_v7(&self.conn)
    }

    pub fn create_call(
        &self,
        session_id: &str,
        turn_id: Option<&str>,
        context_id: Option<&str>,
        cwd: &Path,
        raw_command: &str,
        argv: &[String],
    ) -> Result<PendingCall> {
        let id = Uuid::new_v4().simple().to_string();
        let call = PendingCall {
            id,
            session_id: session_id.to_owned(),
            turn_id: turn_id.map(ToOwned::to_owned),
            context_id: context_id.map(ToOwned::to_owned),
            cwd: cwd.to_path_buf(),
            raw_command: raw_command.to_owned(),
            argv: argv.to_vec(),
        };
        self.conn.execute(
            "INSERT INTO pending_calls (id, session_id, turn_id, context_id, cwd, raw_command, argv_json, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                call.id,
                call.session_id,
                call.turn_id,
                call.context_id,
                call.cwd.to_string_lossy(),
                call.raw_command,
                serde_json::to_string(&call.argv)?,
                now_ms(),
            ],
        )?;
        Ok(call)
    }

    pub fn get_call(&self, id: &str) -> Result<Option<PendingCall>> {
        self.conn
            .query_row(
                "SELECT id, session_id, turn_id, context_id, cwd, raw_command, argv_json FROM pending_calls WHERE id = ?1",
                [id],
                |row| {
                    let argv_json: String = row.get(6)?;
                    let argv = serde_json::from_str(&argv_json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(PendingCall {
                        id: row.get(0)?,
                        session_id: row.get(1)?,
                        turn_id: row.get(2)?,
                        context_id: row.get(3)?,
                        cwd: PathBuf::from(row.get::<_, String>(4)?),
                        raw_command: row.get(5)?,
                        argv,
                    })
                },
            )
            .optional()
            .context("read pending call")
    }

    pub fn delete_call(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_calls WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        if bytes.len() > MAX_LOCAL_BLOB_BYTES {
            bail!("Again blob exceeds the local 16 MiB limit");
        }
        let digest = blake3::hash(bytes).to_hex().to_string();
        let target = self.blob_path(&digest)?;
        // File publication and lifecycle cleanup share the SQLite write lock. This
        // prevents a cleaner from deleting an old orphan between verification and
        // publication in the artifact inventory.
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        ensure_blob_file(&target, &digest, bytes)?;
        transaction.execute(
            "INSERT INTO artifacts (digest, created_ms) VALUES (?1, ?2) ON CONFLICT(digest) DO UPDATE SET created_ms = excluded.created_ms",
            params![digest, now_ms()],
        )?;
        transaction.commit()?;
        Ok(digest)
    }

    pub fn get_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest)?;
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("inspect blob {digest}"))?;
        validate_owned_regular_file(&path, &metadata, "Again blob")?;
        let bytes = read_blob_bounded(&path, digest)?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != digest {
            bail!("CAS corruption: blob {digest} hashes to {actual}");
        }
        Ok(bytes)
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        blob_path_under(&self.blobs, digest)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_result(
        &mut self,
        request_key: &str,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
        duration_ms: u64,
        policy_version: &str,
        proof_json: &str,
    ) -> Result<StoredResult> {
        let stdout_digest = self.put_blob(stdout)?;
        let stderr_digest = self.put_blob(stderr)?;
        let result = StoredResult {
            id: format!("r_{}", Uuid::new_v4().simple()),
            request_key: request_key.to_owned(),
            stdout_digest,
            stderr_digest,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            exit_code,
            duration_ms,
            policy_version: policy_version.to_owned(),
            proof_json: proof_json.to_owned(),
        };
        let now = now_ms();
        // Serialize the read/compare/insert decision. A deferred transaction lets
        // two writers both observe absence and turns divergence into a bare UNIQUE
        // error instead of quarantine.
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, quarantined FROM results WHERE request_key = ?1",
                [request_key],
                |row| Ok((row_to_result(row)?, row.get::<_, bool>(10)?)),
            )
            .optional()?;
        if let Some((existing, quarantined)) = existing {
            if quarantined {
                bail!("request key {request_key} is quarantined");
            }
            if existing.stdout_digest != result.stdout_digest
                || existing.stderr_digest != result.stderr_digest
                || existing.stdout_bytes != result.stdout_bytes
                || existing.stderr_bytes != result.stderr_bytes
                || existing.exit_code != result.exit_code
                || existing.policy_version != result.policy_version
                || existing.proof_json != result.proof_json
            {
                transaction.execute(
                    "UPDATE results SET quarantined = 1, quarantine_reason = ?2 WHERE id = ?1",
                    params![existing.id, "same_key_different_result"],
                )?;
                transaction.execute(
                    "INSERT INTO events (call_id, result_id, disposition, reason_code, elapsed_ms, bytes_omitted, created_ms) VALUES (NULL, ?1, ?2, ?3, 0, 0, ?4)",
                    params![
                        existing.id,
                        EventDisposition::Quarantined.as_str(),
                        "same_key_different_result",
                        now,
                    ],
                )?;
                transaction.commit()?;
                bail!("differential mismatch for request key {request_key}; entry quarantined");
            }
            transaction.commit()?;
            return Ok(existing);
        }
        transaction.execute(
            "INSERT INTO results (id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, created_ms, last_used_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                result.id,
                result.request_key,
                result.stdout_digest,
                result.stderr_digest,
                result.stdout_bytes,
                result.stderr_bytes,
                result.exit_code,
                result.duration_ms,
                result.policy_version,
                result.proof_json,
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn get_result(&self, request_key: &str) -> Result<Option<StoredResult>> {
        self.conn
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE request_key = ?1 AND quarantined = 0",
                [request_key],
                row_to_result,
            )
            .optional()
            .context("lookup cached result")
    }

    pub fn get_result_by_id(&self, id: &str) -> Result<Option<StoredResult>> {
        self.conn
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE id = ?1 AND quarantined = 0",
                [id],
                row_to_result,
            )
            .optional()
            .context("lookup result by id")
    }

    pub fn note_hit(&self, result_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE results SET hit_count = hit_count + 1, last_used_ms = ?2 WHERE id = ?1",
            params![result_id, now_ms()],
        )?;
        Ok(())
    }

    /// Returns true only when the exact result was already delivered in full to
    /// this Codex session, turn and root/subagent context.
    pub fn was_delivered(
        &self,
        session_id: &str,
        context_id: &str,
        result_id: &str,
    ) -> Result<bool> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE session_id = ?1 AND context_id = ?2 AND result_id = ?3)",
            params![session_id, context_id, result_id],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    pub fn mark_delivered(
        &self,
        session_id: &str,
        context_id: &str,
        result_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO deliveries (session_id, context_id, result_id, delivered_ms) VALUES (?1, ?2, ?3, ?4)",
            params![session_id, context_id, result_id, now_ms()],
        )?;
        Ok(())
    }

    /// Invalidate full-output visibility evidence for the exact active Codex
    /// turn and root/subagent context. Both compaction events call this
    /// idempotently. Turn scoping also prevents stale evidence from surviving a
    /// workspace change where another repository-local store received compact.
    pub fn clear_deliveries_for_context(&self, session_id: &str, context_id: &str) -> Result<u64> {
        let removed = self.conn.execute(
            "DELETE FROM deliveries WHERE session_id = ?1 AND context_id = ?2",
            params![session_id, context_id],
        )?;
        Ok(removed as u64)
    }

    pub fn acquire_gateway_call(
        &self,
        binding: &ValidatedGatewayReadV1,
        owner: &str,
    ) -> Result<GatewayCallAcquisition> {
        validate_gateway_owner(owner)?;
        let now = now_ms();
        if !freshness_is_current(binding, now) {
            return Ok(GatewayCallAcquisition::Refused {
                reason: GatewayRefusalReason::FreshnessExpired,
            });
        }
        let call_id = format!("gc_{}", Uuid::new_v4().simple());
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        expire_gateway_leases_v1_tx(&transaction, now, Some(binding.binding_digest()))?;

        let ready = transaction
            .query_row(
                "SELECT gateway_result_id FROM gateway_results WHERE binding_digest = ?1 AND status = 'ready'",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(gateway_result_id) = ready {
            if gateway_result_row_valid_v1(&transaction, binding, &gateway_result_id)? {
                insert_gateway_request_v1(
                    &transaction,
                    &call_id,
                    binding,
                    owner,
                    "ready",
                    "ready",
                    None,
                    Some(&gateway_result_id),
                    None,
                    now,
                )?;
                record_gateway_event_v1_tx(
                    &transaction,
                    Some(&call_id),
                    None,
                    Some(&gateway_result_id),
                    "requested",
                    None,
                    0,
                    now,
                )?;
                record_gateway_event_v1_tx(
                    &transaction,
                    Some(&call_id),
                    None,
                    Some(&gateway_result_id),
                    "exact_hit",
                    None,
                    0,
                    now,
                )?;
                transaction.commit()?;
                return Ok(GatewayCallAcquisition::Ready {
                    call_id,
                    gateway_result_id,
                });
            }
            transaction.execute(
                "UPDATE gateway_results SET status = 'quarantined', quarantine_reason = 'binding_mismatch', updated_ms = ?2 WHERE gateway_result_id = ?1 AND status = 'ready'",
                params![gateway_result_id, now],
            )?;
            record_gateway_event_v1_tx(
                &transaction,
                Some(&call_id),
                None,
                Some(&gateway_result_id),
                "binding_quarantined",
                Some(GatewayRefusalReason::BindingMismatch.as_str()),
                0,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCallAcquisition::Refused {
                reason: GatewayRefusalReason::Quarantined,
            });
        }

        let quarantined: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results WHERE binding_digest = ?1 AND status = 'quarantined')",
            [binding.binding_digest()],
            |row| row.get(0),
        )?;
        if quarantined {
            transaction.commit()?;
            return Ok(GatewayCallAcquisition::Refused {
                reason: GatewayRefusalReason::Quarantined,
            });
        }

        let active = transaction
            .query_row(
                "SELECT lease_id, call_id, owner, expires_ms FROM inflight_leases WHERE binding_digest = ?1 AND status = 'active'",
                [binding.binding_digest()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((lease_id, leader_call_id, leader, expires_at_ms)) = active {
            insert_gateway_request_v1(
                &transaction,
                &call_id,
                binding,
                owner,
                "follower",
                "waiting",
                Some(&lease_id),
                None,
                None,
                now,
            )?;
            record_gateway_event_v1_tx(
                &transaction,
                Some(&call_id),
                Some(&lease_id),
                None,
                "requested",
                None,
                0,
                now,
            )?;
            record_gateway_event_v1_tx(
                &transaction,
                Some(&call_id),
                Some(&lease_id),
                None,
                "inflight_join",
                None,
                0,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCallAcquisition::Follower {
                call_id,
                lease_id,
                leader_call_id,
                leader,
                expires_at_ms,
            });
        }

        let lease_id = format!("gl_{}", Uuid::new_v4().simple());
        let prior_generation = transaction.query_row(
            "SELECT COALESCE(MAX(lifecycle_generation), 0) FROM inflight_leases WHERE binding_digest = ?1",
            [binding.binding_digest()],
            |row| row.get::<_, i64>(0),
        )?;
        let lifecycle_generation = prior_generation
            .checked_add(1)
            .filter(|generation| *generation > 0)
            .ok_or_else(|| anyhow!("gateway lease lifecycle generation exhausted"))?;
        let expires_at_ms = now
            .saturating_add(GATEWAY_LEASE_TTL_MS)
            .min(binding.input.freshness.valid_until_ms);
        insert_gateway_request_v1(
            &transaction,
            &call_id,
            binding,
            owner,
            "leader",
            "inflight",
            Some(&lease_id),
            None,
            None,
            now,
        )?;
        transaction.execute(
            "INSERT INTO inflight_leases (lease_id, call_id, request_digest, state_digest, policy_digest, binding_digest, freshness_valid_until_ms, owner, status, acquired_ms, heartbeat_ms, expires_ms, lifecycle_generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?9, ?10, ?11)",
            params![
                lease_id,
                call_id,
                binding.request_digest(),
                binding.state_digest(),
                binding.policy_digest(),
                binding.binding_digest(),
                binding.input.freshness.valid_until_ms,
                owner,
                now,
                expires_at_ms,
                lifecycle_generation
            ],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(&call_id),
            Some(&lease_id),
            None,
            "requested",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayCallAcquisition::Leader {
            call_id,
            lease_id,
            expires_at_ms,
        })
    }

    pub fn start_gateway_execution(
        &self,
        lease_id: &str,
        owner: &str,
    ) -> Result<GatewayExecutionStart> {
        validate_gateway_owner(owner)?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        if lease.owner != owner {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::OwnerMismatch,
            });
        }
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        if lease.execution_started_ms.is_some() {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::AlreadyStarted);
        }
        let changed = transaction.execute(
            "UPDATE inflight_leases SET execution_started_ms = ?2 WHERE lease_id = ?1 AND status = 'active' AND execution_started_ms IS NULL",
            params![lease_id, now],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(GatewayExecutionStart::Refused {
                reason: GatewayRefusalReason::LeaseNotCurrent,
            });
        }
        record_gateway_event_v1_tx(
            &transaction,
            Some(&lease.call_id),
            Some(lease_id),
            None,
            "executed",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayExecutionStart::Started)
    }

    pub fn heartbeat_gateway_call(&self, lease_id: &str, owner: &str) -> Result<GatewayHeartbeat> {
        validate_gateway_owner(owner)?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        if lease.owner != owner {
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::OwnerMismatch,
            });
        }
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        let expires_at_ms = now
            .saturating_add(GATEWAY_LEASE_TTL_MS)
            .min(lease.freshness_valid_until_ms);
        let changed = transaction.execute(
            "UPDATE inflight_leases SET heartbeat_ms = ?3, expires_ms = ?4 WHERE lease_id = ?1 AND owner = ?2 AND status = 'active' AND expires_ms > ?3",
            params![lease_id, owner, now, expires_at_ms],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(GatewayHeartbeat::Refused {
                reason: GatewayRefusalReason::LeaseNotCurrent,
            });
        }
        transaction.commit()?;
        Ok(GatewayHeartbeat::Extended { expires_at_ms })
    }

    pub fn observe_gateway_call(
        &self,
        binding: &ValidatedGatewayReadV1,
    ) -> Result<GatewayCallObservation> {
        let now = now_ms();
        if !freshness_is_current(binding, now) {
            return Ok(GatewayCallObservation::Failed {
                reason: GatewayFailureReason::Deadline,
            });
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        expire_gateway_leases_v1_tx(&transaction, now, Some(binding.binding_digest()))?;
        let quarantined = transaction
            .query_row(
                "SELECT COALESCE(quarantine_reason, 'binding_mismatch') FROM gateway_results WHERE binding_digest = ?1 AND status = 'quarantined' ORDER BY updated_ms DESC LIMIT 1",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(reason) = quarantined {
            transaction.commit()?;
            return Ok(GatewayCallObservation::Quarantined { reason });
        }
        let ready = transaction
            .query_row(
                "SELECT gateway_result_id FROM gateway_results WHERE binding_digest = ?1 AND status = 'ready'",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(gateway_result_id) = ready {
            transaction.commit()?;
            return Ok(GatewayCallObservation::Ready { gateway_result_id });
        }
        let inflight = transaction
            .query_row(
                "SELECT call_id, owner, expires_ms, (SELECT COUNT(*) FROM gateway_requests WHERE joined_lease_id = inflight_leases.lease_id AND role = 'follower' AND status = 'waiting') FROM inflight_leases WHERE binding_digest = ?1 AND status = 'active'",
                [binding.binding_digest()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((leader_call_id, leader, expires_at_ms, followers)) = inflight {
            transaction.commit()?;
            return Ok(GatewayCallObservation::Inflight {
                leader_call_id,
                leader,
                expires_at_ms,
                followers,
            });
        }
        let failure = transaction
            .query_row(
                "SELECT reason FROM gateway_requests WHERE binding_digest = ?1 AND status = 'failed' ORDER BY updated_ms DESC LIMIT 1",
                [binding.binding_digest()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        transaction.commit()?;
        Ok(
            match failure.and_then(|reason| GatewayFailureReason::from_str(&reason)) {
                Some(reason) => GatewayCallObservation::Failed { reason },
                None => GatewayCallObservation::Missing,
            },
        )
    }

    /// Observe one validated binding and issue at most one transaction-time
    /// router proof from the exact committed store rows. This does not load or
    /// present result bytes and grants no authority by itself.
    pub fn observe_gateway_route_proof_v1(
        &self,
        binding: &ValidatedGatewayReadV1,
        call: &GatewayToolCallV1,
    ) -> Result<GatewayRouteProofObservationV1> {
        if call.request_digest().as_str() != binding.request_digest()
            || !matches!(
                call.effect_class(),
                EffectClass::SnapshotRead
                    | EffectClass::FreshnessBoundRead
                    | EffectClass::DeterministicCompute
            )
        {
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::BindingMismatch,
            ));
        }
        let now = now_ms();
        if !freshness_is_current(binding, now) {
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Freshness,
            ));
        }
        let observed_at_ms = u64::try_from(now)
            .map_err(|_| anyhow!("gateway proof observation time is negative"))?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        expire_gateway_leases_v1_tx(&transaction, now, Some(binding.binding_digest()))?;
        let quarantined: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results WHERE binding_digest = ?1 AND status = 'quarantined')",
            [binding.binding_digest()],
            |row| row.get(0),
        )?;
        if quarantined {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Quarantined,
            ));
        }
        let ready = transaction
            .query_row(
                "SELECT gateway_result_id, lease_id FROM gateway_results WHERE binding_digest = ?1 AND status = 'ready'",
                [binding.binding_digest()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((gateway_result_id, lease_id)) = ready {
            if !gateway_result_row_valid_v1(&transaction, binding, &gateway_result_id)? {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::BindingMismatch,
                ));
            }
            let Some(lease) = gateway_lease_row_v1(&transaction, &lease_id)? else {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::BindingMismatch,
                ));
            };
            let Some(started_at_ms) = lease
                .execution_started_ms
                .and_then(|value| value.try_into().ok())
            else {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::ExecutionNotStarted,
                ));
            };
            let Some(completed_at_ms) = lease
                .completed_ms
                .and_then(|value| u64::try_from(value).ok())
            else {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::BindingMismatch,
                ));
            };
            let current_generation = transaction.query_row(
                "SELECT MAX(lifecycle_generation) FROM inflight_leases WHERE binding_digest = ?1",
                [binding.binding_digest()],
                |row| row.get::<_, u64>(0),
            )?;
            if lease.status != "completed"
                || lease.gateway_result_id.as_deref() != Some(&gateway_result_id)
                || lease.request_digest != binding.input.request_digest
                || lease.state_digest != binding.input.state_digest
                || lease.policy_digest != binding.input.policy_digest
                || lease.binding_digest != binding.binding_digest
                || current_generation != lease.lifecycle_generation
                || completed_at_ms < started_at_ms
                || completed_at_ms > observed_at_ms
                || !freshness_requirement_holds_v1(call.freshness(), started_at_ms, observed_at_ms)
            {
                transaction.commit()?;
                return Ok(GatewayRouteProofObservationV1::Unavailable(
                    GatewayRouteProofUnavailableV1::Freshness,
                ));
            }
            let dependency_digest = gateway_dependency_digest_v1(&binding.input.dependencies);
            let store_record_digest = exact_store_record_digest_v1(
                binding,
                &lease,
                &gateway_result_id,
                &dependency_digest,
            );
            let proof = StoreExactResultProofV1 {
                used: std::cell::Cell::new(false),
                request_digest: call.request_digest(),
                binding_digest: binding.binding_digest.clone(),
                state_digest: binding.input.state_digest.clone(),
                policy_digest: binding.input.policy_digest.clone(),
                dependency_digest,
                effect: call.effect_class(),
                freshness: call.freshness(),
                lifecycle_generation: lease.lifecycle_generation,
                observed_generation: current_generation,
                execution_started_ms: started_at_ms,
                observed_at_ms,
                gateway_result_id,
                store_record_digest,
            };
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Exact(proof));
        }

        let active_lease_id = transaction
            .query_row(
                "SELECT lease_id FROM inflight_leases WHERE binding_digest = ?1 AND status = 'active'",
                [binding.binding_digest()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(active_lease_id) = active_lease_id else {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Missing,
            ));
        };
        let Some(lease) = gateway_lease_row_v1(&transaction, &active_lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Missing,
            ));
        };
        let Some(started_at_ms) = lease
            .execution_started_ms
            .and_then(|value| value.try_into().ok())
        else {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::ExecutionNotStarted,
            ));
        };
        let current_generation = transaction.query_row(
            "SELECT MAX(lifecycle_generation) FROM inflight_leases WHERE binding_digest = ?1",
            [binding.binding_digest()],
            |row| row.get::<_, u64>(0),
        )?;
        if current_generation != lease.lifecycle_generation
            || lease.request_digest != binding.input.request_digest
            || lease.state_digest != binding.input.state_digest
            || lease.policy_digest != binding.input.policy_digest
            || !freshness_requirement_holds_v1(call.freshness(), started_at_ms, observed_at_ms)
        {
            transaction.commit()?;
            return Ok(GatewayRouteProofObservationV1::Unavailable(
                GatewayRouteProofUnavailableV1::Freshness,
            ));
        }
        let dependency_digest = gateway_dependency_digest_v1(&binding.input.dependencies);
        let lease_record_digest =
            inflight_store_record_digest_v1(binding, &lease, observed_at_ms, &dependency_digest);
        let proof = StoreInflightJoinProofV1 {
            used: std::cell::Cell::new(false),
            request_digest: call.request_digest(),
            binding_digest: binding.binding_digest.clone(),
            state_digest: binding.input.state_digest.clone(),
            policy_digest: binding.input.policy_digest.clone(),
            dependency_digest,
            effect: call.effect_class(),
            freshness: call.freshness(),
            lifecycle_generation: lease.lifecycle_generation,
            observed_generation: current_generation,
            execution_started_ms: started_at_ms,
            observed_at_ms,
            lease_id: lease.lease_id.clone(),
            lease_record_digest,
        };
        transaction.commit()?;
        Ok(GatewayRouteProofObservationV1::Inflight(proof))
    }

    pub fn complete_gateway_call(
        &self,
        lease_id: &str,
        result_id: &str,
    ) -> Result<GatewayCompletion> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        let result = load_visible_result_tx(&transaction, result_id)?;
        let Some(result) = result else {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::ResultNotFound,
            });
        };
        let dependencies = load_request_dependencies_v1(&transaction, &lease.call_id)?;
        let gateway_result_id = gateway_result_content_digest(&lease, &result, &dependencies);
        if lease.status == "completed" {
            if lease.gateway_result_id.as_deref() == Some(&gateway_result_id) {
                transaction.commit()?;
                return Ok(GatewayCompletion::AlreadyCompleted {
                    call_id: lease.call_id,
                    gateway_result_id,
                });
            }
            let existing = lease.gateway_result_id.clone().unwrap_or_default();
            quarantine_gateway_divergence_v1_tx(
                &transaction,
                &lease,
                &existing,
                &gateway_result_id,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCompletion::Quarantined {
                call_id: lease.call_id,
                existing_gateway_result_id: existing,
                conflicting_gateway_result_id: gateway_result_id,
            });
        }
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            record_gateway_event_v1_tx(
                &transaction,
                Some(&lease.call_id),
                Some(lease_id),
                None,
                "stale_completion",
                Some(reason.as_str()),
                0,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            record_gateway_event_v1_tx(
                &transaction,
                Some(&lease.call_id),
                Some(lease_id),
                None,
                "stale_completion",
                Some(GatewayRefusalReason::LeaseExpired.as_str()),
                0,
                now,
            )?;
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        if lease.execution_started_ms.is_none() {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::ExecutionNotStarted,
            });
        }
        if result.request_key != lease.request_digest
            || gateway_policy_digest(&result.policy_version) != lease.policy_digest
        {
            transaction.commit()?;
            return Ok(GatewayCompletion::Refused {
                reason: GatewayRefusalReason::BindingMismatch,
            });
        }
        let proof_digest = blake3::hash(result.proof_json.as_bytes())
            .to_hex()
            .to_string();
        transaction.execute(
            "INSERT INTO gateway_results (gateway_result_id, request_digest, state_digest, policy_digest, binding_digest, result_id, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, result_policy_version, proof_digest, lease_id, status, created_ms, updated_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 'ready', ?16, ?16)",
            params![
                gateway_result_id,
                lease.request_digest,
                lease.state_digest,
                lease.policy_digest,
                lease.binding_digest,
                result.id,
                result.stdout_digest,
                result.stderr_digest,
                result.stdout_bytes,
                result.stderr_bytes,
                result.exit_code,
                result.duration_ms,
                result.policy_version,
                proof_digest,
                lease_id,
                now
            ],
        )?;
        for (ordinal, dependency) in dependencies.iter().enumerate() {
            transaction.execute(
                "INSERT INTO result_dependencies (gateway_result_id, ordinal, dependency_key_digest, dependency_value_digest) VALUES (?1, ?2, ?3, ?4)",
                params![
                    gateway_result_id,
                    i64::try_from(ordinal)?,
                    dependency.key_digest,
                    dependency.value_digest
                ],
            )?;
        }
        let changed = transaction.execute(
            "UPDATE inflight_leases SET status = 'completed', gateway_result_id = ?2, completed_ms = ?3 WHERE lease_id = ?1 AND status = 'active' AND execution_started_ms IS NOT NULL",
            params![lease_id, gateway_result_id, now],
        )?;
        if changed != 1 {
            bail!("gateway completion CAS failed after validated active lease");
        }
        transaction.execute(
            "UPDATE gateway_requests SET status = 'ready', gateway_result_id = ?2, updated_ms = ?3 WHERE joined_lease_id = ?1 AND status IN ('inflight', 'waiting')",
            params![lease_id, gateway_result_id, now],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(&lease.call_id),
            Some(lease_id),
            Some(&gateway_result_id),
            "completed",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayCompletion::Completed {
            call_id: lease.call_id,
            gateway_result_id,
        })
    }

    pub fn fail_gateway_call(
        &self,
        lease_id: &str,
        reason: GatewayFailureReason,
    ) -> Result<GatewayFailure> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let Some(lease) = gateway_lease_row_v1(&transaction, lease_id)? else {
            transaction.commit()?;
            return Ok(GatewayFailure::Refused {
                reason: GatewayRefusalReason::LeaseNotFound,
            });
        };
        if lease.status != "active" {
            let reason = lease_refusal_for_status(&lease.status);
            transaction.commit()?;
            return Ok(GatewayFailure::Refused { reason });
        }
        if lease.expires_ms <= now {
            expire_gateway_leases_v1_tx(&transaction, now, Some(&lease.binding_digest))?;
            transaction.commit()?;
            return Ok(GatewayFailure::Refused {
                reason: GatewayRefusalReason::LeaseExpired,
            });
        }
        let changed = transaction.execute(
            "UPDATE inflight_leases SET status = 'failed', reason = ?2, completed_ms = ?3 WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, reason.as_str(), now],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(GatewayFailure::Refused {
                reason: GatewayRefusalReason::LeaseNotCurrent,
            });
        }
        transaction.execute(
            "UPDATE gateway_requests SET status = 'failed', reason = ?2, updated_ms = ?3 WHERE joined_lease_id = ?1 AND status IN ('inflight', 'waiting')",
            params![lease_id, reason.as_str(), now],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(&lease.call_id),
            Some(lease_id),
            None,
            "failed",
            Some(reason.as_str()),
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayFailure::Failed {
            call_id: lease.call_id,
        })
    }

    pub fn cancel_gateway_follower(&self, call_id: &str) -> Result<GatewayFollowerCancellation> {
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let request = transaction
            .query_row(
                "SELECT role, status, joined_lease_id FROM gateway_requests WHERE call_id = ?1",
                [call_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((role, status, lease_id)) = request else {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::Refused {
                reason: GatewayRefusalReason::CallNotFound,
            });
        };
        if role != "follower" {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::Refused {
                reason: GatewayRefusalReason::NotFollower,
            });
        }
        if status == "cancelled" {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::AlreadyCancelled);
        }
        if status != "waiting" {
            transaction.commit()?;
            return Ok(GatewayFollowerCancellation::Refused {
                reason: GatewayRefusalReason::AlreadyTerminal,
            });
        }
        transaction.execute(
            "UPDATE gateway_requests SET status = 'cancelled', reason = 'cancelled', updated_ms = ?2 WHERE call_id = ?1 AND status = 'waiting'",
            params![call_id, now],
        )?;
        record_gateway_event_v1_tx(
            &transaction,
            Some(call_id),
            lease_id.as_deref(),
            None,
            "follower_cancelled",
            None,
            0,
            now,
        )?;
        transaction.commit()?;
        Ok(GatewayFollowerCancellation::Cancelled)
    }

    pub fn get_gateway_result(
        &self,
        binding: &ValidatedGatewayReadV1,
        gateway_result_id: &str,
    ) -> Result<Option<GatewayFullResultV1>> {
        validate_digest(gateway_result_id, "gateway result digest")?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let Some(result) =
            load_gateway_result_snapshot_v1(&transaction, binding, gateway_result_id)?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let dependencies = load_result_dependencies_v1(&transaction, gateway_result_id)?;
        if dependencies != binding.input.dependencies {
            bail!("gateway result dependency binding mismatch");
        }
        let stdout = self.get_blob(&result.stdout_digest)?;
        let stderr = self.get_blob(&result.stderr_digest)?;
        if stdout.len() as u64 != result.stdout_bytes || stderr.len() as u64 != result.stderr_bytes
        {
            bail!("gateway result blob length mismatch");
        }
        transaction.commit()?;
        Ok(Some(GatewayFullResultV1 {
            gateway_result_id: gateway_result_id.to_owned(),
            result,
            stdout,
            stderr,
            dependencies,
        }))
    }

    pub fn record_gateway_delivery(
        &self,
        agent_context: &GatewayAgentContext,
        gateway_result_id: &str,
        presentation: GatewayPresentation,
    ) -> Result<bool> {
        if !agent_context.is_valid() || agent_context.compaction_epoch > i64::MAX as u64 {
            bail!(GatewayRefusalReason::InvalidAgentContext.as_str());
        }
        validate_digest(gateway_result_id, "gateway result digest")?;
        let now = now_ms();
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let visible: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_results WHERE gateway_result_id = ?1 AND status = 'ready')",
            [gateway_result_id],
            |row| row.get(0),
        )?;
        if !visible {
            transaction.commit()?;
            bail!(GatewayRefusalReason::ResultNotFound.as_str());
        }
        let tokens = presentation.estimated_tokens_avoided();
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO gateway_deliveries (session_id, turn_id, agent_id, compaction_epoch, gateway_result_id, presentation, estimated_tokens_avoided, delivered_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                agent_context.session_id,
                agent_context.turn_id,
                agent_context.agent_id,
                agent_context.compaction_epoch,
                gateway_result_id,
                presentation.as_str(),
                tokens,
                now
            ],
        )? == 1;
        if inserted && matches!(presentation, GatewayPresentation::Compact { .. }) {
            record_gateway_event_v1_tx(
                &transaction,
                None,
                None,
                Some(gateway_result_id),
                "compact_delivery",
                None,
                tokens,
                now,
            )?;
        }
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn clear_gateway_deliveries(&self, agent_context: &GatewayAgentContext) -> Result<u64> {
        if !agent_context.is_valid() || agent_context.compaction_epoch > i64::MAX as u64 {
            bail!(GatewayRefusalReason::InvalidAgentContext.as_str());
        }
        Ok(self.conn.execute(
            "DELETE FROM gateway_deliveries WHERE session_id = ?1 AND turn_id = ?2 AND agent_id = ?3 AND compaction_epoch = ?4",
            params![
                agent_context.session_id,
                agent_context.turn_id,
                agent_context.agent_id,
                agent_context.compaction_epoch
            ],
        )? as u64)
    }

    pub fn gateway_stats(&self) -> Result<GatewayStats> {
        let mut stats = GatewayStats::default();
        let mut statement = self.conn.prepare(
            "SELECT event_type, COUNT(*), COALESCE(SUM(estimated_tokens_avoided), 0) FROM gateway_events GROUP BY event_type",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })?;
        for row in rows {
            let (event_type, count, tokens) = row?;
            match event_type.as_str() {
                "requested" => stats.requested += count,
                "executed" => stats.executed += count,
                "exact_hit" => stats.exact_hits += count,
                "coverage_hit" => stats.coverage_hits += count,
                "inflight_join" => stats.inflight_joins += count,
                "compact_delivery" => {
                    stats.compact_deliveries += count;
                    stats.estimated_tokens_avoided += tokens;
                }
                "stale_completion" | "divergent_result" | "binding_quarantined" => {
                    stats.stale_or_divergent_quarantines += count;
                }
                _ => {}
            }
        }
        Ok(stats)
    }

    #[cfg(test)]
    pub fn expire_abandoned_gateway_calls_at_for_test(&self, now: i64) -> Result<u64> {
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let expired = expire_gateway_leases_v1_tx(&transaction, now, None)?;
        transaction.commit()?;
        Ok(expired)
    }

    pub fn quarantine(&self, result_id: &str, reason: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE results SET quarantined = 1, quarantine_reason = ?2 WHERE id = ?1",
            params![result_id, reason],
        )?;
        self.record_event(
            None,
            Some(result_id),
            EventDisposition::Quarantined,
            reason,
            0,
            0,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &self,
        call_id: Option<&str>,
        result_id: Option<&str>,
        disposition: EventDisposition,
        reason_code: &str,
        metric_ms: u64,
        bytes_omitted: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (call_id, result_id, disposition, reason_code, elapsed_ms, bytes_omitted, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                call_id,
                result_id,
                disposition.as_str(),
                reason_code,
                metric_ms,
                bytes_omitted,
                now_ms(),
            ],
        )?;
        Ok(())
    }

    pub fn last_event(&self) -> Result<Option<(String, String, Option<String>)>> {
        self.conn
            .query_row(
                "SELECT disposition, reason_code, result_id FROM events ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context("read last event")
    }

    /// Run one bounded lifecycle-maintenance pass immediately.
    ///
    /// Results, deliveries, quarantined evidence, and referenced CAS blobs are
    /// deliberately retained. Only expired pending calls, expired telemetry, and
    /// old tracked blobs with no result reference are eligible.
    pub fn cleanup(&mut self) -> Result<CleanupReport> {
        self.cleanup_at(now_ms(), true)
    }

    fn maybe_cleanup(&mut self) -> Result<()> {
        self.cleanup_at(now_ms(), false).map(|_| ())
    }

    fn cleanup_at(&mut self, now: i64, force: bool) -> Result<CleanupReport> {
        let blobs = self.blobs.clone();
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !force {
            let last: Option<i64> = transaction
                .query_row(
                    "SELECT completed_ms FROM maintenance WHERE name = 'lifecycle_cleanup'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if last.is_some_and(|last| now.saturating_sub(last) < CLEANUP_INTERVAL_MS) {
                transaction.commit()?;
                return Ok(CleanupReport::default());
            }
        }

        let pending_cutoff = now.saturating_sub(PENDING_CALL_TTL_MS);
        let event_cutoff = now.saturating_sub(EVENT_TTL_MS);
        let artifact_cutoff = now.saturating_sub(ORPHAN_ARTIFACT_TTL_MS);
        let pending_calls = transaction.execute(
            "DELETE FROM pending_calls WHERE id IN (SELECT id FROM pending_calls WHERE created_ms < ?1 ORDER BY created_ms ASC LIMIT ?2)",
            params![pending_cutoff, CLEANUP_ROW_LIMIT],
        )? as u64;
        let events = transaction.execute(
            "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE created_ms < ?1 ORDER BY created_ms ASC, id ASC LIMIT ?2)",
            params![event_cutoff, CLEANUP_ROW_LIMIT],
        )? as u64;
        let gateway_events = transaction.execute(
            "DELETE FROM gateway_events WHERE id IN (SELECT id FROM gateway_events WHERE created_ms < ?1 ORDER BY created_ms ASC, id ASC LIMIT ?2)",
            params![event_cutoff, CLEANUP_ROW_LIMIT],
        )? as u64;

        let candidates: Vec<String> = {
            let mut statement = transaction.prepare(
                r#"
                SELECT digest FROM artifacts
                WHERE created_ms < ?1
                  AND NOT EXISTS (
                    SELECT 1 FROM results
                    WHERE stdout_digest = artifacts.digest OR stderr_digest = artifacts.digest
                  )
                ORDER BY created_ms ASC, digest ASC LIMIT ?2
                "#,
            )?;
            statement
                .query_map(params![artifact_cutoff, CLEANUP_ARTIFACT_LIMIT], |row| {
                    row.get(0)
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut artifacts = 0_u64;
        for digest in candidates {
            let Ok(path) = blob_path_under(&blobs, &digest) else {
                // A malformed inventory row cannot name a filesystem target.
                transaction.execute("DELETE FROM artifacts WHERE digest = ?1", [&digest])?;
                artifacts += 1;
                continue;
            };
            let removable = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() => metadata
                    .modified()
                    .ok()
                    .and_then(system_time_ms)
                    .is_some_and(|modified| modified < artifact_cutoff),
                Ok(_) => false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if !removable {
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => continue,
            }
            transaction.execute("DELETE FROM artifacts WHERE digest = ?1", [&digest])?;
            artifacts += 1;
        }
        transaction.execute(
            "INSERT INTO maintenance (name, completed_ms) VALUES ('lifecycle_cleanup', ?1) ON CONFLICT(name) DO UPDATE SET completed_ms = excluded.completed_ms",
            [now],
        )?;
        transaction.commit()?;
        Ok(CleanupReport {
            pending_calls,
            events,
            gateway_events,
            artifacts,
        })
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let mut stats = StoreStats::default();
        let mut statement = self.conn.prepare(
            "SELECT disposition, COUNT(*), COALESCE(SUM(bytes_omitted), 0), COALESCE(SUM(elapsed_ms), 0) FROM events GROUP BY disposition",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        for row in rows {
            let (disposition, count, omitted, elapsed) = row?;
            match disposition.as_str() {
                "executed" => stats.executions += count,
                "replayed_full" => {
                    stats.full_replays += count;
                    stats.estimated_execution_ms_saved += elapsed;
                }
                "replayed_compact" => {
                    stats.compact_replays += count;
                    stats.duplicate_bytes_omitted += omitted;
                    stats.estimated_execution_ms_saved += elapsed;
                }
                "passed_through" | "bypassed_no_store" => stats.bypasses += count,
                "quarantined" => stats.quarantines += count,
                _ => {}
            }
        }
        let gateway = self.gateway_stats()?;
        stats.requested = gateway.requested;
        stats.executed = gateway.executed;
        stats.exact_hits = gateway.exact_hits;
        stats.coverage_hits = gateway.coverage_hits;
        stats.inflight_joins = gateway.inflight_joins;
        stats.compact_deliveries = gateway.compact_deliveries;
        stats.estimated_tokens_avoided = gateway.estimated_tokens_avoided;
        stats.stale_or_divergent_quarantines = gateway.stale_or_divergent_quarantines;
        Ok(stats)
    }
}

#[derive(Debug)]
struct GatewayLeaseRowV1 {
    lease_id: String,
    call_id: String,
    request_digest: String,
    state_digest: String,
    policy_digest: String,
    binding_digest: String,
    freshness_valid_until_ms: i64,
    owner: String,
    status: String,
    gateway_result_id: Option<String>,
    expires_ms: i64,
    execution_started_ms: Option<i64>,
    completed_ms: Option<i64>,
    lifecycle_generation: u64,
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_gateway_owner(owner: &str) -> Result<()> {
    if owner.is_empty()
        || owner.len() > GATEWAY_MAX_OWNER_BYTES
        || !owner.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
    {
        bail!(GatewayRefusalReason::InvalidOwner.as_str());
    }
    Ok(())
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn gateway_binding_digest(input: &GatewayCoordinatorInputV1) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.binding.v1\0");
    hash_field(&mut hasher, input.request_digest.as_bytes());
    hash_field(&mut hasher, input.state_digest.as_bytes());
    hash_field(&mut hasher, input.policy_digest.as_bytes());
    hash_field(&mut hasher, b"replay_eligible_read");
    hasher.update(&(input.dependencies.len() as u64).to_le_bytes());
    for dependency in &input.dependencies {
        hash_field(&mut hasher, dependency.key_digest.as_bytes());
        hash_field(&mut hasher, dependency.value_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

pub fn gateway_policy_digest(policy_version: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.policy.v1\0");
    hash_field(&mut hasher, policy_version.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn freshness_is_current(binding: &ValidatedGatewayReadV1, now: i64) -> bool {
    binding.input.freshness.observed_at_ms <= now
        && now <= binding.input.freshness.valid_until_ms
        && binding
            .input
            .freshness
            .valid_until_ms
            .saturating_sub(binding.input.freshness.observed_at_ms)
            <= GATEWAY_FRESHNESS_MAX_MS
}

fn freshness_requirement_holds_v1(
    requirement: FreshnessRequirementV1,
    execution_started_ms: u64,
    observed_at_ms: u64,
) -> bool {
    let Some(age) = observed_at_ms.checked_sub(execution_started_ms) else {
        return false;
    };
    match requirement {
        FreshnessRequirementV1::Snapshot => true,
        FreshnessRequirementV1::MaxAgeMillis(maximum) => age <= maximum,
        // The store can validate its own rows, but it cannot manufacture a
        // fresh external-state revalidation. A later validator must issue a
        // separate bound proof before this mode can route to reuse.
        FreshnessRequirementV1::RequireRevalidation => false,
    }
}

fn valid_digest_v1(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn gateway_dependency_digest_v1(dependencies: &[GatewayDependencyV1]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.dependencies.v1\0");
    hasher.update(&(dependencies.len() as u64).to_le_bytes());
    for dependency in dependencies {
        hash_field(&mut hasher, dependency.key_digest.as_bytes());
        hash_field(&mut hasher, dependency.value_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn exact_store_record_digest_v1(
    binding: &ValidatedGatewayReadV1,
    lease: &GatewayLeaseRowV1,
    gateway_result_id: &str,
    dependency_digest: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.exact-store-record.v1\0");
    for value in [
        binding.request_digest(),
        binding.state_digest(),
        binding.policy_digest(),
        binding.binding_digest(),
        dependency_digest,
        lease.lease_id.as_str(),
        gateway_result_id,
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(&lease.lifecycle_generation.to_le_bytes());
    hasher.update(&lease.execution_started_ms.unwrap_or(-1).to_le_bytes());
    hasher.update(&lease.completed_ms.unwrap_or(-1).to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

fn inflight_store_record_digest_v1(
    binding: &ValidatedGatewayReadV1,
    lease: &GatewayLeaseRowV1,
    observed_at_ms: u64,
    dependency_digest: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.inflight-store-record.v1\0");
    for value in [
        binding.request_digest(),
        binding.state_digest(),
        binding.policy_digest(),
        binding.binding_digest(),
        dependency_digest,
        lease.lease_id.as_str(),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(&lease.lifecycle_generation.to_le_bytes());
    hasher.update(&lease.execution_started_ms.unwrap_or(-1).to_le_bytes());
    hasher.update(&observed_at_ms.to_le_bytes());
    hasher.update(&lease.expires_ms.to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

fn gateway_lease_row_v1(
    transaction: &Transaction<'_>,
    lease_id: &str,
) -> Result<Option<GatewayLeaseRowV1>> {
    transaction
        .query_row(
            "SELECT lease_id, call_id, request_digest, state_digest, policy_digest, binding_digest, freshness_valid_until_ms, owner, status, gateway_result_id, expires_ms, execution_started_ms, completed_ms, lifecycle_generation FROM inflight_leases WHERE lease_id = ?1",
            [lease_id],
            |row| {
                Ok(GatewayLeaseRowV1 {
                    lease_id: row.get(0)?,
                    call_id: row.get(1)?,
                    request_digest: row.get(2)?,
                    state_digest: row.get(3)?,
                    policy_digest: row.get(4)?,
                    binding_digest: row.get(5)?,
                    freshness_valid_until_ms: row.get(6)?,
                    owner: row.get(7)?,
                    status: row.get(8)?,
                    gateway_result_id: row.get(9)?,
                    expires_ms: row.get(10)?,
                    execution_started_ms: row.get(11)?,
                    completed_ms: row.get(12)?,
                    lifecycle_generation: row.get(13)?,
                })
            },
        )
        .optional()
        .context("read exact gateway lease")
}

#[allow(clippy::too_many_arguments)]
fn insert_gateway_request_v1(
    transaction: &Transaction<'_>,
    call_id: &str,
    binding: &ValidatedGatewayReadV1,
    owner: &str,
    role: &str,
    status: &str,
    lease_id: Option<&str>,
    gateway_result_id: Option<&str>,
    reason: Option<&str>,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO gateway_requests (call_id, request_digest, state_digest, policy_digest, binding_digest, freshness_valid_until_ms, owner, role, status, joined_lease_id, gateway_result_id, reason, created_ms, updated_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
        params![
            call_id,
            binding.request_digest(),
            binding.state_digest(),
            binding.policy_digest(),
            binding.binding_digest(),
            binding.input.freshness.valid_until_ms,
            owner,
            role,
            status,
            lease_id,
            gateway_result_id,
            reason,
            now
        ],
    )?;
    for (ordinal, dependency) in binding.input.dependencies.iter().enumerate() {
        transaction.execute(
            "INSERT INTO gateway_request_dependencies (call_id, ordinal, dependency_key_digest, dependency_value_digest) VALUES (?1, ?2, ?3, ?4)",
            params![
                call_id,
                i64::try_from(ordinal)?,
                dependency.key_digest,
                dependency.value_digest
            ],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_gateway_event_v1_tx(
    transaction: &Transaction<'_>,
    call_id: Option<&str>,
    lease_id: Option<&str>,
    gateway_result_id: Option<&str>,
    event_type: &str,
    reason: Option<&str>,
    estimated_tokens_avoided: u64,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO gateway_events (call_id, lease_id, gateway_result_id, event_type, reason, estimated_tokens_avoided, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            call_id,
            lease_id,
            gateway_result_id,
            event_type,
            reason,
            estimated_tokens_avoided,
            now
        ],
    )?;
    Ok(())
}

fn load_visible_result_tx(
    transaction: &Transaction<'_>,
    result_id: &str,
) -> Result<Option<StoredResult>> {
    transaction
        .query_row(
            "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE id = ?1 AND quarantined = 0",
            [result_id],
            row_to_result,
        )
        .optional()
        .context("load visible exact gateway result source")
}

fn load_request_dependencies_v1(
    transaction: &Transaction<'_>,
    call_id: &str,
) -> Result<Vec<GatewayDependencyV1>> {
    let mut statement = transaction.prepare(
        "SELECT dependency_key_digest, dependency_value_digest FROM gateway_request_dependencies WHERE call_id = ?1 ORDER BY ordinal",
    )?;
    statement
        .query_map([call_id], |row| {
            Ok(GatewayDependencyV1 {
                key_digest: row.get(0)?,
                value_digest: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("load exact gateway request dependencies")
}

fn load_result_dependencies_v1(
    transaction: &Transaction<'_>,
    gateway_result_id: &str,
) -> Result<Vec<GatewayDependencyV1>> {
    let mut statement = transaction.prepare(
        "SELECT dependency_key_digest, dependency_value_digest FROM result_dependencies WHERE gateway_result_id = ?1 ORDER BY ordinal",
    )?;
    statement
        .query_map([gateway_result_id], |row| {
            Ok(GatewayDependencyV1 {
                key_digest: row.get(0)?,
                value_digest: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()
        .context("load exact gateway result dependencies")
}

fn gateway_result_content_digest(
    lease: &GatewayLeaseRowV1,
    result: &StoredResult,
    dependencies: &[GatewayDependencyV1],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.gateway.result.v1\0");
    for value in [
        lease.binding_digest.as_str(),
        lease.request_digest.as_str(),
        lease.state_digest.as_str(),
        lease.policy_digest.as_str(),
        result.stdout_digest.as_str(),
        result.stderr_digest.as_str(),
    ] {
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher.update(&result.stdout_bytes.to_le_bytes());
    hasher.update(&result.stderr_bytes.to_le_bytes());
    hasher.update(&result.exit_code.to_le_bytes());
    hasher.update(&result.duration_ms.to_le_bytes());
    hash_field(&mut hasher, result.policy_version.as_bytes());
    hash_field(&mut hasher, result.proof_json.as_bytes());
    hasher.update(&(dependencies.len() as u64).to_le_bytes());
    for dependency in dependencies {
        hash_field(&mut hasher, dependency.key_digest.as_bytes());
        hash_field(&mut hasher, dependency.value_digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn load_gateway_result_snapshot_v1(
    transaction: &Transaction<'_>,
    binding: &ValidatedGatewayReadV1,
    gateway_result_id: &str,
) -> Result<Option<StoredResult>> {
    let snapshot = transaction
        .query_row(
            "SELECT result_id, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, result_policy_version, proof_digest, request_digest, state_digest, policy_digest, binding_digest FROM gateway_results WHERE gateway_result_id = ?1 AND status = 'ready'",
            [gateway_result_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, i32>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                ))
            },
        )
        .optional()?;
    let Some((
        result_id,
        stdout_digest,
        stderr_digest,
        stdout_bytes,
        stderr_bytes,
        exit_code,
        duration_ms,
        policy_version,
        proof_digest,
        request_digest,
        state_digest,
        policy_digest,
        binding_digest,
    )) = snapshot
    else {
        return Ok(None);
    };
    if request_digest != binding.request_digest()
        || state_digest != binding.state_digest()
        || policy_digest != binding.policy_digest()
        || binding_digest != binding.binding_digest()
    {
        bail!("gateway result row is not bound to the admitted request");
    }
    let Some(result) = load_visible_result_tx(transaction, &result_id)? else {
        bail!("gateway result source is missing or quarantined");
    };
    if result.request_key != request_digest
        || result.stdout_digest != stdout_digest
        || result.stderr_digest != stderr_digest
        || result.stdout_bytes != stdout_bytes
        || result.stderr_bytes != stderr_bytes
        || result.exit_code != exit_code
        || result.duration_ms != duration_ms
        || result.policy_version != policy_version
        || blake3::hash(result.proof_json.as_bytes()).to_hex().as_str() != proof_digest
    {
        bail!("gateway result source metadata drifted after publication");
    }
    let dependencies = load_result_dependencies_v1(transaction, gateway_result_id)?;
    let synthetic_lease = GatewayLeaseRowV1 {
        lease_id: String::new(),
        call_id: String::new(),
        request_digest,
        state_digest,
        policy_digest,
        binding_digest,
        freshness_valid_until_ms: 0,
        owner: String::new(),
        status: "completed".to_owned(),
        gateway_result_id: Some(gateway_result_id.to_owned()),
        expires_ms: 0,
        execution_started_ms: Some(0),
        completed_ms: Some(0),
        lifecycle_generation: 1,
    };
    if gateway_result_content_digest(&synthetic_lease, &result, &dependencies) != gateway_result_id
    {
        bail!("gateway result content address mismatch");
    }
    Ok(Some(result))
}

fn gateway_result_row_valid_v1(
    transaction: &Transaction<'_>,
    binding: &ValidatedGatewayReadV1,
    gateway_result_id: &str,
) -> Result<bool> {
    match load_gateway_result_snapshot_v1(transaction, binding, gateway_result_id) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Ok(false),
    }
}

fn expire_gateway_leases_v1_tx(
    transaction: &Transaction<'_>,
    now: i64,
    binding_digest: Option<&str>,
) -> Result<u64> {
    let expired: Vec<(String, String)> = if let Some(binding_digest) = binding_digest {
        let mut statement = transaction.prepare(
            "SELECT lease_id, call_id FROM inflight_leases WHERE status = 'active' AND expires_ms <= ?1 AND binding_digest = ?2",
        )?;
        statement
            .query_map(params![now, binding_digest], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?
    } else {
        let mut statement = transaction.prepare(
            "SELECT lease_id, call_id FROM inflight_leases WHERE status = 'active' AND expires_ms <= ?1",
        )?;
        statement
            .query_map([now], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (lease_id, call_id) in &expired {
        transaction.execute(
            "UPDATE inflight_leases SET status = 'expired', reason = 'deadline', completed_ms = ?2 WHERE lease_id = ?1 AND status = 'active'",
            params![lease_id, now],
        )?;
        transaction.execute(
            "UPDATE gateway_requests SET status = 'failed', reason = 'deadline', updated_ms = ?2 WHERE joined_lease_id = ?1 AND status IN ('inflight', 'waiting')",
            params![lease_id, now],
        )?;
        record_gateway_event_v1_tx(
            transaction,
            Some(call_id),
            Some(lease_id),
            None,
            "lease_expired",
            None,
            0,
            now,
        )?;
    }
    Ok(expired.len() as u64)
}

fn quarantine_gateway_divergence_v1_tx(
    transaction: &Transaction<'_>,
    lease: &GatewayLeaseRowV1,
    existing_gateway_result_id: &str,
    conflicting_gateway_result_id: &str,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "UPDATE gateway_results SET status = 'quarantined', quarantine_reason = 'divergent_result', updated_ms = ?2 WHERE binding_digest = ?1 AND status = 'ready'",
        params![lease.binding_digest, now],
    )?;
    transaction.execute(
        "UPDATE inflight_leases SET status = 'quarantined', reason = 'divergent_result', completed_ms = ?2 WHERE call_id = ?1",
        params![lease.call_id, now],
    )?;
    transaction.execute(
        "UPDATE gateway_requests SET status = 'quarantined', reason = 'divergent_result', updated_ms = ?2 WHERE joined_lease_id = (SELECT lease_id FROM inflight_leases WHERE call_id = ?1)",
        params![lease.call_id, now],
    )?;
    record_gateway_event_v1_tx(
        transaction,
        Some(&lease.call_id),
        None,
        Some(conflicting_gateway_result_id),
        "divergent_result",
        Some(existing_gateway_result_id),
        0,
        now,
    )
}

type ExpectedForeignKeyV1 = (&'static str, &'static str, &'static str, &'static str);
type ExpectedTableForeignKeysV1 = (&'static str, &'static [ExpectedForeignKeyV1]);

fn expected_gateway_column_shape(table: &str, column: &str) -> (&'static str, bool) {
    let integer = matches!(
        column,
        "freshness_valid_until_ms"
            | "ordinal"
            | "stdout_bytes"
            | "stderr_bytes"
            | "exit_code"
            | "duration_ms"
            | "created_ms"
            | "updated_ms"
            | "acquired_ms"
            | "heartbeat_ms"
            | "expires_ms"
            | "execution_started_ms"
            | "completed_ms"
            | "lifecycle_generation"
            | "compaction_epoch"
            | "estimated_tokens_avoided"
            | "delivered_ms"
    ) || (table == "gateway_events" && column == "id");
    let nullable = matches!(
        (table, column),
        (
            "gateway_requests",
            "call_id" | "joined_lease_id" | "gateway_result_id" | "reason"
        ) | ("gateway_results", "gateway_result_id" | "quarantine_reason")
            | (
                "inflight_leases",
                "lease_id"
                    | "gateway_result_id"
                    | "reason"
                    | "execution_started_ms"
                    | "completed_ms"
            )
            | (
                "gateway_events",
                "id" | "call_id" | "lease_id" | "gateway_result_id" | "reason"
            )
    );
    (if integer { "INTEGER" } else { "TEXT" }, !nullable)
}

fn verify_gateway_schema_v7(connection: &Connection) -> Result<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        bail!("Again gateway schema verification requires version {SCHEMA_VERSION}, got {version}");
    }
    let tables: &[(&str, &[&str])] = &[
        (
            "gateway_requests",
            &[
                "call_id",
                "request_digest",
                "state_digest",
                "policy_digest",
                "binding_digest",
                "freshness_valid_until_ms",
                "owner",
                "role",
                "status",
                "joined_lease_id",
                "gateway_result_id",
                "reason",
                "created_ms",
                "updated_ms",
            ],
        ),
        (
            "gateway_request_dependencies",
            &[
                "call_id",
                "ordinal",
                "dependency_key_digest",
                "dependency_value_digest",
            ],
        ),
        (
            "gateway_results",
            &[
                "gateway_result_id",
                "request_digest",
                "state_digest",
                "policy_digest",
                "binding_digest",
                "result_id",
                "stdout_digest",
                "stderr_digest",
                "stdout_bytes",
                "stderr_bytes",
                "exit_code",
                "duration_ms",
                "result_policy_version",
                "proof_digest",
                "lease_id",
                "status",
                "quarantine_reason",
                "created_ms",
                "updated_ms",
            ],
        ),
        (
            "result_dependencies",
            &[
                "gateway_result_id",
                "ordinal",
                "dependency_key_digest",
                "dependency_value_digest",
            ],
        ),
        (
            "inflight_leases",
            &[
                "lease_id",
                "call_id",
                "request_digest",
                "state_digest",
                "policy_digest",
                "binding_digest",
                "freshness_valid_until_ms",
                "owner",
                "status",
                "gateway_result_id",
                "reason",
                "acquired_ms",
                "heartbeat_ms",
                "expires_ms",
                "execution_started_ms",
                "completed_ms",
                "lifecycle_generation",
            ],
        ),
        (
            "gateway_deliveries",
            &[
                "session_id",
                "turn_id",
                "agent_id",
                "compaction_epoch",
                "gateway_result_id",
                "presentation",
                "estimated_tokens_avoided",
                "delivered_ms",
            ],
        ),
        (
            "gateway_events",
            &[
                "id",
                "call_id",
                "lease_id",
                "gateway_result_id",
                "event_type",
                "reason",
                "estimated_tokens_avoided",
                "created_ms",
            ],
        ),
    ];
    for (table, expected) in tables {
        let mut statement = connection
            .prepare("SELECT name, type, \"notnull\" FROM pragma_table_info(?1) ORDER BY cid")?;
        let actual: Vec<(String, String, bool)> = statement
            .query_map([table], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let expected = expected
            .iter()
            .map(|column| {
                let (column_type, not_null) = expected_gateway_column_shape(table, column);
                ((*column).to_owned(), column_type.to_owned(), not_null)
            })
            .collect::<Vec<_>>();
        if actual != expected {
            bail!("Again gateway schema table {table} has an unexpected column shape");
        }
    }
    let required_indexes: &[(&str, &str, &[&str], bool, bool)] = &[
        (
            "gateway_requests",
            "gateway_requests_binding_idx",
            &["binding_digest", "created_ms"],
            false,
            false,
        ),
        (
            "gateway_requests",
            "gateway_requests_lease_idx",
            &["joined_lease_id", "status"],
            false,
            false,
        ),
        (
            "gateway_results",
            "gateway_results_ready_idx",
            &["binding_digest"],
            true,
            true,
        ),
        (
            "gateway_results",
            "gateway_results_result_idx",
            &["result_id"],
            false,
            false,
        ),
        (
            "result_dependencies",
            "result_dependencies_digest_idx",
            &["dependency_key_digest", "dependency_value_digest"],
            false,
            false,
        ),
        (
            "inflight_leases",
            "inflight_leases_active_idx",
            &["binding_digest"],
            true,
            true,
        ),
        (
            "inflight_leases",
            "inflight_leases_expiry_idx",
            &["status", "expires_ms"],
            false,
            false,
        ),
        (
            "inflight_leases",
            "inflight_leases_generation_idx",
            &["binding_digest", "lifecycle_generation"],
            true,
            false,
        ),
        (
            "gateway_events",
            "gateway_events_created_idx",
            &["created_ms"],
            false,
            false,
        ),
        (
            "gateway_events",
            "gateway_events_type_idx",
            &["event_type"],
            false,
            false,
        ),
    ];
    for (table, index, expected_columns, expected_unique, expected_partial) in required_indexes {
        let signature = connection
            .query_row(
                "SELECT \"unique\", partial FROM pragma_index_list(?1) WHERE name = ?2 AND origin = 'c'",
                params![table, index],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        if signature != Some((*expected_unique, *expected_partial)) {
            bail!("Again gateway schema is missing required index {index}");
        }
        let mut statement =
            connection.prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")?;
        let actual_columns: Vec<String> = statement
            .query_map([index], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if actual_columns
            != expected_columns
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        {
            bail!("Again gateway schema index {index} has an unexpected key shape");
        }
    }
    let required_checks = [
        ("gateway_requests", "CHECK(length(request_digest) = 64)"),
        ("gateway_requests", "CHECK(length(state_digest) = 64)"),
        ("gateway_requests", "CHECK(length(policy_digest) = 64)"),
        ("gateway_requests", "CHECK(length(binding_digest) = 64)"),
        ("gateway_requests", "CHECK(length(owner) BETWEEN 1 AND 128)"),
        (
            "gateway_requests",
            "CHECK(role IN ('leader', 'follower', 'ready', 'refused'))",
        ),
        (
            "gateway_request_dependencies",
            "CHECK(ordinal >= 0 AND ordinal < 64)",
        ),
        (
            "gateway_request_dependencies",
            "UNIQUE (call_id, dependency_key_digest)",
        ),
        ("gateway_results", "CHECK(length(gateway_result_id) = 64)"),
        ("gateway_results", "CHECK(stdout_bytes >= 0)"),
        ("gateway_results", "CHECK(stderr_bytes >= 0)"),
        ("gateway_results", "CHECK(duration_ms >= 0)"),
        (
            "gateway_results",
            "CHECK(status IN ('ready', 'quarantined'))",
        ),
        (
            "result_dependencies",
            "UNIQUE (gateway_result_id, dependency_key_digest)",
        ),
        ("inflight_leases", "CHECK(length(request_digest) = 64)"),
        ("inflight_leases", "CHECK(length(owner) BETWEEN 1 AND 128)"),
        (
            "inflight_leases",
            "CHECK(status IN ('active', 'completed', 'failed', 'expired', 'quarantined'))",
        ),
        ("gateway_deliveries", "CHECK(compaction_epoch >= 0)"),
        (
            "gateway_deliveries",
            "FOREIGN KEY (gateway_result_id) REFERENCES gateway_results",
        ),
        (
            "gateway_events",
            "CHECK(length(event_type) BETWEEN 1 AND 64)",
        ),
    ];
    for (table, fragment) in required_checks {
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if !sql.contains(fragment) {
            bail!("Again gateway schema table {table} is missing a required constraint");
        }
    }
    let expected_foreign_keys: &[ExpectedTableForeignKeysV1] = &[
        (
            "gateway_request_dependencies",
            &[("gateway_requests", "call_id", "call_id", "CASCADE")],
        ),
        (
            "gateway_results",
            &[("results", "result_id", "id", "RESTRICT")],
        ),
        (
            "result_dependencies",
            &[(
                "gateway_results",
                "gateway_result_id",
                "gateway_result_id",
                "CASCADE",
            )],
        ),
        (
            "inflight_leases",
            &[("gateway_requests", "call_id", "call_id", "RESTRICT")],
        ),
        (
            "gateway_deliveries",
            &[(
                "gateway_results",
                "gateway_result_id",
                "gateway_result_id",
                "CASCADE",
            )],
        ),
    ];
    for (table, expected) in expected_foreign_keys {
        let mut statement = connection.prepare(
            "SELECT \"table\", \"from\", \"to\", on_delete FROM pragma_foreign_key_list(?1) ORDER BY id",
        )?;
        let actual: Vec<(String, String, String, String)> = statement
            .query_map([table], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let expected = expected
            .iter()
            .map(|(target, from, to, delete)| {
                (
                    (*target).to_owned(),
                    (*from).to_owned(),
                    (*to).to_owned(),
                    (*delete).to_owned(),
                )
            })
            .collect::<Vec<_>>();
        if actual != expected {
            bail!("Again gateway schema table {table} has unexpected foreign keys");
        }
    }
    let foreign_key_failure: Option<String> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()?;
    if let Some(table) = foreign_key_failure {
        bail!("Again gateway schema foreign-key violation in {table}");
    }
    Ok(())
}

fn lease_refusal_for_status(status: &str) -> GatewayRefusalReason {
    match status {
        "expired" => GatewayRefusalReason::LeaseExpired,
        "quarantined" => GatewayRefusalReason::Quarantined,
        "completed" | "failed" => GatewayRefusalReason::AlreadyTerminal,
        _ => GatewayRefusalReason::LeaseNotCurrent,
    }
}

impl FileDigestCache for Store {
    fn lookup(&mut self, identity: &FileIdentity) -> Option<[u8; 32]> {
        if !identity.is_valid() {
            return None;
        }
        let device = u64_blob(identity.device);
        let inode = u64_blob(identity.inode);
        let row = self
            .conn
            .query_row(
                r#"
                SELECT digest, row_checksum
                FROM file_digests
                WHERE device = ?1 AND inode = ?2 AND mode = ?3 AND uid = ?4
                  AND gid = ?5 AND size = ?6 AND mtime_sec = ?7 AND mtime_nsec = ?8
                  AND ctime_sec = ?9 AND ctime_nsec = ?10
                "#,
                params![
                    device,
                    inode,
                    i64::from(identity.mode),
                    i64::from(identity.uid),
                    i64::from(identity.gid),
                    u64_blob(identity.size),
                    identity.mtime_sec,
                    identity.mtime_nsec,
                    identity.ctime_sec,
                    identity.ctime_nsec,
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional();

        let (digest_bytes, checksum_bytes) = match row {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(_) => return None,
        };
        let Ok(digest) = <[u8; 32]>::try_from(digest_bytes.as_slice()) else {
            self.delete_file_digest(identity);
            return None;
        };
        let Ok(checksum) = <[u8; 32]>::try_from(checksum_bytes.as_slice()) else {
            self.delete_file_digest(identity);
            return None;
        };
        if checksum != file_digest_row_checksum(identity, &digest) {
            self.delete_file_digest(identity);
            return None;
        }
        // Keep warm fingerprinting read-only. Updating LRU state for every file in
        // a recursive tree turns a cache hit into thousands of SQLite writes.
        // `last_used_ms` therefore means last validated/recorded time in v0; an
        // evicted hot digest is merely recomputed, never a correctness failure.
        Some(digest)
    }

    fn record(&mut self, identity: &FileIdentity, digest: [u8; 32]) {
        if !identity.is_valid() {
            return;
        }
        let checksum = file_digest_row_checksum(identity, &digest);
        let insert_result = self.conn.execute(
            r#"
                INSERT INTO file_digests (
                    device, inode, mode, uid, gid, size, mtime_sec, mtime_nsec,
                    ctime_sec, ctime_nsec, digest, row_checksum, last_used_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                ON CONFLICT(device, inode) DO UPDATE SET
                    mode = excluded.mode, uid = excluded.uid, gid = excluded.gid,
                    size = excluded.size, mtime_sec = excluded.mtime_sec,
                    mtime_nsec = excluded.mtime_nsec, ctime_sec = excluded.ctime_sec,
                    ctime_nsec = excluded.ctime_nsec, digest = excluded.digest,
                    row_checksum = excluded.row_checksum, last_used_ms = excluded.last_used_ms
                "#,
            params![
                u64_blob(identity.device),
                u64_blob(identity.inode),
                i64::from(identity.mode),
                i64::from(identity.uid),
                i64::from(identity.gid),
                u64_blob(identity.size),
                identity.mtime_sec,
                identity.mtime_nsec,
                identity.ctime_sec,
                identity.ctime_nsec,
                digest.as_slice(),
                checksum.as_slice(),
                now_ms(),
            ],
        );
        if insert_result.is_err() {
            return;
        }

        self.file_digest_writes_since_prune = self.file_digest_writes_since_prune.saturating_add(1);
        if self.file_digest_writes_since_prune >= FILE_DIGEST_PRUNE_INTERVAL {
            self.prune_file_digests();
            self.file_digest_writes_since_prune = 0;
        }
    }
}

impl Store {
    fn delete_file_digest(&self, identity: &FileIdentity) {
        let _ = self.conn.execute(
            "DELETE FROM file_digests WHERE device = ?1 AND inode = ?2",
            params![u64_blob(identity.device), u64_blob(identity.inode)],
        );
    }

    fn prune_file_digests(&self) {
        let Ok(count) = self
            .conn
            .query_row("SELECT COUNT(*) FROM file_digests", [], |row| {
                row.get::<_, i64>(0)
            })
        else {
            return;
        };
        let excess = (count - MAX_FILE_DIGEST_ROWS).max(0);
        if excess == 0 {
            return;
        }
        let _ = self.conn.execute(
            r#"
            DELETE FROM file_digests
            WHERE (device, inode) IN (
                SELECT device, inode FROM file_digests
                ORDER BY last_used_ms ASC, device ASC, inode ASC LIMIT ?1
            )
            "#,
            [excess],
        );
    }
}

fn u64_blob(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn file_digest_row_checksum(identity: &FileIdentity, digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("again.file-digest-row.v1");
    hasher.update(&identity.device.to_be_bytes());
    hasher.update(&identity.inode.to_be_bytes());
    hasher.update(&identity.mode.to_be_bytes());
    hasher.update(&identity.uid.to_be_bytes());
    hasher.update(&identity.gid.to_be_bytes());
    hasher.update(&identity.size.to_be_bytes());
    hasher.update(&identity.mtime_sec.to_be_bytes());
    hasher.update(&identity.mtime_nsec.to_be_bytes());
    hasher.update(&identity.ctime_sec.to_be_bytes());
    hasher.update(&identity.ctime_nsec.to_be_bytes());
    hasher.update(digest);
    *hasher.finalize().as_bytes()
}

fn default_workspace_state_root(workspace: &Path, temporary_directory: &Path) -> Result<PathBuf> {
    let temporary_directory = fs::canonicalize(temporary_directory).with_context(|| {
        format!(
            "resolve operating-system temporary directory {}",
            temporary_directory.display()
        )
    })?;
    let base = temporary_directory.join(format!("again-{}", user_namespace()));
    validate_external_state_root(workspace, &base)?;
    let base = prepare_store_root(&base)?;
    let workspaces = prepare_private_child_dir(&base, "workspaces")?;
    let root = workspaces.join(workspace_state_id(workspace));
    validate_external_state_root(workspace, &root)?;
    Ok(root)
}

fn workspace_state_id(workspace: &Path) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("again.workspace-state-path.v1");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(workspace.as_os_str().as_bytes());
    }
    #[cfg(not(unix))]
    hasher.update(workspace.to_string_lossy().as_bytes());
    hasher.finalize().to_hex().to_string()
}

#[cfg(unix)]
fn user_namespace() -> String {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }.to_string()
}

#[cfg(not(unix))]
fn user_namespace() -> String {
    let identity = std::env::var_os("USERNAME")
        .or_else(|| std::env::var_os("USER"))
        .unwrap_or_else(|| std::ffi::OsString::from("unknown"));
    blake3::hash(identity.to_string_lossy().as_bytes())
        .to_hex()
        .to_string()
}

fn prepare_store_root(requested: &Path) -> Result<PathBuf> {
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()?.join(requested)
    };
    match fs::symlink_metadata(&requested) {
        Ok(metadata) => {
            // Never chmod an arbitrary existing AGAIN_HOME or caller-supplied
            // path: a typo such as AGAIN_HOME=$HOME must fail without changing
            // broad directory permissions. Existing roots opt in with 0700.
            validate_private_directory(&requested, &metadata, "Again state root")?;
            fs::canonicalize(&requested)
                .with_context(|| format!("canonicalize Again state root {}", requested.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = requested.parent().ok_or_else(|| {
                anyhow!("Again state root has no parent: {}", requested.display())
            })?;
            let name = requested
                .file_name()
                .ok_or_else(|| anyhow!("Again state root has no final component"))?;
            let parent = fs::canonicalize(parent).with_context(|| {
                format!(
                    "resolve parent of Again state root {}; create its parent directories first",
                    requested.display()
                )
            })?;
            let root = parent.join(name);
            match create_private_directory(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create Again state root {}", root.display()));
                }
            }
            let metadata = fs::symlink_metadata(&root)
                .with_context(|| format!("inspect Again state root {}", root.display()))?;
            validate_private_directory(&root, &metadata, "Again state root")?;
            fs::canonicalize(&root)
                .with_context(|| format!("canonicalize Again state root {}", root.display()))
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspect Again state root {}", requested.display()))
        }
    }
}

fn prospective_store_root(requested: &Path) -> Result<PathBuf> {
    let requested = requested.to_path_buf();
    match fs::symlink_metadata(&requested) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!("AGAIN_HOME must not be a symlink: {}", requested.display());
            }
            fs::canonicalize(&requested).with_context(|| {
                format!(
                    "resolve configured Again state root {}",
                    requested.display()
                )
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = requested.parent().ok_or_else(|| {
                anyhow!("Again state root has no parent: {}", requested.display())
            })?;
            let name = requested
                .file_name()
                .ok_or_else(|| anyhow!("Again state root has no final component"))?;
            Ok(fs::canonicalize(parent)
                .with_context(|| {
                    format!(
                        "resolve parent of Again state root {}; create its parent directories first",
                        requested.display()
                    )
                })?
                .join(name))
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspect Again state root {}", requested.display()))
        }
    }
}

fn validate_external_state_root(workspace: &Path, root: &Path) -> Result<()> {
    if root.starts_with(workspace) {
        bail!(
            "Again state must be outside the active workspace {}; set AGAIN_HOME to an absolute external directory",
            workspace.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_state_ancestors(root: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    let parent = root
        .parent()
        .ok_or_else(|| anyhow!("configured Again state root has no parent"))?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).with_context(|| {
            format!(
                "inspect configured Again state ancestor {}",
                ancestor.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "configured Again state ancestor must be a real directory: {}",
                ancestor.display()
            );
        }
        if metadata.uid() != effective_uid && metadata.uid() != 0 {
            bail!(
                "configured Again state ancestor has an untrusted owner: {}",
                ancestor.display()
            );
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            bail!(
                "configured Again state ancestor is writable by other users without sticky protection: {}",
                ancestor.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_state_ancestors(_root: &Path) -> Result<()> {
    Ok(())
}

fn prepare_private_child_dir(parent: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || matches!(name, "." | "..") {
        bail!("invalid Again state directory component");
    }
    let path = parent.join(name);
    let created = match create_private_directory(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("create Again state directory {}", path.display()));
        }
    };
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect Again state directory {}", path.display()))?;
    let label = if created {
        "new Again state directory"
    } else {
        "Again state directory"
    };
    validate_private_directory(&path, &metadata, label)?;
    Ok(path)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

fn validate_owned_directory(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "{label} must be a real directory, not a symlink: {}",
            path.display()
        );
    }
    validate_current_owner(path, metadata, label)
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    validate_owned_directory(path, metadata, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            bail!("{label} must already have mode 0700: {}", path.display());
        }
    }
    Ok(())
}

fn reject_unsafe_existing_file(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_owned_regular_file(path, &metadata, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {label} {}", path.display())),
    }
}

fn ensure_private_database_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => {
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_unsafe_existing_file(path, "Again database")?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("create Again database {}", path.display()));
        }
    }
    set_private_file(path)
}

fn validate_owned_regular_file(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    validate_owned_regular_file_identity(path, metadata, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("{label} must already have mode 0600: {}", path.display());
        }
    }
    Ok(())
}

fn validate_owned_regular_file_identity(
    path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{label} must be a regular file, not a symlink: {}",
            path.display()
        );
    }
    validate_current_owner(path, metadata, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!("{label} must not be hard-linked: {}", path.display());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_current_owner(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!(
            "{label} is not owned by the current user: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_current_owner(_path: &Path, _metadata: &fs::Metadata, _label: &str) -> Result<()> {
    Ok(())
}

fn blob_path_under(blobs: &Path, digest: &str) -> Result<PathBuf> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid BLAKE3 digest");
    }
    Ok(blobs.join(&digest[..2]).join(&digest[2..]))
}

fn ensure_blob_file(target: &Path, digest: &str, expected: &[u8]) -> Result<()> {
    match fs::symlink_metadata(target) {
        Ok(metadata) => {
            validate_owned_regular_file(target, &metadata, "Again blob")?;
            return verify_blob_file(target, digest, expected);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect Again blob {digest}"));
        }
    }

    let parent = target.parent().context("blob target has no parent")?;
    let blobs = parent.parent().context("blob shard has no CAS parent")?;
    let shard = parent
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("blob shard is not valid UTF-8"))?;
    let parent = prepare_private_child_dir(blobs, shard)?;
    let staged = parent.join(format!(".{digest}.{}.tmp", Uuid::new_v4().simple()));
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(expected)?;
        file.sync_all()?;
        set_private_file(&staged)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    match fs::rename(&staged, target) {
        Ok(()) => Ok(()),
        Err(error) if fs::symlink_metadata(target).is_ok() => {
            let _ = fs::remove_file(&staged);
            let metadata = fs::symlink_metadata(target)
                .with_context(|| format!("inspect raced Again blob {digest}"))?;
            validate_owned_regular_file(target, &metadata, "Again blob")?;
            verify_blob_file(target, digest, expected).context(error)
        }
        Err(error) => {
            let _ = fs::remove_file(&staged);
            Err(error).context("commit CAS blob")
        }
    }
}

fn verify_blob_file(path: &Path, digest: &str, expected: &[u8]) -> Result<()> {
    let existing = read_blob_bounded(path, digest)?;
    let actual = blake3::hash(&existing).to_hex().to_string();
    if actual != digest {
        bail!("CAS corruption: blob {digest} hashes to {actual}");
    }
    if existing != expected {
        bail!("CAS collision or corruption for blob {digest}");
    }
    Ok(())
}

fn read_blob_bounded(path: &Path, digest: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect blob {digest} before bounded read"))?;
    if metadata.len() > MAX_LOCAL_BLOB_BYTES as u64 {
        bail!("Again blob {digest} exceeds the local 16 MiB limit");
    }
    let file = File::open(path).with_context(|| format!("open blob {digest}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_LOCAL_BLOB_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read blob {digest}"))?;
    if bytes.len() > MAX_LOCAL_BLOB_BYTES {
        bail!("Again blob {digest} grew beyond the local 16 MiB limit");
    }
    Ok(bytes)
}

fn system_time_ms(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
}

fn create_self_ignoring_gitignore(root: &Path) -> Result<()> {
    if root.file_name().and_then(|name| name.to_str()) != Some(".again") {
        return Ok(());
    }
    let path = root.join(".gitignore");
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(b"*\n")?;
            file.sync_all()?;
            set_private_file(&path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_unsafe_existing_file(&path, "Again .gitignore")
        }
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

fn row_to_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredResult> {
    Ok(StoredResult {
        id: row.get(0)?,
        request_key: row.get(1)?,
        stdout_digest: row.get(2)?,
        stderr_digest: row.get(3)?,
        stdout_bytes: row.get(4)?,
        stderr_bytes: row.get(5)?,
        exit_code: row.get(6)?,
        duration_ms: row.get(7)?,
        policy_version: row.get(8)?,
        proof_json: row.get(9)?,
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(all(test, unix))]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    validate_owned_directory(path, &metadata, "Again private directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(all(test, not(unix)))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_owned_regular_file_identity(path, &metadata, "Again private file")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{File, FileTimes};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use tempfile::TempDir;

    #[test]
    fn state_root_and_fixed_children_reject_symlinks() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();

        let untrusted_root = temp.path().join("untrusted-root");
        fs::create_dir(&untrusted_root).unwrap();
        fs::set_permissions(&untrusted_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::open_with_policy(&untrusted_root).is_err());
        assert_eq!(
            fs::symlink_metadata(&untrusted_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        let root_link = temp.path().join("root-link");
        symlink(&outside, &root_link).unwrap();
        assert!(Store::open(&root_link).is_err());
        assert!(!outside.join("blobs").exists());

        let blobs_root = temp.path().join("blobs-root");
        fs::create_dir(&blobs_root).unwrap();
        set_private_dir(&blobs_root).unwrap();
        symlink(&outside, blobs_root.join("blobs")).unwrap();
        assert!(Store::open(&blobs_root).is_err());

        let database_root = temp.path().join("database-root");
        fs::create_dir(&database_root).unwrap();
        set_private_dir(&database_root).unwrap();
        let outside_file = outside.join("victim");
        fs::write(&outside_file, b"unchanged").unwrap();
        symlink(&outside_file, database_root.join("again.sqlite")).unwrap();
        assert!(Store::open(&database_root).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(), b"unchanged");

        let ignore_root = temp.path().join(".again");
        fs::create_dir(&ignore_root).unwrap();
        set_private_dir(&ignore_root).unwrap();
        symlink(&outside_file, ignore_root.join(".gitignore")).unwrap();
        assert!(Store::open(&ignore_root).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(), b"unchanged");
    }

    #[test]
    fn default_state_is_external_stable_and_workspace_scoped() {
        let temp = TempDir::new().unwrap();
        let workspace = temp.path().join("workspace");
        let other_workspace = temp.path().join("other-workspace");
        let temporary_directory = temp.path().join("system-temp");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&other_workspace).unwrap();
        fs::create_dir(&temporary_directory).unwrap();

        let root = default_workspace_state_root(&workspace, &temporary_directory).unwrap();
        let repeated = default_workspace_state_root(&workspace, &temporary_directory).unwrap();
        let other = default_workspace_state_root(&other_workspace, &temporary_directory).unwrap();

        assert_eq!(root, repeated);
        assert_ne!(root, other);
        assert!(root.starts_with(temporary_directory.canonicalize().unwrap()));
        assert!(!root.starts_with(workspace.canonicalize().unwrap()));
        assert!(!workspace.join(".again").exists());
        let store = Store::open(&root).unwrap();
        assert_eq!(store.root(), root.canonicalize().unwrap());
    }

    #[test]
    fn configured_state_must_be_external_and_final_symlinks_are_rejected() {
        let temp = TempDir::new().unwrap();
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&outside).unwrap();

        assert!(validate_external_state_root(&workspace, &workspace.join(".again")).is_err());
        assert!(validate_external_state_root(&workspace, &outside).is_ok());

        let link = temp.path().join("configured-link");
        symlink(&outside, &link).unwrap();
        assert!(prospective_store_root(&link).is_err());
    }

    #[test]
    fn configured_state_rejects_an_unprotected_writable_parent_namespace() {
        let temp = TempDir::new().unwrap();
        let parent = temp.path().join("shared-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let root = prospective_store_root(&parent.join("state")).unwrap();
        assert!(validate_trusted_state_ancestors(&root).is_err());

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(validate_trusted_state_ancestors(&root).is_ok());
    }

    #[test]
    fn blob_shards_and_reads_reject_symlinks() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let store = Store::open(temp.path().join("state")).unwrap();
        let bytes = b"immutable blob";
        let digest = blake3::hash(bytes).to_hex().to_string();
        symlink(&outside, store.blobs.join(&digest[..2])).unwrap();
        assert!(store.put_blob(bytes).is_err());

        fs::remove_file(store.blobs.join(&digest[..2])).unwrap();
        let stored = store.put_blob(bytes).unwrap();
        let path = store.blob_path(&stored).unwrap();
        fs::remove_file(&path).unwrap();
        let outside_file = outside.join("blob-victim");
        fs::write(&outside_file, bytes).unwrap();
        symlink(&outside_file, &path).unwrap();
        assert!(store.get_blob(&stored).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(), bytes);
    }

    #[test]
    fn blob_reads_are_bounded_even_if_state_is_tampered() {
        let temp = TempDir::new().unwrap();
        let store = Store::open(temp.path().join("state")).unwrap();
        let digest = store.put_blob(b"small").unwrap();
        let path = store.blob_path(&digest).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_LOCAL_BLOB_BYTES as u64 + 1)
            .unwrap();
        assert!(store.get_blob(&digest).is_err());
    }

    fn test_file_identity() -> FileIdentity {
        FileIdentity {
            device: 17,
            inode: 29,
            mode: 0o100644,
            uid: 501,
            gid: 20,
            size: 4096,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 123,
            ctime_sec: 1_700_000_001,
            ctime_nsec: 456,
        }
    }

    #[test]
    fn blobs_round_trip_and_detect_invalid_digest() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let digest = store.put_blob(b"hello").unwrap();
        assert_eq!(store.get_blob(&digest).unwrap(), b"hello");
        assert!(store.get_blob("../escape").is_err());
    }

    #[test]
    fn file_digest_memo_survives_reopen_without_persisting_paths() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let identity = test_file_identity();
        let digest = [0x5a; 32];
        {
            let mut store = Store::open(temp.path()).unwrap();
            store.record(&identity, digest);
            assert_eq!(store.lookup(&identity), Some(digest));
        }

        let mut reopened = Store::open(temp.path()).unwrap();
        assert_eq!(reopened.lookup(&identity), Some(digest));
        let columns: Vec<String> = reopened
            .conn
            .prepare("PRAGMA table_info(file_digests)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!columns.iter().any(|column| column.contains("path")));
    }

    #[test]
    fn corrupted_file_digest_row_is_a_miss_and_can_be_recomputed() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let identity = test_file_identity();
        let digest = [0x71; 32];
        let mut store = Store::open(temp.path()).unwrap();
        store.record(&identity, digest);
        store
            .conn
            .execute("UPDATE file_digests SET digest = zeroblob(32)", [])
            .unwrap();

        assert_eq!(store.lookup(&identity), None, "checksum failure is a miss");
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM file_digests", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "corrupt row is discarded");

        store.record(&identity, digest);
        assert_eq!(store.lookup(&identity), Some(digest));
    }

    #[test]
    fn version_one_database_migrates_file_digest_table() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let database = temp.path().join("again.sqlite");
        Connection::open(&database)
            .unwrap()
            .execute_batch(
                r#"
                CREATE TABLE pending_calls (id TEXT PRIMARY KEY, created_ms INTEGER NOT NULL);
                CREATE TABLE results (
                    id TEXT PRIMARY KEY,
                    stdout_digest TEXT NOT NULL,
                    stderr_digest TEXT NOT NULL
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY,
                    disposition TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL
                );
                PRAGMA user_version = 1;
                "#,
            )
            .unwrap();
        set_private_file(&database).unwrap();

        let store = Store::open(temp.path()).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let exists: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'file_digests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn version_four_replay_metrics_are_reset_before_net_savings_are_reported() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        {
            let store = Store::open(temp.path()).unwrap();
            store
                .record_event(
                    None,
                    None,
                    EventDisposition::ReplayedFull,
                    "LEGACY_GROSS_DURATION",
                    9_999,
                    0,
                )
                .unwrap();
            store
                .conn
                .execute_batch(
                    "DROP TABLE gateway_deliveries;
                     DROP TABLE result_dependencies;
                     DROP TABLE gateway_results;
                     DROP TABLE gateway_request_dependencies;
                     DROP TABLE inflight_leases;
                     DROP TABLE gateway_requests;
                     DROP TABLE gateway_events;",
                )
                .unwrap();
            store.conn.pragma_update(None, "user_version", 4).unwrap();
        }

        let reopened = Store::open(temp.path()).unwrap();
        let version: i64 = reopened
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let stats = reopened.stats().unwrap();
        assert_eq!(stats.full_replays, 1);
        assert_eq!(stats.estimated_execution_ms_saved, 0);
    }

    #[test]
    fn repository_scoped_store_is_self_ignored_without_overwriting_user_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join(".again");
        let store = Store::open(&root).unwrap();
        assert_eq!(fs::read_to_string(root.join(".gitignore")).unwrap(), "*\n");
        drop(store);

        fs::write(root.join(".gitignore"), "user-owned\n").unwrap();
        drop(Store::open(&root).unwrap());
        assert_eq!(
            fs::read_to_string(root.join(".gitignore")).unwrap(),
            "user-owned\n"
        );
    }

    #[test]
    fn pending_calls_round_trip_without_shell_interpolation() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let store = Store::open(temp.path()).unwrap();
        let call = store
            .create_call(
                "session",
                Some("turn"),
                Some("root-turn"),
                temp.path(),
                "rg needle src",
                &["rg".into(), "needle".into(), "src".into()],
            )
            .unwrap();
        assert_eq!(store.get_call(&call.id).unwrap(), Some(call.clone()));
        store.delete_call(&call.id).unwrap();
        assert_eq!(store.get_call(&call.id).unwrap(), None);
    }

    #[test]
    fn cleanup_expires_only_stale_unreferenced_state() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let current = now_ms();
        let stale_pending = current - PENDING_CALL_TTL_MS - 1;
        let stale_event = current - EVENT_TTL_MS - 1;
        let stale_artifact = current - ORPHAN_ARTIFACT_TTL_MS - 1;

        store
            .conn
            .execute(
                "INSERT INTO pending_calls (id, session_id, cwd, raw_command, argv_json, created_ms) VALUES ('stale', 's', '/tmp', 'cat x', '[]', ?1)",
                [stale_pending],
            )
            .unwrap();
        let recent = store
            .create_call("session", None, None, temp.path(), "cat x", &["cat".into()])
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO events (disposition, reason_code, elapsed_ms, bytes_omitted, created_ms) VALUES ('passed_through', 'old', 0, 0, ?1)",
                [stale_event],
            )
            .unwrap();
        store
            .record_event(None, None, EventDisposition::Executed, "recent", 0, 0)
            .unwrap();

        let orphan_digest = store.put_blob(b"orphan").unwrap();
        let retained = store
            .insert_result("retained", b"referenced", b"", 0, 1, "v0", "{}")
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE artifacts SET created_ms = ?1 WHERE digest = ?2",
                params![stale_artifact, orphan_digest],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE artifacts SET created_ms = ?1 WHERE digest = ?2 OR digest = ?3",
                params![
                    stale_artifact,
                    retained.stdout_digest,
                    retained.stderr_digest
                ],
            )
            .unwrap();
        let old_time = UNIX_EPOCH + Duration::from_millis(stale_artifact as u64);
        for digest in [
            orphan_digest.as_str(),
            retained.stdout_digest.as_str(),
            retained.stderr_digest.as_str(),
        ] {
            File::open(store.blob_path(digest).unwrap())
                .unwrap()
                .set_times(FileTimes::new().set_modified(old_time))
                .unwrap();
        }

        let report = store.cleanup_at(current, true).unwrap();
        assert_eq!(
            report,
            CleanupReport {
                pending_calls: 1,
                events: 1,
                gateway_events: 0,
                artifacts: 1,
            }
        );
        assert!(store.get_call("stale").unwrap().is_none());
        assert_eq!(store.get_call(&recent.id).unwrap(), Some(recent));
        assert!(store.get_blob(&orphan_digest).is_err());
        assert_eq!(
            store.get_blob(&retained.stdout_digest).unwrap(),
            b"referenced"
        );
        assert_eq!(store.get_result("retained").unwrap(), Some(retained));
        assert_eq!(store.stats().unwrap().executions, 1);
    }

    #[test]
    fn cleanup_batches_are_strictly_bounded() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let current = now_ms();
        let stale = current - PENDING_CALL_TTL_MS - 1;
        let transaction = store.conn.transaction().unwrap();
        for index in 0..(CLEANUP_ROW_LIMIT + 1) {
            transaction
                .execute(
                    "INSERT INTO pending_calls (id, session_id, cwd, raw_command, argv_json, created_ms) VALUES (?1, 's', '/tmp', 'cat', '[]', ?2)",
                    params![format!("stale-{index}"), stale],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        assert_eq!(
            store.cleanup_at(current, true).unwrap().pending_calls,
            CLEANUP_ROW_LIMIT as u64
        );
        let remaining: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM pending_calls", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
        assert_eq!(store.cleanup_at(current, true).unwrap().pending_calls, 1);
    }

    #[test]
    fn results_and_delivery_state_round_trip() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let result = store
            .insert_result("key", b"out", b"", 0, 50, "v0", "{}")
            .unwrap();
        assert_eq!(store.get_result("key").unwrap(), Some(result.clone()));
        assert!(!store.was_delivered("s", "root-turn", &result.id).unwrap());
        store.mark_delivered("s", "root-turn", &result.id).unwrap();
        assert!(store.was_delivered("s", "root-turn", &result.id).unwrap());
    }

    #[test]
    fn same_key_with_different_output_is_quarantined() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        store
            .insert_result("key", b"first", b"", 0, 1, "v0", "{}")
            .unwrap();
        assert!(
            store
                .insert_result("key", b"second", b"", 0, 1, "v0", "{}")
                .is_err()
        );
        assert!(store.get_result("key").unwrap().is_none());
    }

    #[test]
    fn concurrent_identical_writes_converge_on_one_result() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        drop(Store::open(temp.path()).unwrap());
        let root = temp.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = Store::open(root).unwrap();
                    barrier.wait();
                    store
                        .insert_result("shared", b"same", b"", 0, 1, "v0", "{}")
                        .unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert!(results.iter().all(|result| result.id == results[0].id));
        let store = Store::open(temp.path()).unwrap();
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM results", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.get_blob(&results[0].stdout_digest).unwrap(), b"same");
    }

    #[test]
    fn concurrent_same_key_divergence_is_atomically_quarantined() {
        let temp = TempDir::new().unwrap();
        set_private_dir(temp.path()).unwrap();
        drop(Store::open(temp.path()).unwrap());
        let root = temp.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|output| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = Store::open(root).unwrap();
                    barrier.wait();
                    store.insert_result("shared", output, b"", 0, 1, "v0", "{}")
                })
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);

        let store = Store::open(temp.path()).unwrap();
        assert!(store.get_result("shared").unwrap().is_none());
        let quarantined: i64 = store
            .conn
            .query_row(
                "SELECT quarantined FROM results WHERE request_key = 'shared'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(quarantined, 1);
        let quarantine_events: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE reason_code = 'same_key_different_result'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(quarantine_events, 1);
    }
}
