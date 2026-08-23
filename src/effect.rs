//! Versioned records shared by the executor, validator, and future remote cache.
//!
//! This module intentionally contains no raw environment-value field.  An
//! invocation can record that an environment variable participated in a key,
//! but only its digest is serialised.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// The on-disk/wire schema version for [`ExecutionRecord`].
pub const EFFECT_IR_V1_SCHEMA_VERSION: u32 = 1;
/// Short alias used by callers that do not need to spell out the format name.
pub const SCHEMA_VERSION: u32 = EFFECT_IR_V1_SCHEMA_VERSION;
/// Human-readable schema identifier for logs and remote-store negotiation.
pub const EFFECT_IR_V1_SCHEMA: &str = "effect_ir.v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EffectIrError {
    #[error("unsupported EffectIR schema version {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("duplicate environment variable {0}")]
    DuplicateEnvironmentVariable(String),
    #[error("{stream} byte count does not match its blob reference")]
    ByteCountMismatch { stream: &'static str },
}

/// A content-addressed digest.  `value` is normally lowercase hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<u64>,
}

pub type ContentDigest = Digest;

impl Digest {
    pub fn new(algorithm: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            value: value.into(),
            byte_count: None,
        }
    }

    pub fn with_byte_count(mut self, byte_count: u64) -> Self {
        self.byte_count = Some(byte_count);
        self
    }

    fn validate(&self, field: &'static str) -> Result<(), EffectIrError> {
        if self.algorithm.trim().is_empty() || self.value.trim().is_empty() {
            return Err(EffectIrError::EmptyField(field));
        }
        Ok(())
    }
}

/// A reference to bytes stored in the local or remote CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BlobRef {
    pub digest: Digest,
    pub byte_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

impl BlobRef {
    pub fn new(digest: Digest, byte_count: u64) -> Self {
        Self {
            digest,
            byte_count,
            media_type: None,
        }
    }

    pub fn with_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.media_type = Some(media_type.into());
        self
    }

    fn validate(&self) -> Result<(), EffectIrError> {
        self.digest.validate("blob digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Invocation {
    pub program: String,
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<BlobRef>,
    /// Environment names and digests only; never the raw environment value.
    #[serde(default)]
    pub environment: Vec<EnvironmentValueDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
}

impl Invocation {
    pub fn new(program: impl Into<String>, argv: Vec<String>, cwd: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            argv,
            cwd: cwd.into(),
            stdin: None,
            environment: Vec::new(),
            shell: None,
        }
    }

    pub fn add_environment_digest(&mut self, name: impl Into<String>, digest: Digest) {
        self.environment.push(EnvironmentValueDigest {
            name: name.into(),
            digest,
        });
    }

    fn validate(&self) -> Result<(), EffectIrError> {
        if self.program.trim().is_empty() {
            return Err(EffectIrError::EmptyField("program"));
        }
        if self.cwd.trim().is_empty() {
            return Err(EffectIrError::EmptyField("cwd"));
        }
        let mut names = std::collections::BTreeSet::new();
        for item in &self.environment {
            if item.name.trim().is_empty() {
                return Err(EffectIrError::EmptyField("environment name"));
            }
            item.digest.validate("environment digest")?;
            if !names.insert(item.name.clone()) {
                return Err(EffectIrError::DuplicateEnvironmentVariable(
                    item.name.clone(),
                ));
            }
        }
        if let Some(stdin) = &self.stdin {
            stdin.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EnvironmentValueDigest {
    pub name: String,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct PlatformIdentity {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

impl PlatformIdentity {
    pub fn new(os: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            architecture: architecture.into(),
            kernel: None,
            runtime: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PlatformProfileIdentity {
    pub platform: PlatformIdentity,
    pub profile: String,
}

pub type PlatformProfile = PlatformProfileIdentity;
pub type EffectIrV1 = ExecutionRecord;

impl PlatformProfileIdentity {
    pub fn new(platform: PlatformIdentity, profile: impl Into<String>) -> Self {
        Self {
            platform,
            profile: profile.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ns: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_ns: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    File,
    Directory,
    Symlink,
    Executable,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectoryEntry {
    pub name: String,
    pub kind: ResourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FileMetadata>,
}

/// Inputs observed while executing an invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceObservation {
    File {
        path: String,
        content: ContentDigest,
        metadata: FileMetadata,
    },
    Directory {
        path: String,
        entries: Vec<DirectoryEntry>,
    },
    Symlink {
        path: String,
        target: String,
    },
    AbsentPath {
        path: String,
    },
    Executable {
        path: String,
        content: ContentDigest,
        metadata: FileMetadata,
    },
    EnvironmentValueDigest {
        name: String,
        digest: ContentDigest,
    },
}

impl ResourceObservation {
    fn validate(&self) -> Result<(), EffectIrError> {
        let path = match self {
            Self::File { path, .. }
            | Self::Directory { path, .. }
            | Self::Symlink { path, .. }
            | Self::AbsentPath { path }
            | Self::Executable { path, .. } => Some(path),
            Self::EnvironmentValueDigest { name, .. } => Some(name),
        };
        if path.is_some_and(|value| value.trim().is_empty()) {
            return Err(EffectIrError::EmptyField("resource path"));
        }
        match self {
            Self::File { content, .. }
            | Self::Executable { content, .. }
            | Self::EnvironmentValueDigest {
                digest: content, ..
            } => content.validate("resource digest"),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    FileWrite {
        path: String,
        before: Option<ContentDigest>,
        after: ContentDigest,
    },
    Rename {
        from: String,
        to: String,
    },
    Unlink {
        path: String,
    },
    Mkdir {
        path: String,
    },
    Network {
        destination: String,
        allowed: bool,
    },
    Opaque {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    RecordOnly,
    CacheHit,
    CacheMiss,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyReason {
    SafeReplayableEffects,
    UnknownEffect,
    IncompleteTrace,
    NondeterministicInput,
    ExternalSideEffect,
    PreconditionConflict,
    PrivacyRestricted,
    ValidatorMismatch,
    UnsupportedPlatform,
    ExplicitlyDisabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub reason: PolicyReason,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitStatus {
    Exited { code: i32 },
    Signaled { signal: i32 },
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExecutionResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<BlobRef>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub exit: ExitStatus,
    pub duration_ms: u64,
}

impl ExecutionResult {
    pub fn new(exit: ExitStatus, duration_ms: u64) -> Self {
        Self {
            stdout: None,
            stderr: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            exit,
            duration_ms,
        }
    }

    fn validate(&self) -> Result<(), EffectIrError> {
        if let Some(blob) = &self.stdout {
            blob.validate()?;
            if blob.byte_count != self.stdout_bytes {
                return Err(EffectIrError::ByteCountMismatch { stream: "stdout" });
            }
        } else if self.stdout_bytes != 0 {
            return Err(EffectIrError::ByteCountMismatch { stream: "stdout" });
        }
        if let Some(blob) = &self.stderr {
            blob.validate()?;
            if blob.byte_count != self.stderr_bytes {
                return Err(EffectIrError::ByteCountMismatch { stream: "stderr" });
            }
        } else if self.stderr_bytes != 0 {
            return Err(EffectIrError::ByteCountMismatch { stream: "stderr" });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheDisposition {
    NotEligible { reason: PolicyReason },
    Recorded,
    Hit { source: String },
    Miss { reason: PolicyReason },
    ReplayApplied,
    Invalidated { reason: PolicyReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValidationOutcome {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidationEvent {
    pub validator: String,
    pub outcome: ValidationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compared_record: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ValidationHistory {
    pub events: Vec<ValidationEvent>,
}

impl ValidationHistory {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, event: ValidationEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ExecutionMetrics {
    pub trace_events: u64,
    pub trace_bytes: u64,
    pub lookup_duration_ms: u64,
    pub stored_bytes: u64,
    pub context_bytes_avoided: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaintLabel {
    Public,
    UserData,
    Pii,
    Secret,
    Credential,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PrivacyTaint {
    #[serde(default)]
    pub labels: Vec<TaintLabel>,
    pub redacted: bool,
    #[serde(default)]
    pub sources: Vec<String>,
}

impl Default for PrivacyTaint {
    fn default() -> Self {
        Self {
            labels: vec![TaintLabel::Public],
            redacted: false,
            sources: Vec::new(),
        }
    }
}

/// Complete, versioned EffectIR record for one invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExecutionRecord {
    pub schema_version: u32,
    pub record_id: Uuid,
    pub invocation: Invocation,
    pub platform: PlatformProfileIdentity,
    pub policy: PolicyEvaluation,
    #[serde(default)]
    pub observations: Vec<ResourceObservation>,
    #[serde(default)]
    pub effects: Vec<Effect>,
    pub result: ExecutionResult,
    pub cache: CacheDisposition,
    pub validation: ValidationHistory,
    pub metrics: ExecutionMetrics,
    pub privacy: PrivacyTaint,
    pub trace_complete: bool,
}

impl ExecutionRecord {
    pub fn new(
        invocation: Invocation,
        platform: PlatformProfileIdentity,
        result: ExecutionResult,
    ) -> Self {
        Self {
            schema_version: EFFECT_IR_V1_SCHEMA_VERSION,
            record_id: Uuid::new_v4(),
            invocation,
            platform,
            policy: PolicyEvaluation {
                decision: PolicyDecision::RecordOnly,
                reason: PolicyReason::SafeReplayableEffects,
                notes: Vec::new(),
            },
            observations: Vec::new(),
            effects: Vec::new(),
            result,
            cache: CacheDisposition::Recorded,
            validation: ValidationHistory::new(),
            metrics: ExecutionMetrics::default(),
            privacy: PrivacyTaint::default(),
            trace_complete: false,
        }
    }

    pub fn validate(&self) -> Result<(), EffectIrError> {
        if self.schema_version != EFFECT_IR_V1_SCHEMA_VERSION {
            return Err(EffectIrError::UnsupportedSchemaVersion(self.schema_version));
        }
        self.invocation.validate()?;
        for observation in &self.observations {
            observation.validate()?;
        }
        self.result.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: &str) -> Digest {
        Digest::new("blake3", value)
    }

    #[test]
    fn record_round_trips_as_stable_snake_case_json() {
        let mut invocation =
            Invocation::new("rg", vec!["rg".into(), "needle".into()], "/workspace");
        invocation.add_environment_digest("PATH", digest("path-digest"));
        let mut result = ExecutionResult::new(ExitStatus::Exited { code: 0 }, 12);
        result.stdout = Some(BlobRef::new(digest("stdout"), 3));
        result.stdout_bytes = 3;
        let mut record = ExecutionRecord::new(
            invocation,
            PlatformProfileIdentity::new(PlatformIdentity::new("linux", "x86_64"), "default"),
            result,
        );
        record.trace_complete = true;
        record.observations.push(ResourceObservation::AbsentPath {
            path: "/workspace/missing".into(),
        });
        record
            .observations
            .push(ResourceObservation::EnvironmentValueDigest {
                name: "PATH".into(),
                digest: digest("path-digest"),
            });
        record.validate().unwrap();
        let json = serde_json::to_string_pretty(&record).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("environment_value_digest"));
        assert!(json.contains("\"stdout_bytes\""));
        assert!(!json.contains("stdoutBytes")); // serialization is stable snake_case
        let decoded: ExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.schema_version, EFFECT_IR_V1_SCHEMA_VERSION);
        assert_eq!(decoded.invocation.environment[0].name, "PATH");
        assert_eq!(decoded.result.stdout_bytes, 3);
    }

    #[test]
    fn environment_values_cannot_leak_into_serialized_record() {
        let secret = "SUPER_SECRET_TOKEN_123";
        let mut invocation = Invocation::new("echo", vec!["echo".into()], "/tmp");
        invocation.add_environment_digest("TOKEN", digest("digest-only"));
        let record = ExecutionRecord::new(
            invocation,
            PlatformProfileIdentity::new(PlatformIdentity::new("linux", "x86_64"), "test"),
            ExecutionResult::new(ExitStatus::Exited { code: 0 }, 1),
        );
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains(secret));
        assert!(!json.contains("\"value\":\"SUPER_SECRET_TOKEN_123\""));
        assert!(json.contains("digest-only"));
    }

    #[test]
    fn validation_rejects_inconsistent_stream_counts_and_duplicate_environment_names() {
        let mut invocation = Invocation::new("cat", vec![], "/tmp");
        invocation.add_environment_digest("A", digest("one"));
        invocation.add_environment_digest("A", digest("two"));
        let mut result = ExecutionResult::new(ExitStatus::Exited { code: 0 }, 0);
        result.stdout = Some(BlobRef::new(digest("out"), 2));
        result.stdout_bytes = 1;
        let record = ExecutionRecord::new(
            invocation,
            PlatformProfileIdentity::new(PlatformIdentity::new("linux", "x86_64"), "test"),
            result.clone(),
        );
        assert!(matches!(
            record.validate(),
            Err(EffectIrError::DuplicateEnvironmentVariable(_))
        ));
        let mut invocation = Invocation::new("cat", vec![], "/tmp");
        invocation.add_environment_digest("A", digest("one"));
        let record = ExecutionRecord::new(
            invocation,
            PlatformProfileIdentity::new(PlatformIdentity::new("linux", "x86_64"), "test"),
            result,
        );
        assert_eq!(
            record.validate(),
            Err(EffectIrError::ByteCountMismatch { stream: "stdout" })
        );
    }
}
