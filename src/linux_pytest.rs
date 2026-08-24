//! Frozen shared contract for the future `linux-pytest-v1` execution profile.
//!
//! This module is intentionally unreachable from the public CLI.  It defines
//! the privacy, completeness, snapshot-capability, trace-record, and promotion
//! boundaries that the isolated Linux implementations build against.  The
//! contract-only implementations fail closed and never execute Python.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub const LINUX_PYTEST_PROFILE_ID: &str = "linux-pytest-v1";
pub const EFFECT_IR_V2_SCHEMA: &str = "again.effect_ir.v2";
pub const EFFECT_IR_V2_REQUIRED_MASK: u64 = 0x0000_0000_ffff_ffff;
pub const EFFECT_IR_V2_COMPARISON_DOMAIN: &str = "again linux pytest effect comparison v1";
pub const EFFECT_IR_V2_COMPARISON_VIEW_DOMAIN: &str =
    "again linux pytest effect comparison view v1";
pub const EFFECT_IR_V2_COMPARISON_RULES_DOMAIN: &str =
    "again linux pytest effect comparison rules v1";
pub const EFFECT_IR_V2_WIRE_MAGIC: &[u8; 8] = b"AGNCAN01";
pub const EFFECT_IR_V2_WIRE_VERSION: u16 = 1;
pub const EFFECT_IR_V2_MAX_CANONICAL_BYTES: u64 = 512 * 1024 * 1024;
pub const EFFECT_IR_V2_MAX_COLLECTION_ITEMS: u64 = 10_000_000;
pub const LINUX_PYTEST_V1_MAX_TRACE_EVENTS: u64 = 10_000_000;
pub const LINUX_PYTEST_V1_MAX_TRACE_BYTES: u64 = 512 * 1024 * 1024;
pub const LINUX_PYTEST_V1_MAX_DESCENDANT_TASKS: u64 = 256;
pub const LINUX_PYTEST_V1_MAX_STREAM_BYTES: u64 = 16 * 1024 * 1024;
pub const LINUX_PYTEST_V1_MAX_SELECTORS: usize = 4_096;
pub const LINUX_PYTEST_SHAPE_V1_SCHEMA: &str = "again.linux-pytest.shape.v1";
pub const LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES: u16 = 64;
pub const HASH_FRAME_MAGIC: &[u8; 8] = b"AGNHSH01";
pub const LEXICAL_SHAPE_DOMAIN: &str = "again linux pytest lexical shape v1";
pub const SHAPE_DOMAIN: &str = "again linux pytest shape v1";
pub const OBSERVATION_CLOSURE_DOMAIN: &str = "again linux pytest observation closure v1";
pub const REQUEST_DOMAIN: &str = "again linux pytest request v1";
pub const EXECUTABLE_CHAIN_DOMAIN: &str = "again linux pytest executable chain v1";
pub const PROFILE_DOMAIN: &str = "again linux pytest profile v1";
pub const WORKSPACE_IDENTITY_DOMAIN: &str = "again linux pytest workspace identity v1";
pub const CAS_OBJECT_DOMAIN: &str = "again linux pytest cas object v1";
pub const FILE_CONTENT_DOMAIN: &str = "again linux pytest file content v1";
pub const EFFECT_SHAPE_DOMAIN: &str = "again linux pytest effect shape v1";
pub const QUARANTINE_CLASS_DOMAIN: &str = "again linux pytest quarantine class v1";
pub const ENVIRONMENT_KEY_RELATIVE_PATH: &str = "keys/linux-pytest-environment-v1";
pub const ENVIRONMENT_DIGEST_DOMAIN: &str = "again linux pytest environment v1";
pub const ENVIRONMENT_NAMES_DIGEST_DOMAIN: &str = "again linux pytest environment names v1";
pub const ENVIRONMENT_KEY_ID_DOMAIN: &str = "again linux pytest environment key id v1";
pub const HARDLINK_GROUP_DOMAIN: &str = "again linux pytest hardlink group v1";
pub const REGULAR_NODE_DOMAIN: &str = "again linux pytest regular node v1";
pub const SYMLINK_NODE_DOMAIN: &str = "again linux pytest symlink node v1";
pub const DIRECTORY_NODE_DOMAIN: &str = "again linux pytest directory node v1";
pub const EXTERNAL_TREE_NODE_DOMAIN: &str = "again linux pytest external tree node v1";
pub const WORKSPACE_MERKLE_DOMAIN: &str = "again linux pytest workspace merkle v1";
pub const RUNTIME_MERKLE_DOMAIN: &str = "again linux pytest runtime merkle v1";

mod canonical;
mod identity;
mod snapshot_connector;
mod snapshot_materialize;
mod snapshot_policy;
mod snapshot_publish;
mod snapshot_regular;
mod snapshot_tree;
mod snapshot_verify;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake3Digest([u8; 32]);

impl Blake3Digest {
    pub fn derive(domain: &'static str, fields: &[&[u8]]) -> Self {
        let tagged = fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let tag = u16::try_from(index + 1).expect("digest field count fits u16");
                (tag, *field)
            })
            .collect::<Vec<_>>();
        Self::derive_tagged(domain, &tagged)
    }

    pub fn derive_tagged(domain: &'static str, fields: &[(u16, &[u8])]) -> Self {
        assert!(
            fields.windows(2).all(|window| window[0].0 < window[1].0),
            "digest field tags must be unique and strictly increasing"
        );
        let mut hasher = Hasher::new_derive_key(domain);
        hasher.update(HASH_FRAME_MAGIC);
        hasher.update(
            &u32::try_from(fields.len())
                .expect("digest field count fits u32")
                .to_be_bytes(),
        );
        for (tag, field) in fields {
            hasher.update(&tag.to_be_bytes());
            hasher.update(
                &u64::try_from(field.len())
                    .expect("digest field length fits u64")
                    .to_be_bytes(),
            );
            hasher.update(field);
        }
        Self(*hasher.finalize().as_bytes())
    }

    pub fn parse(value: &str) -> Result<Self, LinuxPytestContractError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(LinuxPytestContractError::InvalidDigest);
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(LinuxPytestContractError::InvalidDigest);
        }
        let mut bytes = [0u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
    }
}

fn hex_nibble(byte: u8) -> Result<u8, LinuxPytestContractError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(LinuxPytestContractError::InvalidDigest),
    }
}

impl fmt::Debug for Blake3Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Blake3Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Blake3Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for Blake3Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Blake3Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

fn keyed_hash_v1(domain: &'static str, master_key: &[u8; 32], fields: &[(u16, &[u8])]) -> [u8; 32] {
    assert!(
        fields.windows(2).all(|window| window[0].0 < window[1].0),
        "keyed digest field tags must be unique and strictly increasing"
    );
    let mut subkey = blake3::derive_key(domain, master_key);
    let mut hasher = Hasher::new_keyed(&subkey);
    hasher.update(HASH_FRAME_MAGIC);
    hasher.update(
        &u32::try_from(fields.len())
            .expect("digest field count fits u32")
            .to_be_bytes(),
    );
    for (tag, field) in fields {
        hasher.update(&tag.to_be_bytes());
        hasher.update(
            &u64::try_from(field.len())
                .expect("digest field length fits u64")
                .to_be_bytes(),
        );
        hasher.update(field);
    }
    let digest = *hasher.finalize().as_bytes();
    hasher.zeroize();
    subkey.zeroize();
    digest
}

macro_rules! typed_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) fn derive(domain: &'static str, fields: &[&[u8]]) -> Self {
                Self(Blake3Digest::derive(domain, fields).0)
            }

            pub(crate) fn derive_tagged(domain: &'static str, fields: &[(u16, &[u8])]) -> Self {
                Self(Blake3Digest::derive_tagged(domain, fields).0)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn is_zero(self) -> bool {
                self.0 == [0; 32]
            }

            pub fn to_hex(self) -> String {
                Blake3Digest(self.0).to_hex()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.to_hex())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let raw = Blake3Digest::deserialize(deserializer)?;
                Ok(Self(raw.0))
            }
        }
    };
}

typed_digest!(BlobDigest);
typed_digest!(ProfileDigest);
typed_digest!(WorkspaceIdentity);
typed_digest!(MerkleRoot);
typed_digest!(LexicalShapeKey);
typed_digest!(ShapeKey);
typed_digest!(RequestKey);
typed_digest!(ClassKey);
typed_digest!(ComparisonViewDigest);
typed_digest!(PairComparisonDigest);
typed_digest!(EffectShapeDigest);
typed_digest!(EnvironmentDigest);
typed_digest!(EnvironmentNamesDigest);
typed_digest!(EnvironmentKeyId);
typed_digest!(CapabilityDigest);
typed_digest!(PolicyDigest);
typed_digest!(NodeDigest);
typed_digest!(HardlinkGroupDigest);
typed_digest!(ObservationClosureDigest);
typed_digest!(FileContentDigest);
typed_digest!(ExecutableChainDigest);

/// Domain-fixed streaming form of `FileContentDigest::derive(..., &[bytes])`.
///
/// The declared logical length is framed before any bytes are accepted.  A
/// caller cannot finalize a prefix or append beyond that commitment.
pub(super) struct FileContentHasherV1 {
    hasher: Hasher,
    remaining: Option<u64>,
}

impl FileContentHasherV1 {
    pub(super) fn new(logical_size: u64) -> Self {
        let mut hasher = Hasher::new_derive_key(FILE_CONTENT_DOMAIN);
        hasher.update(HASH_FRAME_MAGIC);
        hasher.update(&1u32.to_be_bytes());
        hasher.update(&1u16.to_be_bytes());
        hasher.update(&logical_size.to_be_bytes());
        Self {
            hasher,
            remaining: Some(logical_size),
        }
    }

    #[must_use = "a rejected update permanently poisons the digest"]
    pub(super) fn update(&mut self, bytes: &[u8]) -> bool {
        let Ok(length) = u64::try_from(bytes.len()) else {
            self.remaining = None;
            return false;
        };
        let Some(remaining) = self.remaining else {
            return false;
        };
        if length > remaining {
            self.remaining = None;
            return false;
        }
        self.hasher.update(bytes);
        self.remaining = Some(remaining - length);
        true
    }

    pub(super) fn finish(self) -> Option<FileContentDigest> {
        (self.remaining == Some(0)).then(|| FileContentDigest(*self.hasher.finalize().as_bytes()))
    }
}

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            pub fn is_nil(self) -> bool {
                self.0 == [0; 16]
            }

            #[cfg(test)]
            fn new_test() -> Self {
                Self(*Uuid::new_v4().as_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&Uuid::from_bytes(self.0).to_string())
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&Uuid::from_bytes(self.0).to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Uuid::parse_str(&value)
                    .map(|uuid| Self(*uuid.as_bytes()))
                    .map_err(de::Error::custom)
            }
        }
    };
}

typed_id!(RecordId);
typed_id!(SnapshotId);
typed_id!(ShadowJobId);
typed_id!(WorkerId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LogicalTaskId(pub u32);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MonotonicNs(pub u64);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EpochNs(pub u64);

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EffectBitmap(u64);

impl EffectBitmap {
    pub const EMPTY: Self = Self(0);
    pub const REQUIRED_V2: Self = Self(EFFECT_IR_V2_REQUIRED_MASK);

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, dimension: CompletenessDimensionV2) -> bool {
        self.0 & dimension.bit() != 0
    }

    pub fn insert(&mut self, dimension: CompletenessDimensionV2) {
        self.0 |= dimension.bit();
    }

    pub const fn has_unknown_bits(self) -> bool {
        self.0 & !EFFECT_IR_V2_REQUIRED_MASK != 0
    }

    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

impl fmt::Debug for EffectBitmap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EffectBitmap")
            .field(&self.to_hex())
            .finish()
    }
}

impl Serialize for EffectBitmap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

struct EffectBitmapVisitor;

impl Visitor<'_> for EffectBitmapVisitor {
    type Value = EffectBitmap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 16 lower-case hexadecimal digits")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() != 16
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(E::custom("bitmap must be 16 lower-case hexadecimal digits"));
        }
        u64::from_str_radix(value, 16)
            .map(EffectBitmap)
            .map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for EffectBitmap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(EffectBitmapVisitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessDimensionV2 {
    SealedSnapshot = 0,
    RuntimeClosure = 1,
    TmpfsMountRoot = 2,
    NamespaceSet = 3,
    FdHygiene = 4,
    DescendantLifecycle = 5,
    SeccompStream = 6,
    PathResolution = 7,
    FileContent = 8,
    FileMapping = 9,
    FileMetadata = 10,
    DirectoryMembership = 11,
    NegativeLookup = 12,
    SymlinkMagiclink = 13,
    ExecLibraryIdentity = 14,
    Environment = 15,
    Stdin = 16,
    Stdout = 17,
    Stderr = 18,
    FilesystemEffects = 19,
    FinalWorkspaceRoot = 20,
    NetworkIsolation = 21,
    IpcIsolation = 22,
    SignalsExitStatus = 23,
    LogicalTime = 24,
    LogicalRandom = 25,
    LogicalPidIdentity = 26,
    SingleRunnableSchedule = 27,
    LimitsCpuIdentity = 28,
    Landlock = 29,
    Cleanup = 30,
    TraceIntegrity = 31,
}

impl CompletenessDimensionV2 {
    pub const ALL: [Self; 32] = [
        Self::SealedSnapshot,
        Self::RuntimeClosure,
        Self::TmpfsMountRoot,
        Self::NamespaceSet,
        Self::FdHygiene,
        Self::DescendantLifecycle,
        Self::SeccompStream,
        Self::PathResolution,
        Self::FileContent,
        Self::FileMapping,
        Self::FileMetadata,
        Self::DirectoryMembership,
        Self::NegativeLookup,
        Self::SymlinkMagiclink,
        Self::ExecLibraryIdentity,
        Self::Environment,
        Self::Stdin,
        Self::Stdout,
        Self::Stderr,
        Self::FilesystemEffects,
        Self::FinalWorkspaceRoot,
        Self::NetworkIsolation,
        Self::IpcIsolation,
        Self::SignalsExitStatus,
        Self::LogicalTime,
        Self::LogicalRandom,
        Self::LogicalPidIdentity,
        Self::SingleRunnableSchedule,
        Self::LimitsCpuIdentity,
        Self::Landlock,
        Self::Cleanup,
        Self::TraceIntegrity,
    ];

    pub const fn bit(self) -> u64 {
        1u64 << self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        if value < Self::ALL.len() as u8 {
            Some(Self::ALL[value as usize])
        } else {
            None
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SealedSnapshot => "sealed_snapshot",
            Self::RuntimeClosure => "runtime_closure",
            Self::TmpfsMountRoot => "tmpfs_mount_root",
            Self::NamespaceSet => "namespace_set",
            Self::FdHygiene => "fd_hygiene",
            Self::DescendantLifecycle => "descendant_lifecycle",
            Self::SeccompStream => "seccomp_stream",
            Self::PathResolution => "path_resolution",
            Self::FileContent => "file_content",
            Self::FileMapping => "file_mapping",
            Self::FileMetadata => "file_metadata",
            Self::DirectoryMembership => "directory_membership",
            Self::NegativeLookup => "negative_lookup",
            Self::SymlinkMagiclink => "symlink_magiclink",
            Self::ExecLibraryIdentity => "exec_library_identity",
            Self::Environment => "environment",
            Self::Stdin => "stdin",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::FilesystemEffects => "filesystem_effects",
            Self::FinalWorkspaceRoot => "final_workspace_root",
            Self::NetworkIsolation => "network_isolation",
            Self::IpcIsolation => "ipc_isolation",
            Self::SignalsExitStatus => "signals_exit_status",
            Self::LogicalTime => "logical_time",
            Self::LogicalRandom => "logical_random",
            Self::LogicalPidIdentity => "logical_pid_identity",
            Self::SingleRunnableSchedule => "single_runnable_schedule",
            Self::LimitsCpuIdentity => "limits_cpu_identity",
            Self::Landlock => "landlock",
            Self::Cleanup => "cleanup",
            Self::TraceIntegrity => "trace_integrity",
        }
    }
}

macro_rules! closed_reason_code {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident = $value:literal => $text:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[repr(u16)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant = $value),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            pub const fn from_u16(value: u16) -> Option<Self> {
                match value {
                    $($value => Some(Self::$variant)),+,
                    _ => None,
                }
            }
        }
    };
}

closed_reason_code! {
    /// A pre-exec refusal. Every variant guarantees that Python did not start.
    pub enum RefusalCode {
        ProfileDisabled = 1 => "profile_disabled",
        UnsupportedOs = 2 => "unsupported_os",
        UnsupportedArchitecture = 3 => "unsupported_architecture",
        KernelTupleNotEnabled = 4 => "kernel_tuple_not_enabled",
        RequiredKernelCapabilityMissing = 5 => "required_kernel_capability_missing",
        CwdNotWorkspaceRoot = 0x0010 => "cwd_not_workspace_root",
        Argv0NotExact = 0x0011 => "argv0_not_exact",
        PytestPrefixNotExact = 0x0012 => "pytest_prefix_not_exact",
        SelectorMissing = 0x0013 => "selector_missing",
        SelectorNonUtf8 = 0x0014 => "selector_non_utf8",
        SelectorOptionLike = 0x0015 => "selector_option_like",
        SelectorMalformed = 0x0016 => "selector_malformed",
        SelectorPathEscape = 0x0017 => "selector_path_escape",
        SelectorTargetMissing = 0x0018 => "selector_target_missing",
        SelectorTargetType = 0x0019 => "selector_target_type",
        ForbiddenArgument = 0x001a => "forbidden_argument",
        ExecutableSymlinkEscape = 0x001b => "executable_symlink_escape",
        ExecutableRuntimeMismatch = 0x001c => "executable_runtime_mismatch",
        StdinTty = 0x0020 => "stdin_tty",
        StdinNonempty = 0x0021 => "stdin_nonempty",
        StdoutTty = 0x0022 => "stdout_tty",
        StderrTty = 0x0023 => "stderr_tty",
        EnvironmentMalformed = 0x0030 => "environment_malformed",
        LoaderInjectionEnvironment = 0x0031 => "loader_injection_environment",
        SnapshotRequiredObjectUnsupported = 0x0040 => "snapshot_required_object_unsupported",
        SnapshotConstructionFailed = 0x0041 => "snapshot_construction_failed",
        UserNamespaceUnavailable = 0x0050 => "user_namespace_unavailable",
        RequiredNamespaceFailed = 0x0051 => "required_namespace_failed",
        MountRootFailed = 0x0052 => "mount_root_failed",
        CloseRangeUnavailable = 0x0053 => "close_range_unavailable",
        SeccompUnavailable = 0x0054 => "seccomp_unavailable",
        PtraceUnavailable = 0x0055 => "ptrace_unavailable",
        LandlockUnavailable = 0x0056 => "landlock_unavailable",
        IsolationPreflightFailed = 0x0057 => "isolation_preflight_failed"
    }
}

closed_reason_code! {
    /// A safely sandboxed foreground result that cannot enter promotion.
    pub enum ExecuteOnlyCode {
        SourceMutatedDuringSnapshot = 0x1001 => "source_mutated_during_snapshot",
        SnapshotManifestUnstable = 0x1002 => "snapshot_manifest_unstable",
        UnsupportedSnapshotObject = 0x1003 => "unsupported_snapshot_object",
        SparseLayoutLoss = 0x1004 => "sparse_layout_loss",
        XattrLoss = 0x1005 => "xattr_loss",
        RuntimeClosureIncomplete = 0x1010 => "runtime_closure_incomplete",
        DescendantExecUnsealed = 0x1011 => "descendant_exec_unsealed",
        ExecutableMappingUnsupported = 0x1012 => "executable_mapping_unsupported",
        SyscallUnknown = 0x1020 => "syscall_unknown",
        TraceOperationUnsupported = 0x1021 => "trace_operation_unsupported",
        PathResolutionUnsupported = 0x1022 => "path_resolution_unsupported",
        MetadataSurfaceUnsupported = 0x1023 => "metadata_surface_unsupported",
        SharedWritableMapping = 0x1024 => "shared_writable_mapping",
        SplicePathUnsupported = 0x1025 => "splice_path_unsupported",
        TimeSurfaceUnsupported = 0x1030 => "time_surface_unsupported",
        EntropySurfaceUnsupported = 0x1031 => "entropy_surface_unsupported",
        PidIdentitySurfaceUnsupported = 0x1032 => "pid_identity_surface_unsupported",
        ConcurrentRunnableWorkload = 0x1033 => "concurrent_runnable_workload",
        SchedulingSurfaceUnsupported = 0x1034 => "scheduling_surface_unsupported",
        AsynchronousSignal = 0x1035 => "asynchronous_signal",
        NetworkAttempt = 0x2001 => "network_attempt",
        ExternalUnixSocketAttempt = 0x2002 => "external_unix_socket_attempt",
        ExternalFdAcquired = 0x2003 => "external_fd_acquired",
        ForbiddenSyscallAttempt = 0x2004 => "forbidden_syscall_attempt",
        NamespaceEscapeAttempt = 0x2005 => "namespace_escape_attempt",
        MountEscapeAttempt = 0x2006 => "mount_escape_attempt",
        ProcessIntrospectionAttempt = 0x2007 => "process_introspection_attempt",
        RuntimeClosureViolation = 0x2008 => "runtime_closure_violation",
        LandlockPolicyViolation = 0x2009 => "landlock_policy_violation",
        FdHygieneViolation = 0x200a => "fd_hygiene_violation",
        StdoutLimit = 0x3001 => "stdout_limit",
        StderrLimit = 0x3002 => "stderr_limit",
        DescendantTaskLimit = 0x3003 => "descendant_task_limit",
        TraceEventLimit = 0x3004 => "trace_event_limit",
        TraceEncodingLimit = 0x3005 => "trace_encoding_limit",
        WallTimeLimit = 0x3006 => "wall_time_limit",
        SnapshotLimit = 0x3007 => "snapshot_limit",
        BranchLimit = 0x3008 => "branch_limit",
        ScratchLimit = 0x3009 => "scratch_limit",
        MemoryLimit = 0x300a => "memory_limit",
        OpenFileLimit = 0x300b => "open_file_limit",
        PerFileLimit = 0x300c => "per_file_limit",
        ForegroundNonzeroExit = 0x3010 => "foreground_nonzero_exit",
        ForegroundSignaled = 0x3011 => "foreground_signaled",
        TraceEventLost = 0x4001 => "trace_event_lost",
        TraceEventMalformed = 0x4002 => "trace_event_malformed",
        TraceEventOutOfOrder = 0x4003 => "trace_event_out_of_order",
        TraceEventUnknown = 0x4004 => "trace_event_unknown",
        CounterOverflow = 0x4005 => "counter_overflow",
        DecoderDisagreement = 0x4006 => "decoder_disagreement",
        TracerRestart = 0x4007 => "tracer_restart",
        MissingFinalAck = 0x4008 => "missing_final_ack",
        DescendantUnreaped = 0x4009 => "descendant_unreaped",
        EffectDiffMismatch = 0x400a => "effect_diff_mismatch",
        FinalRootUnstable = 0x400b => "final_root_unstable",
        RecordEncodingFailure = 0x400c => "record_encoding_failure",
        CaptureFailure = 0x400d => "capture_failure",
        CleanupIncomplete = 0x400e => "cleanup_incomplete",
        CasCorruption = 0x400f => "cas_corruption"
    }
}

closed_reason_code! {
    /// Terminal state of an asynchronous shadow job. It never changes A's result.
    pub enum ShadowTerminalCode {
        HandoffFailed = 1 => "handoff_failed",
        PrimaryIneligible = 2 => "primary_ineligible",
        LeaseExpired = 3 => "lease_expired",
        WorkerCrashed = 4 => "worker_crashed",
        ShadowLaunchFailed = 5 => "shadow_launch_failed",
        ShadowNonzeroExit = 6 => "shadow_nonzero_exit",
        ShadowSignaled = 7 => "shadow_signaled",
        ShadowIncomplete = 8 => "shadow_incomplete",
        SemanticMismatch = 9 => "semantic_mismatch",
        DurableRecordFailed = 0x000a => "durable_record_failed",
        PromotionCompareAndSwapLost = 0x000b => "promotion_compare_and_swap_lost",
        ClassAlreadyQuarantined = 0x000c => "class_already_quarantined",
        SupersededByPromotedPair = 0x000d => "superseded_by_promoted_pair"
    }
}

closed_reason_code! {
    /// Monotonic quarantine reason for a corrupt or divergent reuse class.
    pub enum QuarantineCode {
        ComparisonViewMismatch = 1 => "comparison_view_mismatch",
        ProfileMismatch = 2 => "profile_mismatch",
        InvocationMismatch = 3 => "invocation_mismatch",
        EnvironmentMismatch = 4 => "environment_mismatch",
        SnapshotRootMismatch = 5 => "snapshot_root_mismatch",
        PlatformPolicyMismatch = 6 => "platform_policy_mismatch",
        TraceMaskMismatch = 7 => "trace_mask_mismatch",
        TraceCounterMismatch = 8 => "trace_counter_mismatch",
        ObservationMismatch = 9 => "observation_mismatch",
        AmbientMismatch = 0x000a => "ambient_mismatch",
        OrderedEffectMismatch = 0x000b => "ordered_effect_mismatch",
        FinalWorkspaceRootMismatch = 0x000c => "final_workspace_root_mismatch",
        StdoutMismatch = 0x000d => "stdout_mismatch",
        StderrMismatch = 0x000e => "stderr_mismatch",
        WaitStatusMismatch = 0x000f => "wait_status_mismatch",
        NoncanonicalRecord = 0x0010 => "noncanonical_record",
        UnknownSchema = 0x0011 => "unknown_schema",
        UnknownBitmapBit = 0x0012 => "unknown_bitmap_bit",
        ForgedCompleteMask = 0x0013 => "forged_complete_mask",
        RecordCasCorruption = 0x0014 => "record_cas_corruption",
        StreamCasCorruption = 0x0015 => "stream_cas_corruption",
        SameRequestDifferentPair = 0x0016 => "same_request_different_pair"
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LinuxPytestContractError {
    #[error("invalid lower-case BLAKE3 digest")]
    InvalidDigest,
    #[error("unknown or inconsistent EffectIR v2 completeness masks")]
    InvalidCompletenessMasks,
    #[error("EffectIR v2 schema/profile mismatch")]
    SchemaProfileMismatch,
    #[error("EffectIR v2 record has an empty or malformed field")]
    MalformedRecord,
    #[error("Linux pytest lookup identity is malformed or internally inconsistent")]
    MalformedLookupIdentity,
    #[error("Linux pytest snapshot manifest is malformed or internally inconsistent")]
    MalformedManifest,
    #[error("EffectIR v2 canonical encoding failed")]
    CanonicalEncoding,
    #[error("EffectIR v2 canonical decoding failed")]
    CanonicalDecoding,
    #[error("EffectIR v2 primary and shadow comparison views differ")]
    ComparisonMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceCountersV1 {
    pub final_sequence: u64,
    pub event_count: u64,
    pub syscall_event_count: u64,
    pub seccomp_trace_count: u64,
    pub ptrace_event_count: u64,
    pub trace_encoded_bytes: u64,
    pub task_birth_count: u64,
    pub task_exec_count: u64,
    pub task_exit_count: u64,
    pub task_reap_count: u64,
    pub observation_count: u64,
    pub ambient_event_count: u64,
    pub ordered_effect_count: u64,
    pub denied_operation_count: u64,
    pub unsupported_operation_count: u64,
    pub decoder_error_count: u64,
    pub lost_event_count: u64,
    pub final_ack_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum TracePhaseV1 {
    Snapshot = 1,
    Isolation = 2,
    Trace = 3,
    Finalize = 4,
    Capture = 5,
    Cleanup = 6,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirstFailureV1 {
    pub dimension: CompletenessDimensionV2,
    pub reason: ExecuteOnlyCode,
    pub phase: TracePhaseV1,
    pub event_sequence: Option<u64>,
    pub logical_task_id: Option<LogicalTaskId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceCompletenessV2 {
    required: EffectBitmap,
    complete: EffectBitmap,
    unsupported: EffectBitmap,
    violation: EffectBitmap,
    counters: TraceCountersV1,
    first_failure: Option<FirstFailureV1>,
}

impl TraceCompletenessV2 {
    pub fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if self.required != EffectBitmap::REQUIRED_V2
            || self.required.has_unknown_bits()
            || self.complete.has_unknown_bits()
            || self.unsupported.has_unknown_bits()
            || self.violation.has_unknown_bits()
            || self.complete.bits() & !self.required.bits() != 0
            || self.unsupported.bits() & !self.required.bits() != 0
            || self.violation.bits() & !self.required.bits() != 0
            || self.complete.bits() & self.unsupported.bits() != 0
            || self.complete.bits() & self.violation.bits() != 0
            || self.first_failure.as_ref().is_some_and(|failure| {
                !self.required.contains(failure.dimension)
                    || self.complete.contains(failure.dimension)
                    || failure.event_sequence.is_some_and(|sequence| {
                        sequence == 0 || sequence > self.counters.final_sequence
                    })
                    || failure.logical_task_id.is_some_and(|task| {
                        task.0 == 0 || u64::from(task.0) > self.counters.task_birth_count
                    })
            })
            || ((self.complete != self.required
                || self.unsupported != EffectBitmap::EMPTY
                || self.violation != EffectBitmap::EMPTY)
                && self.first_failure.is_none())
            || self.counters.final_sequence > LINUX_PYTEST_V1_MAX_TRACE_EVENTS
            || self.counters.event_count > LINUX_PYTEST_V1_MAX_TRACE_EVENTS
            || self.counters.syscall_event_count > LINUX_PYTEST_V1_MAX_TRACE_EVENTS
            || self.counters.seccomp_trace_count > self.counters.syscall_event_count
            || self.counters.ptrace_event_count > LINUX_PYTEST_V1_MAX_TRACE_EVENTS
            || self.counters.trace_encoded_bytes > LINUX_PYTEST_V1_MAX_TRACE_BYTES
            || self.counters.task_birth_count > LINUX_PYTEST_V1_MAX_DESCENDANT_TASKS
            || self.counters.task_exec_count > self.counters.task_birth_count
            || self.counters.task_exit_count > self.counters.task_birth_count
            || self.counters.task_reap_count > self.counters.task_exit_count
            || self.counters.final_ack_count > 1
        {
            return Err(LinuxPytestContractError::InvalidCompletenessMasks);
        }
        Ok(())
    }

    pub fn candidate_complete(&self) -> bool {
        self.required == EffectBitmap::REQUIRED_V2
            && self.complete == self.required
            && self.unsupported == EffectBitmap::EMPTY
            && self.violation == EffectBitmap::EMPTY
            && self.counters.final_sequence == self.counters.event_count
            && self.counters.event_count != 0
            && self.counters.syscall_event_count == self.counters.event_count
            && self.counters.seccomp_trace_count == self.counters.syscall_event_count
            && self.counters.ptrace_event_count
                == self.counters.task_birth_count
                    + self.counters.task_exec_count
                    + self.counters.task_exit_count
            && self.counters.trace_encoded_bytes >= self.counters.event_count
            && self.counters.task_birth_count != 0
            && self.counters.task_exec_count != 0
            && self.counters.task_birth_count == self.counters.task_exit_count
            && self.counters.task_exit_count == self.counters.task_reap_count
            && self.counters.denied_operation_count == 0
            && self.counters.unsupported_operation_count == 0
            && self.counters.decoder_error_count == 0
            && self.counters.lost_event_count == 0
            && self.counters.final_ack_count == 1
            && self.first_failure.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRefV2 {
    pub digest: BlobDigest,
    pub byte_count: u64,
}

pub const SNAPSHOT_MANIFEST_V1_SCHEMA: &str = "again.linux-pytest.snapshot-manifest.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum TreeRoleV1 {
    Workspace = 1,
    Runtime = 2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum ManifestEntryKindV1 {
    Directory = 1,
    Regular = 2,
    Symlink = 3,
    ExternalTree = 4,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimespecV1 {
    pub seconds: i64,
    pub nanoseconds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XattrV1 {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataV1 {
    pub mode: u32,
    pub logical_uid: u32,
    pub logical_gid: u32,
    pub size: u64,
    pub nlink: u64,
    pub atime: TimespecV1,
    pub mtime: TimespecV1,
    pub ctime: TimespecV1,
    pub btime: Option<TimespecV1>,
    pub xattrs: Vec<XattrV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtentV1 {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChildCommitmentV1 {
    pub name: Vec<u8>,
    pub kind: ManifestEntryKindV1,
    pub node_digest: NodeDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManifestPayloadV1 {
    Directory {
        children: Vec<ChildCommitmentV1>,
    },
    Regular {
        content_digest: FileContentDigest,
        data_extents: Vec<ExtentV1>,
    },
    Symlink {
        target: Vec<u8>,
    },
    ExternalTree {
        tree_role: TreeRoleV1,
        target_root: NodeDigest,
        readonly: bool,
    },
}

impl ManifestPayloadV1 {
    pub const fn kind(&self) -> ManifestEntryKindV1 {
        match self {
            Self::Directory { .. } => ManifestEntryKindV1::Directory,
            Self::Regular { .. } => ManifestEntryKindV1::Regular,
            Self::Symlink { .. } => ManifestEntryKindV1::Symlink,
            Self::ExternalTree { .. } => ManifestEntryKindV1::ExternalTree,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntryV1 {
    /// Raw relative Linux path. The root entry is the sole empty path.
    pub relative_path: Vec<u8>,
    pub metadata: MetadataV1,
    pub payload: ManifestPayloadV1,
    pub hardlink_group: Option<HardlinkGroupDigest>,
    pub node_digest: NodeDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TreeManifestV1 {
    pub mount_path: SandboxPath,
    pub tree_role: TreeRoleV1,
    pub entries: Vec<ManifestEntryV1>,
    pub root_digest: NodeDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifestV1 {
    pub schema: String,
    pub profile_digest: ProfileDigest,
    pub workspace_identity: WorkspaceIdentity,
    pub workspace_tree: TreeManifestV1,
    pub runtime_trees: Vec<TreeManifestV1>,
    pub workspace_root: MerkleRoot,
    pub runtime_root: MerkleRoot,
}

impl MetadataV1 {
    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        let times = [
            Some(&self.atime),
            Some(&self.mtime),
            Some(&self.ctime),
            self.btime.as_ref(),
        ];
        if self.nlink == 0
            || times
                .into_iter()
                .flatten()
                .any(|time| time.nanoseconds >= 1_000_000_000)
            || self
                .xattrs
                .windows(2)
                .any(|window| window[0].name >= window[1].name)
            || self
                .xattrs
                .iter()
                .any(|xattr| xattr.name.is_empty() || xattr.name.contains(&0))
        {
            return Err(LinuxPytestContractError::MalformedManifest);
        }
        Ok(())
    }
}

impl ManifestEntryV1 {
    fn computed_node_digest(&self) -> Result<NodeDigest, LinuxPytestContractError> {
        let metadata = canonical::encode_metadata_for_hash(&self.metadata)?;
        let hardlink = encode_optional_digest(
            self.hardlink_group
                .as_ref()
                .map(HardlinkGroupDigest::as_bytes),
        );
        match &self.payload {
            ManifestPayloadV1::Directory { children } => {
                if self.hardlink_group.is_some() {
                    return Err(LinuxPytestContractError::MalformedManifest);
                }
                let children = canonical::encode_children_for_hash(children)?;
                Ok(NodeDigest::derive_tagged(
                    DIRECTORY_NODE_DOMAIN,
                    &[(1, &metadata), (2, &children)],
                ))
            }
            ManifestPayloadV1::Regular {
                content_digest,
                data_extents,
            } => {
                let extents = canonical::encode_extents_for_hash(data_extents)?;
                Ok(NodeDigest::derive_tagged(
                    REGULAR_NODE_DOMAIN,
                    &[
                        (1, &metadata),
                        (2, content_digest.as_bytes()),
                        (3, &extents),
                        (4, &hardlink),
                    ],
                ))
            }
            ManifestPayloadV1::Symlink { target } => Ok(NodeDigest::derive_tagged(
                SYMLINK_NODE_DOMAIN,
                &[(1, &metadata), (2, target), (3, &hardlink)],
            )),
            ManifestPayloadV1::ExternalTree {
                tree_role,
                target_root,
                readonly,
            } => {
                if !readonly || *tree_role != TreeRoleV1::Runtime || self.hardlink_group.is_some() {
                    return Err(LinuxPytestContractError::MalformedManifest);
                }
                let role = (*tree_role as u16).to_be_bytes();
                Ok(NodeDigest::derive_tagged(
                    EXTERNAL_TREE_NODE_DOMAIN,
                    &[
                        (1, &metadata),
                        (2, &role),
                        (3, target_root.as_bytes()),
                        (4, &[1]),
                    ],
                ))
            }
        }
    }
}

impl TreeManifestV1 {
    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        const S_IFMT: u32 = 0o170_000;
        const S_IFDIR: u32 = 0o040_000;
        const S_IFREG: u32 = 0o100_000;
        const S_IFLNK: u32 = 0o120_000;

        if self.entries.is_empty()
            || self.entries[0].relative_path != b""
            || self.entries.windows(2).any(|window| {
                window[0].relative_path.as_slice() >= window[1].relative_path.as_slice()
            })
            || !matches!(self.entries[0].payload, ManifestPayloadV1::Directory { .. })
        {
            return Err(LinuxPytestContractError::MalformedManifest);
        }

        let by_path = self
            .entries
            .iter()
            .map(|entry| (entry.relative_path.as_slice(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut linked_from_parent = BTreeSet::new();
        let mut hardlink_members = BTreeMap::<HardlinkGroupDigest, Vec<&[u8]>>::new();

        for entry in &self.entries {
            if !valid_manifest_relative_path(&entry.relative_path) {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
            entry.metadata.validate()?;
            let expected_file_type = match entry.payload {
                ManifestPayloadV1::Directory { .. } | ManifestPayloadV1::ExternalTree { .. } => {
                    S_IFDIR
                }
                ManifestPayloadV1::Regular { .. } => S_IFREG,
                ManifestPayloadV1::Symlink { .. } => S_IFLNK,
            };
            if entry.metadata.mode & S_IFMT != expected_file_type
                || entry.computed_node_digest()? != entry.node_digest
            {
                return Err(LinuxPytestContractError::MalformedManifest);
            }

            match &entry.payload {
                ManifestPayloadV1::Directory { children } => {
                    if children
                        .windows(2)
                        .any(|window| window[0].name >= window[1].name)
                        || children.iter().any(|child| !valid_basename(&child.name))
                    {
                        return Err(LinuxPytestContractError::MalformedManifest);
                    }
                    for child in children {
                        let child_path = join_relative(&entry.relative_path, &child.name);
                        let Some(target) = by_path.get(child_path.as_slice()) else {
                            return Err(LinuxPytestContractError::MalformedManifest);
                        };
                        if target.payload.kind() != child.kind
                            || target.node_digest != child.node_digest
                            || !linked_from_parent.insert(child_path)
                        {
                            return Err(LinuxPytestContractError::MalformedManifest);
                        }
                    }
                }
                ManifestPayloadV1::Regular { data_extents, .. } => {
                    let mut end = 0u64;
                    for extent in data_extents {
                        let next = extent
                            .offset
                            .checked_add(extent.length)
                            .ok_or(LinuxPytestContractError::MalformedManifest)?;
                        if extent.length == 0 || extent.offset < end || next > entry.metadata.size {
                            return Err(LinuxPytestContractError::MalformedManifest);
                        }
                        end = next;
                    }
                }
                ManifestPayloadV1::Symlink { target } => {
                    if target.is_empty()
                        || target.contains(&0)
                        || u64::try_from(target.len()).ok() != Some(entry.metadata.size)
                    {
                        return Err(LinuxPytestContractError::MalformedManifest);
                    }
                }
                ManifestPayloadV1::ExternalTree { .. } => {
                    if self.tree_role != TreeRoleV1::Workspace {
                        return Err(LinuxPytestContractError::MalformedManifest);
                    }
                }
            }

            if let Some(group) = entry.hardlink_group {
                if matches!(
                    entry.payload,
                    ManifestPayloadV1::Directory { .. } | ManifestPayloadV1::ExternalTree { .. }
                ) || entry.metadata.nlink < 2
                {
                    return Err(LinuxPytestContractError::MalformedManifest);
                }
                hardlink_members
                    .entry(group)
                    .or_default()
                    .push(&entry.relative_path);
            } else if matches!(
                entry.payload,
                ManifestPayloadV1::Regular { .. } | ManifestPayloadV1::Symlink { .. }
            ) && entry.metadata.nlink != 1
            {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
        }

        if linked_from_parent.len() + 1 != self.entries.len()
            || linked_from_parent
                .iter()
                .any(|path| !by_path.contains_key(path.as_slice()))
        {
            return Err(LinuxPytestContractError::MalformedManifest);
        }

        for (group, mut members) in hardlink_members {
            members.sort_unstable();
            let first = by_path
                .get(members[0])
                .ok_or(LinuxPytestContractError::MalformedManifest)?;
            if u64::try_from(members.len()).ok() != Some(first.metadata.nlink)
                || members.iter().any(|path| {
                    by_path.get(*path).is_none_or(|entry| {
                        entry.metadata.nlink != first.metadata.nlink
                            || entry.payload.kind() != first.payload.kind()
                            || entry.node_digest != first.node_digest
                    })
                })
            {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
            let encoded = canonical::encode_paths_for_hash(&members)?;
            if HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[&encoded]) != group {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
        }

        if self.root_digest != self.entries[0].node_digest {
            return Err(LinuxPytestContractError::MalformedManifest);
        }
        Ok(())
    }
}

impl SnapshotManifestV1 {
    pub fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if self.schema != SNAPSHOT_MANIFEST_V1_SCHEMA
            || self.workspace_tree.tree_role != TreeRoleV1::Workspace
            || self.workspace_tree.mount_path.as_bytes() != b"/workspace"
            || !valid_sandbox_path_bytes(self.workspace_tree.mount_path.as_bytes())
            || self.runtime_trees.is_empty()
            || self.runtime_trees.iter().any(|tree| {
                tree.tree_role != TreeRoleV1::Runtime
                    || !valid_sandbox_path_bytes(tree.mount_path.as_bytes())
                    || runtime_mount_is_reserved(tree.mount_path.as_bytes())
            })
            || self.runtime_trees.windows(2).any(|window| {
                let left = window[0].mount_path.as_bytes();
                let right = window[1].mount_path.as_bytes();
                left >= right || sandbox_path_is_ancestor(left, right)
            })
        {
            return Err(LinuxPytestContractError::MalformedManifest);
        }
        self.workspace_tree.validate()?;
        for tree in &self.runtime_trees {
            tree.validate()?;
        }

        let workspace_root = MerkleRoot::derive(
            WORKSPACE_MERKLE_DOMAIN,
            &[self.workspace_tree.root_digest.as_bytes()],
        );
        let runtime_forest = canonical::encode_runtime_forest_for_hash(&self.runtime_trees)?;
        let runtime_root = MerkleRoot::derive(RUNTIME_MERKLE_DOMAIN, &[&runtime_forest]);
        if self.workspace_root != workspace_root || self.runtime_root != runtime_root {
            return Err(LinuxPytestContractError::MalformedManifest);
        }

        for entry in &self.workspace_tree.entries {
            let ManifestPayloadV1::ExternalTree {
                target_root,
                tree_role,
                readonly,
            } = &entry.payload
            else {
                continue;
            };
            let mount_path = join_sandbox_relative(
                self.workspace_tree.mount_path.as_bytes(),
                &entry.relative_path,
            );
            let matches = self
                .runtime_trees
                .iter()
                .filter(|tree| {
                    tree.mount_path.as_bytes() == mount_path
                        && tree.root_digest == *target_root
                        && tree.tree_role == *tree_role
                        && *readonly
                })
                .count();
            if matches != 1 {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
        }

        for runtime in &self.runtime_trees {
            if !runtime.mount_path.as_bytes().starts_with(b"/workspace/") {
                continue;
            }
            let matches = self
                .workspace_tree
                .entries
                .iter()
                .filter(|entry| {
                    let ManifestPayloadV1::ExternalTree {
                        target_root,
                        tree_role,
                        readonly,
                    } = &entry.payload
                    else {
                        return false;
                    };
                    join_sandbox_relative(
                        self.workspace_tree.mount_path.as_bytes(),
                        &entry.relative_path,
                    ) == runtime.mount_path.as_bytes()
                        && *target_root == runtime.root_digest
                        && *tree_role == runtime.tree_role
                        && *readonly
                })
                .count();
            if matches != 1 {
                return Err(LinuxPytestContractError::MalformedManifest);
            }
        }
        Ok(())
    }
}

fn sandbox_path_is_ancestor(parent: &[u8], child: &[u8]) -> bool {
    child
        .strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn runtime_mount_is_reserved(path: &[u8]) -> bool {
    if path == b"/" || path == b"/workspace" {
        return true;
    }
    const PROFILE_OWNED: [&[u8]; 5] = [b"/tmp", b"/run", b"/home/again", b"/proc", b"/dev"];
    PROFILE_OWNED
        .iter()
        .any(|root| sandbox_path_is_within(root, path))
}

fn encode_optional_digest(value: Option<&[u8; 32]>) -> Vec<u8> {
    match value {
        None => vec![0],
        Some(value) => {
            let mut output = Vec::with_capacity(41);
            output.push(1);
            output.extend_from_slice(&32u64.to_be_bytes());
            output.extend_from_slice(value);
            output
        }
    }
}

fn valid_manifest_relative_path(path: &[u8]) -> bool {
    if path.is_empty() {
        return true;
    }
    !path.starts_with(b"/")
        && !path.ends_with(b"/")
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

fn valid_basename(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&0) && !name.contains(&b'/')
}

fn join_relative(parent: &[u8], child: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        return child.to_vec();
    }
    let mut output = Vec::with_capacity(parent.len() + child.len() + 1);
    output.extend_from_slice(parent);
    output.push(b'/');
    output.extend_from_slice(child);
    output
}

fn join_sandbox_relative(mount: &[u8], relative: &[u8]) -> Vec<u8> {
    if relative.is_empty() {
        return mount.to_vec();
    }
    let mut output = Vec::with_capacity(mount.len() + relative.len() + 1);
    output.extend_from_slice(mount);
    output.push(b'/');
    output.extend_from_slice(relative);
    output
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SandboxPath(Box<[u8]>);

impl SandboxPath {
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Result<Self, LinuxPytestContractError> {
        let bytes = bytes.into();
        if !valid_sandbox_path_bytes(&bytes) {
            return Err(LinuxPytestContractError::MalformedRecord);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SandboxPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Box::<[u8]>::deserialize(deserializer)?;
        Self::new(bytes).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PytestSelectorV1 {
    raw: Vec<u8>,
    path: Vec<u8>,
    nodes: Vec<Vec<u8>>,
}

impl PytestSelectorV1 {
    pub fn parse(raw: &[u8]) -> Result<Self, RefusalCode> {
        let text = std::str::from_utf8(raw).map_err(|_| RefusalCode::SelectorNonUtf8)?;
        if raw.is_empty() {
            return Err(RefusalCode::SelectorMalformed);
        }

        let mut parts = text.split("::");
        let path = parts
            .next()
            .expect("split always yields one part")
            .as_bytes();
        if path.is_empty() {
            return Err(RefusalCode::SelectorMalformed);
        }
        if path.starts_with(b"-") {
            return Err(RefusalCode::SelectorOptionLike);
        }
        if path.starts_with(b"@") {
            return Err(RefusalCode::ForbiddenArgument);
        }
        if path.starts_with(b"/")
            || path.ends_with(b"/")
            || path
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || component == b"." || component == b"..")
        {
            return Err(RefusalCode::SelectorPathEscape);
        }

        let nodes = parts
            .map(|node| {
                if node.is_empty() {
                    Err(RefusalCode::SelectorMalformed)
                } else {
                    Ok(node.as_bytes().to_vec())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selector = Self {
            raw: raw.to_vec(),
            path: path.to_vec(),
            nodes,
        };
        if selector.reconstructed_raw() != raw {
            return Err(RefusalCode::SelectorMalformed);
        }
        Ok(selector)
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn path(&self) -> &[u8] {
        &self.path
    }

    pub fn nodes(&self) -> &[Vec<u8>] {
        &self.nodes
    }

    fn reconstructed_raw(&self) -> Vec<u8> {
        let node_bytes = self.nodes.iter().map(Vec::len).sum::<usize>();
        let mut raw = Vec::with_capacity(self.path.len() + node_bytes + self.nodes.len() * 2);
        raw.extend_from_slice(&self.path);
        for node in &self.nodes {
            raw.extend_from_slice(b"::");
            raw.extend_from_slice(node);
        }
        raw
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentBindingV1 {
    /// Digest of the owner-private environment digest key. Rotating the key
    /// partitions all prior entries without persisting the key itself.
    pub key_id: EnvironmentKeyId,
    pub digest: EnvironmentDigest,
    pub names_digest: EnvironmentNamesDigest,
    pub entry_count: u32,
    pub policy_digest: PolicyDigest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum StdinProfileV1 {
    ClosedEof = 1,
    EmptyNonTtyEof = 2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PytestInvocationIdentityV1 {
    pub argv: Vec<Vec<u8>>,
    pub cwd: Vec<u8>,
    pub selectors: Vec<PytestSelectorV1>,
    pub stdin_profile: StdinProfileV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdinKind {
    Closed,
    EmptyNonTty,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioFacts {
    pub stdin: StdinKind,
    pub stdout_is_tty: bool,
    pub stderr_is_tty: bool,
}

pub struct AdmissionInput<'a> {
    pub argv: &'a [OsString],
    pub cwd: &'a Path,
    pub workspace_root: &'a Path,
    pub stdio: StdioFacts,
    pub environment: &'a [(OsString, OsString)],
}

/// Exact profile-owned environment values. Caller values with these names are
/// discarded before hashing and replaced by these bytes.
pub const PROFILE_ENVIRONMENT_V1: &[(&[u8], &[u8])] = &[
    (b"COLUMNS", b"80"),
    (b"HOME", b"/home/again"),
    (b"LANG", b"C.UTF-8"),
    (b"LC_ALL", b"C.UTF-8"),
    (b"LINES", b"24"),
    (b"LOGNAME", b"again"),
    (b"NO_COLOR", b"1"),
    (b"PATH", b"/workspace/.venv/bin:/usr/bin:/bin"),
    (b"PWD", b"/workspace"),
    (b"PYTHONDONTWRITEBYTECODE", b"1"),
    (b"PYTHONHASHSEED", b"0"),
    (b"PYTHONIOENCODING", b"utf-8:surrogateescape"),
    (b"PYTHONPYCACHEPREFIX", b"/tmp/pycache"),
    (b"PYTHONUTF8", b"1"),
    (b"TEMP", b"/tmp"),
    (b"TMP", b"/tmp"),
    (b"TMPDIR", b"/tmp"),
    (b"TZ", b"UTC"),
    (b"USER", b"again"),
    (b"VIRTUAL_ENV", b"/workspace/.venv"),
    (b"XDG_CACHE_HOME", b"/tmp/xdg-cache"),
    (b"XDG_CONFIG_HOME", b"/home/again/.config"),
    (b"XDG_DATA_HOME", b"/home/again/.local/share"),
];

const FORBIDDEN_ENVIRONMENT_EXACT_V1: &[&[u8]] = &[
    b"BASH_ENV",
    b"ENV",
    b"GCONV_PATH",
    b"GLIBC_TUNABLES",
    b"LOCPATH",
    b"MALLOC_TRACE",
    b"NLSPATH",
    b"TZDIR",
];

fn forbidden_environment_name_v1(name: &[u8]) -> bool {
    name.starts_with(b"LD_")
        || name.starts_with(b"DYLD_")
        || name.starts_with(b"PYTHON")
        || name.starts_with(b"PYTEST_")
        || FORBIDDEN_ENVIRONMENT_EXACT_V1.contains(&name)
}

pub struct EnvironmentKeyMaterialV1 {
    key_id: EnvironmentKeyId,
    bytes: Box<[u8; 32]>,
}

impl EnvironmentKeyMaterialV1 {
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let key_id = EnvironmentKeyId::derive(ENVIRONMENT_KEY_ID_DOMAIN, &[&bytes]);
        let mut pinned = Box::new([0; 32]);
        pinned.copy_from_slice(&bytes);
        bytes.zeroize();
        Self {
            key_id,
            bytes: pinned,
        }
    }

    pub fn key_id(&self) -> EnvironmentKeyId {
        self.key_id
    }
}

impl Drop for EnvironmentKeyMaterialV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for EnvironmentKeyMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentKeyMaterialV1")
            .field("key_id", &self.key_id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

struct SecretEnvironmentEntry {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Drop for SecretEnvironmentEntry {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

#[derive(Default)]
struct SecretEnvironment {
    entries: Vec<SecretEnvironmentEntry>,
}

impl SecretEnvironment {
    pub(super) fn entries(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.entries
            .iter()
            .map(|entry| (entry.name.as_slice(), entry.value.as_slice()))
    }

    fn bind_v1(
        environment: &[(OsString, OsString)],
        key: &EnvironmentKeyMaterialV1,
        policy_digest: PolicyDigest,
    ) -> Result<(EnvironmentBindingV1, Self), ProfileFailure> {
        let mut secret = Self {
            entries: Vec::with_capacity(environment.len() + PROFILE_ENVIRONMENT_V1.len()),
        };
        for (name, value) in environment {
            let name = name.as_os_str().as_bytes();
            let value = value.as_os_str().as_bytes();
            if name.is_empty() || name.contains(&0) || name.contains(&b'=') || value.contains(&0) {
                return Err(ProfileFailure::refused(RefusalCode::EnvironmentMalformed));
            }
            secret.entries.push(SecretEnvironmentEntry {
                name: name.to_vec(),
                value: value.to_vec(),
            });
        }
        secret
            .entries
            .sort_by(|left, right| left.name.cmp(&right.name));
        if secret
            .entries
            .windows(2)
            .any(|window| window[0].name == window[1].name)
        {
            return Err(ProfileFailure::refused(RefusalCode::EnvironmentMalformed));
        }
        for entry in &mut secret.entries {
            if let Some((_, owned_value)) = PROFILE_ENVIRONMENT_V1
                .iter()
                .find(|(owned_name, _)| *owned_name == entry.name.as_slice())
            {
                entry.value.zeroize();
                entry.value.clear();
                entry.value.extend_from_slice(owned_value);
            } else if forbidden_environment_name_v1(&entry.name) {
                return Err(ProfileFailure::refused(
                    RefusalCode::LoaderInjectionEnvironment,
                ));
            }
        }
        for (name, value) in PROFILE_ENVIRONMENT_V1 {
            if !secret
                .entries
                .iter()
                .any(|entry| entry.name.as_slice() == *name)
            {
                secret.entries.push(SecretEnvironmentEntry {
                    name: name.to_vec(),
                    value: value.to_vec(),
                });
            }
        }
        secret
            .entries
            .sort_by(|left, right| left.name.cmp(&right.name));

        let entry_count = u32::try_from(secret.entries.len())
            .map_err(|_| ProfileFailure::refused(RefusalCode::EnvironmentMalformed))?;
        let mut names = Vec::new();
        names.extend_from_slice(&entry_count.to_be_bytes());
        let mut entries = Vec::new();
        entries.extend_from_slice(&entry_count.to_be_bytes());
        for entry in &secret.entries {
            let name_len = u64::try_from(entry.name.len())
                .map_err(|_| ProfileFailure::refused(RefusalCode::EnvironmentMalformed))?;
            let value_len = u64::try_from(entry.value.len())
                .map_err(|_| ProfileFailure::refused(RefusalCode::EnvironmentMalformed))?;
            names.extend_from_slice(&name_len.to_be_bytes());
            names.extend_from_slice(&entry.name);
            entries.extend_from_slice(&name_len.to_be_bytes());
            entries.extend_from_slice(&entry.name);
            entries.extend_from_slice(&value_len.to_be_bytes());
            entries.extend_from_slice(&entry.value);
        }
        let count_bytes = entry_count.to_be_bytes();
        let names_digest = EnvironmentNamesDigest(keyed_hash_v1(
            ENVIRONMENT_NAMES_DIGEST_DOMAIN,
            key.bytes.as_ref(),
            &[
                (1, policy_digest.as_bytes()),
                (2, &count_bytes),
                (3, &names),
            ],
        ));
        let digest = EnvironmentDigest(keyed_hash_v1(
            ENVIRONMENT_DIGEST_DOMAIN,
            key.bytes.as_ref(),
            &[
                (1, policy_digest.as_bytes()),
                (2, &count_bytes),
                (3, &entries),
            ],
        ));
        names.zeroize();
        entries.zeroize();

        Ok((
            EnvironmentBindingV1 {
                key_id: key.key_id,
                digest,
                names_digest,
                entry_count,
                policy_digest,
            },
            secret,
        ))
    }
}

impl fmt::Debug for SecretEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvironment")
            .field("entry_count", &self.entries.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

pub struct PytestAdmissionDraft {
    argv: Vec<Vec<u8>>,
    selectors: Vec<PytestSelectorV1>,
    workspace_root: PathBuf,
    stdin_empty: bool,
    environment_binding: EnvironmentBindingV1,
    environment: SecretEnvironment,
    lexical_shape_key: LexicalShapeKey,
}

impl PytestAdmissionDraft {
    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    pub fn selectors(&self) -> &[PytestSelectorV1] {
        &self.selectors
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn lexical_shape_key(&self) -> LexicalShapeKey {
        self.lexical_shape_key
    }
}

impl fmt::Debug for PytestAdmissionDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PytestAdmissionDraft")
            .field("argv", &self.argv)
            .field("selectors", &self.selectors)
            .field("workspace_root", &"<sealed-local-path>")
            .field("stdin_empty", &self.stdin_empty)
            .field("environment_binding", &self.environment_binding)
            .field("environment", &self.environment)
            .field("lexical_shape_key", &self.lexical_shape_key)
            .finish()
    }
}

pub struct AdmittedPytest {
    invocation: PytestInvocationIdentityV1,
    workspace_root: PathBuf,
    shape: ShapeV1,
    shape_key: ShapeKey,
    environment: SecretEnvironment,
}

impl AdmittedPytest {
    pub fn invocation(&self) -> &PytestInvocationIdentityV1 {
        &self.invocation
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn shape_key(&self) -> ShapeKey {
        self.shape_key
    }

    pub fn shape(&self) -> &ShapeV1 {
        &self.shape
    }

    pub(super) fn environment(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.environment.entries()
    }
}

impl fmt::Debug for AdmittedPytest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedPytest")
            .field("invocation", &self.invocation)
            .field("workspace_root", &"<sealed-local-path>")
            .field("shape", &self.shape)
            .field("shape_key", &self.shape_key)
            .field("environment", &self.environment)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedSnapshotIdentityV2 {
    pub snapshot_id: SnapshotId,
    pub workspace_root: MerkleRoot,
    pub runtime_root: MerkleRoot,
    pub manifest_blob: BlobRefV2,
    pub profile_digest: ProfileDigest,
}

pub struct VerifiedSnapshotManifestV1 {
    manifest: SnapshotManifestV1,
    canonical_bytes: Box<[u8]>,
    blob: BlobRefV2,
}

impl VerifiedSnapshotManifestV1 {
    pub fn from_manifest(manifest: SnapshotManifestV1) -> Result<Self, LinuxPytestContractError> {
        let canonical_bytes = manifest.canonical_bytes()?.into_boxed_slice();
        let blob = BlobRefV2 {
            digest: BlobDigest::derive(CAS_OBJECT_DOMAIN, &[&canonical_bytes]),
            byte_count: u64::try_from(canonical_bytes.len())
                .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?,
        };
        Ok(Self {
            manifest,
            canonical_bytes,
            blob,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let manifest = SnapshotManifestV1::from_canonical_bytes(bytes)?;
        let value = Self::from_manifest(manifest)?;
        if value.canonical_bytes.as_ref() != bytes {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        Ok(value)
    }

    pub fn manifest(&self) -> &SnapshotManifestV1 {
        &self.manifest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn blob(&self) -> &BlobRefV2 {
        &self.blob
    }

    fn matches_identity(&self, identity: &SealedSnapshotIdentityV2) -> bool {
        self.blob == identity.manifest_blob
            && self.manifest.workspace_root == identity.workspace_root
            && self.manifest.runtime_root == identity.runtime_root
            && self.manifest.profile_digest == identity.profile_digest
    }
}

impl fmt::Debug for VerifiedSnapshotManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSnapshotManifestV1")
            .field("schema", &self.manifest.schema)
            .field("workspace_root", &self.manifest.workspace_root)
            .field("runtime_root", &self.manifest.runtime_root)
            .field("blob", &self.blob)
            .finish()
    }
}

pub struct SealedSnapshot {
    identity: SealedSnapshotIdentityV2,
    manifest: VerifiedSnapshotManifestV1,
    workspace_dir: OwnedFd,
    runtime_dir: OwnedFd,
}

impl SealedSnapshot {
    pub(crate) fn from_owned_directories(
        identity: SealedSnapshotIdentityV2,
        manifest: VerifiedSnapshotManifestV1,
        workspace_dir: OwnedFd,
        runtime_dir: OwnedFd,
    ) -> Result<Self, LinuxPytestContractError> {
        if identity.snapshot_id.is_nil() || !manifest.matches_identity(&identity) {
            return Err(LinuxPytestContractError::MalformedManifest);
        }
        Ok(Self {
            identity,
            manifest,
            workspace_dir,
            runtime_dir,
        })
    }

    pub fn identity(&self) -> &SealedSnapshotIdentityV2 {
        &self.identity
    }

    pub fn manifest(&self) -> &VerifiedSnapshotManifestV1 {
        &self.manifest
    }

    pub(crate) fn workspace_dir(&self) -> BorrowedFd<'_> {
        self.workspace_dir.as_fd()
    }

    pub(crate) fn runtime_dir(&self) -> BorrowedFd<'_> {
        self.runtime_dir.as_fd()
    }

    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            identity: self.identity.clone(),
            manifest: VerifiedSnapshotManifestV1::from_canonical_bytes(
                self.manifest.canonical_bytes(),
            )
            .map_err(std::io::Error::other)?,
            workspace_dir: self.workspace_dir.try_clone()?,
            runtime_dir: self.runtime_dir.try_clone()?,
        })
    }
}

impl fmt::Debug for SealedSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedSnapshot")
            .field("identity", &self.identity)
            .field("directory_capabilities", &"<sealed-fds>")
            .finish()
    }
}

/// The only execution authority for this profile. The admitted invocation and
/// its raw in-memory environment are inseparably paired with the exact sealed
/// directory capabilities against which the shape was finalized.
pub struct PreparedPytest {
    snapshot: SealedSnapshot,
    admitted: AdmittedPytest,
}

impl PreparedPytest {
    pub(crate) fn new(
        snapshot: SealedSnapshot,
        admitted: AdmittedPytest,
    ) -> Result<Self, LinuxPytestContractError> {
        admitted.shape.validate()?;
        let executable_chain = admitted.shape.executable_chain()?;
        if admitted.invocation != admitted.shape.invocation
            || admitted.shape_key != admitted.shape.key()?
            || admitted.shape.runtime_root != snapshot.identity.runtime_root
            || admitted.shape.profile_digest != snapshot.identity.profile_digest
            || admitted.shape.workspace_identity != snapshot.manifest.manifest().workspace_identity
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        executable_chain.validate_against_manifest(snapshot.manifest.manifest())?;
        Ok(Self { snapshot, admitted })
    }

    pub fn snapshot(&self) -> &SealedSnapshot {
        &self.snapshot
    }

    pub fn admitted(&self) -> &AdmittedPytest {
        &self.admitted
    }
}

impl fmt::Debug for PreparedPytest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPytest")
            .field("snapshot", &self.snapshot)
            .field("admitted", &self.admitted)
            .finish()
    }
}

pub struct ValidationSnapshot(SealedSnapshot);

impl ValidationSnapshot {
    pub(crate) fn from_sealed(snapshot: SealedSnapshot) -> Self {
        Self(snapshot)
    }

    pub fn identity(&self) -> &SealedSnapshotIdentityV2 {
        self.0.identity()
    }
}

pub struct RevalidatedObservationClosureV1 {
    snapshot: ValidationSnapshot,
    closure: ObservationClosureV1,
}

impl RevalidatedObservationClosureV1 {
    pub(crate) fn new(
        snapshot: ValidationSnapshot,
        closure: ObservationClosureV1,
    ) -> Result<Self, LinuxPytestContractError> {
        closure.validate()?;
        Ok(Self { snapshot, closure })
    }

    pub fn snapshot(&self) -> &ValidationSnapshot {
        &self.snapshot
    }

    pub fn closure(&self) -> &ObservationClosureV1 {
        &self.closure
    }
}

impl fmt::Debug for RevalidatedObservationClosureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevalidatedObservationClosureV1")
            .field("snapshot_identity", self.snapshot.identity())
            .field("closure", &self.closure)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureV1 {
    X86_64 = 1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceIdsV1 {
    pub user: u64,
    pub mount: u64,
    pub pid: u64,
    pub network: u64,
    pub uts: u64,
    pub ipc: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDigestsV1 {
    pub seccomp: PolicyDigest,
    pub landlock: PolicyDigest,
    pub namespace: PolicyDigest,
    pub tracer_runtime: PolicyDigest,
    pub ambient_broker: PolicyDigest,
    pub limits: PolicyDigest,
    pub environment: PolicyDigest,
    pub selector_grammar: PolicyDigest,
    pub runtime_closure: PolicyDigest,
    pub codec: PolicyDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformIdentityV2 {
    pub architecture: ArchitectureV1,
    pub kernel_release: Vec<u8>,
    pub capability_digest: CapabilityDigest,
    /// Raw per-run namespace inode identities prove freshness but necessarily
    /// differ between primary and shadow runs. They are diagnostic fields and
    /// are excluded from semantic A/B comparison.
    pub namespace_ids: NamespaceIdsV1,
    /// Stable commitment to the required namespace kinds and verification
    /// policy; unlike raw inode identities, this must match across runs.
    pub namespace_policy_digest: PolicyDigest,
    pub policy_digests: PolicyDigestsV1,
}

/// Stable, cheap lookup identity computed only after selectors, the Python
/// executable chain, and runtime material have been resolved against a sealed
/// snapshot. It deliberately excludes the full workspace root and every
/// observation/result/effect so unrelated workspace edits remain candidate
/// misses rather than global invalidations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShapeV1 {
    pub schema: String,
    pub profile_id: String,
    pub profile_digest: ProfileDigest,
    pub workspace_identity: WorkspaceIdentity,
    pub invocation: PytestInvocationIdentityV1,
    pub environment: EnvironmentBindingV1,
    pub resolved_selector_targets: Vec<SandboxPath>,
    pub executable_chain_digest: ExecutableChainDigest,
    /// Exact canonical executable-chain witness. Keeping the witness, rather
    /// than only its digest, lets admission and candidate verification bind
    /// every symlink hop to the exact sealed manifest before execution or
    /// promotion.
    pub executable_chain_witness: Vec<u8>,
    pub runtime_root: MerkleRoot,
    pub architecture: ArchitectureV1,
    pub capability_digest: CapabilityDigest,
    pub namespace_policy_digest: PolicyDigest,
    pub policy_digests: PolicyDigestsV1,
}

impl ShapeV1 {
    pub fn validate(&self) -> Result<(), LinuxPytestContractError> {
        let profile = identity::ProfileCommitmentV1::from_compiled_policy_digests(
            self.policy_digests.clone(),
        )?;
        if self.schema != LINUX_PYTEST_SHAPE_V1_SCHEMA
            || self.profile_id != LINUX_PYTEST_PROFILE_ID
            || self.profile_digest.is_zero()
            || self.profile_digest != profile.digest()?
            || self.workspace_identity.is_zero()
            || !valid_pytest_invocation(&self.invocation)
            || self.environment.key_id.is_zero()
            || self.environment.digest.is_zero()
            || self.environment.names_digest.is_zero()
            || self.environment.entry_count == 0
            || self.environment.policy_digest != self.policy_digests.environment
            || self.resolved_selector_targets.len() != self.invocation.selectors.len()
            || self.resolved_selector_targets.iter().any(|target| {
                !valid_sandbox_path_bytes(target.as_bytes())
                    || !sandbox_path_is_within(b"/workspace", target.as_bytes())
            })
            || self.executable_chain_digest.is_zero()
            || self.runtime_root.is_zero()
            || self.capability_digest.is_zero()
            || self.namespace_policy_digest.is_zero()
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        let executable_chain = self.executable_chain()?;
        executable_chain.validate_requested_by(&self.invocation)?;
        if executable_chain.digest()? != self.executable_chain_digest {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(())
    }

    fn executable_chain(&self) -> Result<identity::ExecutableChainV1, LinuxPytestContractError> {
        identity::ExecutableChainV1::from_canonical_bytes(&self.executable_chain_witness)
    }

    pub fn key(&self) -> Result<ShapeKey, LinuxPytestContractError> {
        let encoded = self.canonical_bytes()?;
        Ok(ShapeKey::derive_tagged(SHAPE_DOMAIN, &[(1, &encoded)]))
    }

    pub fn request_key(
        &self,
        closure: &ObservationClosureV1,
    ) -> Result<RequestKey, LinuxPytestContractError> {
        self.validate()?;
        let shape_key = self.key()?;
        let closure_digest = closure.digest()?;
        Ok(RequestKey::derive_tagged(
            REQUEST_DOMAIN,
            &[
                (1, self.schema.as_bytes()),
                (2, self.profile_id.as_bytes()),
                (3, self.profile_digest.as_bytes()),
                (4, shape_key.as_bytes()),
                (5, closure_digest.as_bytes()),
            ],
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKindV2 {
    File = 1,
    Directory = 2,
    AbsentPath = 3,
    Symlink = 4,
    Executable = 5,
    Mapping = 6,
    Metadata = 7,
}

impl ObservationKindV2 {
    pub const fn fixed_dependency_key(self) -> Option<&'static [u8]> {
        match self {
            Self::File => Some(b"bytes"),
            Self::Directory => Some(b"members"),
            Self::AbsentPath => Some(b"absent"),
            Self::Symlink => Some(b"target"),
            Self::Executable => Some(b"executable"),
            Self::Mapping | Self::Metadata => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationDetailV1 {
    File {
        content_digest: FileContentDigest,
        byte_count: u64,
    },
    Directory {
        membership_digest: BlobDigest,
        entry_count: u64,
    },
    AbsentPath {
        parent_membership_digest: BlobDigest,
        missing_component: Vec<u8>,
    },
    Symlink {
        target: Vec<u8>,
    },
    Executable {
        node_digest: NodeDigest,
        chain_digest: ExecutableChainDigest,
    },
    Mapping {
        content_digest: FileContentDigest,
        offset: u64,
        length: u64,
        protection: u32,
        flags: u32,
    },
    Metadata {
        field_mask: u64,
        value_digest: BlobDigest,
    },
}

impl ObservationDetailV1 {
    pub const fn kind(&self) -> ObservationKindV2 {
        match self {
            Self::File { .. } => ObservationKindV2::File,
            Self::Directory { .. } => ObservationKindV2::Directory,
            Self::AbsentPath { .. } => ObservationKindV2::AbsentPath,
            Self::Symlink { .. } => ObservationKindV2::Symlink,
            Self::Executable { .. } => ObservationKindV2::Executable,
            Self::Mapping { .. } => ObservationKindV2::Mapping,
            Self::Metadata { .. } => ObservationKindV2::Metadata,
        }
    }

    fn validate(&self) -> Result<(), LinuxPytestContractError> {
        let valid = match self {
            Self::File { content_digest, .. } => !content_digest.is_zero(),
            Self::Directory {
                membership_digest, ..
            } => !membership_digest.is_zero(),
            Self::AbsentPath {
                parent_membership_digest,
                missing_component,
            } => !parent_membership_digest.is_zero() && valid_basename(missing_component),
            Self::Symlink { target } => {
                !target.is_empty()
                    && !target.contains(&0)
                    && u64::try_from(target.len())
                        .is_ok_and(|length| length <= EFFECT_IR_V2_MAX_CANONICAL_BYTES)
            }
            Self::Executable {
                node_digest,
                chain_digest,
            } => !node_digest.is_zero() && !chain_digest.is_zero(),
            Self::Mapping {
                content_digest,
                offset,
                length,
                ..
            } => !content_digest.is_zero() && *length != 0 && offset.checked_add(*length).is_some(),
            Self::Metadata {
                field_mask,
                value_digest,
            } => *field_mask != 0 && *field_mask & !0x01ff == 0 && !value_digest.is_zero(),
        };
        if valid {
            Ok(())
        } else {
            Err(LinuxPytestContractError::MalformedRecord)
        }
    }

    fn dependency_key(&self) -> Vec<u8> {
        if let Some(fixed) = self.kind().fixed_dependency_key() {
            return fixed.to_vec();
        }
        match self {
            Self::Mapping {
                offset,
                length,
                protection,
                flags,
                ..
            } => {
                let mut key = b"mapping-v1".to_vec();
                key.extend_from_slice(&offset.to_be_bytes());
                key.extend_from_slice(&length.to_be_bytes());
                key.extend_from_slice(&protection.to_be_bytes());
                key.extend_from_slice(&flags.to_be_bytes());
                key
            }
            Self::Metadata { field_mask, .. } => {
                let mut key = b"metadata-v1".to_vec();
                key.extend_from_slice(&field_mask.to_be_bytes());
                key
            }
            _ => unreachable!("fixed observation key handled above"),
        }
    }

    fn current_value(&self) -> Result<BlobRefV2, LinuxPytestContractError> {
        self.validate()?;
        let bytes = canonical::encode_observation_detail_top(self)?;
        Ok(BlobRefV2 {
            digest: BlobDigest::derive(CAS_OBJECT_DOMAIN, &[&bytes]),
            byte_count: u64::try_from(bytes.len())
                .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationV2 {
    pub sequence: u64,
    pub logical_task_id: LogicalTaskId,
    pub kind: ObservationKindV2,
    pub sandbox_subject: SandboxPath,
    pub canonical_detail: ObservationDetailV1,
}

/// A dependency identity omits trace ordering and logical task identity. The
/// `key` is operation-specific canonical data (for example a metadata field or
/// negative path component); `current_value` commits to the re-observed value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationDependencyV1 {
    pub key: Vec<u8>,
    pub kind: ObservationKindV2,
    pub subject: SandboxPath,
    pub current_value: BlobRefV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationClosureV1 {
    dependencies: Vec<ObservationDependencyV1>,
}

impl ObservationClosureV1 {
    /// Sort and merge byte-identical repeated dependencies. Two observations
    /// with the same identity but different values are ambiguous and refuse
    /// identity construction rather than depending on input order.
    pub fn new(
        mut dependencies: Vec<ObservationDependencyV1>,
    ) -> Result<Self, LinuxPytestContractError> {
        dependencies.sort_by(compare_dependency_identity);
        let mut normalized = Vec::<ObservationDependencyV1>::with_capacity(dependencies.len());
        for dependency in dependencies {
            if let Some(previous) = normalized.last() {
                match compare_dependency_identity(previous, &dependency) {
                    std::cmp::Ordering::Equal if previous == &dependency => continue,
                    std::cmp::Ordering::Equal => {
                        return Err(LinuxPytestContractError::MalformedLookupIdentity);
                    }
                    _ => {}
                }
            }
            normalized.push(dependency);
        }
        let value = Self {
            dependencies: normalized,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_observations(
        observations: &[ObservationV2],
    ) -> Result<Self, LinuxPytestContractError> {
        Self::new(
            observations
                .iter()
                .map(|observation| {
                    if observation.kind != observation.canonical_detail.kind() {
                        return Err(LinuxPytestContractError::MalformedRecord);
                    }
                    Ok(ObservationDependencyV1 {
                        key: observation.canonical_detail.dependency_key(),
                        kind: observation.kind,
                        subject: observation.sandbox_subject.clone(),
                        current_value: observation.canonical_detail.current_value()?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
    }

    pub fn dependencies(&self) -> &[ObservationDependencyV1] {
        &self.dependencies
    }

    pub fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if self.dependencies.is_empty()
            || self.dependencies.windows(2).any(|window| {
                compare_dependency_identity(&window[0], &window[1]) != std::cmp::Ordering::Less
            })
            || self.dependencies.iter().any(|dependency| {
                !valid_sandbox_path_bytes(dependency.subject.as_bytes())
                    || !valid_observation_dependency_key(dependency.kind, &dependency.key)
                    || dependency.current_value.digest.is_zero()
                    || dependency.current_value.byte_count > EFFECT_IR_V2_MAX_CANONICAL_BYTES
            })
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<ObservationClosureDigest, LinuxPytestContractError> {
        let encoded = self.canonical_bytes()?;
        Ok(ObservationClosureDigest::derive_tagged(
            OBSERVATION_CLOSURE_DOMAIN,
            &[(1, &encoded)],
        ))
    }
}

fn valid_observation_dependency_key(kind: ObservationKindV2, key: &[u8]) -> bool {
    if let Some(fixed) = kind.fixed_dependency_key() {
        return key == fixed;
    }
    match kind {
        ObservationKindV2::Mapping => {
            key.starts_with(b"mapping-v1") && key.len() == 10 + 8 + 8 + 4 + 4
        }
        ObservationKindV2::Metadata => {
            if !key.starts_with(b"metadata-v1") || key.len() != 11 + 8 {
                return false;
            }
            let Ok(mask) = <[u8; 8]>::try_from(&key[11..]).map(u64::from_be_bytes) else {
                return false;
            };
            mask != 0 && mask & !0x01ff == 0
        }
        _ => false,
    }
}

fn compare_dependency_identity(
    left: &ObservationDependencyV1,
    right: &ObservationDependencyV1,
) -> std::cmp::Ordering {
    (left.kind as u16)
        .cmp(&(right.kind as u16))
        .then_with(|| left.subject.as_bytes().cmp(right.subject.as_bytes()))
        .then_with(|| left.key.cmp(&right.key))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum AmbientKindV2 {
    LogicalTime = 1,
    LogicalRandom = 2,
    LogicalPid = 3,
    Sleep = 4,
    Signal = 5,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmbientEventV2 {
    pub sequence: u64,
    pub logical_task_id: LogicalTaskId,
    pub kind: AmbientKindV2,
    pub canonical_detail: BlobRefV2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum EffectKindV2 {
    Write = 1,
    Truncate = 2,
    Metadata = 3,
    Link = 4,
    Rename = 5,
    Unlink = 6,
    Mkdir = 7,
    Rmdir = 8,
    WritableMapping = 9,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedEffectV2 {
    pub sequence: u64,
    pub logical_task_id: LogicalTaskId,
    pub kind: EffectKindV2,
    pub sandbox_subject: SandboxPath,
    pub canonical_detail: BlobRefV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StreamCaptureV2 {
    Complete {
        blob: BlobRefV2,
    },
    Exceeded {
        observed_bytes: u64,
    },
    Incomplete {
        observed_bytes: u64,
        reason: ExecuteOnlyCode,
    },
}

impl StreamCaptureV2 {
    pub fn complete_blob(&self) -> Option<&BlobRefV2> {
        match self {
            Self::Complete { blob } => Some(blob),
            Self::Exceeded { .. } | Self::Incomplete { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RawLinuxWaitStatusV1(pub u32);

impl RawLinuxWaitStatusV1 {
    pub const fn exited(code: u8) -> Self {
        Self((code as u32) << 8)
    }

    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    pub const fn exit_code(self) -> Option<u8> {
        if self.0 <= u16::MAX as u32 && self.0 & 0xff == 0 {
            Some(((self.0 >> 8) & 0xff) as u8)
        } else {
            None
        }
    }

    pub const fn terminating_signal(self) -> Option<(u8, bool)> {
        if self.0 > u16::MAX as u32 || self.0 & 0xff00 != 0 {
            return None;
        }
        let low_byte = self.0 & 0xff;
        let signal = low_byte & 0x7f;
        if signal >= 1 && signal <= 64 {
            Some((signal as u8, low_byte & 0x80 != 0))
        } else {
            None
        }
    }

    pub const fn is_final(self) -> bool {
        if self.0 > u16::MAX as u32 {
            return false;
        }
        let low_byte = self.0 & 0xff;
        if low_byte == 0 {
            return true;
        }
        if self.0 == 0xffff || low_byte == 0x7f || self.0 & 0xff00 != 0 {
            return false;
        }
        let signal = low_byte & 0x7f;
        signal >= 1 && signal <= 64
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResultV2 {
    pub stdout: StreamCaptureV2,
    pub stderr: StreamCaptureV2,
    pub raw_linux_wait_status: RawLinuxWaitStatusV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u16)]
#[serde(rename_all = "snake_case")]
pub enum EffectRecordDispositionV2 {
    ExecutedOnly = 1,
    PrimaryCandidate = 2,
    ShadowCandidate = 3,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRecordV2 {
    schema: String,
    record_id: RecordId,
    profile_id: String,
    profile_digest: ProfileDigest,
    shape_key: ShapeKey,
    request_key: RequestKey,
    invocation: PytestInvocationIdentityV1,
    workspace_identity: WorkspaceIdentity,
    environment: EnvironmentBindingV1,
    sealed_snapshot: SealedSnapshotIdentityV2,
    platform: PlatformIdentityV2,
    trace: TraceCompletenessV2,
    observations: Vec<ObservationV2>,
    ambient_events: Vec<AmbientEventV2>,
    ordered_effects: Vec<OrderedEffectV2>,
    final_workspace_root: MerkleRoot,
    result: EffectResultV2,
    disposition: EffectRecordDispositionV2,
    disposition_reason: Option<ExecuteOnlyCode>,
    primary_record_id: Option<RecordId>,
    created_monotonic_ns: MonotonicNs,
    /// Full canonical lookup shape. The duplicated record fields are retained
    /// for direct indexing, but validation requires exact equality with this
    /// object and recomputes `shape_key` from its bytes.
    shape: ShapeV1,
    /// Exact normalized projection of `observations`. Validation reconstructs
    /// this closure and recomputes `request_key`; it is never caller asserted.
    observation_closure: ObservationClosureV1,
}

struct ComparisonViewV1<'a> {
    schema: &'a str,
    profile_id: &'a str,
    profile_digest: ProfileDigest,
    shape_key: ShapeKey,
    request_key: RequestKey,
    invocation: &'a PytestInvocationIdentityV1,
    workspace_identity: WorkspaceIdentity,
    environment: &'a EnvironmentBindingV1,
    sealed_snapshot: ComparisonSnapshotV1<'a>,
    platform: ComparisonPlatformV1<'a>,
    trace: &'a TraceCompletenessV2,
    observations: &'a [ObservationV2],
    ambient_events: &'a [AmbientEventV2],
    ordered_effects: &'a [OrderedEffectV2],
    final_workspace_root: MerkleRoot,
    result: &'a EffectResultV2,
    shape: &'a ShapeV1,
    observation_closure: &'a ObservationClosureV1,
}

struct ComparisonSnapshotV1<'a> {
    workspace_root: MerkleRoot,
    runtime_root: MerkleRoot,
    manifest_blob: &'a BlobRefV2,
    profile_digest: ProfileDigest,
}

struct ComparisonPlatformV1<'a> {
    architecture: ArchitectureV1,
    kernel_release: &'a [u8],
    capability_digest: CapabilityDigest,
    namespace_policy_digest: PolicyDigest,
    policy_digests: &'a PolicyDigestsV1,
}

fn valid_pytest_invocation(invocation: &PytestInvocationIdentityV1) -> bool {
    invocation.argv.len() == 4 + invocation.selectors.len()
        && invocation.argv.len() >= 5
        && invocation.selectors.len() <= LINUX_PYTEST_V1_MAX_SELECTORS
        && invocation.argv[0].as_slice() == b".venv/bin/python"
        && invocation.argv[1].as_slice() == b"-I"
        && invocation.argv[2].as_slice() == b"-m"
        && invocation.argv[3].as_slice() == b"pytest"
        && invocation.cwd == b"."
        && !invocation.selectors.is_empty()
        && invocation
            .argv
            .iter()
            .all(|argument| !argument.is_empty() && !argument.contains(&0))
        && invocation
            .selectors
            .iter()
            .enumerate()
            .all(|(index, selector)| {
                PytestSelectorV1::parse(&invocation.argv[index + 4])
                    .is_ok_and(|parsed| parsed == *selector)
            })
}

impl EffectRecordV2 {
    pub fn validate(&self) -> Result<(), LinuxPytestContractError> {
        if self.schema != EFFECT_IR_V2_SCHEMA
            || self.profile_id != LINUX_PYTEST_PROFILE_ID
            || self.record_id.is_nil()
            || self.sealed_snapshot.snapshot_id.is_nil()
        {
            return Err(LinuxPytestContractError::SchemaProfileMismatch);
        }
        self.trace.validate()?;
        self.shape.validate()?;
        self.observation_closure.validate()?;
        let derived_closure = ObservationClosureV1::from_observations(&self.observations)?;
        let derived_shape_key = self.shape.key()?;
        let derived_request_key = self.shape.request_key(&derived_closure)?;
        if !valid_pytest_invocation(&self.invocation)
            || self.shape_key != derived_shape_key
            || self.request_key != derived_request_key
            || self.observation_closure != derived_closure
            || self.shape.profile_id != self.profile_id
            || self.shape.profile_digest != self.profile_digest
            || self.shape.invocation != self.invocation
            || self.shape.workspace_identity != self.workspace_identity
            || self.shape.environment != self.environment
            || self.shape.runtime_root != self.sealed_snapshot.runtime_root
            || self.shape.architecture != self.platform.architecture
            || self.shape.capability_digest != self.platform.capability_digest
            || self.shape.namespace_policy_digest != self.platform.namespace_policy_digest
            || self.shape.policy_digests != self.platform.policy_digests
            || self.sealed_snapshot.profile_digest != self.profile_digest
            || self.environment.policy_digest != self.platform.policy_digests.environment
            || self.sealed_snapshot.manifest_blob.digest.is_zero()
            || self.sealed_snapshot.manifest_blob.byte_count > EFFECT_IR_V2_MAX_CANONICAL_BYTES
            || self.platform.kernel_release.is_empty()
            || self.platform.kernel_release.contains(&0)
            || !valid_namespace_ids(&self.platform.namespace_ids)
            || !valid_trace_event_union(self)
            || !strictly_increasing(self.observations.iter().map(|item| item.sequence))
            || !strictly_increasing(self.ambient_events.iter().map(|item| item.sequence))
            || !strictly_increasing(self.ordered_effects.iter().map(|item| item.sequence))
            || u64::try_from(self.observations.len()).ok()
                != Some(self.trace.counters.observation_count)
            || u64::try_from(self.ambient_events.len()).ok()
                != Some(self.trace.counters.ambient_event_count)
            || u64::try_from(self.ordered_effects.len()).ok()
                != Some(self.trace.counters.ordered_effect_count)
            || self
                .observations
                .iter()
                .any(|item| !valid_sandbox_path_bytes(item.sandbox_subject.as_bytes()))
            || self
                .ordered_effects
                .iter()
                .any(|item| !valid_sandbox_path_bytes(item.sandbox_subject.as_bytes()))
            || !valid_result_capture(&self.result)
            || !self.result.raw_linux_wait_status.is_final()
        {
            return Err(LinuxPytestContractError::MalformedRecord);
        }
        if matches!(
            self.disposition,
            EffectRecordDispositionV2::PrimaryCandidate
                | EffectRecordDispositionV2::ShadowCandidate
        ) && !self.has_complete_success_result()
        {
            return Err(LinuxPytestContractError::InvalidCompletenessMasks);
        }
        match self.disposition {
            EffectRecordDispositionV2::ExecutedOnly => {
                if self.disposition_reason != derived_execute_only_reason(self)
                    || self.disposition_reason.is_none()
                    || self.primary_record_id.is_some()
                {
                    return Err(LinuxPytestContractError::MalformedRecord);
                }
            }
            EffectRecordDispositionV2::PrimaryCandidate => {
                if self.disposition_reason.is_some() || self.primary_record_id.is_some() {
                    return Err(LinuxPytestContractError::MalformedRecord);
                }
            }
            EffectRecordDispositionV2::ShadowCandidate => {
                if self.disposition_reason.is_some()
                    || self
                        .primary_record_id
                        .is_none_or(|primary| primary.is_nil() || primary == self.record_id)
                {
                    return Err(LinuxPytestContractError::MalformedRecord);
                }
            }
        }
        Ok(())
    }

    /// This proves only that an immutable primary/shadow record may
    /// participate in promotion. Replay authority lives exclusively in a
    /// validated promotion row that references two distinct complete records.
    pub fn is_complete_candidate(&self) -> bool {
        self.validate().is_ok()
            && matches!(
                self.disposition,
                EffectRecordDispositionV2::PrimaryCandidate
                    | EffectRecordDispositionV2::ShadowCandidate
            )
            && self.has_complete_success_result()
    }

    fn has_complete_success_result(&self) -> bool {
        self.trace.candidate_complete()
            && self.result.stdout.complete_blob().is_some()
            && self.result.stderr.complete_blob().is_some()
            && self.result.raw_linux_wait_status.is_success()
    }

    fn comparison_view(&self) -> ComparisonViewV1<'_> {
        ComparisonViewV1 {
            schema: &self.schema,
            profile_id: &self.profile_id,
            profile_digest: self.profile_digest,
            shape_key: self.shape_key,
            request_key: self.request_key,
            invocation: &self.invocation,
            workspace_identity: self.workspace_identity,
            environment: &self.environment,
            sealed_snapshot: ComparisonSnapshotV1 {
                workspace_root: self.sealed_snapshot.workspace_root,
                runtime_root: self.sealed_snapshot.runtime_root,
                manifest_blob: &self.sealed_snapshot.manifest_blob,
                profile_digest: self.sealed_snapshot.profile_digest,
            },
            platform: ComparisonPlatformV1 {
                architecture: self.platform.architecture,
                kernel_release: &self.platform.kernel_release,
                capability_digest: self.platform.capability_digest,
                namespace_policy_digest: self.platform.namespace_policy_digest,
                policy_digests: &self.platform.policy_digests,
            },
            trace: &self.trace,
            observations: &self.observations,
            ambient_events: &self.ambient_events,
            ordered_effects: &self.ordered_effects,
            final_workspace_root: self.final_workspace_root,
            result: &self.result,
            shape: &self.shape,
            observation_closure: &self.observation_closure,
        }
    }

    pub fn semantic_comparison_digest(
        &self,
    ) -> Result<ComparisonViewDigest, LinuxPytestContractError> {
        self.comparison_view_digest()
    }
}

fn derived_execute_only_reason(record: &EffectRecordV2) -> Option<ExecuteOnlyCode> {
    if let Some(failure) = &record.trace.first_failure {
        return Some(failure.reason);
    }
    match &record.result.stdout {
        StreamCaptureV2::Exceeded { .. } => return Some(ExecuteOnlyCode::StdoutLimit),
        StreamCaptureV2::Incomplete { reason, .. } => return Some(*reason),
        StreamCaptureV2::Complete { .. } => {}
    }
    match &record.result.stderr {
        StreamCaptureV2::Exceeded { .. } => return Some(ExecuteOnlyCode::StderrLimit),
        StreamCaptureV2::Incomplete { reason, .. } => return Some(*reason),
        StreamCaptureV2::Complete { .. } => {}
    }
    if record
        .result
        .raw_linux_wait_status
        .terminating_signal()
        .is_some()
    {
        return Some(ExecuteOnlyCode::ForegroundSignaled);
    }
    if record
        .result
        .raw_linux_wait_status
        .exit_code()
        .is_some_and(|code| code != 0)
    {
        return Some(ExecuteOnlyCode::ForegroundNonzeroExit);
    }
    None
}

/// A record paired with the exact canonical bytes and V2 CAS identity derived
/// from those bytes. This type is the minimum authority accepted by pair
/// attestation; callers cannot supply an unrelated record digest.
pub struct CanonicalEffectRecordV2 {
    record: EffectRecordV2,
    canonical_bytes: Box<[u8]>,
    record_blob: BlobRefV2,
}

impl CanonicalEffectRecordV2 {
    pub fn from_record(record: EffectRecordV2) -> Result<Self, LinuxPytestContractError> {
        let canonical_bytes = record.canonical_bytes()?.into_boxed_slice();
        let record_blob = BlobRefV2 {
            digest: BlobDigest::derive(CAS_OBJECT_DOMAIN, &[&canonical_bytes]),
            byte_count: u64::try_from(canonical_bytes.len())
                .map_err(|_| LinuxPytestContractError::CanonicalEncoding)?,
        };
        Ok(Self {
            record,
            canonical_bytes,
            record_blob,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxPytestContractError> {
        let record = EffectRecordV2::from_canonical_bytes(bytes)?;
        let value = Self::from_record(record)?;
        if value.canonical_bytes.as_ref() != bytes {
            return Err(LinuxPytestContractError::CanonicalDecoding);
        }
        Ok(value)
    }

    pub fn record(&self) -> &EffectRecordV2 {
        &self.record
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn record_blob(&self) -> &BlobRefV2 {
        &self.record_blob
    }
}

impl fmt::Debug for CanonicalEffectRecordV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalEffectRecordV2")
            .field("record_id", &self.record.record_id)
            .field("record_blob", &self.record_blob)
            .finish()
    }
}

/// A complete candidate whose canonical record has been cross-checked against
/// the exact canonical manifest object referenced by its sealed snapshot.
/// Promotion accepts only this type, never a raw record or bare CAS id.
pub struct VerifiedCandidateRecordV2 {
    canonical: CanonicalEffectRecordV2,
    manifest: VerifiedSnapshotManifestV1,
}

impl VerifiedCandidateRecordV2 {
    pub fn new(
        canonical: CanonicalEffectRecordV2,
        manifest: VerifiedSnapshotManifestV1,
    ) -> Result<Self, LinuxPytestContractError> {
        let record = canonical.record();
        let snapshot = &record.sealed_snapshot;
        let manifest_value = manifest.manifest();
        let executable_chain = record.shape.executable_chain()?;
        if !record.is_complete_candidate()
            || !manifest.matches_identity(snapshot)
            || manifest_value.workspace_identity != record.workspace_identity
            || manifest_value.profile_digest != record.profile_digest
            || manifest_value.workspace_root != snapshot.workspace_root
            || manifest_value.runtime_root != snapshot.runtime_root
        {
            return Err(LinuxPytestContractError::MalformedRecord);
        }
        executable_chain.validate_against_manifest(manifest_value)?;
        Ok(Self {
            canonical,
            manifest,
        })
    }

    pub fn from_canonical_bytes(
        record_bytes: &[u8],
        manifest_bytes: &[u8],
    ) -> Result<Self, LinuxPytestContractError> {
        Self::new(
            CanonicalEffectRecordV2::from_canonical_bytes(record_bytes)?,
            VerifiedSnapshotManifestV1::from_canonical_bytes(manifest_bytes)?,
        )
    }

    pub fn canonical(&self) -> &CanonicalEffectRecordV2 {
        &self.canonical
    }

    pub fn record(&self) -> &EffectRecordV2 {
        self.canonical.record()
    }

    pub fn manifest(&self) -> &VerifiedSnapshotManifestV1 {
        &self.manifest
    }
}

impl fmt::Debug for VerifiedCandidateRecordV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedCandidateRecordV2")
            .field("canonical", &self.canonical)
            .field("manifest", &self.manifest)
            .finish()
    }
}

pub enum VerifiedExecutionRecordV2 {
    ExecutedOnly(Box<CanonicalEffectRecordV2>),
    Candidate(Box<VerifiedCandidateRecordV2>),
}

impl VerifiedExecutionRecordV2 {
    pub fn bind(
        prepared: &PreparedPytest,
        mode: TraceExecutionMode,
        canonical: CanonicalEffectRecordV2,
    ) -> Result<Self, LinuxPytestContractError> {
        let record = canonical.record();
        if record.shape != prepared.admitted.shape
            || record.shape_key != prepared.admitted.shape_key
            || record.invocation != prepared.admitted.invocation
            || record.sealed_snapshot != prepared.snapshot.identity
        {
            return Err(LinuxPytestContractError::MalformedRecord);
        }

        match (mode, record.disposition) {
            (TraceExecutionMode::Foreground, EffectRecordDispositionV2::ExecutedOnly) => {
                Ok(Self::ExecutedOnly(Box::new(canonical)))
            }
            (TraceExecutionMode::Foreground, EffectRecordDispositionV2::PrimaryCandidate) => {
                let manifest = VerifiedSnapshotManifestV1::from_canonical_bytes(
                    prepared.snapshot.manifest.canonical_bytes(),
                )?;
                Ok(Self::Candidate(Box::new(VerifiedCandidateRecordV2::new(
                    canonical, manifest,
                )?)))
            }
            (
                TraceExecutionMode::Shadow { primary_record_id },
                EffectRecordDispositionV2::ShadowCandidate,
            ) if record.primary_record_id == Some(primary_record_id) => {
                let manifest = VerifiedSnapshotManifestV1::from_canonical_bytes(
                    prepared.snapshot.manifest.canonical_bytes(),
                )?;
                Ok(Self::Candidate(Box::new(VerifiedCandidateRecordV2::new(
                    canonical, manifest,
                )?)))
            }
            _ => Err(LinuxPytestContractError::MalformedRecord),
        }
    }

    pub fn record(&self) -> &EffectRecordV2 {
        match self {
            Self::ExecutedOnly(record) => record.record(),
            Self::Candidate(record) => record.record(),
        }
    }

    pub fn candidate(&self) -> Option<&VerifiedCandidateRecordV2> {
        match self {
            Self::ExecutedOnly(_) => None,
            Self::Candidate(record) => Some(record),
        }
    }
}

fn valid_namespace_ids(ids: &NamespaceIdsV1) -> bool {
    let values = [ids.user, ids.mount, ids.pid, ids.network, ids.uts, ids.ipc];
    values.iter().all(|value| *value != 0)
        && values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_trace_event_union(record: &EffectRecordV2) -> bool {
    let semantic_count = record
        .observations
        .len()
        .checked_add(record.ambient_events.len())
        .and_then(|count| count.checked_add(record.ordered_effects.len()));
    let Some(semantic_count) = semantic_count.and_then(|count| u64::try_from(count).ok()) else {
        return false;
    };
    if semantic_count == 0 || semantic_count > record.trace.counters.event_count {
        return false;
    }

    let mut sequences = BTreeSet::new();
    let final_sequence = record.trace.counters.final_sequence;
    let task_birth_count = record.trace.counters.task_birth_count;
    let mut accept = |sequence: u64, task: LogicalTaskId, detail_valid: bool| {
        sequence != 0
            && sequence <= final_sequence
            && task.0 != 0
            && u64::from(task.0) <= task_birth_count
            && detail_valid
            && sequences.insert(sequence)
    };
    record.observations.iter().all(|event| {
        accept(
            event.sequence,
            event.logical_task_id,
            event.kind == event.canonical_detail.kind()
                && event.canonical_detail.validate().is_ok(),
        )
    }) && record.ambient_events.iter().all(|event| {
        accept(
            event.sequence,
            event.logical_task_id,
            !event.canonical_detail.digest.is_zero()
                && event.canonical_detail.byte_count <= EFFECT_IR_V2_MAX_CANONICAL_BYTES,
        )
    }) && record.ordered_effects.iter().all(|event| {
        accept(
            event.sequence,
            event.logical_task_id,
            !event.canonical_detail.digest.is_zero()
                && event.canonical_detail.byte_count <= EFFECT_IR_V2_MAX_CANONICAL_BYTES,
        )
    })
}

fn valid_result_capture(result: &EffectResultV2) -> bool {
    fn valid_stream(stream: &StreamCaptureV2) -> bool {
        match stream {
            StreamCaptureV2::Complete { blob } => {
                !blob.digest.is_zero() && blob.byte_count <= LINUX_PYTEST_V1_MAX_STREAM_BYTES
            }
            StreamCaptureV2::Exceeded { observed_bytes } => {
                *observed_bytes > LINUX_PYTEST_V1_MAX_STREAM_BYTES
            }
            StreamCaptureV2::Incomplete { observed_bytes, .. } => {
                *observed_bytes <= LINUX_PYTEST_V1_MAX_STREAM_BYTES
            }
        }
    }
    valid_stream(&result.stdout) && valid_stream(&result.stderr)
}

fn strictly_increasing(values: impl IntoIterator<Item = u64>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior| value <= prior) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn valid_sandbox_path_bytes(subject: &[u8]) -> bool {
    if subject.first() != Some(&b'/') || subject.contains(&0) {
        return false;
    }
    if subject == b"/" {
        return true;
    }
    !subject.ends_with(b"/")
        && subject[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

fn sandbox_path_is_within(root: &[u8], candidate: &[u8]) -> bool {
    candidate == root || sandbox_path_is_ancestor(root, candidate)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceExecutionMode {
    Foreground,
    Shadow { primary_record_id: RecordId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonCapabilityProbeV1 {
    IsolatedImportPytest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileFailure {
    Refused { code: RefusalCode },
    ExecuteOnly { code: ExecuteOnlyCode },
    Shadow { code: ShadowTerminalCode },
    Quarantined { code: QuarantineCode },
}

impl ProfileFailure {
    pub const fn refused(code: RefusalCode) -> Self {
        Self::Refused { code }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Refused { code } => code.as_str(),
            Self::ExecuteOnly { code } => code.as_str(),
            Self::Shadow { code } => code.as_str(),
            Self::Quarantined { code } => code.as_str(),
        }
    }
}

impl fmt::Display for ProfileFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ProfileFailure {}

pub trait ProfileAdmission: Send + Sync {
    /// Parse only the public argv/cwd/stdio/environment envelope. This phase
    /// must not execute Python and cannot claim that selector or venv targets
    /// are safe until they are resolved against the sealed snapshot.
    fn parse_lexical(
        &self,
        input: AdmissionInput<'_>,
    ) -> Result<PytestAdmissionDraft, ProfileFailure>;

    /// Consume the in-memory draft only after the immutable snapshot exists.
    /// Symlink chains, selector targets, runtime closure, and request identity
    /// are finalized against destination bytes and descriptor capabilities.
    fn finalize_against_snapshot(
        &self,
        draft: PytestAdmissionDraft,
        snapshot: SealedSnapshot,
    ) -> Result<PreparedPytest, ProfileFailure>;
}

pub trait SnapshotProvider: Send + Sync {
    fn seal_full(&self, draft: &PytestAdmissionDraft) -> Result<SealedSnapshot, ProfileFailure>;

    fn seal_validation_snapshot(
        &self,
        draft: &PytestAdmissionDraft,
        expected_shape: &ShapeV1,
        expected_closure: &ObservationClosureV1,
    ) -> Result<RevalidatedObservationClosureV1, ProfileFailure>;
}

pub trait SandboxTracer: Send + Sync {
    fn execute(
        &self,
        prepared: &PreparedPytest,
        mode: TraceExecutionMode,
    ) -> Result<VerifiedExecutionRecordV2, ProfileFailure>;

    fn capability_probe(
        &self,
        snapshot: &ValidationSnapshot,
        probe: PythonCapabilityProbeV1,
    ) -> Result<(), ProfileFailure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowJobV2 {
    job_id: ShadowJobId,
    primary_record_id: RecordId,
    shape_key: ShapeKey,
    request_key: RequestKey,
    snapshot_identity: SealedSnapshotIdentityV2,
}

impl ShadowJobV2 {
    pub(crate) fn new(
        job_id: ShadowJobId,
        primary: &VerifiedCandidateRecordV2,
    ) -> Result<Self, LinuxPytestContractError> {
        let record = primary.record();
        if record.disposition != EffectRecordDispositionV2::PrimaryCandidate
            || !record.is_complete_candidate()
            || job_id.is_nil()
        {
            return Err(LinuxPytestContractError::MalformedRecord);
        }
        Ok(Self {
            job_id,
            primary_record_id: record.record_id,
            shape_key: record.shape_key,
            request_key: record.request_key,
            snapshot_identity: record.sealed_snapshot.clone(),
        })
    }

    pub fn job_id(&self) -> ShadowJobId {
        self.job_id
    }

    pub fn primary_record_id(&self) -> RecordId {
        self.primary_record_id
    }

    pub fn shape_key(&self) -> ShapeKey {
        self.shape_key
    }

    pub fn request_key(&self) -> RequestKey {
        self.request_key
    }

    pub fn snapshot_identity(&self) -> &SealedSnapshotIdentityV2 {
        &self.snapshot_identity
    }
}

/// Live, nonserializable handoff. It deliberately owns the sealed descriptor
/// capabilities and raw environment; neither can be reconstructed from the
/// durable shadow-job row.
pub struct ShadowEnvelopeV2 {
    job: ShadowJobV2,
    prepared: PreparedPytest,
}

impl ShadowEnvelopeV2 {
    pub fn new(
        job: ShadowJobV2,
        prepared: PreparedPytest,
    ) -> Result<Self, LinuxPytestContractError> {
        if job.shape_key != prepared.admitted.shape_key
            || job.snapshot_identity != prepared.snapshot.identity
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(Self { job, prepared })
    }

    pub fn job(&self) -> &ShadowJobV2 {
        &self.job
    }

    pub fn prepared(&self) -> &PreparedPytest {
        &self.prepared
    }
}

impl fmt::Debug for ShadowEnvelopeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShadowEnvelopeV2")
            .field("job", &self.job)
            .field("prepared", &"<sealed-fds-and-secret-environment>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowHandoffReceiptV2 {
    pub job_id: ShadowJobId,
    pub worker_id: WorkerId,
}

pub trait ShadowDispatcher: Send + Sync {
    /// Success means a worker has synchronously acknowledged ownership of the
    /// complete live envelope. A dropped/error envelope is terminal and must
    /// be recorded through `PromotionStore::fail_shadow`.
    fn handoff(&self, envelope: ShadowEnvelopeV2)
    -> Result<ShadowHandoffReceiptV2, ProfileFailure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotedPairV2 {
    shape_key: ShapeKey,
    request_key: RequestKey,
    primary_record_id: RecordId,
    shadow_record_id: RecordId,
    primary_record_blob: BlobRefV2,
    shadow_record_blob: BlobRefV2,
    comparison_digest: PairComparisonDigest,
    class_key: ClassKey,
    promoted_monotonic_ns: MonotonicNs,
}

impl PromotedPairV2 {
    pub fn new(
        primary: &VerifiedCandidateRecordV2,
        shadow: &VerifiedCandidateRecordV2,
        promoted_monotonic_ns: MonotonicNs,
    ) -> Result<Self, LinuxPytestContractError> {
        let comparison_digest = canonical::pair_comparison_digest(primary, shadow)?;
        let primary_record = primary.record();
        let shadow_record = shadow.record();
        if promoted_monotonic_ns.0 == 0
            || promoted_monotonic_ns.0 < primary_record.created_monotonic_ns.0
            || promoted_monotonic_ns.0 < shadow_record.created_monotonic_ns.0
        {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(Self {
            shape_key: primary_record.shape_key,
            request_key: primary_record.request_key,
            primary_record_id: primary_record.record_id,
            shadow_record_id: shadow_record.record_id,
            primary_record_blob: primary.canonical().record_blob().clone(),
            shadow_record_blob: shadow.canonical().record_blob().clone(),
            comparison_digest,
            class_key: identity::QuarantineClassV1::from_record(primary_record)?.key()?,
            promoted_monotonic_ns,
        })
    }

    pub fn shape_key(&self) -> ShapeKey {
        self.shape_key
    }

    pub fn request_key(&self) -> RequestKey {
        self.request_key
    }

    pub fn primary_record_id(&self) -> RecordId {
        self.primary_record_id
    }

    pub fn shadow_record_id(&self) -> RecordId {
        self.shadow_record_id
    }

    pub fn primary_record_blob(&self) -> &BlobRefV2 {
        &self.primary_record_blob
    }

    pub fn shadow_record_blob(&self) -> &BlobRefV2 {
        &self.shadow_record_blob
    }

    pub fn comparison_digest(&self) -> PairComparisonDigest {
        self.comparison_digest
    }

    pub fn class_key(&self) -> ClassKey {
        self.class_key
    }

    pub fn promoted_monotonic_ns(&self) -> MonotonicNs {
        self.promoted_monotonic_ns
    }
}

pub struct PromotedCandidateV2 {
    pair: PromotedPairV2,
    primary: VerifiedCandidateRecordV2,
    shadow: VerifiedCandidateRecordV2,
}

impl PromotedCandidateV2 {
    pub fn new(
        pair: PromotedPairV2,
        primary: VerifiedCandidateRecordV2,
        shadow: VerifiedCandidateRecordV2,
    ) -> Result<Self, LinuxPytestContractError> {
        if PromotedPairV2::new(&primary, &shadow, pair.promoted_monotonic_ns)? != pair {
            return Err(LinuxPytestContractError::ComparisonMismatch);
        }
        Ok(Self {
            pair,
            primary,
            shadow,
        })
    }

    pub fn pair(&self) -> &PromotedPairV2 {
        &self.pair
    }

    pub fn primary(&self) -> &VerifiedCandidateRecordV2 {
        &self.primary
    }

    pub fn shadow(&self) -> &VerifiedCandidateRecordV2 {
        &self.shadow
    }
}

pub struct PromotedLookupV2 {
    candidates: Vec<PromotedCandidateV2>,
}

impl PromotedLookupV2 {
    pub fn new(
        shape_key: ShapeKey,
        candidates: Vec<PromotedCandidateV2>,
    ) -> Result<Self, LinuxPytestContractError> {
        if candidates.len() > usize::from(LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES) {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        let mut request_keys = BTreeSet::new();
        let mut record_ids = BTreeSet::new();
        for candidate in &candidates {
            if candidate.pair.shape_key != shape_key
                || !request_keys.insert(candidate.pair.request_key)
                || !record_ids.insert(candidate.pair.primary_record_id)
                || !record_ids.insert(candidate.pair.shadow_record_id)
            {
                return Err(LinuxPytestContractError::MalformedLookupIdentity);
            }
        }
        if candidates.windows(2).any(|window| {
            let left = &window[0].pair;
            let right = &window[1].pair;
            left.promoted_monotonic_ns.0 < right.promoted_monotonic_ns.0
                || (left.promoted_monotonic_ns == right.promoted_monotonic_ns
                    && left.request_key >= right.request_key)
        }) {
            return Err(LinuxPytestContractError::MalformedLookupIdentity);
        }
        Ok(Self { candidates })
    }

    pub fn candidates(&self) -> &[PromotedCandidateV2] {
        &self.candidates
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PromotionGcReportV2 {
    pub jobs: u64,
    pub snapshots: u64,
    pub records: u64,
    pub blobs: u64,
}

pub trait PromotionStore: Send {
    fn record_primary(
        &mut self,
        record: &VerifiedCandidateRecordV2,
    ) -> Result<ShadowJobV2, ProfileFailure>;

    fn finish_shadow(
        &mut self,
        job: &ShadowJobV2,
        shadow: &VerifiedCandidateRecordV2,
    ) -> Result<PromotedPairV2, ProfileFailure>;

    fn fail_shadow(
        &mut self,
        job: &ShadowJobV2,
        reason: ShadowTerminalCode,
    ) -> Result<(), ProfileFailure>;

    /// Return at most `LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES` immutable pairs
    /// for the finalized shape, newest promotion first with request-key tie
    /// breaking. The caller must decode both records, reconstruct each
    /// observation closure against a validation snapshot, recompute the exact
    /// request key, and validate the capability probe before selecting a hit.
    fn lookup_promoted_by_shape(
        &mut self,
        shape_key: ShapeKey,
    ) -> Result<PromotedLookupV2, ProfileFailure>;

    fn quarantine(
        &mut self,
        class_key: ClassKey,
        first_record_id: RecordId,
        reason: QuarantineCode,
    ) -> Result<(), ProfileFailure>;

    fn expire(
        &mut self,
        now_ns: EpochNs,
        limit: u32,
    ) -> Result<PromotionGcReportV2, ProfileFailure>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ContractOnlyProfile;

impl ProfileAdmission for ContractOnlyProfile {
    fn parse_lexical(
        &self,
        _input: AdmissionInput<'_>,
    ) -> Result<PytestAdmissionDraft, ProfileFailure> {
        Err(ProfileFailure::refused(RefusalCode::ProfileDisabled))
    }

    fn finalize_against_snapshot(
        &self,
        _draft: PytestAdmissionDraft,
        _snapshot: SealedSnapshot,
    ) -> Result<PreparedPytest, ProfileFailure> {
        Err(ProfileFailure::refused(RefusalCode::ProfileDisabled))
    }
}

impl SnapshotProvider for ContractOnlyProfile {
    fn seal_full(&self, _draft: &PytestAdmissionDraft) -> Result<SealedSnapshot, ProfileFailure> {
        Err(ProfileFailure::refused(RefusalCode::ProfileDisabled))
    }

    fn seal_validation_snapshot(
        &self,
        _draft: &PytestAdmissionDraft,
        _expected_shape: &ShapeV1,
        _expected_closure: &ObservationClosureV1,
    ) -> Result<RevalidatedObservationClosureV1, ProfileFailure> {
        Err(ProfileFailure::refused(RefusalCode::ProfileDisabled))
    }
}

impl SandboxTracer for ContractOnlyProfile {
    fn execute(
        &self,
        _prepared: &PreparedPytest,
        _mode: TraceExecutionMode,
    ) -> Result<VerifiedExecutionRecordV2, ProfileFailure> {
        Err(ProfileFailure::refused(RefusalCode::ProfileDisabled))
    }

    fn capability_probe(
        &self,
        _snapshot: &ValidationSnapshot,
        _probe: PythonCapabilityProbeV1,
    ) -> Result<(), ProfileFailure> {
        Err(ProfileFailure::refused(RefusalCode::ProfileDisabled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! digest {
        ($kind:ident, $label:expr) => {
            $kind::derive("again linux pytest contract test", &[$label.as_bytes()])
        };
    }

    fn blob(label: &str, byte_count: u64) -> BlobRefV2 {
        BlobRefV2 {
            digest: digest!(BlobDigest, label),
            byte_count,
        }
    }

    fn policy_digests() -> PolicyDigestsV1 {
        PolicyDigestsV1 {
            seccomp: digest!(PolicyDigest, "seccomp"),
            landlock: digest!(PolicyDigest, "landlock"),
            namespace: digest!(PolicyDigest, "namespace"),
            tracer_runtime: digest!(PolicyDigest, "tracer-runtime"),
            ambient_broker: digest!(PolicyDigest, "ambient-broker"),
            limits: digest!(PolicyDigest, "limits"),
            environment: digest!(PolicyDigest, "environment-policy"),
            selector_grammar: digest!(PolicyDigest, "selector-grammar"),
            runtime_closure: digest!(PolicyDigest, "runtime-closure"),
            codec: digest!(PolicyDigest, "codec"),
        }
    }

    fn profile_digest() -> ProfileDigest {
        identity::ProfileCommitmentV1::from_compiled_policy_digests(policy_digests())
            .unwrap()
            .digest()
            .unwrap()
    }

    fn bound_environment() -> (EnvironmentBindingV1, SecretEnvironment) {
        SecretEnvironment::bind_v1(
            &[],
            &EnvironmentKeyMaterialV1::from_bytes([0x42; 32]),
            policy_digests().environment,
        )
        .unwrap()
    }

    fn metadata(mode: u32, size: u64, nlink: u64) -> MetadataV1 {
        let time = TimespecV1 {
            seconds: 1,
            nanoseconds: 2,
        };
        MetadataV1 {
            mode,
            logical_uid: 0,
            logical_gid: 0,
            size,
            nlink,
            atime: time.clone(),
            mtime: time.clone(),
            ctime: time,
            btime: None,
            xattrs: Vec::new(),
        }
    }

    fn manifest() -> SnapshotManifestV1 {
        let mut runtime_python_entry = ManifestEntryV1 {
            relative_path: b"bin/python".to_vec(),
            metadata: metadata(0o100_555, 6, 1),
            payload: ManifestPayloadV1::Regular {
                content_digest: digest!(FileContentDigest, "runtime-python"),
                data_extents: vec![ExtentV1 {
                    offset: 0,
                    length: 6,
                }],
            },
            hardlink_group: None,
            node_digest: digest!(NodeDigest, "placeholder-runtime-python"),
        };
        runtime_python_entry.node_digest = runtime_python_entry.computed_node_digest().unwrap();
        let mut runtime_bin_entry = ManifestEntryV1 {
            relative_path: b"bin".to_vec(),
            metadata: metadata(0o040_755, 0, 2),
            payload: ManifestPayloadV1::Directory {
                children: vec![ChildCommitmentV1 {
                    name: b"python".to_vec(),
                    kind: ManifestEntryKindV1::Regular,
                    node_digest: runtime_python_entry.node_digest,
                }],
            },
            hardlink_group: None,
            node_digest: digest!(NodeDigest, "placeholder-runtime-bin"),
        };
        runtime_bin_entry.node_digest = runtime_bin_entry.computed_node_digest().unwrap();
        let mut runtime_root_entry = ManifestEntryV1 {
            relative_path: Vec::new(),
            metadata: metadata(0o040_755, 0, 2),
            payload: ManifestPayloadV1::Directory {
                children: vec![ChildCommitmentV1 {
                    name: b"bin".to_vec(),
                    kind: ManifestEntryKindV1::Directory,
                    node_digest: runtime_bin_entry.node_digest,
                }],
            },
            hardlink_group: None,
            node_digest: digest!(NodeDigest, "placeholder-runtime"),
        };
        runtime_root_entry.node_digest = runtime_root_entry.computed_node_digest().unwrap();
        let runtime_tree = TreeManifestV1 {
            mount_path: SandboxPath::new(b"/workspace/.venv".to_vec().into_boxed_slice()).unwrap(),
            tree_role: TreeRoleV1::Runtime,
            root_digest: runtime_root_entry.node_digest,
            entries: vec![runtime_root_entry, runtime_bin_entry, runtime_python_entry],
        };

        let mut external = ManifestEntryV1 {
            relative_path: b".venv".to_vec(),
            metadata: metadata(0o040_555, 0, 2),
            payload: ManifestPayloadV1::ExternalTree {
                tree_role: TreeRoleV1::Runtime,
                target_root: runtime_tree.root_digest,
                readonly: true,
            },
            hardlink_group: None,
            node_digest: digest!(NodeDigest, "placeholder-external"),
        };
        external.node_digest = external.computed_node_digest().unwrap();
        let mut workspace_root_entry = ManifestEntryV1 {
            relative_path: Vec::new(),
            metadata: metadata(0o040_755, 0, 3),
            payload: ManifestPayloadV1::Directory {
                children: vec![ChildCommitmentV1 {
                    name: b".venv".to_vec(),
                    kind: ManifestEntryKindV1::ExternalTree,
                    node_digest: external.node_digest,
                }],
            },
            hardlink_group: None,
            node_digest: digest!(NodeDigest, "placeholder-workspace"),
        };
        workspace_root_entry.node_digest = workspace_root_entry.computed_node_digest().unwrap();
        let workspace_tree = TreeManifestV1 {
            mount_path: SandboxPath::new(b"/workspace".to_vec().into_boxed_slice()).unwrap(),
            tree_role: TreeRoleV1::Workspace,
            root_digest: workspace_root_entry.node_digest,
            entries: vec![workspace_root_entry, external],
        };
        let runtime_trees = vec![runtime_tree];
        let workspace_root = MerkleRoot::derive(
            WORKSPACE_MERKLE_DOMAIN,
            &[workspace_tree.root_digest.as_bytes()],
        );
        let runtime_forest = canonical::encode_runtime_forest_for_hash(&runtime_trees).unwrap();
        let runtime_root = MerkleRoot::derive(RUNTIME_MERKLE_DOMAIN, &[&runtime_forest]);
        SnapshotManifestV1 {
            schema: SNAPSHOT_MANIFEST_V1_SCHEMA.to_owned(),
            profile_digest: profile_digest(),
            workspace_identity: digest!(WorkspaceIdentity, "workspace"),
            workspace_tree,
            runtime_trees,
            workspace_root,
            runtime_root,
        }
    }

    fn complete_trace() -> TraceCompletenessV2 {
        TraceCompletenessV2 {
            required: EffectBitmap::REQUIRED_V2,
            complete: EffectBitmap::REQUIRED_V2,
            unsupported: EffectBitmap::EMPTY,
            violation: EffectBitmap::EMPTY,
            counters: TraceCountersV1 {
                final_sequence: 3,
                event_count: 3,
                syscall_event_count: 3,
                seccomp_trace_count: 3,
                ptrace_event_count: 3,
                trace_encoded_bytes: 100,
                task_birth_count: 1,
                task_exec_count: 1,
                task_exit_count: 1,
                task_reap_count: 1,
                observation_count: 1,
                ambient_event_count: 1,
                ordered_effect_count: 1,
                denied_operation_count: 0,
                unsupported_operation_count: 0,
                decoder_error_count: 0,
                lost_event_count: 0,
                final_ack_count: 1,
            },
            first_failure: None,
        }
    }

    fn executable_chain(manifest: &SnapshotManifestV1) -> identity::ExecutableChainV1 {
        let path =
            SandboxPath::new(b"/workspace/.venv/bin/python".to_vec().into_boxed_slice()).unwrap();
        let node_digest = manifest
            .runtime_trees
            .iter()
            .find(|tree| tree.mount_path.as_bytes() == b"/workspace/.venv")
            .and_then(|tree| {
                tree.entries
                    .iter()
                    .find(|entry| entry.relative_path == b"bin/python")
            })
            .expect("runtime Python fixture")
            .node_digest;
        identity::ExecutableChainV1::new(
            path.clone(),
            vec![identity::ExecutableHopV1::terminal_regular(path, node_digest).unwrap()],
        )
        .unwrap()
    }

    fn record() -> EffectRecordV2 {
        let profile_digest = profile_digest();
        let workspace_identity = digest!(WorkspaceIdentity, "workspace");
        let invocation = PytestInvocationIdentityV1 {
            argv: vec![
                b".venv/bin/python".to_vec(),
                b"-I".to_vec(),
                b"-m".to_vec(),
                b"pytest".to_vec(),
                b"tests/test_unit.py::test_one".to_vec(),
            ],
            cwd: b".".to_vec(),
            selectors: vec![PytestSelectorV1::parse(b"tests/test_unit.py::test_one").unwrap()],
            stdin_profile: StdinProfileV1::ClosedEof,
        };
        let policy_digests = policy_digests();
        let (environment, _) = bound_environment();
        let manifest = manifest();
        let executable_chain = executable_chain(&manifest);
        let executable_chain_witness = executable_chain.canonical_bytes().unwrap();
        let executable_chain_digest = executable_chain.digest().unwrap();
        let verified_manifest = VerifiedSnapshotManifestV1::from_manifest(manifest).unwrap();
        let sealed_snapshot = SealedSnapshotIdentityV2 {
            snapshot_id: SnapshotId::from_bytes([2; 16]),
            workspace_root: verified_manifest.manifest().workspace_root,
            runtime_root: verified_manifest.manifest().runtime_root,
            manifest_blob: verified_manifest.blob().clone(),
            profile_digest,
        };
        let platform = PlatformIdentityV2 {
            architecture: ArchitectureV1::X86_64,
            kernel_release: b"fixture".to_vec(),
            capability_digest: digest!(CapabilityDigest, "capability"),
            namespace_ids: NamespaceIdsV1 {
                user: 4_026_533_000,
                mount: 4_026_533_001,
                pid: 4_026_533_002,
                network: 4_026_533_003,
                uts: 4_026_533_004,
                ipc: 4_026_533_005,
            },
            namespace_policy_digest: digest!(PolicyDigest, "namespace-policy"),
            policy_digests,
        };
        let shape = ShapeV1 {
            schema: LINUX_PYTEST_SHAPE_V1_SCHEMA.to_owned(),
            profile_id: LINUX_PYTEST_PROFILE_ID.to_owned(),
            profile_digest,
            workspace_identity,
            invocation: invocation.clone(),
            environment: environment.clone(),
            resolved_selector_targets: vec![
                SandboxPath::new(b"/workspace/tests/test_unit.py".to_vec().into_boxed_slice())
                    .unwrap(),
            ],
            executable_chain_digest,
            executable_chain_witness,
            runtime_root: sealed_snapshot.runtime_root,
            architecture: platform.architecture,
            capability_digest: platform.capability_digest,
            namespace_policy_digest: platform.namespace_policy_digest,
            policy_digests: platform.policy_digests.clone(),
        };
        let observations = vec![ObservationV2 {
            sequence: 1,
            logical_task_id: LogicalTaskId(1),
            kind: ObservationKindV2::File,
            sandbox_subject: SandboxPath::new(
                b"/workspace/tests/test_unit.py".to_vec().into_boxed_slice(),
            )
            .unwrap(),
            canonical_detail: ObservationDetailV1::File {
                content_digest: digest!(FileContentDigest, "observation"),
                byte_count: 10,
            },
        }];
        let observation_closure = ObservationClosureV1::from_observations(&observations).unwrap();
        let shape_key = shape.key().unwrap();
        let request_key = shape.request_key(&observation_closure).unwrap();
        EffectRecordV2 {
            schema: EFFECT_IR_V2_SCHEMA.to_owned(),
            record_id: RecordId::from_bytes([1; 16]),
            profile_id: LINUX_PYTEST_PROFILE_ID.to_owned(),
            profile_digest,
            shape_key,
            request_key,
            invocation,
            workspace_identity,
            environment,
            sealed_snapshot,
            platform,
            trace: complete_trace(),
            observations,
            ambient_events: vec![AmbientEventV2 {
                sequence: 2,
                logical_task_id: LogicalTaskId(1),
                kind: AmbientKindV2::LogicalTime,
                canonical_detail: blob("ambient", 8),
            }],
            ordered_effects: vec![OrderedEffectV2 {
                sequence: 3,
                logical_task_id: LogicalTaskId(1),
                kind: EffectKindV2::Write,
                sandbox_subject: SandboxPath::new(
                    b"/workspace/.pytest_cache/state"
                        .to_vec()
                        .into_boxed_slice(),
                )
                .unwrap(),
                canonical_detail: blob("effect", 9),
            }],
            final_workspace_root: digest!(MerkleRoot, "final-root"),
            result: EffectResultV2 {
                stdout: StreamCaptureV2::Complete {
                    blob: blob("stdout", 2),
                },
                stderr: StreamCaptureV2::Complete {
                    blob: blob("stderr", 0),
                },
                raw_linux_wait_status: RawLinuxWaitStatusV1::exited(0),
            },
            disposition: EffectRecordDispositionV2::PrimaryCandidate,
            disposition_reason: None,
            primary_record_id: None,
            created_monotonic_ns: MonotonicNs(10),
            shape,
            observation_closure,
        }
    }

    fn sealed_snapshot() -> SealedSnapshot {
        let manifest = VerifiedSnapshotManifestV1::from_manifest(manifest()).unwrap();
        let identity = SealedSnapshotIdentityV2 {
            snapshot_id: SnapshotId::from_bytes([2; 16]),
            workspace_root: manifest.manifest().workspace_root,
            runtime_root: manifest.manifest().runtime_root,
            manifest_blob: manifest.blob().clone(),
            profile_digest: profile_digest(),
        };
        SealedSnapshot::from_owned_directories(
            identity,
            manifest,
            std::fs::File::open("/").unwrap().into(),
            std::fs::File::open("/").unwrap().into(),
        )
        .unwrap()
    }

    fn admitted() -> AdmittedPytest {
        let record = record();
        let (environment_binding, environment) = bound_environment();
        assert_eq!(record.environment, environment_binding);
        AdmittedPytest {
            invocation: record.invocation,
            workspace_root: PathBuf::from("/fixture/workspace"),
            shape: record.shape,
            shape_key: record.shape_key,
            environment,
        }
    }

    fn prepared() -> PreparedPytest {
        PreparedPytest::new(sealed_snapshot(), admitted()).unwrap()
    }

    fn candidate_pair(index: u64, promoted_monotonic_ns: u64) -> PromotedCandidateV2 {
        fn record_id(prefix: u8, index: u64) -> RecordId {
            let mut bytes = [0; 16];
            bytes[0] = prefix;
            bytes[8..].copy_from_slice(&index.to_be_bytes());
            RecordId::from_bytes(bytes)
        }

        let value = index.to_be_bytes();
        let mut primary_record = record();
        primary_record.record_id = record_id(1, index);
        primary_record.observations[0].canonical_detail = ObservationDetailV1::File {
            content_digest: FileContentDigest::derive(
                "again linux pytest lookup fixture v1",
                &[&value],
            ),
            byte_count: 10,
        };
        primary_record.observation_closure =
            ObservationClosureV1::from_observations(&primary_record.observations).unwrap();
        primary_record.request_key = primary_record
            .shape
            .request_key(&primary_record.observation_closure)
            .unwrap();

        let mut shadow_record = primary_record.clone();
        shadow_record.record_id = record_id(2, index);
        shadow_record.disposition = EffectRecordDispositionV2::ShadowCandidate;
        shadow_record.primary_record_id = Some(primary_record.record_id);

        let primary = verified_candidate(primary_record);
        let shadow = verified_candidate(shadow_record);
        let pair =
            PromotedPairV2::new(&primary, &shadow, MonotonicNs(promoted_monotonic_ns)).unwrap();
        PromotedCandidateV2::new(pair, primary, shadow).unwrap()
    }

    fn shape() -> ShapeV1 {
        record().shape
    }

    fn verified_candidate(record: EffectRecordV2) -> VerifiedCandidateRecordV2 {
        VerifiedCandidateRecordV2::new(
            CanonicalEffectRecordV2::from_record(record).unwrap(),
            VerifiedSnapshotManifestV1::from_manifest(manifest()).unwrap(),
        )
        .unwrap()
    }

    fn observation_closure() -> ObservationClosureV1 {
        ObservationClosureV1::new(vec![
            ObservationDependencyV1 {
                key: b"members".to_vec(),
                kind: ObservationKindV2::Directory,
                subject: SandboxPath::new(b"/workspace/tests".to_vec().into_boxed_slice()).unwrap(),
                current_value: blob("directory-members", 25),
            },
            ObservationDependencyV1 {
                key: b"bytes".to_vec(),
                kind: ObservationKindV2::File,
                subject: SandboxPath::new(
                    b"/workspace/tests/test_unit.py".to_vec().into_boxed_slice(),
                )
                .unwrap(),
                current_value: blob("test-file", 400),
            },
        ])
        .unwrap()
    }

    #[test]
    fn bitmap_is_exact_lower_hex_and_all_dimensions_are_unique() {
        let encoded = serde_json::to_string(&EffectBitmap::REQUIRED_V2).unwrap();
        assert_eq!(encoded, "\"00000000ffffffff\"");
        assert!(serde_json::from_str::<EffectBitmap>("\"00000000FFFFFFFF\"").is_err());
        assert!(serde_json::from_str::<EffectBitmap>("4294967295").is_err());
        let mut combined = 0u64;
        for (index, dimension) in CompletenessDimensionV2::ALL.into_iter().enumerate() {
            assert_eq!(dimension as usize, index);
            assert_eq!(combined & dimension.bit(), 0);
            assert!(!dimension.name().is_empty());
            combined |= dimension.bit();
        }
        assert_eq!(combined, EFFECT_IR_V2_REQUIRED_MASK);
    }

    #[test]
    fn selector_parser_and_wait_words_match_the_frozen_grammar() {
        let parsed = PytestSelectorV1::parse(b"tests/test_unit.py::Suite::test_one").unwrap();
        assert_eq!(parsed.path(), b"tests/test_unit.py");
        assert_eq!(parsed.nodes(), &[b"Suite".to_vec(), b"test_one".to_vec()]);
        assert_eq!(parsed.raw(), b"tests/test_unit.py::Suite::test_one");

        for invalid in [
            b"".as_slice(),
            b"-q",
            b"@args.txt",
            b"/tmp/test.py",
            b"../test.py",
            b"tests/./test.py",
            b"tests//test.py",
            b"tests/test.py::",
        ] {
            assert!(PytestSelectorV1::parse(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(
            PytestSelectorV1::parse(&[0xff]),
            Err(RefusalCode::SelectorNonUtf8)
        );

        for valid in [0x0000, 0x0100, 0x7f00, 0x0001, 0x0081, 0x0040] {
            assert!(RawLinuxWaitStatusV1(valid).is_final(), "{valid:#x}");
        }
        for invalid in [0x0080, 0x0101, 0x007f, 0xffff, 0x1_0000, 0x0041] {
            assert!(!RawLinuxWaitStatusV1(invalid).is_final(), "{invalid:#x}");
        }
    }

    #[test]
    fn record_validation_recomputes_keys_and_global_trace_relations() {
        let mut forged = record();
        forged.shape_key = digest!(ShapeKey, "forged-shape");
        assert!(forged.validate().is_err());

        let mut forged = record();
        forged.request_key = digest!(RequestKey, "forged-request");
        assert!(forged.validate().is_err());

        let mut forged = record();
        forged.sealed_snapshot.profile_digest = digest!(ProfileDigest, "other-profile");
        assert!(forged.validate().is_err());

        let mut forged = record();
        forged.ambient_events[0].sequence = forged.observations[0].sequence;
        assert!(forged.validate().is_err());

        let mut forged = record();
        forged.observations[0].sequence = 0;
        assert!(forged.validate().is_err());

        let mut forged = record();
        forged.trace.counters.task_birth_count = LINUX_PYTEST_V1_MAX_DESCENDANT_TASKS + 1;
        assert!(forged.validate().is_err());

        let mut forged = record();
        forged.trace.counters.ptrace_event_count = 2;
        assert!(forged.validate().is_err());

        let mut forged = record();
        forged.result.stdout = StreamCaptureV2::Complete {
            blob: blob("too-large", LINUX_PYTEST_V1_MAX_STREAM_BYTES + 1),
        };
        assert!(forged.validate().is_err());
    }

    #[test]
    fn typed_observation_details_have_total_dependency_projection() {
        let details = vec![
            ObservationDetailV1::File {
                content_digest: digest!(FileContentDigest, "file"),
                byte_count: 10,
            },
            ObservationDetailV1::Directory {
                membership_digest: digest!(BlobDigest, "members"),
                entry_count: 3,
            },
            ObservationDetailV1::AbsentPath {
                parent_membership_digest: digest!(BlobDigest, "parent"),
                missing_component: b"missing.py".to_vec(),
            },
            ObservationDetailV1::Symlink {
                target: b"../target".to_vec(),
            },
            ObservationDetailV1::Executable {
                node_digest: digest!(NodeDigest, "executable"),
                chain_digest: digest!(ExecutableChainDigest, "chain"),
            },
            ObservationDetailV1::Mapping {
                content_digest: digest!(FileContentDigest, "mapping"),
                offset: 4096,
                length: 8192,
                protection: 5,
                flags: 2,
            },
            ObservationDetailV1::Metadata {
                field_mask: 0x101,
                value_digest: digest!(BlobDigest, "metadata"),
            },
        ];
        let observations = details
            .iter()
            .enumerate()
            .map(|(index, detail)| {
                let bytes = canonical::encode_observation_detail_top(detail).unwrap();
                assert_eq!(
                    canonical::decode_observation_detail_top(&bytes).unwrap(),
                    detail.clone()
                );
                ObservationV2 {
                    sequence: u64::try_from(index + 1).unwrap(),
                    logical_task_id: LogicalTaskId(1),
                    kind: detail.kind(),
                    sandbox_subject: SandboxPath::new(
                        format!("/workspace/subject-{index}")
                            .into_bytes()
                            .into_boxed_slice(),
                    )
                    .unwrap(),
                    canonical_detail: detail.clone(),
                }
            })
            .collect::<Vec<_>>();
        let closure = ObservationClosureV1::from_observations(&observations).unwrap();
        assert_eq!(closure.dependencies().len(), details.len());
        assert!(
            closure
                .dependencies()
                .iter()
                .all(|dependency| valid_observation_dependency_key(
                    dependency.kind,
                    &dependency.key
                ))
        );

        let mut malformed = details[6].clone();
        if let ObservationDetailV1::Metadata { field_mask, .. } = &mut malformed {
            *field_mask = 1 << 63;
        }
        assert!(malformed.validate().is_err());
    }

    #[test]
    fn canonical_decoder_rejects_allocation_amplification_headers() {
        let mut excessive_list = observation_closure().canonical_bytes().unwrap();
        let list_count_offset = EFFECT_IR_V2_WIRE_MAGIC.len() + 6 + 11;
        excessive_list[list_count_offset..list_count_offset + 8]
            .copy_from_slice(&(EFFECT_IR_V2_MAX_COLLECTION_ITEMS + 1).to_be_bytes());
        assert_eq!(
            ObservationClosureV1::from_canonical_bytes(&excessive_list),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );

        let mut excessive_fields = shape().canonical_bytes().unwrap();
        let field_count_offset = EFFECT_IR_V2_WIRE_MAGIC.len() + 4;
        excessive_fields[field_count_offset..field_count_offset + 2]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            ShapeV1::from_canonical_bytes(&excessive_fields),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );
    }

    #[test]
    fn strict_roundtrip_rejects_unknown_fields_and_unknown_bits() {
        let record = record();
        record.validate().unwrap();
        let encoded = serde_json::to_vec(&record).unwrap();
        assert_eq!(
            serde_json::from_slice::<EffectRecordV2>(&encoded).unwrap(),
            record
        );

        let mut value = serde_json::to_value(&record).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EffectRecordV2>(value).is_err());

        let mut invalid = record;
        invalid.trace.complete = EffectBitmap::from_bits(1u64 << 63);
        assert_eq!(
            invalid.validate(),
            Err(LinuxPytestContractError::InvalidCompletenessMasks)
        );
        assert!(!invalid.is_complete_candidate());
    }

    #[test]
    fn comparison_digest_excludes_only_record_lifecycle_fields() {
        let first = record();
        let mut second = first.clone();
        second.record_id = RecordId::new_test();
        second.created_monotonic_ns.0 += 1;
        second.disposition = EffectRecordDispositionV2::ShadowCandidate;
        second.primary_record_id = Some(first.record_id);
        second.platform.namespace_ids.user = 4_026_533_999;
        assert_eq!(
            first.semantic_comparison_digest().unwrap(),
            second.semantic_comparison_digest().unwrap()
        );
        second.result.stdout = StreamCaptureV2::Complete {
            blob: blob("changed", 2),
        };
        assert_ne!(
            first.semantic_comparison_digest().unwrap(),
            second.semantic_comparison_digest().unwrap()
        );
    }

    #[test]
    fn pair_attestation_requires_equal_views_but_commits_both_immutable_records() {
        let primary = record();
        let mut shadow = primary.clone();
        shadow.record_id = RecordId::from_bytes([3; 16]);
        shadow.disposition = EffectRecordDispositionV2::ShadowCandidate;
        shadow.primary_record_id = Some(primary.record_id);
        shadow.created_monotonic_ns = MonotonicNs(99);
        shadow.platform.namespace_ids.user += 10;
        let primary = verified_candidate(primary);
        let shadow = verified_candidate(shadow);
        let pair = PromotedPairV2::new(&primary, &shadow, MonotonicNs(100)).unwrap();
        assert_ne!(
            pair.primary_record_blob().digest,
            pair.shadow_record_blob().digest
        );
        assert_eq!(
            canonical::pair_comparison_digest(&shadow, &primary),
            Err(LinuxPytestContractError::ComparisonMismatch)
        );

        let second_primary = verified_candidate(primary.record().clone());
        assert_eq!(
            canonical::pair_comparison_digest(&primary, &second_primary),
            Err(LinuxPytestContractError::ComparisonMismatch)
        );

        let mut wrong_link = shadow.record().clone();
        wrong_link.primary_record_id = Some(RecordId::from_bytes([9; 16]));
        let wrong_link = verified_candidate(wrong_link);
        assert_eq!(
            canonical::pair_comparison_digest(&primary, &wrong_link),
            Err(LinuxPytestContractError::ComparisonMismatch)
        );

        let mut changed_shadow = shadow.record().clone();
        changed_shadow.result.stdout = StreamCaptureV2::Complete {
            blob: blob("different-stdout", 2),
        };
        let changed_shadow = verified_candidate(changed_shadow);
        assert_eq!(
            canonical::pair_comparison_digest(&primary, &changed_shadow),
            Err(LinuxPytestContractError::ComparisonMismatch)
        );
    }

    #[test]
    fn debug_and_json_have_no_raw_environment_value_field() {
        let json = serde_json::to_string(&record()).unwrap();
        assert!(!json.contains("environment_value"));
        assert!(!json.contains("SUPER_SECRET"));
        assert!(format!("{ContractOnlyProfile:?}").contains("ContractOnlyProfile"));
    }

    #[test]
    fn contract_only_admission_refuses_without_execution() {
        let argv = vec![OsString::from(".venv/bin/python")];
        let profile = ContractOnlyProfile;
        let error = profile
            .parse_lexical(AdmissionInput {
                argv: &argv,
                cwd: Path::new("/workspace"),
                workspace_root: Path::new("/workspace"),
                stdio: StdioFacts {
                    stdin: StdinKind::Closed,
                    stdout_is_tty: false,
                    stderr_is_tty: false,
                },
                environment: &[],
            })
            .unwrap_err();
        assert_eq!(
            error,
            ProfileFailure::Refused {
                code: RefusalCode::ProfileDisabled
            }
        );
    }

    #[test]
    fn canonical_record_and_comparison_views_use_tagged_binary_bytes() {
        let record = record();
        let canonical = record.canonical_bytes().unwrap();
        let comparison = record.comparison_view_bytes().unwrap();
        assert!(canonical.starts_with(EFFECT_IR_V2_WIRE_MAGIC));
        assert!(comparison.starts_with(EFFECT_IR_V2_WIRE_MAGIC));
        assert_ne!(canonical, serde_json::to_vec(&record).unwrap());
        assert_eq!(canonical, record.canonical_bytes().unwrap());
        assert_eq!(
            EffectRecordV2::from_canonical_bytes(&canonical).unwrap(),
            record
        );
        assert_eq!(
            blake3::hash(&canonical).to_hex().to_string(),
            "10e5cc32af103e9f634c27eebe6c718c67ba3ba44373e35b6c32778527e3577e"
        );
        assert_eq!(
            blake3::hash(&comparison).to_hex().to_string(),
            "b883648f1806c78212cd794802f01e481b57f9ac934ca1b91352aec02374f349"
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            EffectRecordV2::from_canonical_bytes(&trailing),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );
        let mut unknown_version = canonical.clone();
        unknown_version[EFFECT_IR_V2_WIRE_MAGIC.len() + 3] ^= 1;
        assert_eq!(
            EffectRecordV2::from_canonical_bytes(&unknown_version),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );
        for length in 0..canonical.len() {
            assert!(EffectRecordV2::from_canonical_bytes(&canonical[..length]).is_err());
        }
    }

    #[test]
    fn snapshot_manifest_commits_raw_tree_shape_and_rejects_drift() {
        let manifest = manifest();
        manifest.validate().unwrap();
        let canonical = manifest.canonical_bytes().unwrap();
        assert!(canonical.starts_with(EFFECT_IR_V2_WIRE_MAGIC));
        assert_eq!(canonical, manifest.canonical_bytes().unwrap());
        assert_eq!(
            SnapshotManifestV1::from_canonical_bytes(&canonical).unwrap(),
            manifest
        );
        assert_eq!(
            blake3::hash(&canonical).to_hex().to_string(),
            "52e87ad307267ad0452e4310023e48431b2f32c8475be13f00fb84250095c747"
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            SnapshotManifestV1::from_canonical_bytes(&trailing),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );
        let mut unknown_version = canonical.clone();
        unknown_version[EFFECT_IR_V2_WIRE_MAGIC.len() + 3] ^= 1;
        assert_eq!(
            SnapshotManifestV1::from_canonical_bytes(&unknown_version),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );
        for length in 0..canonical.len() {
            assert!(SnapshotManifestV1::from_canonical_bytes(&canonical[..length]).is_err());
        }

        let mut changed = manifest;
        changed.workspace_tree.entries[1].relative_path = b"renamed".to_vec();
        assert_eq!(
            changed.validate(),
            Err(LinuxPytestContractError::MalformedManifest)
        );
    }

    #[test]
    fn hardlink_groups_require_identical_inode_commitments() {
        let member_paths = [b"a".as_slice(), b"b".as_slice()];
        let encoded_paths = canonical::encode_paths_for_hash(&member_paths).unwrap();
        let group = HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[&encoded_paths]);
        let make_member = |path: &[u8], content: &str| {
            let mut entry = ManifestEntryV1 {
                relative_path: path.to_vec(),
                metadata: metadata(0o100_444, 1, 2),
                payload: ManifestPayloadV1::Regular {
                    content_digest: digest!(FileContentDigest, content),
                    data_extents: vec![ExtentV1 {
                        offset: 0,
                        length: 1,
                    }],
                },
                hardlink_group: Some(group),
                node_digest: digest!(NodeDigest, "placeholder-hardlink"),
            };
            entry.node_digest = entry.computed_node_digest().unwrap();
            entry
        };
        let first = make_member(b"a", "same");
        let second = make_member(b"b", "same");
        assert_eq!(first.node_digest, second.node_digest);
        let mut root = ManifestEntryV1 {
            relative_path: Vec::new(),
            metadata: metadata(0o040_555, 0, 2),
            payload: ManifestPayloadV1::Directory {
                children: vec![
                    ChildCommitmentV1 {
                        name: b"a".to_vec(),
                        kind: ManifestEntryKindV1::Regular,
                        node_digest: first.node_digest,
                    },
                    ChildCommitmentV1 {
                        name: b"b".to_vec(),
                        kind: ManifestEntryKindV1::Regular,
                        node_digest: second.node_digest,
                    },
                ],
            },
            hardlink_group: None,
            node_digest: digest!(NodeDigest, "placeholder-hardlink-root"),
        };
        root.node_digest = root.computed_node_digest().unwrap();
        let mut tree = TreeManifestV1 {
            mount_path: SandboxPath::new(b"/usr".to_vec().into_boxed_slice()).unwrap(),
            tree_role: TreeRoleV1::Runtime,
            root_digest: root.node_digest,
            entries: vec![root, first, second],
        };
        tree.validate().unwrap();

        tree.entries[2] = make_member(b"b", "different");
        let changed_digest = tree.entries[2].node_digest;
        let ManifestPayloadV1::Directory { children } = &mut tree.entries[0].payload else {
            unreachable!();
        };
        children[1].node_digest = changed_digest;
        tree.entries[0].node_digest = tree.entries[0].computed_node_digest().unwrap();
        tree.root_digest = tree.entries[0].node_digest;
        assert_eq!(
            tree.validate(),
            Err(LinuxPytestContractError::MalformedManifest)
        );
    }

    #[test]
    fn runtime_mounts_reject_shadowing_and_unbound_workspace_mounts() {
        let mut overlapping = manifest();
        let template = overlapping.runtime_trees[0].clone();
        let mut usr = template.clone();
        usr.mount_path = SandboxPath::new(b"/usr".to_vec().into_boxed_slice()).unwrap();
        let mut usr_lib = template.clone();
        usr_lib.mount_path = SandboxPath::new(b"/usr/lib".to_vec().into_boxed_slice()).unwrap();
        overlapping.runtime_trees.extend([usr, usr_lib]);
        overlapping
            .runtime_trees
            .sort_by(|left, right| left.mount_path.as_bytes().cmp(right.mount_path.as_bytes()));
        let forest = canonical::encode_runtime_forest_for_hash(&overlapping.runtime_trees).unwrap();
        overlapping.runtime_root = MerkleRoot::derive(RUNTIME_MERKLE_DOMAIN, &[&forest]);
        assert_eq!(
            overlapping.validate(),
            Err(LinuxPytestContractError::MalformedManifest)
        );

        let mut unbound = manifest();
        let mut extra = unbound.runtime_trees[0].clone();
        extra.mount_path =
            SandboxPath::new(b"/workspace/unbound".to_vec().into_boxed_slice()).unwrap();
        unbound.runtime_trees.push(extra);
        unbound
            .runtime_trees
            .sort_by(|left, right| left.mount_path.as_bytes().cmp(right.mount_path.as_bytes()));
        let forest = canonical::encode_runtime_forest_for_hash(&unbound.runtime_trees).unwrap();
        unbound.runtime_root = MerkleRoot::derive(RUNTIME_MERKLE_DOMAIN, &[&forest]);
        assert_eq!(
            unbound.validate(),
            Err(LinuxPytestContractError::MalformedManifest)
        );
    }

    #[test]
    fn environment_binding_is_keyed_order_independent_and_redacted() {
        let key = EnvironmentKeyMaterialV1::from_bytes([7; 32]);
        let policy = digest!(PolicyDigest, "environment-policy");
        let first = vec![
            (OsString::from("SAFE_B"), OsString::from("SUPER_SECRET_B")),
            (OsString::from("SAFE_A"), OsString::from("SUPER_SECRET_A")),
        ];
        let second = vec![first[1].clone(), first[0].clone()];
        let (first_binding, first_secret) =
            SecretEnvironment::bind_v1(&first, &key, policy).unwrap();
        let (second_binding, second_secret) =
            SecretEnvironment::bind_v1(&second, &key, policy).unwrap();
        assert_eq!(first_binding, second_binding);
        assert_eq!(
            first_secret.entries().count(),
            second_secret.entries().count()
        );
        let diagnostic = serde_json::to_string(&first_binding).unwrap();
        assert!(!diagnostic.contains("SUPER_SECRET"));
        assert!(!format!("{key:?}").contains("070707"));

        let profile_override = vec![(
            OsString::from("PYTHONHASHSEED"),
            OsString::from("attacker-value"),
        )];
        let (_, normalized) = SecretEnvironment::bind_v1(&profile_override, &key, policy).unwrap();
        assert_eq!(
            normalized
                .entries()
                .find(|(name, _)| *name == b"PYTHONHASHSEED")
                .map(|(_, value)| value),
            Some(b"0".as_slice())
        );
        assert!(
            normalized
                .entries()
                .all(|(_, value)| value != b"attacker-value")
        );

        let duplicate = vec![
            (OsString::from("SAFE_A"), OsString::from("one")),
            (OsString::from("SAFE_A"), OsString::from("two")),
        ];
        assert_eq!(
            SecretEnvironment::bind_v1(&duplicate, &key, policy).unwrap_err(),
            ProfileFailure::Refused {
                code: RefusalCode::EnvironmentMalformed
            }
        );

        let forbidden = vec![(OsString::from("LD_PRELOAD"), OsString::from("/tmp/x"))];
        assert_eq!(
            SecretEnvironment::bind_v1(&forbidden, &key, policy).unwrap_err(),
            ProfileFailure::Refused {
                code: RefusalCode::LoaderInjectionEnvironment
            }
        );
    }

    #[test]
    fn shape_and_observation_closure_are_canonical_and_drive_request_identity() {
        let shape = shape();
        let closure = observation_closure();
        assert_eq!(closure.dependencies()[0].kind, ObservationKindV2::File);
        assert_eq!(closure.dependencies()[1].kind, ObservationKindV2::Directory);

        let shape_bytes = shape.canonical_bytes().unwrap();
        let closure_bytes = closure.canonical_bytes().unwrap();
        assert_eq!(ShapeV1::from_canonical_bytes(&shape_bytes).unwrap(), shape);
        assert_eq!(
            ObservationClosureV1::from_canonical_bytes(&closure_bytes).unwrap(),
            closure
        );
        assert_eq!(
            blake3::hash(&shape_bytes).to_hex().to_string(),
            "89ac44956175ade521cc04ff8711e4d27f2c3979dfbce6156dcca9e07636ad3d"
        );
        assert_eq!(
            blake3::hash(&closure_bytes).to_hex().to_string(),
            "423bf57cf6bd71b7529d24c712fd6fe83835947bc233df52f991c5051ea15ac4"
        );
        assert_eq!(shape.key().unwrap(), shape.key().unwrap());
        assert_eq!(
            shape.request_key(&closure).unwrap(),
            shape.request_key(&closure).unwrap()
        );

        let duplicate = closure.dependencies()[0].clone();
        let merged = ObservationClosureV1::new(vec![duplicate.clone(), duplicate.clone()]).unwrap();
        assert_eq!(merged.dependencies(), &[duplicate.clone()]);
        let mut conflicting = duplicate;
        conflicting.current_value = blob("different-current-value", 1);
        assert_eq!(
            ObservationClosureV1::new(vec![merged.dependencies()[0].clone(), conflicting]),
            Err(LinuxPytestContractError::MalformedLookupIdentity)
        );

        let original_shape_key = shape.key().unwrap();
        let original_request_key = shape.request_key(&closure).unwrap();
        assert_eq!(
            original_shape_key.to_hex(),
            "bc49db9c18ffaced96fb7383e73ec3f1a16e9eb6ecf11644e6937d3b12169d4c"
        );
        assert_eq!(
            original_request_key.to_hex(),
            "0e169a17bebc5432db5c83c030dc6bb5d27eac217f744e4afb7b56577f2a2c20"
        );
        let mut changed_shape = shape.clone();
        changed_shape.runtime_root = digest!(MerkleRoot, "changed-runtime");
        assert_ne!(changed_shape.key().unwrap(), original_shape_key);

        let mut changed_dependencies = closure.dependencies().to_vec();
        changed_dependencies[0].current_value = blob("changed-file", 400);
        let changed_closure = ObservationClosureV1::new(changed_dependencies).unwrap();
        assert_eq!(shape.key().unwrap(), original_shape_key);
        assert_ne!(
            shape.request_key(&changed_closure).unwrap(),
            original_request_key
        );

        let mut trailing = closure_bytes.clone();
        trailing.push(0);
        assert_eq!(
            ObservationClosureV1::from_canonical_bytes(&trailing),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );
        for length in 0..shape_bytes.len() {
            assert!(ShapeV1::from_canonical_bytes(&shape_bytes[..length]).is_err());
        }
    }

    #[test]
    fn executable_chain_and_profile_commitment_are_not_self_asserted() {
        let mut malformed = shape();
        malformed.executable_chain_witness[0] ^= 1;
        assert_eq!(
            malformed.validate(),
            Err(LinuxPytestContractError::CanonicalDecoding)
        );

        let mut wrong_policy = shape();
        wrong_policy.policy_digests.seccomp = digest!(PolicyDigest, "other-seccomp");
        assert_eq!(
            wrong_policy.validate(),
            Err(LinuxPytestContractError::MalformedLookupIdentity)
        );

        let path =
            SandboxPath::new(b"/workspace/.venv/bin/python".to_vec().into_boxed_slice()).unwrap();
        let wrong_chain = identity::ExecutableChainV1::new(
            path.clone(),
            vec![
                identity::ExecutableHopV1::terminal_regular(
                    path,
                    digest!(NodeDigest, "wrong-runtime-python"),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let mut forged = record();
        forged.shape.executable_chain_digest = wrong_chain.digest().unwrap();
        forged.shape.executable_chain_witness = wrong_chain.canonical_bytes().unwrap();
        forged.shape_key = forged.shape.key().unwrap();
        forged.request_key = forged
            .shape
            .request_key(&forged.observation_closure)
            .unwrap();
        forged.validate().unwrap();
        assert!(
            VerifiedCandidateRecordV2::new(
                CanonicalEffectRecordV2::from_record(forged).unwrap(),
                VerifiedSnapshotManifestV1::from_manifest(manifest()).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn manifests_prepared_execution_and_candidates_are_cross_bound() {
        let verified_manifest = VerifiedSnapshotManifestV1::from_manifest(manifest()).unwrap();
        let nil_identity = SealedSnapshotIdentityV2 {
            snapshot_id: SnapshotId::from_bytes([0; 16]),
            workspace_root: verified_manifest.manifest().workspace_root,
            runtime_root: verified_manifest.manifest().runtime_root,
            manifest_blob: verified_manifest.blob().clone(),
            profile_digest: profile_digest(),
        };
        assert!(
            SealedSnapshot::from_owned_directories(
                nil_identity,
                VerifiedSnapshotManifestV1::from_manifest(manifest()).unwrap(),
                std::fs::File::open("/").unwrap().into(),
                std::fs::File::open("/").unwrap().into(),
            )
            .is_err()
        );

        let mut wrong_identity = SealedSnapshotIdentityV2 {
            snapshot_id: SnapshotId::from_bytes([2; 16]),
            workspace_root: verified_manifest.manifest().workspace_root,
            runtime_root: verified_manifest.manifest().runtime_root,
            manifest_blob: verified_manifest.blob().clone(),
            profile_digest: profile_digest(),
        };
        wrong_identity.manifest_blob.byte_count += 1;
        assert!(
            SealedSnapshot::from_owned_directories(
                wrong_identity,
                verified_manifest,
                std::fs::File::open("/").unwrap().into(),
                std::fs::File::open("/").unwrap().into(),
            )
            .is_err()
        );

        let mut wrong_manifest = manifest();
        wrong_manifest.workspace_identity = digest!(WorkspaceIdentity, "wrong-workspace");
        let wrong_manifest = VerifiedSnapshotManifestV1::from_manifest(wrong_manifest).unwrap();
        assert!(
            VerifiedCandidateRecordV2::new(
                CanonicalEffectRecordV2::from_record(record()).unwrap(),
                wrong_manifest,
            )
            .is_err()
        );

        let manifest_bytes = manifest().canonical_bytes().unwrap();
        let mut trailing = manifest_bytes.clone();
        trailing.push(0);
        assert!(VerifiedSnapshotManifestV1::from_canonical_bytes(&trailing).is_err());

        let mut wrong_workspace = admitted();
        wrong_workspace.shape.workspace_identity =
            digest!(WorkspaceIdentity, "different-workspace");
        wrong_workspace.shape_key = wrong_workspace.shape.key().unwrap();
        assert!(PreparedPytest::new(sealed_snapshot(), wrong_workspace).is_err());

        let prepared_value = prepared();
        let bound = VerifiedExecutionRecordV2::bind(
            &prepared_value,
            TraceExecutionMode::Foreground,
            CanonicalEffectRecordV2::from_record(record()).unwrap(),
        )
        .unwrap();
        assert!(bound.candidate().is_some());

        assert!(
            VerifiedExecutionRecordV2::bind(
                &prepared_value,
                TraceExecutionMode::Shadow {
                    primary_record_id: RecordId::from_bytes([9; 16]),
                },
                CanonicalEffectRecordV2::from_record(record()).unwrap(),
            )
            .is_err()
        );

        let mut wrong_snapshot = record();
        wrong_snapshot.sealed_snapshot.snapshot_id = SnapshotId::from_bytes([8; 16]);
        assert!(
            VerifiedExecutionRecordV2::bind(
                &prepared_value,
                TraceExecutionMode::Foreground,
                CanonicalEffectRecordV2::from_record(wrong_snapshot).unwrap(),
            )
            .is_err()
        );

        let primary_id = RecordId::from_bytes([9; 16]);
        let mut shadow = record();
        shadow.record_id = RecordId::from_bytes([7; 16]);
        shadow.disposition = EffectRecordDispositionV2::ShadowCandidate;
        shadow.primary_record_id = Some(primary_id);
        assert!(
            VerifiedExecutionRecordV2::bind(
                &prepared_value,
                TraceExecutionMode::Shadow {
                    primary_record_id: primary_id,
                },
                CanonicalEffectRecordV2::from_record(shadow).unwrap(),
            )
            .unwrap()
            .candidate()
            .is_some()
        );

        let primary = verified_candidate(record());
        let job = ShadowJobV2::new(ShadowJobId::from_bytes([4; 16]), &primary).unwrap();
        assert!(ShadowEnvelopeV2::new(job.clone(), prepared()).is_ok());
        let mut different_snapshot_identity = sealed_snapshot().identity().clone();
        different_snapshot_identity.snapshot_id = SnapshotId::from_bytes([5; 16]);
        let different_snapshot = SealedSnapshot::from_owned_directories(
            different_snapshot_identity,
            VerifiedSnapshotManifestV1::from_manifest(manifest()).unwrap(),
            std::fs::File::open("/").unwrap().into(),
            std::fs::File::open("/").unwrap().into(),
        )
        .unwrap();
        let different_prepared = PreparedPytest::new(different_snapshot, admitted()).unwrap();
        assert!(ShadowEnvelopeV2::new(job, different_prepared).is_err());
    }

    #[test]
    fn execute_only_reason_precedence_is_total_and_cannot_enter_promotion() {
        fn assert_reason(mut record: EffectRecordV2, expected: ExecuteOnlyCode) {
            record.disposition = EffectRecordDispositionV2::ExecutedOnly;
            record.disposition_reason = Some(expected);
            record.primary_record_id = None;
            record.validate().unwrap();
            let prepared = prepared();
            let bound = VerifiedExecutionRecordV2::bind(
                &prepared,
                TraceExecutionMode::Foreground,
                CanonicalEffectRecordV2::from_record(record).unwrap(),
            )
            .unwrap();
            assert!(bound.candidate().is_none());
        }

        let mut stdout_limit = record();
        stdout_limit.result.stdout = StreamCaptureV2::Exceeded {
            observed_bytes: LINUX_PYTEST_V1_MAX_STREAM_BYTES + 1,
        };
        assert_reason(stdout_limit, ExecuteOnlyCode::StdoutLimit);

        let mut stdout_incomplete = record();
        stdout_incomplete.result.stdout = StreamCaptureV2::Incomplete {
            observed_bytes: 1,
            reason: ExecuteOnlyCode::CaptureFailure,
        };
        assert_reason(stdout_incomplete, ExecuteOnlyCode::CaptureFailure);

        let mut stderr_limit = record();
        stderr_limit.result.stderr = StreamCaptureV2::Exceeded {
            observed_bytes: LINUX_PYTEST_V1_MAX_STREAM_BYTES + 1,
        };
        assert_reason(stderr_limit, ExecuteOnlyCode::StderrLimit);

        let mut signaled = record();
        signaled.result.raw_linux_wait_status = RawLinuxWaitStatusV1(9);
        assert_reason(signaled, ExecuteOnlyCode::ForegroundSignaled);

        let mut nonzero = record();
        nonzero.result.raw_linux_wait_status = RawLinuxWaitStatusV1::exited(7);
        assert_reason(nonzero, ExecuteOnlyCode::ForegroundNonzeroExit);

        let mut first_failure = record();
        first_failure.trace.complete = EffectBitmap::from_bits(
            EffectBitmap::REQUIRED_V2.bits() & !CompletenessDimensionV2::Stdout.bit(),
        );
        first_failure.trace.first_failure = Some(FirstFailureV1 {
            dimension: CompletenessDimensionV2::Stdout,
            reason: ExecuteOnlyCode::TraceEventLost,
            phase: TracePhaseV1::Trace,
            event_sequence: Some(1),
            logical_task_id: Some(LogicalTaskId(1)),
        });
        first_failure.result.stdout = StreamCaptureV2::Exceeded {
            observed_bytes: LINUX_PYTEST_V1_MAX_STREAM_BYTES + 1,
        };
        assert_reason(first_failure.clone(), ExecuteOnlyCode::TraceEventLost);
        first_failure.disposition = EffectRecordDispositionV2::ExecutedOnly;
        first_failure.disposition_reason = Some(ExecuteOnlyCode::StdoutLimit);
        assert!(first_failure.validate().is_err());

        let mut invalid_candidate = record();
        invalid_candidate.result.raw_linux_wait_status = RawLinuxWaitStatusV1::exited(1);
        assert!(invalid_candidate.validate().is_err());
    }

    #[test]
    fn promoted_lookup_enforces_cap_uniqueness_and_deterministic_order() {
        let shape_key = record().shape_key;
        let exact_cap = (0..u64::from(LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES))
            .map(|index| candidate_pair(index, 1_000 - index))
            .collect();
        assert_eq!(
            PromotedLookupV2::new(shape_key, exact_cap)
                .unwrap()
                .candidates()
                .len(),
            usize::from(LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES)
        );

        let over_cap = (0..=u64::from(LINUX_PYTEST_V1_MAX_LOOKUP_CANDIDATES))
            .map(|index| candidate_pair(index, 1_000 - index))
            .collect();
        assert!(PromotedLookupV2::new(shape_key, over_cap).is_err());
        assert!(
            PromotedLookupV2::new(
                digest!(ShapeKey, "wrong-shape"),
                vec![candidate_pair(0, 20)],
            )
            .is_err()
        );
        assert!(
            PromotedLookupV2::new(
                shape_key,
                vec![candidate_pair(0, 20), candidate_pair(0, 20)],
            )
            .is_err()
        );
        assert!(
            PromotedLookupV2::new(
                shape_key,
                vec![candidate_pair(0, 20), candidate_pair(1, 21)],
            )
            .is_err()
        );

        let mut tied = vec![candidate_pair(0, 20), candidate_pair(1, 20)];
        tied.sort_by_key(|candidate| candidate.pair.request_key);
        assert!(PromotedLookupV2::new(shape_key, tied).is_ok());
        let mut reversed_tie = vec![candidate_pair(0, 20), candidate_pair(1, 20)];
        reversed_tie.sort_by_key(|candidate| std::cmp::Reverse(candidate.pair.request_key));
        assert!(PromotedLookupV2::new(shape_key, reversed_tie).is_err());
    }
}
