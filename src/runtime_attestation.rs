//! Fail-closed runtime identity for the current macOS team-cache profile.
//!
//! A portable request must not obtain `platform_digest` or `image_digest` from
//! a caller.  This module is the only production authority for those values.
//! It admits one reviewed host: native arm64 macOS 15.6.1 (24G90), with SIP and
//! authenticated-root enforcement fully enabled, the exact audited command
//! bytes, Apple's exact dyld, and the exact active arm64e shared-cache pair.
//!
//! The dynamic closure is authenticated rather than guessed.  The selected
//! Mach-O slice may load only `/usr/lib/dyld` and
//! `/usr/lib/libSystem.B.dylib`; loader-sensitive environment variables are
//! excluded by the team request profile.  The in-process dyld UUID must equal
//! the reviewed main cache, the main header must name exactly its reviewed
//! `.01` subcache, and `codesign --strict` must validate both files against
//! their exact reviewed CodeDirectory hashes.  Any OS/runtime change is local
//! only until a new profile is audited.
//!
//! The explicit slow audit can persist those code-signing facts in a
//! versioned checkpoint for at most 24 hours. Fresh-process fast admission
//! never reruns the multi-gigabyte cache scan, but it does revalidate the exact
//! OS/kernel/CSR facts, dyld-selected mapped cache UUID and range, canonical
//! main/subcache headers, exact `codesign`, dyld and command bytes, and the
//! command's Mach-O closure. Missing, stale, corrupt or unsafe checkpoints
//! fail closed; there is no automatic downgrade on a remote hit.
//!
//! This does not defend against a kernel/root adversary that can falsify
//! `sysctl`, CSR state, dyld APIs, or Apple's code-signing verifier inside the
//! running process.  No user-space attestor can establish that stronger root
//! of trust. A same-user attacker can also replace a checkpoint and remains an
//! explicit exclusion; preventing cross-process rollback against that actor
//! requires an external witness or platform monotonic state. It does prevent
//! a different unprivileged caller from inventing portable platform/image
//! identities.

#![allow(
    dead_code,
    reason = "the sealed team runtime is intentionally not wired to the CLI or uploader yet"
)]

#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(test)]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[cfg(target_os = "macos")]
use crate::executable::host_audited_apple_profile;
use crate::executable::{
    ExecutableIdentity, ExecutableProvenance, ToolKind, VerifyError, verify_executable,
};
use crate::team::Digest;
use crate::team_request_key::TeamRequestKeyV1;

const ATTESTATION_SCHEMA_VERSION: u16 = 1;
const PLATFORM_DOMAIN: &[u8] = b"again.team-runtime-platform.v1";
const IMAGE_DOMAIN: &[u8] = b"again.team-runtime-image.v1";
const CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"again.team-runtime-audit-checkpoint.v1";
const CHECKPOINT_NAMESPACE: &str = "again.team-runtime-audit-checkpoint.v1";
const CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const CHECKPOINT_VERIFIER_PROFILE: &str = "again-macos-15.6.1-24G90-arm64e-runtime-verifier-v1";
const CHECKPOINT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024;

const AUDITED_SYSTEM_PROFILE: &str = "macos-15.6.1-24G90-read-v0";
const AUDITED_RG_PROFILE: &str = "codex-rg-15.2.0-e89fff89ac-arm64-read-v0";
const AUDITED_TARGET_ARCH: &str = "aarch64";
const AUDITED_HW_MACHINE: &str = "arm64";
const AUDITED_HW_CPU_TYPE: u32 = 16_777_228;
const AUDITED_HW_CPU_SUBTYPE: u32 = 2;
const AUDITED_KERNEL_RELEASE: &str = "24.6.0";
const AUDITED_KERNEL_BUILD: &str = "24G90";
const AUDITED_KERNEL_VERSION: &str = "Darwin Kernel Version 24.6.0: Mon Jul 14 11:30:29 PDT 2025; root:xnu-11417.140.69~1/RELEASE_ARM64_T6000";
const AUDITED_PRODUCT_VERSION: &str = "15.6.1";
const AUDITED_RELEASE_TYPE: &str = "User";
const AUDITED_SHARED_REGION_VERSION: u32 = 3;
const AUDITED_CSR_CONFIG: u32 = 0;

const CODESIGN_PATH: &str = "/usr/bin/codesign";
const CODESIGN_SIZE: u64 = 378_144;
const CODESIGN_BLAKE3: &str = "0eadb4f5cb0ecea5124a7608057fda8ab88b77c7a2a72dbb419486163b080d62";
const DYLD_PATH: &str = "/usr/lib/dyld";
const DYLD_SIZE: u64 = 2_289_328;
const DYLD_BLAKE3: &str = "807bd6c6538d3930511813b2046db83f91d3617888bd74d6275f35ee3cae1160";
const DYLD_IDENTIFIER: &str = "com.apple.darwin.ignition";
const DYLD_CODE_DIRECTORY_SHA256: &str =
    "b4959acb9d4e635d5b79daa74b5d27f639896af63b4664052a4d6c16c1b3cf3a";

const CACHE_DIRECTORY: &str = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld";
const CACHE_MAIN_PATH: &str =
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e";
const CACHE_SUB_PATH: &str =
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e.01";
const CACHE_MAIN_SIZE: u64 = 2_712_764_416;
const CACHE_SUB_SIZE: u64 = 2_203_500_544;
const CACHE_IDENTIFIER: &str = "com.apple.dyld.cache.arm64e.development";
const CACHE_MAIN_CODE_DIRECTORY_SHA256: &str =
    "2b9cccd5c5728972bc2a3b7f251114e6f1ff9b5eba56db1db3498ed4fe8dfc8a";
const CACHE_SUB_CODE_DIRECTORY_SHA256: &str =
    "8c7ba7e588b0edd43f7334e2de11688cd473219276fec41c1b6660fffd902be4";
const CACHE_MAIN_UUID: [u8; 16] = [
    0x4c, 0x12, 0x23, 0xe5, 0xca, 0xce, 0x39, 0x82, 0xa0, 0x03, 0x61, 0x10, 0xa7, 0xa8, 0xa2, 0x5c,
];
const CACHE_SUB_UUID: [u8; 16] = [
    0x2b, 0x39, 0x06, 0x46, 0xb4, 0xb5, 0x30, 0x2b, 0x84, 0x1a, 0xef, 0xaa, 0x52, 0x83, 0x64, 0x0d,
];
const CACHE_SUB_VM_OFFSET: u64 = 0x0000_0000_a560_c000;
const CACHE_MAGIC: &[u8; 16] = b"dyld_v1  arm64e\0";
const AUDITED_SHARED_CACHE_RANGE_SIZE: u64 = 5_040_898_048;

const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STATIC_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CACHE_HEADER_BYTES: usize = 1024 * 1024;
const MAX_SYSCTL_BYTES: usize = 4096;
const MAX_CODESIGN_OUTPUT_BYTES: usize = 64 * 1024;
const CODESIGN_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_MASK: u32 = 0x00ff_ffff;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_EXECUTE: u32 = 2;
const FAT_MAGIC: u32 = 0xcafe_babe;
const LC_LOAD_DYLIB: u32 = 0x0000_000c;
const LC_LOAD_DYLINKER: u32 = 0x0000_000e;
const LC_CODE_SIGNATURE: u32 = 0x0000_001d;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x0000_0020;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_RPATH: u32 = 0x8000_001c;
const LC_DYLD_ENVIRONMENT: u32 = 0x0000_0027;

/// A sealed, non-cloneable authority for the exact runtime used by one
/// portable team request.  Private fields prevent caller-minted identities.
pub(crate) struct TeamRuntimeAttestationV1 {
    command_name: String,
    executable_identity: ExecutableIdentity,
    executable_digest: Digest,
    platform_digest: Digest,
    image_digest: Digest,
    mode: AttestationMode,
}

enum AttestationMode {
    Live {
        audited_runtime: Box<RuntimeEvidence>,
        checkpoint_path: Option<PathBuf>,
    },
    #[cfg(test)]
    TestOnly(Arc<AtomicBool>),
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestRuntimeInvalidator(Arc<AtomicBool>);

#[cfg(test)]
impl TestRuntimeInvalidator {
    pub(crate) fn invalidate(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl TeamRuntimeAttestationV1 {
    pub(crate) fn command_name(&self) -> &str {
        &self.command_name
    }

    pub(crate) fn executable_identity(&self) -> &ExecutableIdentity {
        &self.executable_identity
    }

    pub(crate) fn executable_digest(&self) -> Digest {
        self.executable_digest
    }

    pub(crate) fn platform_digest(&self) -> Digest {
        self.platform_digest
    }

    pub(crate) fn image_digest(&self) -> Digest {
        self.image_digest
    }

    /// Re-check the path, reviewed identity, and exact bytes before an
    /// immutable capture consumes this authority.
    pub(crate) fn verify_executable_current(&self) -> Result<(), RuntimeAttestationError> {
        #[cfg(test)]
        if let AttestationMode::TestOnly(valid) = &self.mode {
            return if valid.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(RuntimeAttestationError::ExecutableChanged)
            };
        }
        let current =
            inspect_executable(&self.command_name, &self.executable_identity.canonical_path)?;
        if current.identity != self.executable_identity
            || current.executable_digest != self.executable_digest
        {
            return Err(RuntimeAttestationError::ExecutableChanged);
        }
        #[cfg(target_os = "macos")]
        match &self.mode {
            AttestationMode::Live {
                audited_runtime,
                checkpoint_path,
            } => {
                if let Some(path) = checkpoint_path {
                    let checkpoint = load_runtime_checkpoint(path, system_timestamp()?)?;
                    if checkpoint.runtime != **audited_runtime {
                        return Err(RuntimeAttestationError::CheckpointCorrupt);
                    }
                }
                let runtime = inspect_fast_runtime(audited_runtime)?;
                let observation = RuntimeObservation {
                    command_name: self.command_name.clone(),
                    executable: current,
                    runtime,
                };
                let current_platform = platform_digest(&observation.runtime)?;
                let current_image = image_digest(&observation, current_platform)?;
                if current_platform != self.platform_digest || current_image != self.image_digest {
                    return Err(RuntimeAttestationError::RequestBindingMismatch);
                }
            }
            #[cfg(test)]
            AttestationMode::TestOnly(_) => {}
        }
        Ok(())
    }

    pub(crate) fn binds_command(&self, command: &str) -> bool {
        self.command_name == command
    }

    /// Explicit test authority with a controllable invalidation point. This
    /// constructor does not exist in production builds.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        command_name: &str,
        platform_digest: Digest,
        image_digest: Digest,
    ) -> (Self, TestRuntimeInvalidator) {
        let valid = Arc::new(AtomicBool::new(true));
        let (tool, canonical_path) = match command_name {
            "cat" => (ToolKind::Cat, PathBuf::from("/bin/cat")),
            "head" => (ToolKind::Head, PathBuf::from("/usr/bin/head")),
            "tail" => (ToolKind::Tail, PathBuf::from("/usr/bin/tail")),
            "wc" => (ToolKind::Wc, PathBuf::from("/usr/bin/wc")),
            "grep" => (ToolKind::Grep, PathBuf::from("/usr/bin/grep")),
            _ => panic!("unsupported test runtime command"),
        };
        (
            Self {
                command_name: command_name.to_owned(),
                executable_identity: ExecutableIdentity {
                    tool,
                    canonical_path,
                    provenance: ExecutableProvenance::AppleSystem,
                    semantic_profile: AUDITED_SYSTEM_PROFILE.to_owned(),
                },
                executable_digest: Digest::from_hex(&"00".repeat(32))
                    .expect("test digest is valid"),
                platform_digest,
                image_digest,
                mode: AttestationMode::TestOnly(Arc::clone(&valid)),
            },
            TestRuntimeInvalidator(valid),
        )
    }

    /// Re-authenticate a previously derived request before any remote or
    /// publication result is consumed. Network waits cannot turn an old
    /// capability into authority over a replaced executable.
    pub(crate) fn verify_request_binding(
        &self,
        request: &TeamRequestKeyV1,
    ) -> Result<(), RuntimeAttestationError> {
        let descriptor = request.descriptor();
        if descriptor.normalized_argv().first().map(String::as_str)
            != Some(self.command_name.as_str())
            || descriptor.platform_digest() != self.platform_digest
            || descriptor.image_digest() != self.image_digest
        {
            return Err(RuntimeAttestationError::RequestBindingMismatch);
        }
        self.verify_executable_current()
    }
}

impl fmt::Debug for TeamRuntimeAttestationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TeamRuntimeAttestationV1")
            .field("command_name", &self.command_name)
            .field("executable_identity", &self.executable_identity)
            .field("executable_digest", &self.executable_digest)
            .field("platform_digest", &self.platform_digest)
            .field("image_digest", &self.image_digest)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub(crate) enum RuntimeAttestationError {
    #[error("team runtime attestation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("the process is not running natively on the audited architecture")]
    UnsupportedArchitecture,
    #[error("the command executable is outside the audited runtime: {0}")]
    ExecutableNotAudited(VerifyError),
    #[error("the audited executable identity is inconsistent")]
    ExecutableIdentityMismatch,
    #[error("the audited executable changed")]
    ExecutableChanged,
    #[error("the request is not bound to this runtime attestation")]
    RequestBindingMismatch,
    #[error("the executable has an unaudited dynamic dependency closure")]
    DynamicClosureMismatch,
    #[error("the audited system profile changed")]
    SystemProfileMismatch,
    #[error("runtime fact `{field}` does not match the audited profile")]
    RuntimeFactMismatch { field: &'static str },
    #[error("cannot read runtime fact `{field}` ({kind:?})")]
    RuntimeFactIo {
        field: &'static str,
        kind: io::ErrorKind,
    },
    #[error("SIP/authenticated-root state cannot be established")]
    CsrInspectionFailed,
    #[error("SIP or authenticated-root enforcement is not fully enabled")]
    CsrPolicyMismatch,
    #[error("the active dyld shared-cache UUID cannot be established")]
    ActiveCacheUnavailable,
    #[error("the active dyld shared cache is not the audited cache")]
    ActiveCacheMismatch,
    #[error("runtime artifact `{artifact}` is unsafe or changed")]
    UnsafeArtifact { artifact: &'static str },
    #[error("runtime artifact `{artifact}` has the wrong exact bytes")]
    ArtifactDigestMismatch { artifact: &'static str },
    #[error("runtime artifact `{artifact}` has the wrong length")]
    ArtifactSizeMismatch { artifact: &'static str },
    #[error("runtime artifact `{artifact}` exceeds its read bound")]
    ArtifactReadLimit { artifact: &'static str },
    #[error("cannot inspect runtime artifact `{artifact}` ({kind:?})")]
    ArtifactIo {
        artifact: &'static str,
        kind: io::ErrorKind,
    },
    #[error("the dyld shared-cache header is malformed or unexpected")]
    CacheHeaderInvalid,
    #[error("the bounded Apple code-signing verifier timed out")]
    CodeSignTimeout,
    #[error("the Apple code-signing verifier exceeded its output bound")]
    CodeSignOutputLimit,
    #[error("the Apple code-signing verifier failed")]
    CodeSignFailed,
    #[error("the verified code-signing identity does not match the audited artifact")]
    CodeSignIdentityMismatch,
    #[error("the runtime audit checkpoint path is invalid")]
    CheckpointPathInvalid,
    #[error("a current runtime audit checkpoint is required")]
    CheckpointMissing,
    #[error("the runtime audit checkpoint is not a private owner-only single-link file")]
    CheckpointUnsafe,
    #[error("the runtime audit checkpoint cannot be read or written ({kind:?})")]
    CheckpointIo { kind: io::ErrorKind },
    #[error("the runtime audit checkpoint exceeds its size bound")]
    CheckpointSizeLimit,
    #[error("the runtime audit checkpoint has an unknown schema or verifier profile")]
    CheckpointSchemaMismatch,
    #[error("the runtime audit checkpoint is malformed or corrupt")]
    CheckpointCorrupt,
    #[error("the runtime audit checkpoint is older than its maximum admitted age")]
    CheckpointStale,
    #[error("the system clock is inconsistent with the runtime audit checkpoint")]
    CheckpointClockAnomaly,
    #[error("a runtime audit checkpoint write would roll back newer audit state")]
    CheckpointRollback,
    #[error("another runtime audit checkpoint write is in progress")]
    CheckpointLocked,
    #[error("a runtime attestation digest could not be represented")]
    DigestEncoding,
}

/// Inspect and seal the actual host runtime for one audited executable.
pub(crate) fn attest_team_runtime_v1(
    command_name: &str,
    executable: &Path,
) -> Result<TeamRuntimeAttestationV1, RuntimeAttestationError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (command_name, executable);
        Err(RuntimeAttestationError::UnsupportedPlatform)
    }

    #[cfg(target_os = "macos")]
    {
        if std::env::consts::ARCH != AUDITED_TARGET_ARCH {
            return Err(RuntimeAttestationError::UnsupportedArchitecture);
        }
        let executable = inspect_executable(command_name, executable)?;
        let runtime = static_runtime_evidence()?;
        seal_observation(RuntimeObservation {
            command_name: command_name.to_owned(),
            executable,
            runtime: runtime.clone(),
        })
    }
}

/// Perform the complete, slow Apple code-signing audit and persist the exact
/// evidence as a short-lived checkpoint. Unlike [`attest_team_runtime_v1`],
/// this deliberately bypasses the process-local evidence cache: every call is
/// a new full audit.
pub(crate) fn audit_team_runtime_to_checkpoint_v1(
    command_name: &str,
    executable: &Path,
    checkpoint_path: &Path,
) -> Result<TeamRuntimeAttestationV1, RuntimeAttestationError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (command_name, executable, checkpoint_path);
        Err(RuntimeAttestationError::UnsupportedPlatform)
    }

    #[cfg(target_os = "macos")]
    {
        if std::env::consts::ARCH != AUDITED_TARGET_ARCH {
            return Err(RuntimeAttestationError::UnsupportedArchitecture);
        }
        let executable = inspect_executable(command_name, executable)?;
        let runtime = inspect_static_runtime()?;
        validate_identity_shape(command_name, &executable.identity)?;
        validate_dynamic_closure(&executable.closure)?;
        validate_runtime_evidence(&runtime)?;
        persist_runtime_checkpoint(checkpoint_path, &runtime, system_timestamp()?)?;
        seal_observation_with_checkpoint(
            RuntimeObservation {
                command_name: command_name.to_owned(),
                executable,
                runtime,
            },
            checkpoint_path.to_owned(),
        )
    }
}

/// Fast fresh-process admission. A missing, stale, corrupt, unsafe, or
/// mismatched checkpoint is a hard failure; callers must explicitly run the
/// slow audit rather than silently degrading a remote hit's trust boundary.
pub(crate) fn attest_team_runtime_from_checkpoint_v1(
    command_name: &str,
    executable: &Path,
    checkpoint_path: &Path,
) -> Result<TeamRuntimeAttestationV1, RuntimeAttestationError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (command_name, executable, checkpoint_path);
        Err(RuntimeAttestationError::UnsupportedPlatform)
    }

    #[cfg(target_os = "macos")]
    {
        if std::env::consts::ARCH != AUDITED_TARGET_ARCH {
            return Err(RuntimeAttestationError::UnsupportedArchitecture);
        }
        let checkpoint = load_runtime_checkpoint(checkpoint_path, system_timestamp()?)?;
        let executable = inspect_executable(command_name, executable)?;
        let runtime = inspect_fast_runtime(&checkpoint.runtime)?;
        seal_observation_with_checkpoint(
            RuntimeObservation {
                command_name: command_name.to_owned(),
                executable,
                runtime,
            },
            checkpoint_path.to_owned(),
        )
    }
}

#[derive(Clone)]
struct InspectedExecutable {
    identity: ExecutableIdentity,
    executable_digest: Digest,
    closure: MachClosure,
}

#[derive(Clone)]
struct MachClosure {
    cpu_type: u32,
    cpu_subtype: u32,
    dynamic_linker: String,
    libraries: Vec<String>,
    has_code_signature: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeEvidence {
    system_profile: String,
    target_arch: String,
    hw_machine: String,
    hw_cpu_type: u32,
    hw_cpu_subtype: u32,
    translated: u32,
    kernel_release: String,
    kernel_build: String,
    kernel_version: String,
    product_version: String,
    release_type: String,
    shared_region_version: u32,
    csr_config: u32,
    active_cache_uuid: [u8; 16],
    active_cache_range_size: u64,
    active_cache_path: String,
    codesign_digest: Digest,
    dyld_digest: Digest,
    dyld_signature: SignatureEvidence,
    main_cache: CacheEvidence,
    sub_cache: CacheEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEvidence {
    size: u64,
    uuid: [u8; 16],
    subcaches: Vec<SubcacheEvidence>,
    signature: SignatureEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubcacheEvidence {
    uuid: [u8; 16],
    vm_offset: u64,
    suffix: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureEvidence {
    identifier: String,
    code_directory_sha256: String,
    kind: SignatureKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SignatureKind {
    ApplePlatform,
    AdHoc,
}

/// The envelope checksum is not a MAC: it detects truncation and accidental
/// corruption. A same-user attacker can replace both bytes and checksum and is
/// explicitly outside this local-file threat model. Authenticity comes from
/// revalidating SIP/authenticated-root state, the exact OS identity, the live
/// dyld mapping and the root-owned runtime bytes on every fast admission.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCheckpointEnvelopeV1 {
    namespace: String,
    schema_version: u16,
    payload: RuntimeCheckpointPayloadV1,
    payload_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCheckpointPayloadV1 {
    attestation_schema_version: u16,
    verifier_profile: String,
    audited_at_unix_seconds: u64,
    audited_at_nanoseconds: u32,
    valid_for_seconds: u64,
    runtime: RuntimeEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct UnixTimestamp {
    seconds: u64,
    nanoseconds: u32,
}

struct RuntimeObservation {
    command_name: String,
    executable: InspectedExecutable,
    runtime: RuntimeEvidence,
}

#[cfg(target_os = "macos")]
fn static_runtime_evidence() -> Result<&'static RuntimeEvidence, RuntimeAttestationError> {
    static EVIDENCE: OnceLock<Result<RuntimeEvidence, RuntimeAttestationError>> = OnceLock::new();
    EVIDENCE
        .get_or_init(inspect_static_runtime)
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(target_os = "macos")]
fn inspect_static_runtime() -> Result<RuntimeEvidence, RuntimeAttestationError> {
    let system_profile = host_audited_apple_profile()
        .map_err(|_| RuntimeAttestationError::SystemProfileMismatch)?
        .to_owned();
    let hw_machine = sysctl_string("hw.machine", "hw.machine")?;
    let hw_cpu_type = sysctl_u32("hw.cputype", "hw.cputype")?;
    let hw_cpu_subtype = sysctl_u32("hw.cpusubtype", "hw.cpusubtype")?;
    let translated = sysctl_u32("sysctl.proc_translated", "sysctl.proc_translated")?;
    let kernel_release = sysctl_string("kern.osrelease", "kern.osrelease")?;
    let kernel_build = sysctl_string("kern.osversion", "kern.osversion")?;
    let kernel_version = sysctl_string("kern.version", "kern.version")?;
    let product_version = sysctl_string("kern.osproductversion", "kern.osproductversion")?;
    let release_type = sysctl_string("kern.osreleasetype", "kern.osreleasetype")?;
    let shared_region_version = sysctl_u32("vm.shared_region_version", "vm.shared_region_version")?;
    let csr_config = active_csr_config()?;
    let (active_cache_uuid, active_cache_range_size) = active_shared_cache_mapping()?;

    let codesign_digest = inspect_exact_small_artifact(
        Path::new(CODESIGN_PATH),
        CODESIGN_SIZE,
        CODESIGN_BLAKE3,
        "codesign",
    )?;
    let dyld_digest =
        inspect_exact_small_artifact(Path::new(DYLD_PATH), DYLD_SIZE, DYLD_BLAKE3, "dyld")?;
    let dyld_signature = inspect_signature(
        Path::new(DYLD_PATH),
        "dyld",
        DYLD_IDENTIFIER,
        DYLD_CODE_DIRECTORY_SHA256,
        SignatureKind::ApplePlatform,
    )?;
    let main_cache = inspect_cache(
        Path::new(CACHE_MAIN_PATH),
        CACHE_MAIN_SIZE,
        "dyld_cache_main",
        CACHE_MAIN_CODE_DIRECTORY_SHA256,
    )?;
    let sub_cache = inspect_cache(
        Path::new(CACHE_SUB_PATH),
        CACHE_SUB_SIZE,
        "dyld_cache_sub",
        CACHE_SUB_CODE_DIRECTORY_SHA256,
    )?;

    Ok(RuntimeEvidence {
        system_profile,
        target_arch: std::env::consts::ARCH.to_owned(),
        hw_machine,
        hw_cpu_type,
        hw_cpu_subtype,
        translated,
        kernel_release,
        kernel_build,
        kernel_version,
        product_version,
        release_type,
        shared_region_version,
        csr_config,
        active_cache_uuid,
        active_cache_range_size,
        active_cache_path: CACHE_MAIN_PATH.to_owned(),
        codesign_digest,
        dyld_digest,
        dyld_signature,
        main_cache,
        sub_cache,
    })
}

/// Reconstruct current evidence without invoking `codesign` over the 4.9 GB
/// shared-cache pair. The checkpoint contributes only facts established by
/// the recent slow audit. Every mutable/selected identity is re-read here.
/// This shortcut is sound only for the stated threat boundary: CSR 0 and the
/// authenticated root make the exact OS cache/dyld paths immutable to an
/// unprivileged different-user process. Root, the kernel, and the same user
/// that owns the checkpoint remain explicit exclusions.
#[cfg(target_os = "macos")]
fn inspect_fast_runtime(
    audited: &RuntimeEvidence,
) -> Result<RuntimeEvidence, RuntimeAttestationError> {
    // A checkpoint from a different verifier/OS cannot lend signature facts
    // to this process even if its envelope checksum is internally consistent.
    validate_runtime_evidence(audited)?;

    let hw_machine = sysctl_string("hw.machine", "hw.machine")?;
    let hw_cpu_type = sysctl_u32("hw.cputype", "hw.cputype")?;
    let hw_cpu_subtype = sysctl_u32("hw.cpusubtype", "hw.cpusubtype")?;
    let translated = sysctl_u32("sysctl.proc_translated", "sysctl.proc_translated")?;
    let kernel_release = sysctl_string("kern.osrelease", "kern.osrelease")?;
    let kernel_build = sysctl_string("kern.osversion", "kern.osversion")?;
    let kernel_version = sysctl_string("kern.version", "kern.version")?;
    let product_version = sysctl_string("kern.osproductversion", "kern.osproductversion")?;
    let release_type = sysctl_string("kern.osreleasetype", "kern.osreleasetype")?;
    let shared_region_version = sysctl_u32("vm.shared_region_version", "vm.shared_region_version")?;
    let csr_config = active_csr_config()?;
    let (active_cache_uuid, active_cache_range_size) = active_shared_cache_mapping()?;

    let codesign_digest = inspect_exact_small_artifact(
        Path::new(CODESIGN_PATH),
        CODESIGN_SIZE,
        CODESIGN_BLAKE3,
        "codesign",
    )?;
    let dyld_digest =
        inspect_exact_small_artifact(Path::new(DYLD_PATH), DYLD_SIZE, DYLD_BLAKE3, "dyld")?;
    let main_cache = inspect_cache_header_only(
        Path::new(CACHE_MAIN_PATH),
        CACHE_MAIN_SIZE,
        "dyld_cache_main",
        audited.main_cache.signature.clone(),
    )?;
    let sub_cache = inspect_cache_header_only(
        Path::new(CACHE_SUB_PATH),
        CACHE_SUB_SIZE,
        "dyld_cache_sub",
        audited.sub_cache.signature.clone(),
    )?;

    let runtime = RuntimeEvidence {
        system_profile: AUDITED_SYSTEM_PROFILE.to_owned(),
        target_arch: std::env::consts::ARCH.to_owned(),
        hw_machine,
        hw_cpu_type,
        hw_cpu_subtype,
        translated,
        kernel_release,
        kernel_build,
        kernel_version,
        product_version,
        release_type,
        shared_region_version,
        csr_config,
        active_cache_uuid,
        active_cache_range_size,
        active_cache_path: CACHE_MAIN_PATH.to_owned(),
        codesign_digest,
        dyld_digest,
        dyld_signature: audited.dyld_signature.clone(),
        main_cache,
        sub_cache,
    };
    validate_runtime_evidence(&runtime)?;
    Ok(runtime)
}

fn inspect_executable(
    command_name: &str,
    executable: &Path,
) -> Result<InspectedExecutable, RuntimeAttestationError> {
    let first = verify_executable(command_name, executable)
        .map_err(RuntimeAttestationError::ExecutableNotAudited)?;
    validate_identity_shape(command_name, &first)?;
    let stable = read_stable_artifact(
        executable,
        MAX_EXECUTABLE_BYTES,
        None,
        false,
        "command_executable",
    )?;
    if stable.canonical_path != first.canonical_path {
        return Err(RuntimeAttestationError::ExecutableIdentityMismatch);
    }
    let second = verify_executable(command_name, &stable.canonical_path)
        .map_err(RuntimeAttestationError::ExecutableNotAudited)?;
    if first != second {
        return Err(RuntimeAttestationError::ExecutableChanged);
    }
    let closure = parse_mach_closure(&stable.bytes)?;
    validate_dynamic_closure(&closure)?;
    Ok(InspectedExecutable {
        identity: first,
        executable_digest: digest_bytes(&stable.bytes)?,
        closure,
    })
}

fn seal_observation(
    observation: RuntimeObservation,
) -> Result<TeamRuntimeAttestationV1, RuntimeAttestationError> {
    seal_observation_with_mode(observation, None)
}

fn seal_observation_with_checkpoint(
    observation: RuntimeObservation,
    checkpoint_path: PathBuf,
) -> Result<TeamRuntimeAttestationV1, RuntimeAttestationError> {
    seal_observation_with_mode(observation, Some(checkpoint_path))
}

fn seal_observation_with_mode(
    observation: RuntimeObservation,
    checkpoint_path: Option<PathBuf>,
) -> Result<TeamRuntimeAttestationV1, RuntimeAttestationError> {
    validate_identity_shape(&observation.command_name, &observation.executable.identity)?;
    validate_dynamic_closure(&observation.executable.closure)?;
    validate_runtime_evidence(&observation.runtime)?;

    let platform_digest = platform_digest(&observation.runtime)?;
    let image_digest = image_digest(&observation, platform_digest)?;
    let audited_runtime = Box::new(observation.runtime);
    Ok(TeamRuntimeAttestationV1 {
        command_name: observation.command_name,
        executable_identity: observation.executable.identity,
        executable_digest: observation.executable.executable_digest,
        platform_digest,
        image_digest,
        mode: AttestationMode::Live {
            audited_runtime,
            checkpoint_path,
        },
    })
}

fn validate_identity_shape(
    command_name: &str,
    identity: &ExecutableIdentity,
) -> Result<(), RuntimeAttestationError> {
    let (expected_name, expected_path) = match identity.tool {
        ToolKind::Cat => ("cat", Some(Path::new("/bin/cat"))),
        ToolKind::Head => ("head", Some(Path::new("/usr/bin/head"))),
        ToolKind::Tail => ("tail", Some(Path::new("/usr/bin/tail"))),
        ToolKind::Wc => ("wc", Some(Path::new("/usr/bin/wc"))),
        ToolKind::Grep => ("grep", Some(Path::new("/usr/bin/grep"))),
        ToolKind::Ls => ("ls", Some(Path::new("/bin/ls"))),
        ToolKind::Pwd => ("pwd", Some(Path::new("/bin/pwd"))),
        ToolKind::Rg => ("rg", None),
    };
    if command_name != expected_name {
        return Err(RuntimeAttestationError::ExecutableIdentityMismatch);
    }
    match identity.provenance {
        ExecutableProvenance::AppleSystem => {
            if expected_path != Some(identity.canonical_path.as_path())
                || identity.semantic_profile != AUDITED_SYSTEM_PROFILE
            {
                return Err(RuntimeAttestationError::ExecutableIdentityMismatch);
            }
        }
        ExecutableProvenance::OpenAiCodexBundle => {
            if identity.tool != ToolKind::Rg
                || !is_codex_rg_path(&identity.canonical_path)
                || identity.semantic_profile
                    != format!("{AUDITED_SYSTEM_PROFILE}+{AUDITED_RG_PROFILE}")
            {
                return Err(RuntimeAttestationError::ExecutableIdentityMismatch);
            }
        }
    }
    Ok(())
}

fn is_codex_rg_path(path: &Path) -> bool {
    if !path.is_absolute() || path.file_name().and_then(|value| value.to_str()) != Some("rg") {
        return false;
    }
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    components
        .windows(2)
        .any(|pair| pair[0] == "@openai" && pair[1].starts_with("codex"))
        && components.windows(2).any(|pair| pair[0] == "vendor")
        && components.contains(&"codex-path")
}

fn validate_dynamic_closure(closure: &MachClosure) -> Result<(), RuntimeAttestationError> {
    if closure.cpu_type != CPU_TYPE_ARM64
        || !matches!(
            closure.cpu_subtype & CPU_SUBTYPE_MASK,
            CPU_SUBTYPE_ARM64_ALL | CPU_SUBTYPE_ARM64E
        )
        || closure.dynamic_linker != DYLD_PATH
        || closure.libraries != ["/usr/lib/libSystem.B.dylib"]
        || !closure.has_code_signature
    {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    Ok(())
}

fn validate_runtime_evidence(runtime: &RuntimeEvidence) -> Result<(), RuntimeAttestationError> {
    require_fact(
        runtime.system_profile == AUDITED_SYSTEM_PROFILE,
        "system_profile",
    )?;
    require_fact(runtime.target_arch == AUDITED_TARGET_ARCH, "target_arch")?;
    require_fact(runtime.hw_machine == AUDITED_HW_MACHINE, "hw.machine")?;
    require_fact(runtime.hw_cpu_type == AUDITED_HW_CPU_TYPE, "hw.cputype")?;
    require_fact(
        runtime.hw_cpu_subtype == AUDITED_HW_CPU_SUBTYPE,
        "hw.cpusubtype",
    )?;
    require_fact(runtime.translated == 0, "sysctl.proc_translated")?;
    require_fact(
        runtime.kernel_release == AUDITED_KERNEL_RELEASE,
        "kern.osrelease",
    )?;
    require_fact(
        runtime.kernel_build == AUDITED_KERNEL_BUILD,
        "kern.osversion",
    )?;
    require_fact(
        runtime.kernel_version == AUDITED_KERNEL_VERSION,
        "kern.version",
    )?;
    require_fact(
        runtime.product_version == AUDITED_PRODUCT_VERSION,
        "kern.osproductversion",
    )?;
    require_fact(
        runtime.release_type == AUDITED_RELEASE_TYPE,
        "kern.osreleasetype",
    )?;
    require_fact(
        runtime.shared_region_version == AUDITED_SHARED_REGION_VERSION,
        "vm.shared_region_version",
    )?;
    if runtime.csr_config != AUDITED_CSR_CONFIG {
        return Err(RuntimeAttestationError::CsrPolicyMismatch);
    }
    if runtime.active_cache_uuid != CACHE_MAIN_UUID {
        return Err(RuntimeAttestationError::ActiveCacheMismatch);
    }
    require_fact(
        runtime.active_cache_range_size == AUDITED_SHARED_CACHE_RANGE_SIZE,
        "active_cache_range_size",
    )?;
    require_fact(
        runtime.active_cache_path == CACHE_MAIN_PATH,
        "active_cache_path",
    )?;
    require_fact(
        runtime.codesign_digest.to_hex() == CODESIGN_BLAKE3,
        "codesign_digest",
    )?;
    require_fact(runtime.dyld_digest.to_hex() == DYLD_BLAKE3, "dyld_digest")?;
    validate_signature(
        &runtime.dyld_signature,
        DYLD_IDENTIFIER,
        DYLD_CODE_DIRECTORY_SHA256,
        SignatureKind::ApplePlatform,
    )?;
    validate_cache_evidence(
        &runtime.main_cache,
        CACHE_MAIN_SIZE,
        CACHE_MAIN_UUID,
        CACHE_MAIN_CODE_DIRECTORY_SHA256,
        true,
    )?;
    validate_cache_evidence(
        &runtime.sub_cache,
        CACHE_SUB_SIZE,
        CACHE_SUB_UUID,
        CACHE_SUB_CODE_DIRECTORY_SHA256,
        false,
    )?;
    Ok(())
}

fn require_fact(value: bool, field: &'static str) -> Result<(), RuntimeAttestationError> {
    if value {
        Ok(())
    } else {
        Err(RuntimeAttestationError::RuntimeFactMismatch { field })
    }
}

fn validate_cache_evidence(
    cache: &CacheEvidence,
    expected_size: u64,
    expected_uuid: [u8; 16],
    expected_code_directory: &str,
    is_main: bool,
) -> Result<(), RuntimeAttestationError> {
    if cache.size != expected_size || cache.uuid != expected_uuid {
        return Err(RuntimeAttestationError::CacheHeaderInvalid);
    }
    validate_signature(
        &cache.signature,
        CACHE_IDENTIFIER,
        expected_code_directory,
        SignatureKind::AdHoc,
    )?;
    if is_main {
        if cache.subcaches.len() != 1
            || cache.subcaches[0].uuid != CACHE_SUB_UUID
            || cache.subcaches[0].vm_offset != CACHE_SUB_VM_OFFSET
            || cache.subcaches[0].suffix != ".01"
        {
            return Err(RuntimeAttestationError::CacheHeaderInvalid);
        }
    } else if !cache.subcaches.is_empty() {
        return Err(RuntimeAttestationError::CacheHeaderInvalid);
    }
    Ok(())
}

fn validate_signature(
    signature: &SignatureEvidence,
    identifier: &str,
    code_directory: &str,
    kind: SignatureKind,
) -> Result<(), RuntimeAttestationError> {
    if signature.identifier != identifier
        || signature.code_directory_sha256 != code_directory
        || signature.kind != kind
    {
        return Err(RuntimeAttestationError::CodeSignIdentityMismatch);
    }
    Ok(())
}

fn platform_digest(runtime: &RuntimeEvidence) -> Result<Digest, RuntimeAttestationError> {
    let mut hasher = Hasher::new();
    put_bytes(&mut hasher, PLATFORM_DOMAIN);
    hasher.update(&ATTESTATION_SCHEMA_VERSION.to_le_bytes());
    for value in [
        runtime.system_profile.as_bytes(),
        runtime.target_arch.as_bytes(),
        runtime.hw_machine.as_bytes(),
        runtime.kernel_release.as_bytes(),
        runtime.kernel_build.as_bytes(),
        runtime.kernel_version.as_bytes(),
        runtime.product_version.as_bytes(),
        runtime.release_type.as_bytes(),
    ] {
        put_bytes(&mut hasher, value);
    }
    hasher.update(&runtime.hw_cpu_type.to_le_bytes());
    hasher.update(&runtime.hw_cpu_subtype.to_le_bytes());
    hasher.update(&runtime.translated.to_le_bytes());
    hasher.update(&runtime.shared_region_version.to_le_bytes());
    hasher.update(&runtime.csr_config.to_le_bytes());
    digest_hash(hasher.finalize())
}

fn image_digest(
    observation: &RuntimeObservation,
    platform_digest: Digest,
) -> Result<Digest, RuntimeAttestationError> {
    let mut hasher = Hasher::new();
    put_bytes(&mut hasher, IMAGE_DOMAIN);
    hasher.update(&ATTESTATION_SCHEMA_VERSION.to_le_bytes());
    hasher.update(platform_digest.as_bytes());
    put_bytes(&mut hasher, observation.command_name.as_bytes());
    put_bytes(
        &mut hasher,
        provenance_name(observation.executable.identity.provenance).as_bytes(),
    );
    put_bytes(
        &mut hasher,
        observation.executable.identity.semantic_profile.as_bytes(),
    );
    hasher.update(observation.executable.executable_digest.as_bytes());
    hasher.update(&observation.executable.closure.cpu_type.to_le_bytes());
    hasher.update(&observation.executable.closure.cpu_subtype.to_le_bytes());
    put_bytes(
        &mut hasher,
        observation.executable.closure.dynamic_linker.as_bytes(),
    );
    for library in &observation.executable.closure.libraries {
        put_bytes(&mut hasher, library.as_bytes());
    }
    hasher.update(&[u8::from(observation.executable.closure.has_code_signature)]);
    hasher.update(observation.runtime.codesign_digest.as_bytes());
    hasher.update(observation.runtime.dyld_digest.as_bytes());
    put_signature(&mut hasher, &observation.runtime.dyld_signature);
    hasher.update(&observation.runtime.active_cache_uuid);
    hasher.update(&observation.runtime.active_cache_range_size.to_le_bytes());
    put_bytes(
        &mut hasher,
        observation.runtime.active_cache_path.as_bytes(),
    );
    put_cache(&mut hasher, &observation.runtime.main_cache);
    put_cache(&mut hasher, &observation.runtime.sub_cache);
    digest_hash(hasher.finalize())
}

fn provenance_name(provenance: ExecutableProvenance) -> &'static str {
    match provenance {
        ExecutableProvenance::AppleSystem => "apple-system",
        ExecutableProvenance::OpenAiCodexBundle => "openai-codex-bundle",
    }
}

fn put_signature(hasher: &mut Hasher, signature: &SignatureEvidence) {
    put_bytes(hasher, signature.identifier.as_bytes());
    put_bytes(hasher, signature.code_directory_sha256.as_bytes());
    put_bytes(
        hasher,
        match signature.kind {
            SignatureKind::ApplePlatform => b"apple-platform",
            SignatureKind::AdHoc => b"ad-hoc",
        },
    );
}

fn put_cache(hasher: &mut Hasher, cache: &CacheEvidence) {
    hasher.update(&cache.size.to_le_bytes());
    hasher.update(&cache.uuid);
    put_signature(hasher, &cache.signature);
    hasher.update(&(cache.subcaches.len() as u64).to_le_bytes());
    for subcache in &cache.subcaches {
        hasher.update(&subcache.uuid);
        hasher.update(&subcache.vm_offset.to_le_bytes());
        put_bytes(hasher, subcache.suffix.as_bytes());
    }
}

fn put_bytes(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn digest_bytes(value: &[u8]) -> Result<Digest, RuntimeAttestationError> {
    digest_hash(blake3::hash(value))
}

fn digest_hash(value: blake3::Hash) -> Result<Digest, RuntimeAttestationError> {
    Digest::from_hex(value.to_hex().as_str()).map_err(|_| RuntimeAttestationError::DigestEncoding)
}

fn system_timestamp() -> Result<UnixTimestamp, RuntimeAttestationError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeAttestationError::CheckpointClockAnomaly)?;
    Ok(UnixTimestamp {
        seconds: elapsed.as_secs(),
        nanoseconds: elapsed.subsec_nanos(),
    })
}

fn checkpoint_payload_digest(
    payload: &RuntimeCheckpointPayloadV1,
) -> Result<Digest, RuntimeAttestationError> {
    let encoded =
        serde_json::to_vec(payload).map_err(|_| RuntimeAttestationError::CheckpointCorrupt)?;
    let mut hasher = Hasher::new();
    put_bytes(&mut hasher, CHECKPOINT_DIGEST_DOMAIN);
    put_bytes(&mut hasher, &encoded);
    digest_hash(hasher.finalize())
}

fn checkpoint_payload(
    runtime: &RuntimeEvidence,
    audited_at: UnixTimestamp,
) -> RuntimeCheckpointPayloadV1 {
    RuntimeCheckpointPayloadV1 {
        attestation_schema_version: ATTESTATION_SCHEMA_VERSION,
        verifier_profile: CHECKPOINT_VERIFIER_PROFILE.to_owned(),
        audited_at_unix_seconds: audited_at.seconds,
        audited_at_nanoseconds: audited_at.nanoseconds,
        valid_for_seconds: CHECKPOINT_MAX_AGE.as_secs(),
        runtime: runtime.clone(),
    }
}

fn encode_runtime_checkpoint(
    payload: RuntimeCheckpointPayloadV1,
) -> Result<Vec<u8>, RuntimeAttestationError> {
    let payload_digest = checkpoint_payload_digest(&payload)?;
    let envelope = RuntimeCheckpointEnvelopeV1 {
        namespace: CHECKPOINT_NAMESPACE.to_owned(),
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        payload,
        payload_digest,
    };
    let encoded =
        serde_json::to_vec(&envelope).map_err(|_| RuntimeAttestationError::CheckpointCorrupt)?;
    if encoded.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(RuntimeAttestationError::CheckpointSizeLimit);
    }
    Ok(encoded)
}

fn decode_runtime_checkpoint(
    bytes: &[u8],
) -> Result<RuntimeCheckpointPayloadV1, RuntimeAttestationError> {
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(RuntimeAttestationError::CheckpointSizeLimit);
    }
    let envelope: RuntimeCheckpointEnvelopeV1 =
        serde_json::from_slice(bytes).map_err(|_| RuntimeAttestationError::CheckpointCorrupt)?;
    if envelope.namespace != CHECKPOINT_NAMESPACE
        || envelope.schema_version != CHECKPOINT_SCHEMA_VERSION
        || envelope.payload.attestation_schema_version != ATTESTATION_SCHEMA_VERSION
        || envelope.payload.verifier_profile != CHECKPOINT_VERIFIER_PROFILE
        || envelope.payload.valid_for_seconds != CHECKPOINT_MAX_AGE.as_secs()
    {
        return Err(RuntimeAttestationError::CheckpointSchemaMismatch);
    }
    if checkpoint_payload_digest(&envelope.payload)? != envelope.payload_digest {
        return Err(RuntimeAttestationError::CheckpointCorrupt);
    }
    validate_runtime_evidence(&envelope.payload.runtime)?;
    Ok(envelope.payload)
}

fn checkpoint_file_metadata(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), RuntimeAttestationError> {
    // Only the owner may read or replace audit evidence. This is deliberately
    // stricter than merely rejecting group/other writes.
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.len() > MAX_CHECKPOINT_BYTES
    {
        return Err(RuntimeAttestationError::CheckpointUnsafe);
    }
    Ok(())
}

fn validate_checkpoint_parent(path: &Path) -> Result<&Path, RuntimeAttestationError> {
    let Some(file_name) = path.file_name().filter(|name| !name.is_empty()) else {
        return Err(RuntimeAttestationError::CheckpointPathInvalid);
    };
    if !path.is_absolute() {
        return Err(RuntimeAttestationError::CheckpointPathInvalid);
    }
    let parent = path
        .parent()
        .ok_or(RuntimeAttestationError::CheckpointPathInvalid)?;
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    if canonical_parent != parent || canonical_parent.join(file_name) != path {
        return Err(RuntimeAttestationError::CheckpointPathInvalid);
    }

    let current_uid = unsafe { libc::geteuid() };
    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
        let mode = metadata.mode();
        let owner_trusted = metadata.uid() == current_uid || metadata.uid() == 0;
        let root_sticky_directory = metadata.uid() == 0 && mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || !owner_trusted
            || (mode & 0o022 != 0 && !root_sticky_directory)
        {
            return Err(RuntimeAttestationError::CheckpointUnsafe);
        }
    }

    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    if parent_metadata.uid() != current_uid || parent_metadata.mode() & 0o7777 != 0o700 {
        return Err(RuntimeAttestationError::CheckpointUnsafe);
    }
    Ok(parent)
}

fn read_runtime_checkpoint_file(
    path: &Path,
) -> Result<(RuntimeCheckpointPayloadV1, Metadata), RuntimeAttestationError> {
    validate_checkpoint_parent(path)?;
    let before_path = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(RuntimeAttestationError::CheckpointMissing);
        }
        Err(error) => return Err(RuntimeAttestationError::CheckpointIo { kind: error.kind() }),
    };
    checkpoint_file_metadata(path, &before_path)?;
    if std::fs::canonicalize(path).ok().as_deref() != Some(path) {
        return Err(RuntimeAttestationError::CheckpointUnsafe);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    let before = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    checkpoint_file_metadata(path, &before)?;
    if !same_file_epoch(&before_path, &before) {
        return Err(RuntimeAttestationError::CheckpointUnsafe);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(RuntimeAttestationError::CheckpointSizeLimit);
    }
    let after = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    let reopened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    let path_after = reopened
        .metadata()
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    if bytes.len() as u64 != before.len()
        || !same_file_epoch(&before, &after)
        || !same_file_epoch(&before, &path_after)
    {
        return Err(RuntimeAttestationError::CheckpointUnsafe);
    }
    Ok((decode_runtime_checkpoint(&bytes)?, after))
}

fn metadata_timestamp(metadata: &Metadata) -> Result<UnixTimestamp, RuntimeAttestationError> {
    let seconds = u64::try_from(metadata.mtime())
        .map_err(|_| RuntimeAttestationError::CheckpointClockAnomaly)?;
    let nanoseconds = u32::try_from(metadata.mtime_nsec())
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .ok_or(RuntimeAttestationError::CheckpointClockAnomaly)?;
    Ok(UnixTimestamp {
        seconds,
        nanoseconds,
    })
}

fn timestamp_elapsed(
    later: UnixTimestamp,
    earlier: UnixTimestamp,
) -> Result<Duration, RuntimeAttestationError> {
    if later < earlier {
        return Err(RuntimeAttestationError::CheckpointClockAnomaly);
    }
    let mut seconds = later.seconds - earlier.seconds;
    let nanoseconds = if later.nanoseconds >= earlier.nanoseconds {
        later.nanoseconds - earlier.nanoseconds
    } else {
        seconds = seconds
            .checked_sub(1)
            .ok_or(RuntimeAttestationError::CheckpointClockAnomaly)?;
        1_000_000_000 + later.nanoseconds - earlier.nanoseconds
    };
    Ok(Duration::new(seconds, nanoseconds))
}

fn load_runtime_checkpoint(
    path: &Path,
    now: UnixTimestamp,
) -> Result<RuntimeCheckpointPayloadV1, RuntimeAttestationError> {
    let (payload, metadata) = read_runtime_checkpoint_file(path)?;
    let audited_at = UnixTimestamp {
        seconds: payload.audited_at_unix_seconds,
        nanoseconds: payload.audited_at_nanoseconds,
    };
    if audited_at.nanoseconds >= 1_000_000_000 {
        return Err(RuntimeAttestationError::CheckpointClockAnomaly);
    }
    let age = timestamp_elapsed(now, audited_at)?;
    if age > CHECKPOINT_MAX_AGE {
        return Err(RuntimeAttestationError::CheckpointStale);
    }
    let modified_at = metadata_timestamp(&metadata)?;
    // The timestamp is sampled after the slow audit and before the atomic
    // checkpoint write, so a legitimate file mtime lies in this closed range.
    if modified_at < audited_at || modified_at > now {
        return Err(RuntimeAttestationError::CheckpointClockAnomaly);
    }
    Ok(payload)
}

struct RemoveFileOnDrop(PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn create_private_file(path: &Path) -> Result<File, RuntimeAttestationError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    checkpoint_file_metadata(path, &metadata)?;
    Ok(file)
}

fn checkpoint_lock_path(parent: &Path, checkpoint: &Path) -> PathBuf {
    let digest = blake3::hash(checkpoint.as_os_str().as_encoded_bytes());
    parent.join(format!(".again-runtime-audit-{}.lock", digest.to_hex()))
}

/// Acquire a persistent, target-specific advisory lock. The lock inode stays
/// on disk, while the kernel releases ownership whenever the process exits,
/// including crashes. This avoids both stranded create-new sentinels and a
/// cross-target global lock within one checkpoint directory.
fn acquire_checkpoint_lock(
    parent: &Path,
    checkpoint: &Path,
) -> Result<File, RuntimeAttestationError> {
    let lock_path = checkpoint_lock_path(parent, checkpoint);
    let (file, created) = match create_private_file(&lock_path) {
        Ok(file) => {
            file.sync_all()
                .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
            (file, true)
        }
        Err(RuntimeAttestationError::CheckpointIo {
            kind: io::ErrorKind::AlreadyExists,
        }) => {
            let before = std::fs::symlink_metadata(&lock_path)
                .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
            checkpoint_file_metadata(&lock_path, &before)?;
            if std::fs::canonicalize(&lock_path).ok().as_deref() != Some(lock_path.as_path()) {
                return Err(RuntimeAttestationError::CheckpointUnsafe);
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lock_path)
                .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
            let opened = file
                .metadata()
                .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
            checkpoint_file_metadata(&lock_path, &opened)?;
            if !same_file_epoch(&before, &opened) {
                return Err(RuntimeAttestationError::CheckpointUnsafe);
            }
            (file, false)
        }
        Err(error) => return Err(error),
    };

    // SAFETY: `file` owns a live descriptor. `flock` receives no pointer and
    // the kernel releases the lock when this file description is dropped.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        return if error
            .raw_os_error()
            .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
        {
            Err(RuntimeAttestationError::CheckpointLocked)
        } else {
            Err(RuntimeAttestationError::CheckpointIo { kind: error.kind() })
        };
    }
    let opened = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    let path_after = std::fs::symlink_metadata(&lock_path)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    checkpoint_file_metadata(&lock_path, &path_after)?;
    if !same_file_epoch(&opened, &path_after) {
        return Err(RuntimeAttestationError::CheckpointUnsafe);
    }
    if created {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    }
    Ok(file)
}

fn persist_runtime_checkpoint(
    path: &Path,
    runtime: &RuntimeEvidence,
    audited_at: UnixTimestamp,
) -> Result<(), RuntimeAttestationError> {
    let parent = validate_checkpoint_parent(path)?;
    let _lock = acquire_checkpoint_lock(parent, path)?;

    match read_runtime_checkpoint_file(path) {
        Ok((existing, _)) => {
            let existing_at = UnixTimestamp {
                seconds: existing.audited_at_unix_seconds,
                nanoseconds: existing.audited_at_nanoseconds,
            };
            if existing_at >= audited_at {
                return Err(RuntimeAttestationError::CheckpointRollback);
            }
        }
        Err(RuntimeAttestationError::CheckpointMissing) => {}
        Err(error) => return Err(error),
    }

    validate_runtime_evidence(runtime)?;
    let payload = checkpoint_payload(runtime, audited_at);
    let encoded = encode_runtime_checkpoint(payload.clone())?;
    let stage_path = parent.join(format!(
        ".again-runtime-audit-{}.tmp",
        Uuid::new_v4().simple()
    ));
    let mut stage = create_private_file(&stage_path)?;
    let _stage_cleanup = RemoveFileOnDrop(stage_path.clone());
    stage
        .write_all(&encoded)
        .and_then(|()| stage.sync_all())
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    let metadata = stage
        .metadata()
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    checkpoint_file_metadata(&stage_path, &metadata)?;
    drop(stage);

    std::fs::rename(&stage_path, path)
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RuntimeAttestationError::CheckpointIo { kind: error.kind() })?;
    let (committed, _) = read_runtime_checkpoint_file(path)?;
    if committed != payload {
        return Err(RuntimeAttestationError::CheckpointCorrupt);
    }
    Ok(())
}

struct StableArtifact {
    canonical_path: PathBuf,
    bytes: Vec<u8>,
}

fn read_stable_artifact(
    path: &Path,
    max_bytes: u64,
    exact_size: Option<u64>,
    require_root_owner: bool,
    artifact: &'static str,
) -> Result<StableArtifact, RuntimeAttestationError> {
    let before_path = safe_artifact_metadata(path, exact_size, require_root_owner, artifact)?;
    let canonical =
        std::fs::canonicalize(path).map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    if canonical != path {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    let mut file = open_no_follow(path, artifact)?;
    let before = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    if !same_file_epoch(&before_path, &before) {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    if before.len() > max_bytes {
        return Err(RuntimeAttestationError::ArtifactReadLimit { artifact });
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(RuntimeAttestationError::ArtifactReadLimit { artifact });
    }
    let after = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    let reopened = open_no_follow(path, artifact)?;
    let path_after = reopened
        .metadata()
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    if bytes.len() as u64 != before.len()
        || !same_file_epoch(&before, &after)
        || !same_file_epoch(&before, &path_after)
    {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    Ok(StableArtifact {
        canonical_path: canonical,
        bytes,
    })
}

fn inspect_exact_small_artifact(
    path: &Path,
    expected_size: u64,
    expected_digest: &str,
    artifact: &'static str,
) -> Result<Digest, RuntimeAttestationError> {
    let stable = read_stable_artifact(
        path,
        MAX_STATIC_ARTIFACT_BYTES,
        Some(expected_size),
        true,
        artifact,
    )?;
    let digest = digest_bytes(&stable.bytes)?;
    if digest.to_hex() != expected_digest {
        return Err(RuntimeAttestationError::ArtifactDigestMismatch { artifact });
    }
    Ok(digest)
}

fn safe_artifact_metadata(
    path: &Path,
    exact_size: Option<u64>,
    require_root_owner: bool,
    artifact: &'static str,
) -> Result<Metadata, RuntimeAttestationError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || (require_root_owner && metadata.uid() != 0)
    {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    if exact_size.is_some_and(|expected| metadata.len() != expected) {
        return Err(RuntimeAttestationError::ArtifactSizeMismatch { artifact });
    }
    Ok(metadata)
}

fn open_no_follow(path: &Path, artifact: &'static str) -> Result<File, RuntimeAttestationError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })
}

fn same_file_epoch(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(target_os = "macos")]
fn inspect_cache(
    path: &Path,
    expected_size: u64,
    artifact: &'static str,
    expected_code_directory: &str,
) -> Result<CacheEvidence, RuntimeAttestationError> {
    let before = safe_artifact_metadata(path, Some(expected_size), true, artifact)?;
    if std::fs::canonicalize(path).ok().as_deref() != Some(path) {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    let header = read_cache_header(path, artifact)?;
    let signature = inspect_signature(
        path,
        artifact,
        CACHE_IDENTIFIER,
        expected_code_directory,
        SignatureKind::AdHoc,
    )?;
    let after = safe_artifact_metadata(path, Some(expected_size), true, artifact)?;
    if !same_file_epoch(&before, &after) {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    Ok(CacheEvidence {
        size: expected_size,
        uuid: header.uuid,
        subcaches: header.subcaches,
        signature,
    })
}

#[cfg(target_os = "macos")]
fn inspect_cache_header_only(
    path: &Path,
    expected_size: u64,
    artifact: &'static str,
    audited_signature: SignatureEvidence,
) -> Result<CacheEvidence, RuntimeAttestationError> {
    let before = safe_artifact_metadata(path, Some(expected_size), true, artifact)?;
    if std::fs::canonicalize(path).ok().as_deref() != Some(path) {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    let header = read_cache_header(path, artifact)?;
    let after = safe_artifact_metadata(path, Some(expected_size), true, artifact)?;
    if !same_file_epoch(&before, &after) {
        return Err(RuntimeAttestationError::UnsafeArtifact { artifact });
    }
    Ok(CacheEvidence {
        size: expected_size,
        uuid: header.uuid,
        subcaches: header.subcaches,
        signature: audited_signature,
    })
}

struct CacheHeaderEvidence {
    uuid: [u8; 16],
    subcaches: Vec<SubcacheEvidence>,
}

fn read_cache_header(
    path: &Path,
    artifact: &'static str,
) -> Result<CacheHeaderEvidence, RuntimeAttestationError> {
    let mut file = open_no_follow(path, artifact)?;
    let before = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    let mut prefix = vec![0_u8; MAX_CACHE_HEADER_BYTES.min(before.len() as usize)];
    file.read_exact(&mut prefix)
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    let after = file
        .metadata()
        .map_err(|error| RuntimeAttestationError::ArtifactIo {
            artifact,
            kind: error.kind(),
        })?;
    if !same_file_epoch(&before, &after) || prefix.get(..16) != Some(CACHE_MAGIC) {
        return Err(RuntimeAttestationError::CacheHeaderInvalid);
    }
    let mapping_offset = read_le_u32(&prefix, 16)? as usize;
    if mapping_offset < 400 || mapping_offset > prefix.len() {
        return Err(RuntimeAttestationError::CacheHeaderInvalid);
    }
    let uuid = read_array_16(&prefix, 88)?;
    let subcache_offset = read_le_u32(&prefix, 392)? as usize;
    let subcache_count = read_le_u32(&prefix, 396)? as usize;
    if subcache_count > 8 {
        return Err(RuntimeAttestationError::CacheHeaderInvalid);
    }
    if subcache_count == 0 {
        // Subcache headers retain a builder offset even though only the main
        // cache owns the array. No bytes are consumed at that offset.
        // The offset is therefore deliberately not dereferenced.
    } else {
        let end = subcache_offset
            .checked_add(
                subcache_count
                    .checked_mul(56)
                    .ok_or(RuntimeAttestationError::CacheHeaderInvalid)?,
            )
            .ok_or(RuntimeAttestationError::CacheHeaderInvalid)?;
        if end > prefix.len() {
            return Err(RuntimeAttestationError::CacheHeaderInvalid);
        }
    }
    let mut subcaches = Vec::with_capacity(subcache_count);
    for index in 0..subcache_count {
        let offset = subcache_offset + index * 56;
        let suffix_bytes = prefix
            .get(offset + 24..offset + 56)
            .ok_or(RuntimeAttestationError::CacheHeaderInvalid)?;
        let nul = suffix_bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(RuntimeAttestationError::CacheHeaderInvalid)?;
        if suffix_bytes[nul..].iter().any(|byte| *byte != 0) {
            return Err(RuntimeAttestationError::CacheHeaderInvalid);
        }
        let suffix = std::str::from_utf8(&suffix_bytes[..nul])
            .map_err(|_| RuntimeAttestationError::CacheHeaderInvalid)?;
        if suffix.is_empty()
            || suffix
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'/' | b'\\'))
        {
            return Err(RuntimeAttestationError::CacheHeaderInvalid);
        }
        subcaches.push(SubcacheEvidence {
            uuid: read_array_16(&prefix, offset)?,
            vm_offset: read_le_u64(&prefix, offset + 16)?,
            suffix: suffix.to_owned(),
        });
    }
    Ok(CacheHeaderEvidence { uuid, subcaches })
}

#[cfg(target_os = "macos")]
fn inspect_signature(
    path: &Path,
    artifact: &'static str,
    expected_identifier: &str,
    expected_code_directory: &str,
    expected_kind: SignatureKind,
) -> Result<SignatureEvidence, RuntimeAttestationError> {
    run_codesign(&["--verify", "--strict", "--verbose=4"], path, false)?;
    let details = run_codesign(&["-dvvv"], path, true)?;
    let text = std::str::from_utf8(&details)
        .map_err(|_| RuntimeAttestationError::CodeSignIdentityMismatch)?;
    let identifier = unique_detail(text, "Identifier=")?;
    let code_directory = unique_detail(text, "CandidateCDHashFull sha256=")?;
    let kind = if text.lines().any(|line| line == "Signature=adhoc") {
        SignatureKind::AdHoc
    } else if [
        "Authority=Software Signing",
        "Authority=Apple Code Signing Certification Authority",
        "Authority=Apple Root CA",
    ]
    .iter()
    .all(|expected| text.lines().any(|line| line == *expected))
    {
        SignatureKind::ApplePlatform
    } else {
        return Err(RuntimeAttestationError::CodeSignIdentityMismatch);
    };
    let evidence = SignatureEvidence {
        identifier: identifier.to_owned(),
        code_directory_sha256: code_directory.to_owned(),
        kind,
    };
    validate_signature(
        &evidence,
        expected_identifier,
        expected_code_directory,
        expected_kind,
    )?;
    let _ = artifact;
    Ok(evidence)
}

fn unique_detail<'a>(details: &'a str, prefix: &str) -> Result<&'a str, RuntimeAttestationError> {
    let mut matches = details.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = matches
        .next()
        .ok_or(RuntimeAttestationError::CodeSignIdentityMismatch)?;
    if value.is_empty() || matches.next().is_some() {
        return Err(RuntimeAttestationError::CodeSignIdentityMismatch);
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
fn run_codesign(
    arguments: &[&str],
    path: &Path,
    capture: bool,
) -> Result<Vec<u8>, RuntimeAttestationError> {
    let mut command = Command::new(CODESIGN_PATH);
    command
        .env_clear()
        .args(arguments)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command
        .spawn()
        .map_err(|_| RuntimeAttestationError::CodeSignFailed)?;
    let stdout_thread = child.stdout.take().map(|stdout| {
        thread::spawn(move || read_bounded_output(stdout, MAX_CODESIGN_OUTPUT_BYTES))
    });
    let stderr_thread = child.stderr.take().map(|stderr| {
        thread::spawn(move || read_bounded_output(stderr, MAX_CODESIGN_OUTPUT_BYTES))
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < CODESIGN_TIMEOUT => {
                thread::sleep(CHILD_POLL_INTERVAL);
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RuntimeAttestationError::CodeSignTimeout);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RuntimeAttestationError::CodeSignFailed);
            }
        }
    };
    let mut output = Vec::new();
    for handle in [stdout_thread, stderr_thread].into_iter().flatten() {
        let (bytes, overflow) = handle
            .join()
            .map_err(|_| RuntimeAttestationError::CodeSignFailed)?;
        if overflow
            || output
                .len()
                .checked_add(bytes.len().saturating_add(1))
                .is_none_or(|length| length > MAX_CODESIGN_OUTPUT_BYTES)
        {
            return Err(RuntimeAttestationError::CodeSignOutputLimit);
        }
        output.extend_from_slice(&bytes);
        output.push(b'\n');
    }
    if !status.success() {
        return Err(RuntimeAttestationError::CodeSignFailed);
    }
    Ok(output)
}

fn read_bounded_output(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::with_capacity(limit.min(4096));
    let mut overflow = false;
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let remaining = limit.saturating_sub(output.len());
                let retained = remaining.min(read);
                output.extend_from_slice(&buffer[..retained]);
                overflow |= retained != read;
            }
            Err(_) => {
                overflow = true;
                break;
            }
        }
    }
    (output, overflow)
}

fn parse_mach_closure(bytes: &[u8]) -> Result<MachClosure, RuntimeAttestationError> {
    let slice = select_arm64_slice(bytes)?;
    if read_le_u32(slice, 0)? != MH_MAGIC_64 {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    let cpu_type = read_le_u32(slice, 4)?;
    let cpu_subtype = read_le_u32(slice, 8)?;
    if read_le_u32(slice, 12)? != MH_EXECUTE {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    let commands = read_le_u32(slice, 16)? as usize;
    let commands_size = read_le_u32(slice, 20)? as usize;
    if commands == 0 || commands > 4096 || commands_size > 16 * 1024 * 1024 {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    let commands_end = 32_usize
        .checked_add(commands_size)
        .ok_or(RuntimeAttestationError::DynamicClosureMismatch)?;
    if commands_end > slice.len() {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    let mut offset = 32_usize;
    let mut dynamic_linkers = Vec::new();
    let mut libraries = Vec::new();
    let mut has_code_signature = false;
    for _ in 0..commands {
        let command = read_le_u32(slice, offset)?;
        let size = read_le_u32(slice, offset + 4)? as usize;
        if size < 8 || size % 4 != 0 {
            return Err(RuntimeAttestationError::DynamicClosureMismatch);
        }
        let end = offset
            .checked_add(size)
            .ok_or(RuntimeAttestationError::DynamicClosureMismatch)?;
        if end > commands_end {
            return Err(RuntimeAttestationError::DynamicClosureMismatch);
        }
        match command {
            LC_LOAD_DYLINKER => {
                dynamic_linkers.push(load_command_string(slice, offset, end)?);
            }
            LC_LOAD_DYLIB => libraries.push(load_command_string(slice, offset, end)?),
            LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB
            | LC_RPATH | LC_DYLD_ENVIRONMENT => {
                return Err(RuntimeAttestationError::DynamicClosureMismatch);
            }
            LC_CODE_SIGNATURE => has_code_signature = true,
            _ => {}
        }
        offset = end;
    }
    if offset != commands_end || dynamic_linkers.len() != 1 {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    Ok(MachClosure {
        cpu_type,
        cpu_subtype,
        dynamic_linker: dynamic_linkers.remove(0),
        libraries,
        has_code_signature,
    })
}

fn select_arm64_slice(bytes: &[u8]) -> Result<&[u8], RuntimeAttestationError> {
    if read_le_u32(bytes, 0).ok() == Some(MH_MAGIC_64) {
        return Ok(bytes);
    }
    if read_be_u32(bytes, 0)? != FAT_MAGIC {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    let architectures = read_be_u32(bytes, 4)? as usize;
    if architectures == 0 || architectures > 16 {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    let mut selected = None;
    for index in 0..architectures {
        let entry = 8 + index * 20;
        let cpu_type = read_be_u32(bytes, entry)?;
        let cpu_subtype = read_be_u32(bytes, entry + 4)? & CPU_SUBTYPE_MASK;
        let offset = read_be_u32(bytes, entry + 8)? as usize;
        let size = read_be_u32(bytes, entry + 12)? as usize;
        let end = offset
            .checked_add(size)
            .ok_or(RuntimeAttestationError::DynamicClosureMismatch)?;
        if end > bytes.len() {
            return Err(RuntimeAttestationError::DynamicClosureMismatch);
        }
        if cpu_type == CPU_TYPE_ARM64
            && cpu_subtype == CPU_SUBTYPE_ARM64E
            && selected.replace(&bytes[offset..end]).is_some()
        {
            return Err(RuntimeAttestationError::DynamicClosureMismatch);
        }
    }
    selected.ok_or(RuntimeAttestationError::DynamicClosureMismatch)
}

fn load_command_string(
    bytes: &[u8],
    command_offset: usize,
    command_end: usize,
) -> Result<String, RuntimeAttestationError> {
    let relative = read_le_u32(bytes, command_offset + 8)? as usize;
    let start = command_offset
        .checked_add(relative)
        .ok_or(RuntimeAttestationError::DynamicClosureMismatch)?;
    if start < command_offset + 12 || start >= command_end {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    let value = bytes
        .get(start..command_end)
        .and_then(|value| value.split(|byte| *byte == 0).next())
        .ok_or(RuntimeAttestationError::DynamicClosureMismatch)?;
    let value =
        std::str::from_utf8(value).map_err(|_| RuntimeAttestationError::DynamicClosureMismatch)?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(RuntimeAttestationError::DynamicClosureMismatch);
    }
    Ok(value.to_owned())
}

fn read_array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16], RuntimeAttestationError> {
    bytes
        .get(offset..offset + 16)
        .and_then(|value| value.try_into().ok())
        .ok_or(RuntimeAttestationError::CacheHeaderInvalid)
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, RuntimeAttestationError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or(RuntimeAttestationError::DynamicClosureMismatch)?;
    Ok(u32::from_le_bytes(value))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, RuntimeAttestationError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or(RuntimeAttestationError::DynamicClosureMismatch)?;
    Ok(u32::from_be_bytes(value))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Result<u64, RuntimeAttestationError> {
    let value: [u8; 8] = bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .ok_or(RuntimeAttestationError::CacheHeaderInvalid)?;
    Ok(u64::from_le_bytes(value))
}

#[cfg(target_os = "macos")]
fn sysctl_string(
    name: &'static str,
    field: &'static str,
) -> Result<String, RuntimeAttestationError> {
    let mut bytes = sysctl_bytes(name, field)?;
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(RuntimeAttestationError::RuntimeFactMismatch { field });
    }
    String::from_utf8(bytes).map_err(|_| RuntimeAttestationError::RuntimeFactMismatch { field })
}

#[cfg(target_os = "macos")]
fn sysctl_u32(name: &'static str, field: &'static str) -> Result<u32, RuntimeAttestationError> {
    let bytes = sysctl_bytes(name, field)?;
    let value: [u8; 4] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeAttestationError::RuntimeFactMismatch { field })?;
    Ok(u32::from_ne_bytes(value))
}

#[cfg(target_os = "macos")]
fn sysctl_bytes(
    name: &'static str,
    field: &'static str,
) -> Result<Vec<u8>, RuntimeAttestationError> {
    let name = CString::new(name).expect("static sysctl names contain no NUL");
    let mut length = 0_usize;
    // SAFETY: `name` is NUL terminated, the first call writes only `length`,
    // and all other pointers are null as required by sysctlbyname(3).
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length == 0
        || length > MAX_SYSCTL_BYTES
    {
        return Err(RuntimeAttestationError::RuntimeFactIo {
            field,
            kind: io::Error::last_os_error().kind(),
        });
    }
    let mut bytes = vec![0_u8; length];
    let mut actual = length;
    // SAFETY: `bytes` owns `length` writable bytes and `actual` describes that
    // allocation. The kernel receives no new-value pointer.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut actual,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || actual != length
    {
        return Err(RuntimeAttestationError::RuntimeFactIo {
            field,
            kind: io::Error::last_os_error().kind(),
        });
    }
    Ok(bytes)
}

#[cfg(target_os = "macos")]
fn active_csr_config() -> Result<u32, RuntimeAttestationError> {
    unsafe extern "C" {
        fn csr_get_active_config(config: *mut u32) -> i32;
    }
    let mut config = u32::MAX;
    // SAFETY: `config` is a valid writable u32 for the duration of the call.
    if unsafe { csr_get_active_config(&mut config) } != 0 {
        return Err(RuntimeAttestationError::CsrInspectionFailed);
    }
    Ok(config)
}

#[cfg(target_os = "macos")]
fn active_shared_cache_mapping() -> Result<([u8; 16], u64), RuntimeAttestationError> {
    unsafe extern "C" {
        fn _dyld_get_shared_cache_uuid(uuid: *mut u8) -> bool;
        fn _dyld_get_shared_cache_range(length: *mut usize) -> *const libc::c_void;
    }
    let mut uuid = [0_u8; 16];
    // SAFETY: dyld writes exactly one uuid_t (16 bytes) to this valid buffer.
    if !unsafe { _dyld_get_shared_cache_uuid(uuid.as_mut_ptr()) } || uuid == [0_u8; 16] {
        return Err(RuntimeAttestationError::ActiveCacheUnavailable);
    }
    let mut length = 0_usize;
    // SAFETY: dyld writes one `usize` and returns the immutable mapping range
    // already present in this process. A non-null range of at least one full
    // header is required before the bounded header read below.
    let base = unsafe { _dyld_get_shared_cache_range(&mut length) };
    if base.is_null()
        || length < 104
        || u64::try_from(length).ok() != Some(AUDITED_SHARED_CACHE_RANGE_SIZE)
    {
        return Err(RuntimeAttestationError::ActiveCacheUnavailable);
    }
    // SAFETY: the API established an immutable mapped range at least 104 bytes
    // long. Only the fixed header prefix is observed.
    let header = unsafe { std::slice::from_raw_parts(base.cast::<u8>(), 104) };
    if header.get(..16) != Some(CACHE_MAGIC)
        || read_array_16(header, 88)? != uuid
        || uuid != CACHE_MAIN_UUID
    {
        return Err(RuntimeAttestationError::ActiveCacheMismatch);
    }
    Ok((uuid, length as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::TempDir;

    fn fixture_signature(
        identifier: &str,
        code_directory: &str,
        kind: SignatureKind,
    ) -> SignatureEvidence {
        SignatureEvidence {
            identifier: identifier.to_owned(),
            code_directory_sha256: code_directory.to_owned(),
            kind,
        }
    }

    fn fixture_runtime() -> RuntimeEvidence {
        RuntimeEvidence {
            system_profile: AUDITED_SYSTEM_PROFILE.to_owned(),
            target_arch: AUDITED_TARGET_ARCH.to_owned(),
            hw_machine: AUDITED_HW_MACHINE.to_owned(),
            hw_cpu_type: AUDITED_HW_CPU_TYPE,
            hw_cpu_subtype: AUDITED_HW_CPU_SUBTYPE,
            translated: 0,
            kernel_release: AUDITED_KERNEL_RELEASE.to_owned(),
            kernel_build: AUDITED_KERNEL_BUILD.to_owned(),
            kernel_version: AUDITED_KERNEL_VERSION.to_owned(),
            product_version: AUDITED_PRODUCT_VERSION.to_owned(),
            release_type: AUDITED_RELEASE_TYPE.to_owned(),
            shared_region_version: AUDITED_SHARED_REGION_VERSION,
            csr_config: AUDITED_CSR_CONFIG,
            active_cache_uuid: CACHE_MAIN_UUID,
            active_cache_range_size: AUDITED_SHARED_CACHE_RANGE_SIZE,
            active_cache_path: CACHE_MAIN_PATH.to_owned(),
            codesign_digest: Digest::from_hex(CODESIGN_BLAKE3).unwrap(),
            dyld_digest: Digest::from_hex(DYLD_BLAKE3).unwrap(),
            dyld_signature: fixture_signature(
                DYLD_IDENTIFIER,
                DYLD_CODE_DIRECTORY_SHA256,
                SignatureKind::ApplePlatform,
            ),
            main_cache: CacheEvidence {
                size: CACHE_MAIN_SIZE,
                uuid: CACHE_MAIN_UUID,
                subcaches: vec![SubcacheEvidence {
                    uuid: CACHE_SUB_UUID,
                    vm_offset: CACHE_SUB_VM_OFFSET,
                    suffix: ".01".to_owned(),
                }],
                signature: fixture_signature(
                    CACHE_IDENTIFIER,
                    CACHE_MAIN_CODE_DIRECTORY_SHA256,
                    SignatureKind::AdHoc,
                ),
            },
            sub_cache: CacheEvidence {
                size: CACHE_SUB_SIZE,
                uuid: CACHE_SUB_UUID,
                subcaches: Vec::new(),
                signature: fixture_signature(
                    CACHE_IDENTIFIER,
                    CACHE_SUB_CODE_DIRECTORY_SHA256,
                    SignatureKind::AdHoc,
                ),
            },
        }
    }

    fn fixture_observation() -> RuntimeObservation {
        RuntimeObservation {
            command_name: "cat".to_owned(),
            executable: InspectedExecutable {
                identity: ExecutableIdentity {
                    tool: ToolKind::Cat,
                    canonical_path: PathBuf::from("/bin/cat"),
                    provenance: ExecutableProvenance::AppleSystem,
                    semantic_profile: AUDITED_SYSTEM_PROFILE.to_owned(),
                },
                executable_digest: Digest::from_hex(
                    "30fdc8a74ef975c1d61a6110083490ac43fe0c0c28228a5abd2cd5f88187cf1c",
                )
                .unwrap(),
                closure: MachClosure {
                    cpu_type: CPU_TYPE_ARM64,
                    cpu_subtype: CPU_SUBTYPE_ARM64E,
                    dynamic_linker: DYLD_PATH.to_owned(),
                    libraries: vec!["/usr/lib/libSystem.B.dylib".to_owned()],
                    has_code_signature: true,
                },
            },
            runtime: fixture_runtime(),
        }
    }

    fn checkpoint_fixture() -> (TempDir, PathBuf, UnixTimestamp, UnixTimestamp) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let canonical = std::fs::canonicalize(directory.path()).unwrap();
        let path = canonical.join("runtime-audit.json");
        let audited_at = system_timestamp().unwrap();
        persist_runtime_checkpoint(&path, &fixture_runtime(), audited_at).unwrap();
        let now = system_timestamp().unwrap();
        (directory, path, audited_at, now)
    }

    #[test]
    fn deterministic_digest_vectors_bind_the_reviewed_runtime() {
        let attestation = seal_observation(fixture_observation()).unwrap();
        assert_eq!(
            attestation.platform_digest().to_hex(),
            "3f406c802cb5c02fff164fbceab30cf71508bb8353c6da2e6525667ad79925ea"
        );
        assert_eq!(
            attestation.image_digest().to_hex(),
            "1e48a4b0f69a19cb62645d2f3bb9c9600661e4237a42a7090be8191a025f0ab4"
        );
    }

    #[test]
    fn spoofed_path_and_profile_are_rejected() {
        let mut wrong_path = fixture_observation();
        wrong_path.executable.identity.canonical_path = PathBuf::from("/tmp/cat");
        assert_eq!(
            seal_observation(wrong_path).unwrap_err(),
            RuntimeAttestationError::ExecutableIdentityMismatch
        );

        let mut wrong_profile = fixture_observation();
        wrong_profile.executable.identity.semantic_profile = "caller-claimed".to_owned();
        assert_eq!(
            seal_observation(wrong_profile).unwrap_err(),
            RuntimeAttestationError::ExecutableIdentityMismatch
        );
    }

    #[test]
    fn architecture_kernel_and_translation_spoofs_are_rejected() {
        let mut architecture = fixture_observation();
        architecture.runtime.hw_cpu_subtype = 0;
        assert!(matches!(
            seal_observation(architecture),
            Err(RuntimeAttestationError::RuntimeFactMismatch {
                field: "hw.cpusubtype"
            })
        ));

        let mut kernel = fixture_observation();
        kernel.runtime.kernel_build = "24G91".to_owned();
        assert!(matches!(
            seal_observation(kernel),
            Err(RuntimeAttestationError::RuntimeFactMismatch {
                field: "kern.osversion"
            })
        ));

        let mut translated = fixture_observation();
        translated.runtime.translated = 1;
        assert!(matches!(
            seal_observation(translated),
            Err(RuntimeAttestationError::RuntimeFactMismatch {
                field: "sysctl.proc_translated"
            })
        ));
    }

    #[test]
    fn loader_cache_and_signature_spoofs_are_rejected() {
        let mut loader = fixture_observation();
        loader.executable.closure.dynamic_linker = "/tmp/dyld".to_owned();
        assert_eq!(
            seal_observation(loader).unwrap_err(),
            RuntimeAttestationError::DynamicClosureMismatch
        );

        let mut active_cache = fixture_observation();
        active_cache.runtime.active_cache_uuid[0] ^= 1;
        assert_eq!(
            seal_observation(active_cache).unwrap_err(),
            RuntimeAttestationError::ActiveCacheMismatch
        );

        let mut subcache = fixture_observation();
        subcache.runtime.main_cache.subcaches[0].suffix = ".02".to_owned();
        assert_eq!(
            seal_observation(subcache).unwrap_err(),
            RuntimeAttestationError::CacheHeaderInvalid
        );

        let mut code_directory = fixture_observation();
        code_directory
            .runtime
            .main_cache
            .signature
            .code_directory_sha256 = "00".repeat(32);
        assert_eq!(
            seal_observation(code_directory).unwrap_err(),
            RuntimeAttestationError::CodeSignIdentityMismatch
        );
    }

    #[test]
    fn weakened_sip_or_authenticated_root_is_rejected() {
        let mut observation = fixture_observation();
        observation.runtime.csr_config = 1 << 11;
        assert_eq!(
            seal_observation(observation).unwrap_err(),
            RuntimeAttestationError::CsrPolicyMismatch
        );
    }

    #[test]
    fn checkpoint_roundtrip_is_strict_and_deterministic() {
        let (_directory, path, audited_at, now) = checkpoint_fixture();
        let payload = load_runtime_checkpoint(&path, now).unwrap();
        assert_eq!(payload.runtime, fixture_runtime());
        assert_eq!(
            payload.attestation_schema_version,
            ATTESTATION_SCHEMA_VERSION
        );
        assert_eq!(payload.verifier_profile, CHECKPOINT_VERIFIER_PROFILE);

        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.nlink(), 1);

        let encoded =
            encode_runtime_checkpoint(checkpoint_payload(&fixture_runtime(), audited_at)).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), encoded);
    }

    #[test]
    fn corrupt_missing_field_and_changed_cache_checkpoints_fail_closed() {
        let (_directory, path, _audited_at, now) = checkpoint_fixture();
        let mut corrupt = std::fs::read(&path).unwrap();
        let index = corrupt.len() / 2;
        corrupt[index] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(load_runtime_checkpoint(&path, now).is_err());

        let (_directory, path, _audited_at, now) = checkpoint_fixture();
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["payload"].as_object_mut().unwrap().remove("runtime");
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(
            load_runtime_checkpoint(&path, now).unwrap_err(),
            RuntimeAttestationError::CheckpointCorrupt
        );

        // Even an internally consistent checksum cannot smuggle a different
        // cache UUID out of a same-schema checkpoint.
        let (_directory, path, audited_at, now) = checkpoint_fixture();
        let mut changed = fixture_runtime();
        changed.active_cache_uuid[0] ^= 1;
        let encoded = encode_runtime_checkpoint(checkpoint_payload(&changed, audited_at)).unwrap();
        std::fs::write(&path, encoded).unwrap();
        assert_eq!(
            load_runtime_checkpoint(&path, now).unwrap_err(),
            RuntimeAttestationError::ActiveCacheMismatch
        );
    }

    #[test]
    fn checkpoint_rejects_wrong_mode_symlink_and_hardlink() {
        let (_directory, path, _audited_at, now) = checkpoint_fixture();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_runtime_checkpoint(&path, now).unwrap_err(),
            RuntimeAttestationError::CheckpointUnsafe
        );

        let (_directory, path, _audited_at, now) = checkpoint_fixture();
        let hardlink = path.with_file_name("runtime-audit-hardlink.json");
        std::fs::hard_link(&path, hardlink).unwrap();
        assert_eq!(
            load_runtime_checkpoint(&path, now).unwrap_err(),
            RuntimeAttestationError::CheckpointUnsafe
        );

        let (_directory, path, _audited_at, now) = checkpoint_fixture();
        let target = path.with_file_name("target.json");
        std::fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            load_runtime_checkpoint(&path, now).unwrap_err(),
            RuntimeAttestationError::CheckpointUnsafe
        );
    }

    #[test]
    fn checkpoint_rejects_writable_and_symlinked_intermediate_ancestors() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();

        let writable = root.join("writable");
        let private = writable.join("private");
        std::fs::create_dir(&writable).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            persist_runtime_checkpoint(
                &private.join("runtime-audit.json"),
                &fixture_runtime(),
                system_timestamp().unwrap(),
            )
            .unwrap_err(),
            RuntimeAttestationError::CheckpointUnsafe
        );

        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.join("alias");
        symlink(&real, &alias).unwrap();
        assert_eq!(
            persist_runtime_checkpoint(
                &alias.join("runtime-audit.json"),
                &fixture_runtime(),
                system_timestamp().unwrap(),
            )
            .unwrap_err(),
            RuntimeAttestationError::CheckpointPathInvalid
        );
    }

    #[test]
    fn checkpoint_lock_is_crash_recoverable_and_rejects_live_contention() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = std::fs::canonicalize(directory.path()).unwrap();
        let path = parent.join("runtime-audit.json");
        let lock_path = checkpoint_lock_path(&parent, &path);

        // A persistent lock inode left by a prior crash is reusable because no
        // process retains the kernel advisory lock.
        let stale_lock = create_private_file(&lock_path).unwrap();
        stale_lock.sync_all().unwrap();
        drop(stale_lock);
        persist_runtime_checkpoint(&path, &fixture_runtime(), system_timestamp().unwrap()).unwrap();
        let metadata = std::fs::symlink_metadata(&lock_path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);

        let held = acquire_checkpoint_lock(&parent, &path).unwrap();
        let newer = system_timestamp().unwrap();
        assert_eq!(
            persist_runtime_checkpoint(&path, &fixture_runtime(), newer).unwrap_err(),
            RuntimeAttestationError::CheckpointLocked
        );
        drop(held);
        persist_runtime_checkpoint(&path, &fixture_runtime(), system_timestamp().unwrap()).unwrap();
    }

    #[test]
    fn checkpoint_rejects_staleness_clock_anomalies_and_writer_rollback() {
        let (_directory, path, audited_at, _now) = checkpoint_fixture();
        let stale_now = UnixTimestamp {
            seconds: audited_at.seconds + CHECKPOINT_MAX_AGE.as_secs() + 1,
            nanoseconds: audited_at.nanoseconds,
        };
        assert_eq!(
            load_runtime_checkpoint(&path, stale_now).unwrap_err(),
            RuntimeAttestationError::CheckpointStale
        );

        let before_audit = UnixTimestamp {
            seconds: audited_at.seconds.saturating_sub(1),
            nanoseconds: audited_at.nanoseconds,
        };
        assert_eq!(
            load_runtime_checkpoint(&path, before_audit).unwrap_err(),
            RuntimeAttestationError::CheckpointClockAnomaly
        );
        assert_eq!(
            persist_runtime_checkpoint(&path, &fixture_runtime(), before_audit).unwrap_err(),
            RuntimeAttestationError::CheckpointRollback
        );
    }

    #[test]
    fn code_sign_details_require_unique_exact_fields() {
        let details = "Identifier=one\nCandidateCDHashFull sha256=abc\n";
        assert_eq!(unique_detail(details, "Identifier=").unwrap(), "one");
        let duplicate = "Identifier=one\nIdentifier=two\n";
        assert_eq!(
            unique_detail(duplicate, "Identifier=").unwrap_err(),
            RuntimeAttestationError::CodeSignIdentityMismatch
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn current_reviewed_host_mints_a_real_capability() {
        if host_audited_apple_profile().is_err() {
            return;
        }
        let attestation = attest_team_runtime_v1("cat", Path::new("/bin/cat")).unwrap();
        assert_eq!(attestation.command_name(), "cat");
        assert_eq!(attestation.executable_identity().tool, ToolKind::Cat);
        attestation.verify_executable_current().unwrap();

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let checkpoint = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("runtime-audit.json");
        persist_runtime_checkpoint(
            &checkpoint,
            static_runtime_evidence().unwrap(),
            system_timestamp().unwrap(),
        )
        .unwrap();
        let fast =
            attest_team_runtime_from_checkpoint_v1("cat", Path::new("/bin/cat"), &checkpoint)
                .unwrap();
        assert_eq!(attestation.platform_digest(), fast.platform_digest());
        assert_eq!(attestation.image_digest(), fast.image_digest());
        fast.verify_executable_current().unwrap();
        std::fs::remove_file(&checkpoint).unwrap();
        assert_eq!(
            fast.verify_executable_current().unwrap_err(),
            RuntimeAttestationError::CheckpointMissing
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "explicit slow-audit integration test"]
    fn explicit_full_audit_writes_a_fast_path_checkpoint() {
        if host_audited_apple_profile().is_err() {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let checkpoint = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("runtime-audit.json");
        let slow =
            audit_team_runtime_to_checkpoint_v1("cat", Path::new("/bin/cat"), &checkpoint).unwrap();
        let fast =
            attest_team_runtime_from_checkpoint_v1("cat", Path::new("/bin/cat"), &checkpoint)
                .unwrap();
        assert_eq!(slow.platform_digest(), fast.platform_digest());
        assert_eq!(slow.image_digest(), fast.image_digest());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "diagnostic cold/warm runtime-attestation benchmark"]
    fn benchmark_cold_and_warm_runtime_attestation() {
        if host_audited_apple_profile().is_err() {
            return;
        }
        let started = Instant::now();
        let cold = attest_team_runtime_v1("cat", Path::new("/bin/cat")).unwrap();
        let cold_micros = started.elapsed().as_micros();
        let started = Instant::now();
        let warm = attest_team_runtime_v1("cat", Path::new("/bin/cat")).unwrap();
        let warm_micros = started.elapsed().as_micros();
        assert_eq!(cold.platform_digest(), warm.platform_digest());
        assert_eq!(cold.image_digest(), warm.image_digest());
        assert!(warm_micros < cold_micros);
        eprintln!("runtime_attestation cold_micros={cold_micros} warm_micros={warm_micros}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "child process for the fresh-process checkpoint benchmark"]
    fn fast_checkpoint_benchmark_child() {
        let Some(checkpoint) = std::env::var_os("AGAIN_RUNTIME_BENCH_CHECKPOINT") else {
            return;
        };
        let started = Instant::now();
        let attestation = attest_team_runtime_from_checkpoint_v1(
            "cat",
            Path::new("/bin/cat"),
            Path::new(&checkpoint),
        )
        .unwrap();
        assert_eq!(attestation.command_name(), "cat");
        eprintln!(
            "fresh_process_attestation_micros={}",
            started.elapsed().as_micros()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "diagnostic fresh-process runtime-checkpoint benchmark"]
    fn benchmark_fresh_process_checkpoint_attestation() {
        if host_audited_apple_profile().is_err() {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let checkpoint = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("runtime-audit.json");
        persist_runtime_checkpoint(
            &checkpoint,
            static_runtime_evidence().unwrap(),
            system_timestamp().unwrap(),
        )
        .unwrap();

        let executable = std::env::current_exe().unwrap();
        eprintln!(
            "fresh_process_benchmark_executable={}",
            executable.display()
        );
        let mut attestation_micros = Vec::new();
        let mut process_micros = Vec::new();
        for _ in 0..25 {
            let started = Instant::now();
            let output = Command::new(&executable)
                .env("AGAIN_RUNTIME_BENCH_CHECKPOINT", &checkpoint)
                .args([
                    "--ignored",
                    "--exact",
                    "runtime_attestation::tests::fast_checkpoint_benchmark_child",
                    "--nocapture",
                ])
                .output()
                .unwrap_or_else(|error| {
                    panic!(
                        "spawn fresh benchmark process {}: {error}",
                        executable.display()
                    )
                });
            let process_elapsed = started.elapsed().as_micros();
            assert!(
                output.status.success(),
                "fresh process failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let elapsed = text
                .lines()
                .find_map(|line| {
                    line.trim()
                        .strip_prefix("fresh_process_attestation_micros=")
                        .and_then(|value| value.parse::<u128>().ok())
                })
                .expect("child benchmark timing");
            attestation_micros.push(elapsed);
            process_micros.push(process_elapsed);
        }
        attestation_micros.sort_unstable();
        process_micros.sort_unstable();
        let p95_index = (attestation_micros.len() * 95).div_ceil(100) - 1;
        let attestation_p95 = attestation_micros[p95_index];
        let process_p95 = process_micros[p95_index];
        assert!(
            attestation_p95 < 50_000,
            "fresh-process attestation p95 exceeded 50 ms: {attestation_p95} us"
        );
        eprintln!(
            "fresh_process_checkpoint runs={} attestation_p50_micros={} attestation_p95_micros={} process_p50_micros={} process_p95_micros={}",
            attestation_micros.len(),
            attestation_micros[attestation_micros.len() / 2],
            attestation_p95,
            process_micros[process_micros.len() / 2],
            process_p95,
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_spoofed_executable_path_is_rejected_before_runtime_sealing() {
        assert!(matches!(
            attest_team_runtime_v1("cat", Path::new("/usr/bin/head")),
            Err(RuntimeAttestationError::ExecutableNotAudited(_))
                | Err(RuntimeAttestationError::ExecutableIdentityMismatch)
        ));
    }

    #[test]
    fn cache_directory_is_the_reviewed_cryptex_location() {
        assert_eq!(
            Path::new(CACHE_MAIN_PATH).parent(),
            Some(Path::new(CACHE_DIRECTORY))
        );
        assert_eq!(
            Path::new(CACHE_SUB_PATH).parent(),
            Some(Path::new(CACHE_DIRECTORY))
        );
    }
}
