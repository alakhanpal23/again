//! Fixed rootless-namespace diagnostic for `linux-pytest-v1`.
//!
//! This module does not accept a program, arguments, caller-supplied
//! environment parameter, path, callback, descriptor, or output sink. Its
//! Linux leaf creates only one fixed child running a raw-syscall protocol; it
//! never executes caller code. The leaf verifies the namespace bootstrap and
//! a fixed, path-disconnected private tmpfs root with a fixed directory
//! topology, separately bounded scratch mounts, and a fresh procfs for the
//! child's PID namespace. It then authenticates the fixed report pipe at file
//! descriptor 0, closes every descriptor at or above 1 with one
//! `CLOSE_RANGE_UNSHARE` call, and uses the fresh procfs to audit the exact
//! transient descriptor inventory before closing the audit descriptor. It
//! then locks the classic root and UID capability semantics, drops the entire
//! bounding capability set, clears the ambient, effective, permitted, and
//! inheritable sets, sets `no_new_privs`, and independently reads every state
//! back. Finally, it reopens and authenticates only fixed private-root paths,
//! installs a fixed deny-by-default Landlock policy, and exercises exact local
//! filesystem and TCP denial canaries before reporting. The Landlock scope
//! mask and ABI-7-or-newer audit flag are accepted-policy evidence only; this
//! single terminal child does not functionally prove inter-process scope
//! isolation or inspect host audit logs. The child already owns a private
//! descriptor table, so this does not exercise the kernel's shared-table
//! unshare path. After the Landlock proof has closed and audited every transient
//! descriptor, the child installs one fixed TSYNC seccomp filter, verifies the
//! attached filter state, and proves that six otherwise harmless syscall
//! canaries receive the filter's private errno marker. The filter has only the
//! terminal report path's bounded write, poll, monotonic-clock, state-readback,
//! close, and exit surface. Wrong
//! architectures and the x32 syscall bit are fatal. Executable mappings remain
//! outside this slice. It does not prove workload stdio,
//! descriptor-selected workspace/runtime mounts, populated `/dev` endpoints,
//! or executable workload isolation. A completed marker is returned only
//! after that direct child has exited and been reaped. A cleanup-uncertain
//! failure remains possible.
//! The result is not an execution, snapshot, isolation-session, or reuse
//! authority.

use super::RefusalCode;
use std::fmt;

const PROTOCOL_VERSION_V2: u16 = 2;

/// Completed, terminally reaped diagnostic evidence.
///
/// Private fields and the absence of descriptor/PID accessors are deliberate:
/// this value cannot be used to enter the namespaces that were inspected.
pub(super) struct CompletedRootlessNamespaceProbeV1 {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IsolationQualificationStageV1 {
    #[cfg_attr(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        allow(dead_code)
    )]
    Platform,
    DedicatedHelper,
    HostCredentials,
    SupplementaryGroups,
    ParentNamespaces,
    ProtocolNonce,
    ControlChannels,
    CloneNamespaces,
    OpenChildProc,
    WriteUidMap,
    VerifyUidMap,
    WriteSetgroups,
    VerifySetgroups,
    WriteGidMap,
    VerifyGidMap,
    VerifyChildGroups,
    VerifyChildCapabilities,
    PinChildNamespaces,
    VerifyNamespaceFilesystem,
    VerifyNamespaceType,
    VerifyNamespaceFreshness,
    VerifyNamespaceOwner,
    ReceiveChildReady,
    VerifyChildReady,
    SendControl,
    ReceiveChildProof,
    VerifyChildProof,
    ChildUtsConfiguration,
    ChildMountRoot,
    ChildDescriptorScrub,
    ChildCapabilityDrop,
    ChildLandlock,
    ChildSeccomp,
    WaitForChild,
    ReapChild,
    Cleanup,
}

impl IsolationQualificationStageV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::DedicatedHelper => "dedicated_helper",
            Self::HostCredentials => "host_credentials",
            Self::SupplementaryGroups => "supplementary_groups",
            Self::ParentNamespaces => "parent_namespaces",
            Self::ProtocolNonce => "protocol_nonce",
            Self::ControlChannels => "control_channels",
            Self::CloneNamespaces => "clone_namespaces",
            Self::OpenChildProc => "open_child_proc",
            Self::WriteUidMap => "write_uid_map",
            Self::VerifyUidMap => "verify_uid_map",
            Self::WriteSetgroups => "write_setgroups",
            Self::VerifySetgroups => "verify_setgroups",
            Self::WriteGidMap => "write_gid_map",
            Self::VerifyGidMap => "verify_gid_map",
            Self::VerifyChildGroups => "verify_child_groups",
            Self::VerifyChildCapabilities => "verify_child_capabilities",
            Self::PinChildNamespaces => "pin_child_namespaces",
            Self::VerifyNamespaceFilesystem => "verify_namespace_filesystem",
            Self::VerifyNamespaceType => "verify_namespace_type",
            Self::VerifyNamespaceFreshness => "verify_namespace_freshness",
            Self::VerifyNamespaceOwner => "verify_namespace_owner",
            Self::ReceiveChildReady => "receive_child_ready",
            Self::VerifyChildReady => "verify_child_ready",
            Self::SendControl => "send_control",
            Self::ReceiveChildProof => "receive_child_proof",
            Self::VerifyChildProof => "verify_child_proof",
            Self::ChildUtsConfiguration => "child_uts_configuration",
            Self::ChildMountRoot => "child_mount_root",
            Self::ChildDescriptorScrub => "child_descriptor_scrub",
            Self::ChildCapabilityDrop => "child_capability_drop",
            Self::ChildLandlock => "child_landlock",
            Self::ChildSeccomp => "child_seccomp",
            Self::WaitForChild => "wait_for_child",
            Self::ReapChild => "reap_child",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IsolationQualificationReasonV1 {
    #[cfg_attr(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        allow(dead_code)
    )]
    UnsupportedPlatform,
    #[cfg_attr(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        allow(dead_code)
    )]
    UnsupportedArchitecture,
    #[cfg_attr(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        allow(dead_code)
    )]
    UnsupportedEnvironment,
    LoaderInjectionEnvironment,
    MultipleTasks,
    SignalDisposition,
    HostCredentialMismatch,
    BoundExceeded,
    UnstableObservation,
    KernelCapabilityUnavailable,
    AdministrativePolicy,
    Io,
    ShortWrite,
    MalformedKernelResponse,
    MapMismatch,
    GroupMismatch,
    NamespaceFilesystemMismatch,
    NamespaceTypeMismatch,
    NamespaceNotFresh,
    NamespaceOwnerMismatch,
    ProtocolTimeout,
    ProtocolEofMismatch,
    ProtocolFrameMismatch,
    ChildInvariantFailed,
    ChildSignaled,
    ChildExitMismatch,
    WaitFailed,
    CleanupUncertain,
}

impl IsolationQualificationReasonV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsupportedArchitecture => "unsupported_architecture",
            Self::UnsupportedEnvironment => "unsupported_environment",
            Self::LoaderInjectionEnvironment => "loader_injection_environment",
            Self::MultipleTasks => "multiple_tasks",
            Self::SignalDisposition => "signal_disposition",
            Self::HostCredentialMismatch => "host_credential_mismatch",
            Self::BoundExceeded => "bound_exceeded",
            Self::UnstableObservation => "unstable_observation",
            Self::KernelCapabilityUnavailable => "kernel_capability_unavailable",
            Self::AdministrativePolicy => "administrative_policy",
            Self::Io => "io",
            Self::ShortWrite => "short_write",
            Self::MalformedKernelResponse => "malformed_kernel_response",
            Self::MapMismatch => "map_mismatch",
            Self::GroupMismatch => "group_mismatch",
            Self::NamespaceFilesystemMismatch => "namespace_filesystem_mismatch",
            Self::NamespaceTypeMismatch => "namespace_type_mismatch",
            Self::NamespaceNotFresh => "namespace_not_fresh",
            Self::NamespaceOwnerMismatch => "namespace_owner_mismatch",
            Self::ProtocolTimeout => "protocol_timeout",
            Self::ProtocolEofMismatch => "protocol_eof_mismatch",
            Self::ProtocolFrameMismatch => "protocol_frame_mismatch",
            Self::ChildInvariantFailed => "child_invariant_failed",
            Self::ChildSignaled => "child_signaled",
            Self::ChildExitMismatch => "child_exit_mismatch",
            Self::WaitFailed => "wait_failed",
            Self::CleanupUncertain => "cleanup_uncertain",
        }
    }
}

pub(super) struct IsolationQualificationFailureV1 {
    code: RefusalCode,
    stage: IsolationQualificationStageV1,
    reason: IsolationQualificationReasonV1,
    errno: Option<i32>,
    cleanup_complete: bool,
}

impl IsolationQualificationFailureV1 {
    const fn new(
        code: RefusalCode,
        stage: IsolationQualificationStageV1,
        reason: IsolationQualificationReasonV1,
        errno: Option<i32>,
    ) -> Self {
        Self {
            code,
            stage,
            reason,
            errno,
            cleanup_complete: true,
        }
    }

    fn cleanup_uncertain(errno: Option<i32>) -> Self {
        Self {
            code: RefusalCode::IsolationPreflightFailed,
            stage: IsolationQualificationStageV1::Cleanup,
            reason: IsolationQualificationReasonV1::CleanupUncertain,
            errno,
            cleanup_complete: false,
        }
    }

    pub(super) const fn code(&self) -> RefusalCode {
        self.code
    }

    pub(super) const fn stage(&self) -> &'static str {
        self.stage.as_str()
    }

    pub(super) const fn reason(&self) -> &'static str {
        self.reason.as_str()
    }

    pub(super) const fn errno(&self) -> Option<i32> {
        self.errno
    }

    pub(super) const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }

    pub(super) const fn is_expected_unavailable(&self) -> bool {
        if !self.cleanup_complete() {
            return false;
        }
        if matches!(
            (self.code, self.stage, self.reason, self.errno),
            (
                RefusalCode::RequiredNamespaceFailed,
                IsolationQualificationStageV1::ChildUtsConfiguration,
                IsolationQualificationReasonV1::AdministrativePolicy,
                Some(libc::EPERM),
            )
        ) {
            return true;
        }
        if matches!(
            (self.code, self.stage, self.reason, self.errno),
            (
                RefusalCode::SeccompUnavailable,
                IsolationQualificationStageV1::ChildSeccomp,
                IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP),
            )
        ) {
            return true;
        }
        if matches!(
            (self.code, self.stage, self.reason, self.errno),
            (
                RefusalCode::LandlockUnavailable,
                IsolationQualificationStageV1::ChildLandlock,
                IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                None | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP),
            )
        ) {
            return true;
        }
        if matches!(
            (self.code, self.stage, self.reason, self.errno),
            (
                RefusalCode::CloseRangeUnavailable,
                IsolationQualificationStageV1::ChildDescriptorScrub,
                IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                Some(libc::ENOSYS) | Some(libc::EINVAL),
            ) | (
                RefusalCode::CloseRangeUnavailable,
                IsolationQualificationStageV1::ChildDescriptorScrub,
                IsolationQualificationReasonV1::AdministrativePolicy,
                Some(libc::EPERM) | Some(libc::EACCES),
            )
        ) {
            return true;
        }
        matches!(
            (self.stage, self.reason),
            (
                IsolationQualificationStageV1::Platform,
                IsolationQualificationReasonV1::UnsupportedPlatform
                    | IsolationQualificationReasonV1::UnsupportedArchitecture
                    | IsolationQualificationReasonV1::UnsupportedEnvironment,
            ) | (
                IsolationQualificationStageV1::CloneNamespaces,
                IsolationQualificationReasonV1::AdministrativePolicy
                    | IsolationQualificationReasonV1::KernelCapabilityUnavailable,
            ) | (
                IsolationQualificationStageV1::WriteUidMap
                    | IsolationQualificationStageV1::WriteSetgroups
                    | IsolationQualificationStageV1::WriteGidMap,
                IsolationQualificationReasonV1::AdministrativePolicy,
            ) | (
                IsolationQualificationStageV1::DedicatedHelper
                    | IsolationQualificationStageV1::OpenChildProc,
                IsolationQualificationReasonV1::AdministrativePolicy
                    | IsolationQualificationReasonV1::KernelCapabilityUnavailable,
            )
        )
    }
}

/// Run the fixed diagnostic. The caller must be the dedicated, single-threaded
/// hidden helper process; the function independently verifies the task count.
pub(super) fn qualify_rootless_namespace_tuple_v1()
-> Result<CompletedRootlessNamespaceProbeV1, IsolationQualificationFailureV1> {
    platform::qualify_rootless_namespace_tuple_v1()
}

/// Live, cleanup-owning namespace bootstrap stopped on the diagnostic's
/// authenticated release frame after ID-map and namespace-pin verification.
///
/// This is deliberately weaker than an isolation session: the child has not
/// configured its private root, mounted scratch/procfs, scrubbed descriptors,
/// or eliminated capabilities. It exists only as the smallest safe reusable
/// extraction from the fixed diagnostic and exposes no PID or descriptor.
pub(super) struct BlockedRootlessNamespaceBootstrapV1 {
    _inner: platform::BlockedRootlessNamespaceBootstrapV1,
}

impl fmt::Debug for BlockedRootlessNamespaceBootstrapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockedRootlessNamespaceBootstrapV1")
            .field("state", &"blocked-before-release")
            .field("resources", &"<opaque-cleanup-owned>")
            .finish()
    }
}

pub(super) fn begin_blocked_rootless_namespace_bootstrap_v1()
-> Result<BlockedRootlessNamespaceBootstrapV1, IsolationQualificationFailureV1> {
    platform::begin_blocked_rootless_namespace_bootstrap_v1()
        .map(|inner| BlockedRootlessNamespaceBootstrapV1 { _inner: inner })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdMapTupleV1 {
    inside: u32,
    outside: u32,
    length: u32,
}

fn parse_one_id_map_v1(bytes: &[u8]) -> Option<IdMapTupleV1> {
    let row = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if row.is_empty() || row.contains(&b'\n') || row.contains(&b'\r') {
        return None;
    }
    let mut parser = AsciiFieldsV1::new(row);
    let inside = parser.next_u32()?;
    let outside = parser.next_u32()?;
    let length = parser.next_u32()?;
    if parser.has_more_fields() {
        return None;
    }
    Some(IdMapTupleV1 {
        inside,
        outside,
        length,
    })
}

fn parse_setgroups_deny_v1(bytes: &[u8]) -> bool {
    bytes == b"deny\n"
}

struct AsciiFieldsV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> AsciiFieldsV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn next_bytes(&mut self) -> Option<&'a [u8]> {
        self.skip_whitespace();
        let start = self.offset;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| !matches!(byte, b' ' | b'\t'))
        {
            self.offset += 1;
        }
        (self.offset > start).then_some(&self.bytes[start..self.offset])
    }

    fn next_u32(&mut self) -> Option<u32> {
        parse_ascii_u32_field_v1(self.next_bytes()?)
    }

    fn has_more_fields(&mut self) -> bool {
        self.skip_whitespace();
        self.offset != self.bytes.len()
    }
}

fn parse_ascii_u32_field_v1(field: &[u8]) -> Option<u32> {
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    field.iter().try_fold(0_u32, |value, byte| {
        value.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))
    })
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    pub(super) struct BlockedRootlessNamespaceBootstrapV1 {
        _private: (),
    }

    pub(super) fn begin_blocked_rootless_namespace_bootstrap_v1()
    -> Result<BlockedRootlessNamespaceBootstrapV1, IsolationQualificationFailureV1> {
        Err(IsolationQualificationFailureV1::new(
            RefusalCode::UnsupportedOs,
            IsolationQualificationStageV1::Platform,
            IsolationQualificationReasonV1::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn qualify_rootless_namespace_tuple_v1()
    -> Result<CompletedRootlessNamespaceProbeV1, IsolationQualificationFailureV1> {
        Err(IsolationQualificationFailureV1::new(
            RefusalCode::UnsupportedOs,
            IsolationQualificationStageV1::Platform,
            IsolationQualificationReasonV1::UnsupportedPlatform,
            None,
        ))
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn id_map_parser_requires_exactly_one_logical_row() {
        assert_eq!(
            parse_one_id_map_v1(b"0 1000 1\n"),
            Some(IdMapTupleV1 {
                inside: 0,
                outside: 1000,
                length: 1,
            })
        );
        assert_eq!(
            parse_one_id_map_v1(b"0\t1000\t1"),
            parse_one_id_map_v1(b"0 1000 1")
        );
        for invalid in [
            b"0\n1000\n1\n".as_slice(),
            b"0 1000 1\n0 1001 1\n".as_slice(),
            b"0 1000 1\n\n".as_slice(),
            b"0 1000 1\r\n".as_slice(),
            b"0 -1 1\n".as_slice(),
            b"0 4294967296 1\n".as_slice(),
            b"0 1000 1 extra\n".as_slice(),
            b"".as_slice(),
        ] {
            assert_eq!(parse_one_id_map_v1(invalid), None);
        }
    }

    #[test]
    fn setgroups_parser_accepts_only_kernel_canonical_deny() {
        assert!(parse_setgroups_deny_v1(b"deny\n"));
        for invalid in [
            b"deny".as_slice(),
            b"deny\n\n".as_slice(),
            b"allow\n".as_slice(),
            b" deny\n".as_slice(),
            b"deny\r\n".as_slice(),
        ] {
            assert!(!parse_setgroups_deny_v1(invalid));
        }
    }

    #[test]
    fn cleanup_uncertainty_overrides_public_classification() {
        let prior = IsolationQualificationFailureV1::new(
            RefusalCode::UserNamespaceUnavailable,
            IsolationQualificationStageV1::CloneNamespaces,
            IsolationQualificationReasonV1::AdministrativePolicy,
            Some(1),
        );
        assert!(prior.is_expected_unavailable());
        assert!(prior.cleanup_complete());

        let cleanup = IsolationQualificationFailureV1::cleanup_uncertain(Some(110));
        assert_eq!(cleanup.code(), RefusalCode::IsolationPreflightFailed);
        assert_eq!(cleanup.stage(), "cleanup");
        assert_eq!(cleanup.reason(), "cleanup_uncertain");
        assert!(!cleanup.cleanup_complete());
        assert!(!cleanup.is_expected_unavailable());
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
mod platform {
    use std::ffi::CStr;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use super::*;

    const MAX_SUPPLEMENTARY_GROUPS_V1: usize = 256;
    const MAX_PROC_MAP_BYTES_V1: usize = 4 * 1024;
    const MAX_PROC_STATUS_BYTES_V1: usize = 64 * 1024;
    const PROBE_PROTOCOL_SECONDS_V1: i64 = 8;
    const PROBE_HARD_SECONDS_V1: i64 = 10;
    const FRAME_BYTES_V1: usize = 64;
    const NONCE_BYTES_V1: usize = 16;
    const READY_MAGIC_V1: &[u8; 8] = b"AGNNRD01";
    const RELEASE_MAGIC_V1: &[u8; 8] = b"AGNNRL01";
    const PROOF_MAGIC_V1: &[u8; 8] = b"AGNNPF01";
    const PHASE_READY_V1: u8 = 1;
    const PHASE_RELEASE_V1: u8 = 2;
    const PHASE_PROOF_V1: u8 = 3;
    const PROOF_STATUS_SUCCESS_V1: u8 = 0;
    const PROOF_STATUS_OS_ERROR_V1: u8 = 1;
    const PROOF_STATUS_INVARIANT_V1: u8 = 2;
    const PROOF_STATUS_PROTOCOL_V1: u8 = 3;
    const PROOF_STATUS_UTS_CONFIGURATION_V1: u8 = 4;
    const PROOF_STATUS_MOUNT_ROOT_OS_V1: u8 = 5;
    const PROOF_STATUS_MOUNT_ROOT_INVARIANT_V1: u8 = 6;
    const PROOF_STATUS_CLOSE_RANGE_OS_V1: u8 = 7;
    const PROOF_STATUS_FD_SCRUB_V1: u8 = 8;
    const PROOF_STATUS_CAPABILITY_DROP_V1: u8 = 9;
    const PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1: u8 = 10;
    const PROOF_STATUS_LANDLOCK_BROKEN_V1: u8 = 11;
    const PROOF_STATUS_SECCOMP_UNAVAILABLE_V1: u8 = 12;
    const PROOF_STATUS_SECCOMP_BROKEN_V1: u8 = 13;
    const PROOF_FLAGS_V1: u16 = 0x01ff;
    const CHILD_EXIT_PROOF_FAILED_V1: i32 = 125;
    const FRAME_MAGIC_OFFSET_V1: usize = 0;
    const FRAME_VERSION_OFFSET_V1: usize = 8;
    const FRAME_PHASE_OFFSET_V1: usize = 10;
    const FRAME_STATUS_OFFSET_V1: usize = 11;
    const FRAME_FLAGS_OFFSET_V1: usize = 12;
    const FRAME_FLAGS_END_V1: usize = 14;
    const FRAME_NONCE_OFFSET_V1: usize = 16;
    const FRAME_ERROR_OFFSET_V1: usize = 32;
    const FRAME_PID_OFFSET_V1: usize = 36;
    const FRAME_UID_OFFSET_V1: usize = 40;
    const FRAME_EUID_OFFSET_V1: usize = 44;
    const FRAME_GID_OFFSET_V1: usize = 48;
    const FRAME_EGID_OFFSET_V1: usize = 52;
    const FRAME_RESERVED_OFFSET_V1: usize = 56;
    const NSFS_MAGIC_V1: libc::c_long = 0x6e73_6673;
    const PROC_SUPER_MAGIC_V1: libc::c_long = 0x0000_9fa0;
    const RESOLVE_NO_XDEV_V1: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS_V1: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS_V1: u64 = 0x04;
    const RESOLVE_BENEATH_V1: u64 = 0x08;
    const NS_GET_USERNS_V1: libc::c_ulong = 0xb701;
    const NS_GET_NSTYPE_V1: libc::c_ulong = 0xb703;
    const NS_GET_OWNER_UID_V1: libc::c_ulong = 0xb704;
    const CLONE_CLEAR_SIGHAND_V1: u64 = 0x1_0000_0000;
    const CAP_SYS_ADMIN_MASK_V1: u64 = 1_u64 << 21;
    const HOSTNAME_V1: &[u8] = b"again";
    const TMPFS_SUPER_MAGIC_V1: libc::c_long = 0x0102_1994;
    const ROOT_TMPFS_BYTES_V1: u64 = 16 * 1024 * 1024;
    const ROOT_TMPFS_INODES_V1: u64 = 4_096;
    const ROOT_TMPFS_TYPE_V1: &CStr = c"tmpfs";
    const ROOT_TMPFS_OPTIONS_V1: &CStr = c"size=16777216,nr_inodes=4096,mode=0755,noswap";
    const ROOT_PATH_V1: &CStr = c"/";
    const CURRENT_DIRECTORY_V1: &CStr = c".";
    const OLD_ROOT_NAME_V1: &CStr = c".oldroot";
    const OLD_ROOT_PATH_V1: &CStr = c"/.oldroot";
    const WORKSPACE_NAME_V1: &CStr = c"workspace";
    const TMP_NAME_V1: &CStr = c"tmp";
    const RUN_NAME_V1: &CStr = c"run";
    const HOME_NAME_V1: &CStr = c"home";
    const AGAIN_NAME_V1: &CStr = c"again";
    const PROC_NAME_V1: &CStr = c"proc";
    const DEV_NAME_V1: &CStr = c"dev";
    const SYS_NAME_V1: &CStr = c"sys";
    const MEMINFO_NAME_V1: &CStr = c"meminfo";
    const ABSENT_ROOT_NAMES_V1: [&CStr; 4] =
        [OLD_ROOT_NAME_V1, PROC_NAME_V1, DEV_NAME_V1, SYS_NAME_V1];
    const TMP_PATH_V1: &CStr = c"/tmp";
    const RUN_PATH_V1: &CStr = c"/run";
    const AGAIN_HOME_PATH_V1: &CStr = c"/home/again";
    const PROC_PATH_V1: &CStr = c"/proc";
    const PROC_FD_AUDIT_PATH_V1: &CStr = c"proc/1/fd";
    const SCRATCH_TMPFS_BYTES_V1: u64 = 4 * 1024 * 1024;
    const SCRATCH_TMPFS_INODES_V1: u64 = 1_024;
    const TMP_TMPFS_OPTIONS_V1: &CStr = c"size=4194304,nr_inodes=1024,mode=1777,noswap";
    const RUN_TMPFS_OPTIONS_V1: &CStr = c"size=4194304,nr_inodes=1024,mode=0755,noswap";
    const AGAIN_HOME_TMPFS_OPTIONS_V1: &CStr = c"size=4194304,nr_inodes=1024,mode=0700,noswap";
    const PROCFS_OPTIONS_V1: &CStr = c"subset=pid";
    const ACTIVE_PID_NAMESPACE_PATH_V1: &CStr = c"/proc/self/ns/pid";
    const PROC_PID_ONE_NAME_V1: &CStr = c"1";
    const PROC_NAMESPACE_DIRECTORY_NAME_V1: &CStr = c"ns";
    const PID_NAMESPACE_NAME_V1: &CStr = c"pid";
    const PROC_SELF_NAME_V1: &CStr = c"self";
    const PROC_SUBSET_ABSENT_NAMES_V1: [&CStr; 2] = [SYS_NAME_V1, MEMINFO_NAME_V1];
    const WORKSPACE_MODE_V1: libc::mode_t = 0o755;
    const TMP_MODE_V1: libc::mode_t = 0o1777;
    const RUN_MODE_V1: libc::mode_t = 0o755;
    const HOME_MODE_V1: libc::mode_t = 0o755;
    const AGAIN_HOME_MODE_V1: libc::mode_t = 0o700;
    const PROC_MODE_V1: libc::mode_t = 0o555;
    const DEV_MODE_V1: libc::mode_t = 0o755;
    const SCRATCH_MOUNT_FLAGS_V1: libc::c_ulong =
        (libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong;
    const PROC_MOUNT_FLAGS_V1: libc::c_ulong =
        (libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong;
    const REQUIRED_PATH_STATX_MASK_V1: u32 = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_UID
        | libc::STATX_GID
        | libc::STATX_INO
        | libc::STATX_MNT_ID;
    const REPORT_DESCRIPTOR_V1: RawFd = 0;
    const FD_AUDIT_DESCRIPTOR_V1: RawFd = 1;
    const CLOSE_RANGE_FIRST_V1: u32 = 1;
    const CLOSE_RANGE_LAST_V1: u32 = u32::MAX;
    const FD_AUDIT_BUFFER_BYTES_V1: usize = 256;
    const FD_AUDIT_MAX_GETDENTS_CALLS_V1: usize = 8;
    const DIRENT64_NAME_OFFSET_V1: usize = 19;
    const DIRENT64_MIN_RECORD_BYTES_V1: usize = 24;
    const DIRENT64_ALIGNMENT_V1: usize = 8;
    const FD_AUDIT_DOT_BIT_V1: u8 = 1 << 0;
    const FD_AUDIT_DOT_DOT_BIT_V1: u8 = 1 << 1;
    const FD_AUDIT_ZERO_BIT_V1: u8 = 1 << 2;
    const FD_AUDIT_ONE_BIT_V1: u8 = 1 << 3;
    const FD_AUDIT_COMPLETE_MASK_V1: u8 =
        FD_AUDIT_DOT_BIT_V1 | FD_AUDIT_DOT_DOT_BIT_V1 | FD_AUDIT_ZERO_BIT_V1 | FD_AUDIT_ONE_BIT_V1;
    const LINUX_CAPABILITY_VERSION_3_V1: u32 = 0x2008_0522;
    const CAPABILITY_SCAN_MAX_V1: u32 = 64;
    const CAPABILITY_SCAN_LENGTH_V1: usize = CAPABILITY_SCAN_MAX_V1 as usize + 1;
    const CAPABILITY_MINIMUM_LAST_V1: u32 = 40;
    const CAP_SETPCAP_V1: u32 = 8;
    const CAPABILITY_SCAN_UNOBSERVED_V1: i8 = -2;
    const CAPABILITY_SCAN_INVALID_V1: i8 = -1;
    const CAPABILITY_SCAN_CLEAR_V1: i8 = 0;
    const CAPABILITY_SCAN_SET_V1: i8 = 1;
    const CAPABILITY_SECUREBITS_V1: libc::c_int = libc::SECBIT_NOROOT
        | libc::SECBIT_NOROOT_LOCKED
        | libc::SECBIT_NO_SETUID_FIXUP
        | libc::SECBIT_NO_SETUID_FIXUP_LOCKED
        | libc::SECBIT_KEEP_CAPS_LOCKED
        | libc::SECBIT_NO_CAP_AMBIENT_RAISE
        | libc::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
    const LANDLOCK_CREATE_RULESET_VERSION_V1: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH_V1: u32 = 1;
    // ABI 7 introduced this stable bit assignment; ABI 8 added TSYNC at bit 3.
    const LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF_V1: u32 = 1;
    // The VERSION query returns a positive kernel `int`, surfaced as `c_long`.
    const LANDLOCK_ABI_MAX_V1: libc::c_long = i32::MAX as libc::c_long;
    const LANDLOCK_HANDLED_FS_V1: u64 = 0xffff;
    const LANDLOCK_HANDLED_NET_V1: u64 = 0x3;
    const LANDLOCK_SCOPED_V1: u64 = 0x3;
    const LANDLOCK_TMP_ACCESS_V1: u64 = 0x77be;
    const LANDLOCK_RESTRICTED_ACCESS_V1: u64 = 0x17be;
    const LANDLOCK_MAX_TRACKED_FDS_V1: usize = 2;
    const LANDLOCK_FIRST_TRANSIENT_FD_V1: RawFd = 2;
    const WORKSPACE_FIXTURE_PATH_V1: &CStr = c"/workspace/input";
    const WORKSPACE_PATH_V1: &CStr = c"/workspace";
    const TMP_PREEXISTING_PATH_V1: &CStr = c"/tmp/preexisting";
    const TMP_FROM_ITEM_PATH_V1: &CStr = c"/tmp/from/item";
    const TMP_TO_ITEM_PATH_V1: &CStr = c"/tmp/to/item";
    const TMP_NEW_PATH_V1: &CStr = c"/tmp/new";
    const RUN_RESTRICTED_PATH_V1: &CStr = c"/run/restricted";
    const RUN_RESTRICTED_RELATIVE_PATH_V1: &CStr = c"run/restricted";
    const RUN_RESTRICTED_PREEXISTING_PATH_V1: &CStr = c"/run/restricted/preexisting";
    const RUN_RESTRICTED_FROM_ITEM_PATH_V1: &CStr = c"/run/restricted/from/item";
    const RUN_RESTRICTED_TO_ITEM_PATH_V1: &CStr = c"/run/restricted/to/item";
    const LANDLOCK_CANARY_BYTES_V1: &[u8] = b"again-landlock";
    const SECCOMP_SET_MODE_FILTER_V1: u32 = 1;
    const SECCOMP_GET_ACTION_AVAIL_V1: u32 = 2;
    const SECCOMP_FILTER_FLAG_TSYNC_V1: u32 = 1;
    const SECCOMP_MODE_DISABLED_V1: libc::c_long = 0;
    const SECCOMP_MODE_FILTER_V1: libc::c_long = 2;
    const SECCOMP_RET_KILL_PROCESS_V1: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO_V1: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW_V1: u32 = 0x7fff_0000;
    const SECCOMP_ERRNO_MARKER_V1: u16 = 0x05a5;
    const SECCOMP_RET_MARKER_V1: u32 = SECCOMP_RET_ERRNO_V1 | SECCOMP_ERRNO_MARKER_V1 as u32;
    const AUDIT_ARCH_X86_64_V1: u32 = 0xc000_003e;
    const X32_SYSCALL_BIT_V1: u32 = 0x4000_0000;
    const SECCOMP_DATA_NR_OFFSET_V1: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET_V1: u32 = 4;
    const SECCOMP_DATA_ARGS_OFFSET_V1: u32 = 16;
    const SECCOMP_DATA_ARG_STRIDE_V1: u32 = 8;
    const SECCOMP_DATA_ARG_HIGH_OFFSET_V1: u32 = 4;
    const SECCOMP_MAX_POLL_MILLISECONDS_V1: u32 = (PROBE_PROTOCOL_SECONDS_V1 as u32) * 1_000;
    const SECCOMP_SYSCALL_WRITE_V1: u32 = 1;
    const SECCOMP_SYSCALL_CLOSE_V1: u32 = 3;
    const SECCOMP_SYSCALL_POLL_V1: u32 = 7;
    const SECCOMP_SYSCALL_IOCTL_V1: u32 = 16;
    const SECCOMP_SYSCALL_SOCKET_V1: u32 = 41;
    const SECCOMP_SYSCALL_EXIT_V1: u32 = 60;
    const SECCOMP_SYSCALL_PRCTL_V1: u32 = 157;
    const SECCOMP_SYSCALL_CLOCK_GETTIME_V1: u32 = 228;
    const SECCOMP_SYSCALL_OPENAT_V1: u32 = 257;
    const SECCOMP_SYSCALL_UNSHARE_V1: u32 = 272;
    const SECCOMP_SYSCALL_SETNS_V1: u32 = 308;
    const SECCOMP_SYSCALL_CLONE3_V1: u32 = 435;
    const SECCOMP_PR_GET_SECCOMP_V1: u32 = 21;
    const SECCOMP_PR_GET_NO_NEW_PRIVS_V1: u32 = 39;
    const SECCOMP_EXIT_SUCCESS_V1: u32 = 0;
    const SECCOMP_EXIT_FAILURE_V1: u32 = CHILD_EXIT_PROOF_FAILED_V1 as u32;
    const SECCOMP_BPF_LD_W_ABS_V1: u16 = 0x20;
    const SECCOMP_BPF_JMP_JEQ_K_V1: u16 = 0x15;
    const SECCOMP_BPF_JMP_JGT_K_V1: u16 = 0x25;
    const SECCOMP_BPF_JMP_JSET_K_V1: u16 = 0x45;
    const SECCOMP_BPF_RET_K_V1: u16 = 0x06;
    const MAX_LINUX_ERRNO_V1: i32 = 4_095;

    #[repr(C)]
    #[derive(Default)]
    struct CloneArgsV1 {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    #[repr(C)]
    struct OpenHowV1 {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxCapabilityHeaderV1 {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct LinuxCapabilityDataV1 {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ChildPathIdentityV1 {
        mount_id: u64,
        inode: u64,
        device_major: u32,
        device_minor: u32,
        mode: u16,
        uid: u32,
        gid: u32,
    }

    struct ChildPrivateRootEvidenceV1 {
        root: ChildPathIdentityV1,
        tmp: ChildPathIdentityV1,
        run: ChildPathIdentityV1,
        proc: ChildPathIdentityV1,
    }

    enum ChildMountRootFailureV1 {
        Os(i32),
        Invariant,
    }

    enum ChildDescriptorFailureV1 {
        CloseRange(i32),
        Os(i32),
        Invariant,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ChildCapabilityFailureV1 {
        Os(i32),
        Invariant,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ChildLandlockFailureV1 {
        Unavailable(i32),
        Os(i32),
        Invariant,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ChildLandlockPolicyV1 {
        Abi6,
        Abi7OrNewer,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ChildSeccompFailureV1 {
        Unavailable(i32),
        Os(i32),
        Invariant,
    }

    #[repr(C)]
    struct LinuxLandlockRulesetAttrV1 {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C, packed)]
    struct LinuxLandlockPathBeneathAttrV1 {
        allowed_access: u64,
        parent_fd: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxSockFilterV1 {
        code: u16,
        jump_true: u8,
        jump_false: u8,
        operand: u32,
    }

    #[repr(C)]
    struct LinuxSockFprogV1 {
        length: u16,
        filter: *const LinuxSockFilterV1,
    }

    #[cfg(test)]
    #[repr(C)]
    struct LinuxSeccompDataV1 {
        syscall: i32,
        architecture: u32,
        instruction_pointer: u64,
        arguments: [u64; 6],
    }

    const fn seccomp_statement_v1(code: u16, operand: u32) -> LinuxSockFilterV1 {
        LinuxSockFilterV1 {
            code,
            jump_true: 0,
            jump_false: 0,
            operand,
        }
    }

    const fn seccomp_jump_v1(
        code: u16,
        operand: u32,
        jump_true: u8,
        jump_false: u8,
    ) -> LinuxSockFilterV1 {
        LinuxSockFilterV1 {
            code,
            jump_true,
            jump_false,
            operand,
        }
    }

    const fn seccomp_arg_low_offset_v1(index: u32) -> u32 {
        SECCOMP_DATA_ARGS_OFFSET_V1 + index * SECCOMP_DATA_ARG_STRIDE_V1
    }

    const fn seccomp_arg_high_offset_v1(index: u32) -> u32 {
        seccomp_arg_low_offset_v1(index) + SECCOMP_DATA_ARG_HIGH_OFFSET_V1
    }

    const SECCOMP_FILTER_INSTRUCTION_COUNT_V1: usize = 93;
    static SECCOMP_FILTER_V1: [LinuxSockFilterV1; SECCOMP_FILTER_INSTRUCTION_COUNT_V1] = [
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, SECCOMP_DATA_ARCH_OFFSET_V1),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, AUDIT_ARCH_X86_64_V1, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_KILL_PROCESS_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, SECCOMP_DATA_NR_OFFSET_V1),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JSET_K_V1, X32_SYSCALL_BIT_V1, 0, 1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_KILL_PROCESS_V1),
        // write(0, pointer, 64)
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_SYSCALL_WRITE_V1, 0, 13),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(2)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, FRAME_BYTES_V1 as u32, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(2)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1),
        // poll(pointer, 1, 0..=8_000)
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_SYSCALL_POLL_V1, 0, 13),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(1)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 1, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(1)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(2)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(2)),
        seccomp_jump_v1(
            SECCOMP_BPF_JMP_JGT_K_V1,
            SECCOMP_MAX_POLL_MILLISECONDS_V1,
            0,
            1,
        ),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1),
        // clock_gettime(CLOCK_MONOTONIC, pointer)
        seccomp_jump_v1(
            SECCOMP_BPF_JMP_JEQ_K_V1,
            SECCOMP_SYSCALL_CLOCK_GETTIME_V1,
            0,
            7,
        ),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, libc::CLOCK_MONOTONIC as u32, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1),
        // prctl(PR_GET_SECCOMP | PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_SYSCALL_PRCTL_V1, 0, 32),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_PR_GET_SECCOMP_V1, 2, 0),
        seccomp_jump_v1(
            SECCOMP_BPF_JMP_JEQ_K_V1,
            SECCOMP_PR_GET_NO_NEW_PRIVS_V1,
            1,
            0,
        ),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(1)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(1)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(2)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(2)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(3)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(3)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(4)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(4)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1),
        // close(0)
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_SYSCALL_CLOSE_V1, 0, 7),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1),
        // exit(0 | 125)
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_SYSCALL_EXIT_V1, 0, 8),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_EXIT_SUCCESS_V1, 2, 0),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, SECCOMP_EXIT_FAILURE_V1, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(0)),
        seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1),
        seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1),
    ];

    struct ChildLandlockTrackedFdsV1 {
        audit_descriptor: RawFd,
        descriptors: [RawFd; LANDLOCK_MAX_TRACKED_FDS_V1],
    }

    impl ChildLandlockTrackedFdsV1 {
        const fn new() -> Self {
            Self {
                audit_descriptor: -1,
                descriptors: [-1; LANDLOCK_MAX_TRACKED_FDS_V1],
            }
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct ChildReportDescriptorIdentityV1 {
        device: libc::dev_t,
        inode: libc::ino_t,
        mode: libc::mode_t,
        status_flags: libc::c_long,
    }

    struct ChildPinnedPidNamespaceV1 {
        descriptor: RawFd,
        identity: NamespaceIdentityV1,
    }

    #[derive(Clone, Copy)]
    enum NamespaceKindV1 {
        User,
        Mount,
        Pid,
        Network,
        Uts,
        Ipc,
    }

    impl NamespaceKindV1 {
        const ALL: [Self; 6] = [
            Self::User,
            Self::Mount,
            Self::Pid,
            Self::Network,
            Self::Uts,
            Self::Ipc,
        ];

        const fn relative_path(self) -> &'static CStr {
            match self {
                Self::User => c"ns/user",
                Self::Mount => c"ns/mnt",
                Self::Pid => c"ns/pid",
                Self::Network => c"ns/net",
                Self::Uts => c"ns/uts",
                Self::Ipc => c"ns/ipc",
            }
        }

        const fn clone_flag(self) -> i32 {
            match self {
                Self::User => libc::CLONE_NEWUSER,
                Self::Mount => libc::CLONE_NEWNS,
                Self::Pid => libc::CLONE_NEWPID,
                Self::Network => libc::CLONE_NEWNET,
                Self::Uts => libc::CLONE_NEWUTS,
                Self::Ipc => libc::CLONE_NEWIPC,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct NamespaceIdentityV1 {
        device: u64,
        inode: u64,
    }

    struct PinnedNamespaceV1 {
        fd: OwnedFd,
        identity: NamespaceIdentityV1,
    }

    struct NamespaceFdSetV1 {
        user: PinnedNamespaceV1,
        mount: PinnedNamespaceV1,
        pid: PinnedNamespaceV1,
        network: PinnedNamespaceV1,
        uts: PinnedNamespaceV1,
        ipc: PinnedNamespaceV1,
    }

    impl NamespaceFdSetV1 {
        fn open_at(
            proc_directory: RawFd,
            open_stage: IsolationQualificationStageV1,
        ) -> Result<Self, IsolationQualificationFailureV1> {
            Ok(Self {
                user: open_namespace_at(proc_directory, NamespaceKindV1::User, open_stage)?,
                mount: open_namespace_at(proc_directory, NamespaceKindV1::Mount, open_stage)?,
                pid: open_namespace_at(proc_directory, NamespaceKindV1::Pid, open_stage)?,
                network: open_namespace_at(proc_directory, NamespaceKindV1::Network, open_stage)?,
                uts: open_namespace_at(proc_directory, NamespaceKindV1::Uts, open_stage)?,
                ipc: open_namespace_at(proc_directory, NamespaceKindV1::Ipc, open_stage)?,
            })
        }

        fn get(&self, kind: NamespaceKindV1) -> &PinnedNamespaceV1 {
            match kind {
                NamespaceKindV1::User => &self.user,
                NamespaceKindV1::Mount => &self.mount,
                NamespaceKindV1::Pid => &self.pid,
                NamespaceKindV1::Network => &self.network,
                NamespaceKindV1::Uts => &self.uts,
                NamespaceKindV1::Ipc => &self.ipc,
            }
        }

        fn raw_fds(&self) -> [RawFd; 6] {
            [
                self.user.fd.as_raw_fd(),
                self.mount.fd.as_raw_fd(),
                self.pid.fd.as_raw_fd(),
                self.network.fd.as_raw_fd(),
                self.uts.fd.as_raw_fd(),
                self.ipc.fd.as_raw_fd(),
            ]
        }
    }

    struct HostCredentialsV1 {
        real_uid: u32,
        real_gid: u32,
    }

    #[derive(Clone, Copy)]
    struct MonotonicDeadlineV1 {
        seconds: i64,
        nanoseconds: i64,
    }

    struct ChildChannelsV1 {
        control_read: OwnedFd,
        control_write: OwnedFd,
        report_read: OwnedFd,
        report_write: OwnedFd,
    }

    struct ProbeChildGuardV1 {
        pid: Option<libc::pid_t>,
        pidfd: Option<OwnedFd>,
        control_write: Option<OwnedFd>,
        report_read: Option<OwnedFd>,
        proc_directory: Option<OwnedFd>,
        child_namespaces: Option<NamespaceFdSetV1>,
        deadline: MonotonicDeadlineV1,
        reaped: bool,
    }

    impl ProbeChildGuardV1 {
        fn refuse(
            mut self,
            failure: IsolationQualificationFailureV1,
        ) -> IsolationQualificationFailureV1 {
            match self.kill_and_reap() {
                Ok(()) => failure,
                Err(errno) => IsolationQualificationFailureV1::cleanup_uncertain(errno),
            }
        }

        fn kill_and_reap(&mut self) -> Result<(), Option<i32>> {
            self.control_write.take();
            self.report_read.take();
            if self.reaped {
                return Ok(());
            }
            let mut signal_errno = None;
            let mut needs_pid_fallback = pid_signal_fallback_required(self.pidfd.is_some(), None);
            if let Some(pidfd) = self.pidfd.as_ref() {
                let signal_result = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0_u32,
                    )
                };
                if signal_result != 0 {
                    signal_errno = last_errno();
                    needs_pid_fallback = pid_signal_fallback_required(true, signal_errno);
                }
            }
            if needs_pid_fallback {
                // This is the known, unreaped direct child. The pre-clone
                // single-task and SIGCHLD disposition checks exclude an
                // in-process reaper, so this PID cannot be recycled here.
                let Some(pid) = positive_direct_pid(self.pid) else {
                    return Err(signal_errno.or(Some(libc::EINVAL)));
                };
                if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
                    let errno = last_errno();
                    if errno != Some(libc::ESRCH) {
                        signal_errno = errno.or(signal_errno);
                    }
                }
            }
            let reap_result = self.reap_bounded();
            merge_cleanup_results(signal_errno, reap_result)
        }

        fn reap_bounded(&mut self) -> Result<(), Option<i32>> {
            if self.reaped {
                return Ok(());
            }
            if let Some(pidfd) = self.pidfd.as_ref().map(|fd| fd.as_raw_fd()) {
                let wait_error = wait_pidfd_terminal(pidfd, self.deadline).err();
                match self.reap_pidfd(pidfd) {
                    Ok(_) => return Ok(()),
                    Err(pidfd_reap_error) => {
                        let pid_reap_result = self.reap_pid_bounded();
                        return merge_reap_fallback(
                            pidfd_reap_error,
                            wait_error.and_then(|error| error.errno()),
                            pid_reap_result,
                        );
                    }
                }
            }
            self.reap_pid_bounded()
        }

        fn reap_pid_bounded(&mut self) -> Result<(), Option<i32>> {
            let Some(pid) = positive_direct_pid(self.pid) else {
                return Err(Some(libc::EINVAL));
            };
            loop {
                let mut status = 0_i32;
                let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if waited == pid {
                    if decode_wait_status(status).is_none() {
                        return Err(Some(libc::ECHILD));
                    }
                    self.reaped = true;
                    return Ok(());
                }
                if waited < 0 {
                    let errno = last_errno();
                    if errno == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(errno);
                }
                let remaining = self
                    .deadline
                    .remaining_milliseconds()
                    .map_err(|_| Some(libc::ETIMEDOUT))?;
                let pause = remaining.min(10);
                let poll_result = unsafe { libc::poll(std::ptr::null_mut(), 0, pause) };
                if poll_result < 0 && last_errno() != Some(libc::EINTR) {
                    return Err(last_errno());
                }
            }
        }

        fn reap_success(
            &mut self,
            deadline: MonotonicDeadlineV1,
        ) -> Result<(), IsolationQualificationFailureV1> {
            let pidfd = self
                .pidfd
                .as_ref()
                .map(|fd| fd.as_raw_fd())
                .ok_or_else(|| {
                    failure(
                        RefusalCode::RequiredNamespaceFailed,
                        IsolationQualificationStageV1::WaitForChild,
                        IsolationQualificationReasonV1::MalformedKernelResponse,
                        None,
                    )
                })?;
            wait_pidfd_terminal(pidfd, deadline)?;
            let terminal = self.reap_pidfd(pidfd).map_err(|errno| {
                failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::ReapChild,
                    IsolationQualificationReasonV1::WaitFailed,
                    errno,
                )
            })?;
            if terminal.code == libc::CLD_KILLED || terminal.code == libc::CLD_DUMPED {
                return Err(failure(
                    RefusalCode::RequiredNamespaceFailed,
                    IsolationQualificationStageV1::ReapChild,
                    IsolationQualificationReasonV1::ChildSignaled,
                    Some(terminal.status),
                ));
            }
            if terminal.code != libc::CLD_EXITED || terminal.status != 0 {
                return Err(failure(
                    RefusalCode::RequiredNamespaceFailed,
                    IsolationQualificationStageV1::ReapChild,
                    IsolationQualificationReasonV1::ChildExitMismatch,
                    Some(terminal.status),
                ));
            }
            Ok(())
        }

        fn reap_pidfd(&mut self, pidfd: RawFd) -> Result<ChildTerminalV1, Option<i32>> {
            let mut information = MaybeUninit::<libc::siginfo_t>::zeroed();
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pidfd as libc::id_t,
                    information.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            if result != 0 {
                return Err(last_errno());
            }
            let information = unsafe { information.assume_init() };
            let observed_pid = unsafe { information.si_pid() };
            if observed_pid <= 0 || self.pid.is_some_and(|expected| expected != observed_pid) {
                return Err(Some(libc::ECHILD));
            }
            self.reaped = true;
            Ok(ChildTerminalV1 {
                code: information.si_code,
                status: unsafe { information.si_status() },
            })
        }
    }

    struct ChildTerminalV1 {
        code: i32,
        status: i32,
    }

    fn decode_wait_status(status: i32) -> Option<ChildTerminalV1> {
        if libc::WIFEXITED(status) {
            Some(ChildTerminalV1 {
                code: libc::CLD_EXITED,
                status: libc::WEXITSTATUS(status),
            })
        } else if libc::WIFSIGNALED(status) {
            Some(ChildTerminalV1 {
                code: if libc::WCOREDUMP(status) {
                    libc::CLD_DUMPED
                } else {
                    libc::CLD_KILLED
                },
                status: libc::WTERMSIG(status),
            })
        } else {
            None
        }
    }

    fn positive_direct_pid(pid: Option<libc::pid_t>) -> Option<libc::pid_t> {
        pid.filter(|pid| *pid > 0)
    }

    fn pid_signal_fallback_required(pidfd_present: bool, pidfd_errno: Option<i32>) -> bool {
        !pidfd_present || pidfd_errno.is_some()
    }

    fn merge_cleanup_results(
        signal_errno: Option<i32>,
        reap_result: Result<(), Option<i32>>,
    ) -> Result<(), Option<i32>> {
        reap_result.map_err(|wait_errno| wait_errno.or(signal_errno))
    }

    fn merge_reap_fallback(
        pidfd_errno: Option<i32>,
        wait_errno: Option<i32>,
        pid_reap_result: Result<(), Option<i32>>,
    ) -> Result<(), Option<i32>> {
        pid_reap_result.map_err(|pid_errno| pid_errno.or(pidfd_errno).or(wait_errno))
    }

    impl Drop for ProbeChildGuardV1 {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.kill_and_reap();
            }
        }
    }

    pub(super) struct BlockedRootlessNamespaceBootstrapV1 {
        guard: ProbeChildGuardV1,
        deadline: MonotonicDeadlineV1,
        nonce: [u8; NONCE_BYTES_V1],
    }

    pub(super) fn begin_blocked_rootless_namespace_bootstrap_v1()
    -> Result<BlockedRootlessNamespaceBootstrapV1, IsolationQualificationFailureV1> {
        let proc_root = pin_proc_root()?;
        let host_pid = unsafe { libc::getpid() };
        verify_proc_self_target(proc_root.as_raw_fd(), host_pid)?;
        let self_proc = open_pid_directory_at(
            proc_root.as_raw_fd(),
            host_pid,
            IsolationQualificationStageV1::DedicatedHelper,
        )?;
        verify_dedicated_helper_process(self_proc.as_raw_fd(), host_pid)?;
        verify_no_loader_injection_environment(self_proc.as_raw_fd())?;
        verify_signal_dispositions()?;
        let (deadline, cleanup_deadline) = probe_deadlines()?;
        let credentials = host_credentials(self_proc.as_raw_fd())?;
        let supplementary_groups = capture_supplementary_groups()?;
        let parent_namespaces = NamespaceFdSetV1::open_at(
            self_proc.as_raw_fd(),
            IsolationQualificationStageV1::ParentNamespaces,
        )?;
        let parent_namespace_fds = parent_namespaces.raw_fds();
        let mut inherited_parent_fds = [-1_i32; 8];
        inherited_parent_fds[..6].copy_from_slice(&parent_namespace_fds);
        inherited_parent_fds[6] = proc_root.as_raw_fd();
        inherited_parent_fds[7] = self_proc.as_raw_fd();
        let nonce = protocol_nonce(deadline)?;
        let channels = create_channels()?;
        deadline.ensure_open(IsolationQualificationStageV1::CloneNamespaces)?;

        let mut pidfd_raw = -1_i32;
        let mut arguments = CloneArgsV1 {
            flags: (libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_PIDFD) as u64
                | CLONE_CLEAR_SIGHAND_V1,
            pidfd: (&mut pidfd_raw as *mut i32) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgsV1::default()
        };
        let clone_result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut arguments,
                std::mem::size_of::<CloneArgsV1>(),
            )
        };
        if clone_result == 0 {
            child_entry_v1(
                channels.control_read.as_raw_fd(),
                channels.control_write.as_raw_fd(),
                channels.report_read.as_raw_fd(),
                channels.report_write.as_raw_fd(),
                inherited_parent_fds,
                nonce,
                deadline,
            );
        }
        if clone_result < 0 {
            return Err(clone_failure(last_errno()));
        }
        // Establish cleanup ownership before validating any returned field or
        // performing any fallible operation. A malformed value never reaches
        // `kill(2)`, `waitpid(2)`, or a proc pathname.
        let child_pid = checked_child_pid(clone_result);
        let pidfd = (pidfd_raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd_raw) });
        let mut guard = ProbeChildGuardV1 {
            pid: child_pid,
            pidfd,
            control_write: Some(channels.control_write),
            report_read: Some(channels.report_read),
            proc_directory: None,
            child_namespaces: None,
            deadline: cleanup_deadline,
            reaped: false,
        };
        drop(channels.control_read);
        drop(channels.report_write);
        let child_pidfd = match guard.pidfd.as_ref() {
            Some(pidfd) => pidfd.as_raw_fd(),
            None => {
                let failure = failure(
                    RefusalCode::RequiredNamespaceFailed,
                    IsolationQualificationStageV1::CloneNamespaces,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                );
                return Err(guard.refuse(failure));
            }
        };
        let child_pid = match guard.pid {
            Some(pid) => pid,
            None => {
                let failure = failure(
                    RefusalCode::RequiredNamespaceFailed,
                    IsolationQualificationStageV1::CloneNamespaces,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                );
                return Err(guard.refuse(failure));
            }
        };
        if let Err(error) = require_cloexec(child_pidfd) {
            let failure = failure(
                RefusalCode::RequiredNamespaceFailed,
                IsolationQualificationStageV1::CloneNamespaces,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            );
            return Err(guard.refuse(failure));
        }
        macro_rules! guarded {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => return Err(guard.refuse(error)),
                }
            };
        }

        let report_fd = guarded!(retained_fd(
            &guard.report_read,
            IsolationQualificationStageV1::ReceiveChildReady,
        ));
        let ready = guarded!(read_parent_frame(
            report_fd,
            child_pidfd,
            deadline,
            false,
            IsolationQualificationStageV1::ReceiveChildReady,
        ));
        guarded!(verify_ready_frame(&ready, &nonce));
        guarded!(verify_no_pending_report_byte(
            report_fd,
            child_pidfd,
            deadline,
        ));

        // SIGCHLD is DFL without SA_NOCLDWAIT and this exact direct child is
        // deliberately unreaped through validation, so its PID cannot be
        // recycled while this descriptor-relative proc view is opened.
        let proc_directory = guarded!(open_pid_directory_at(
            proc_root.as_raw_fd(),
            child_pid,
            IsolationQualificationStageV1::OpenChildProc,
        ));
        guard.proc_directory = Some(proc_directory);
        let proc_fd = guarded!(retained_fd(
            &guard.proc_directory,
            IsolationQualificationStageV1::OpenChildProc,
        ));

        guarded!(write_and_verify_id_map(
            proc_fd,
            c"uid_map",
            credentials.real_uid,
            IsolationQualificationStageV1::WriteUidMap,
            IsolationQualificationStageV1::VerifyUidMap,
            deadline,
        ));
        guarded!(write_and_verify_setgroups(proc_fd, deadline));
        guarded!(write_and_verify_id_map(
            proc_fd,
            c"gid_map",
            credentials.real_gid,
            IsolationQualificationStageV1::WriteGidMap,
            IsolationQualificationStageV1::VerifyGidMap,
            deadline,
        ));
        guarded!(verify_child_groups_and_capabilities(
            proc_fd,
            &supplementary_groups,
            deadline,
        ));

        let child_namespaces = guarded!(NamespaceFdSetV1::open_at(
            proc_fd,
            IsolationQualificationStageV1::PinChildNamespaces,
        ));
        guarded!(verify_namespace_set(
            &parent_namespaces,
            &child_namespaces,
            credentials.real_uid,
        ));
        guard.child_namespaces = Some(child_namespaces);

        Ok(BlockedRootlessNamespaceBootstrapV1 {
            guard,
            deadline,
            nonce,
        })
    }

    pub(super) fn qualify_rootless_namespace_tuple_v1()
    -> Result<CompletedRootlessNamespaceProbeV1, IsolationQualificationFailureV1> {
        begin_blocked_rootless_namespace_bootstrap_v1()?.complete_diagnostic()
    }

    impl BlockedRootlessNamespaceBootstrapV1 {
        fn complete_diagnostic(
            mut self,
        ) -> Result<CompletedRootlessNamespaceProbeV1, IsolationQualificationFailureV1> {
            let deadline = self.deadline;
            let nonce = self.nonce;
            macro_rules! guarded {
                ($expression:expr) => {
                    match $expression {
                        Ok(value) => value,
                        Err(error) => return Err(self.guard.refuse(error)),
                    }
                };
            }

            let child_pidfd = match self.guard.pidfd.as_ref() {
                Some(pidfd) => pidfd.as_raw_fd(),
                None => {
                    let error = failure(
                        RefusalCode::RequiredNamespaceFailed,
                        IsolationQualificationStageV1::SendControl,
                        IsolationQualificationReasonV1::MalformedKernelResponse,
                        None,
                    );
                    return Err(self.guard.refuse(error));
                }
            };
            let report_fd = guarded!(retained_fd(
                &self.guard.report_read,
                IsolationQualificationStageV1::ReceiveChildProof,
            ));

            let release = encode_common_frame(RELEASE_MAGIC_V1, PHASE_RELEASE_V1, &nonce);
            let control_fd = guarded!(retained_fd(
                &self.guard.control_write,
                IsolationQualificationStageV1::SendControl,
            ));
            guarded!(write_parent_frame(
                control_fd,
                child_pidfd,
                &release,
                deadline,
            ));
            self.guard.control_write.take();

            let proof = guarded!(read_parent_frame(
                report_fd,
                child_pidfd,
                deadline,
                true,
                IsolationQualificationStageV1::ReceiveChildProof,
            ));
            guarded!(expect_report_eof(report_fd, child_pidfd, deadline,));
            self.guard.report_read.take();
            guarded!(verify_proof_frame(&proof, &nonce));
            if let Err(error) = self.guard.reap_success(deadline) {
                return Err(self.guard.refuse(error));
            }

            Ok(CompletedRootlessNamespaceProbeV1 { _private: () })
        }
    }

    fn failure(
        code: RefusalCode,
        stage: IsolationQualificationStageV1,
        reason: IsolationQualificationReasonV1,
        errno: Option<i32>,
    ) -> IsolationQualificationFailureV1 {
        IsolationQualificationFailureV1::new(code, stage, reason, errno)
    }

    fn retained_fd(
        descriptor: &Option<OwnedFd>,
        stage: IsolationQualificationStageV1,
    ) -> Result<RawFd, IsolationQualificationFailureV1> {
        descriptor.as_ref().map(|fd| fd.as_raw_fd()).ok_or_else(|| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            )
        })
    }

    impl MonotonicDeadlineV1 {
        fn from_start(
            start: libc::timespec,
            seconds: i64,
        ) -> Result<Self, IsolationQualificationFailureV1> {
            let deadline_seconds = start.tv_sec.checked_add(seconds).ok_or_else(|| {
                failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::DedicatedHelper,
                    IsolationQualificationReasonV1::BoundExceeded,
                    None,
                )
            })?;
            Ok(Self {
                seconds: deadline_seconds,
                nanoseconds: start.tv_nsec,
            })
        }

        fn remaining_milliseconds(self) -> Result<i32, ()> {
            let now = monotonic_now().map_err(|_| ())?;
            self.remaining_milliseconds_at(now)
        }

        fn remaining_milliseconds_at(self, now: libc::timespec) -> Result<i32, ()> {
            if now.tv_sec < 0 || !(0..1_000_000_000).contains(&now.tv_nsec) {
                return Err(());
            }
            let seconds = self.seconds.checked_sub(now.tv_sec).ok_or(())?;
            let nanoseconds = self.nanoseconds - now.tv_nsec;
            let total_nanoseconds = i128::from(seconds)
                .checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(i128::from(nanoseconds)))
                .ok_or(())?;
            if total_nanoseconds <= 0 {
                return Err(());
            }
            let rounded_milliseconds =
                total_nanoseconds.checked_add(999_999).ok_or(())? / 1_000_000;
            i32::try_from(rounded_milliseconds).map_err(|_| ())
        }

        fn ensure_open(
            self,
            stage: IsolationQualificationStageV1,
        ) -> Result<(), IsolationQualificationFailureV1> {
            self.remaining_milliseconds().map(|_| ()).map_err(|_| {
                failure(
                    RefusalCode::IsolationPreflightFailed,
                    stage,
                    IsolationQualificationReasonV1::ProtocolTimeout,
                    Some(libc::ETIMEDOUT),
                )
            })
        }
    }

    fn probe_deadlines()
    -> Result<(MonotonicDeadlineV1, MonotonicDeadlineV1), IsolationQualificationFailureV1> {
        let start = monotonic_now().map_err(|error| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        Ok((
            MonotonicDeadlineV1::from_start(start, PROBE_PROTOCOL_SECONDS_V1)?,
            MonotonicDeadlineV1::from_start(start, PROBE_HARD_SECONDS_V1)?,
        ))
    }

    fn monotonic_now() -> io::Result<libc::timespec> {
        let mut value = MaybeUninit::<libc::timespec>::zeroed();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let value = unsafe { value.assume_init() };
        if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(value)
    }

    fn verify_dedicated_helper_process(
        self_proc: RawFd,
        pid: libc::pid_t,
    ) -> Result<(), IsolationQualificationFailureV1> {
        if pid <= 0 {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        let task_raw = unsafe {
            libc::openat(
                self_proc,
                c"task".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if task_raw < 0 {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let task = unsafe { OwnedFd::from_raw_fd(task_raw) };
        require_cloexec(task.as_raw_fd()).map_err(|error| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            )
        })?;
        let tids = read_task_ids(task.as_raw_fd()).map_err(|error| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        if tids.as_slice() != [pid] {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MultipleTasks,
                None,
            ));
        }
        Ok(())
    }

    fn read_task_ids(directory: RawFd) -> io::Result<Vec<libc::pid_t>> {
        const DIRENT_HEADER_BYTES: usize = 19;
        let mut buffer = [0_u8; 4096];
        let mut tids = Vec::new();
        loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    directory,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if count == 0 {
                break;
            }
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            let count = usize::try_from(count)
                .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            if count > buffer.len() {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let mut offset = 0_usize;
            while offset < count {
                let remaining = &buffer[offset..count];
                if remaining.len() < DIRENT_HEADER_BYTES {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                let record_length = usize::from(u16::from_ne_bytes([remaining[16], remaining[17]]));
                if record_length < DIRENT_HEADER_BYTES || record_length > remaining.len() {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                let record = &remaining[..record_length];
                let name_field = &record[DIRENT_HEADER_BYTES..];
                let terminator = name_field
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
                let name = &name_field[..terminator];
                if name != b"." && name != b".." {
                    let tid = parse_decimal_i32(name)
                        .filter(|tid| *tid > 0)
                        .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
                    tids.push(tid);
                    if tids.len() > 1 {
                        return Ok(tids);
                    }
                }
                offset = offset
                    .checked_add(record_length)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            }
        }
        Ok(tids)
    }

    fn parse_decimal_i32(bytes: &[u8]) -> Option<i32> {
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        bytes.iter().try_fold(0_i32, |value, byte| {
            value.checked_mul(10)?.checked_add(i32::from(*byte - b'0'))
        })
    }

    fn verify_no_loader_injection_environment(
        self_proc: RawFd,
    ) -> Result<(), IsolationQualificationFailureV1> {
        const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
        let bytes = read_bounded_file_at(self_proc, c"environ", MAX_ENVIRONMENT_BYTES).map_err(
            |error| {
                failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::DedicatedHelper,
                    IsolationQualificationReasonV1::Io,
                    error.raw_os_error(),
                )
            },
        )?;
        if !bytes.is_empty() && bytes.last() != Some(&0) {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        for entry in bytes
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let Some(separator) = entry.iter().position(|byte| *byte == b'=') else {
                return Err(failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::DedicatedHelper,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                ));
            };
            let name = &entry[..separator];
            if name.starts_with(b"LD_")
                || name.starts_with(b"MALLOC_")
                || matches!(
                    name,
                    b"GLIBC_TUNABLES" | b"GCONV_PATH" | b"LOCPATH" | b"NLSPATH"
                )
            {
                return Err(failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::DedicatedHelper,
                    IsolationQualificationReasonV1::LoaderInjectionEnvironment,
                    None,
                ));
            }
        }
        Ok(())
    }

    fn verify_signal_dispositions() -> Result<(), IsolationQualificationFailureV1> {
        let mut child_action = MaybeUninit::<libc::sigaction>::zeroed();
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), child_action.as_mut_ptr()) }
            != 0
        {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let child_action = unsafe { child_action.assume_init() };
        let mut pipe_action = MaybeUninit::<libc::sigaction>::zeroed();
        if unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), pipe_action.as_mut_ptr()) }
            != 0
        {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let pipe_action = unsafe { pipe_action.assume_init() };
        if child_action.sa_sigaction != libc::SIG_DFL
            || child_action.sa_flags & libc::SA_NOCLDWAIT != 0
            || pipe_action.sa_sigaction != libc::SIG_IGN
        {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::SignalDisposition,
                None,
            ));
        }
        Ok(())
    }

    fn host_credentials(
        self_proc: RawFd,
    ) -> Result<HostCredentialsV1, IsolationQualificationFailureV1> {
        let status = read_bounded_file_at(self_proc, c"status", MAX_PROC_STATUS_BYTES_V1).map_err(
            |error| {
                failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::HostCredentials,
                    IsolationQualificationReasonV1::Io,
                    error.raw_os_error(),
                )
            },
        )?;
        let uid = parse_exact_status_u32_row(&status, b"Uid:")?;
        let gid = parse_exact_status_u32_row(&status, b"Gid:")?;
        for capability in [b"CapInh:", b"CapPrm:", b"CapEff:", b"CapAmb:"] {
            if parse_exact_status_hex(&status, capability)? != 0 {
                return Err(failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::HostCredentials,
                    IsolationQualificationReasonV1::HostCredentialMismatch,
                    None,
                ));
            }
        }
        let credentials = HostCredentialsV1 {
            real_uid: uid[0],
            real_gid: gid[0],
        };
        if credentials.real_uid == 0
            || uid.iter().any(|value| *value != credentials.real_uid)
            || gid.iter().any(|value| *value != credentials.real_gid)
            || unsafe { libc::getuid() } != credentials.real_uid
            || unsafe { libc::geteuid() } != credentials.real_uid
            || unsafe { libc::getgid() } != credentials.real_gid
            || unsafe { libc::getegid() } != credentials.real_gid
        {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::HostCredentials,
                IsolationQualificationReasonV1::HostCredentialMismatch,
                None,
            ));
        }
        Ok(credentials)
    }

    fn parse_exact_status_u32_row(
        status: &[u8],
        label: &[u8],
    ) -> Result<[u32; 4], IsolationQualificationFailureV1> {
        let row = exact_status_row(status, label)?;
        let mut parser = AsciiFieldsV1::new(row);
        let mut values = [0_u32; 4];
        for value in &mut values {
            *value = parser.next_u32().ok_or_else(status_malformed)?;
        }
        if parser.has_more_fields() {
            return Err(status_malformed());
        }
        Ok(values)
    }

    fn parse_exact_status_hex(
        status: &[u8],
        label: &[u8],
    ) -> Result<u64, IsolationQualificationFailureV1> {
        let row = exact_status_row(status, label)?;
        let mut parser = AsciiFieldsV1::new(row);
        let field = parser.next_bytes().ok_or_else(status_malformed)?;
        if parser.has_more_fields() || field.is_empty() || !field.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(status_malformed());
        }
        field
            .iter()
            .try_fold(0_u64, |value, byte| {
                value.checked_mul(16)?.checked_add(u64::from(match byte {
                    b'0'..=b'9' => *byte - b'0',
                    b'a'..=b'f' => *byte - b'a' + 10,
                    b'A'..=b'F' => *byte - b'A' + 10,
                    _ => return None,
                }))
            })
            .ok_or_else(status_malformed)
    }

    fn exact_status_row<'a>(
        status: &'a [u8],
        label: &[u8],
    ) -> Result<&'a [u8], IsolationQualificationFailureV1> {
        let mut found = None;
        for line in status.split(|byte| *byte == b'\n') {
            if line.contains(&b'\r') {
                return Err(status_malformed());
            }
            if let Some(row) = line.strip_prefix(label) {
                if found.replace(row).is_some() {
                    return Err(status_malformed());
                }
            }
        }
        found.ok_or_else(status_malformed)
    }

    fn status_malformed() -> IsolationQualificationFailureV1 {
        failure(
            RefusalCode::IsolationPreflightFailed,
            IsolationQualificationStageV1::HostCredentials,
            IsolationQualificationReasonV1::MalformedKernelResponse,
            None,
        )
    }

    fn capture_supplementary_groups() -> Result<Vec<u32>, IsolationQualificationFailureV1> {
        let first = capture_groups_once()?;
        let second = capture_groups_once()?;
        if first != second {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::SupplementaryGroups,
                IsolationQualificationReasonV1::UnstableObservation,
                None,
            ));
        }
        Ok(first)
    }

    fn capture_groups_once() -> Result<Vec<u32>, IsolationQualificationFailureV1> {
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(group_failure(
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let count = usize::try_from(count)
            .ok()
            .filter(|count| *count <= MAX_SUPPLEMENTARY_GROUPS_V1)
            .ok_or_else(|| group_failure(IsolationQualificationReasonV1::BoundExceeded, None))?;
        let mut groups = vec![0 as libc::gid_t; count];
        let observed = unsafe { libc::getgroups(count as i32, groups.as_mut_ptr()) };
        if observed < 0 {
            return Err(group_failure(
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        if usize::try_from(observed).ok() != Some(count) {
            return Err(group_failure(
                IsolationQualificationReasonV1::UnstableObservation,
                None,
            ));
        }
        groups.sort_unstable();
        if groups.windows(2).any(|window| window[0] == window[1]) {
            return Err(group_failure(
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(groups)
    }

    fn group_failure(
        reason: IsolationQualificationReasonV1,
        errno: Option<i32>,
    ) -> IsolationQualificationFailureV1 {
        failure(
            RefusalCode::IsolationPreflightFailed,
            IsolationQualificationStageV1::SupplementaryGroups,
            reason,
            errno,
        )
    }

    fn protocol_nonce(
        deadline: MonotonicDeadlineV1,
    ) -> Result<[u8; NONCE_BYTES_V1], IsolationQualificationFailureV1> {
        let mut nonce = [0_u8; NONCE_BYTES_V1];
        let mut offset = 0_usize;
        while offset < nonce.len() {
            deadline.ensure_open(IsolationQualificationStageV1::ProtocolNonce)?;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_getrandom,
                    nonce[offset..].as_mut_ptr(),
                    nonce.len() - offset,
                    libc::GRND_NONBLOCK,
                )
            };
            if result < 0 {
                let errno = last_errno();
                if errno == Some(libc::EINTR) {
                    continue;
                }
                return Err(failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::ProtocolNonce,
                    IsolationQualificationReasonV1::Io,
                    errno,
                ));
            }
            if result == 0 {
                return Err(failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::ProtocolNonce,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            offset = offset
                .checked_add(usize::try_from(result).map_err(|_| {
                    failure(
                        RefusalCode::IsolationPreflightFailed,
                        IsolationQualificationStageV1::ProtocolNonce,
                        IsolationQualificationReasonV1::MalformedKernelResponse,
                        None,
                    )
                })?)
                .ok_or_else(|| {
                    failure(
                        RefusalCode::IsolationPreflightFailed,
                        IsolationQualificationStageV1::ProtocolNonce,
                        IsolationQualificationReasonV1::BoundExceeded,
                        None,
                    )
                })?;
        }
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::ProtocolNonce,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(nonce)
    }

    fn create_channels() -> Result<ChildChannelsV1, IsolationQualificationFailureV1> {
        let (control_read, control_write) = create_pipe()?;
        let (report_read, report_write) = create_pipe()?;
        Ok(ChildChannelsV1 {
            control_read,
            control_write,
            report_read,
            report_write,
        })
    }

    fn create_pipe() -> Result<(OwnedFd, OwnedFd), IsolationQualificationFailureV1> {
        let mut descriptors = [-1_i32; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0
        {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::ControlChannels,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        if descriptors[0] < 0 || descriptors[1] < 0 || descriptors[0] == descriptors[1] {
            if descriptors[0] >= 0 {
                unsafe { libc::close(descriptors[0]) };
            }
            if descriptors[1] >= 0 && descriptors[1] != descriptors[0] {
                unsafe { libc::close(descriptors[1]) };
            }
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::ControlChannels,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        require_cloexec(read.as_raw_fd()).map_err(|error| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::ControlChannels,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            )
        })?;
        require_cloexec(write.as_raw_fd()).map_err(|error| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::ControlChannels,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            )
        })?;
        Ok((read, write))
    }

    fn pin_proc_root() -> Result<OwnedFd, IsolationQualificationFailureV1> {
        let raw = unsafe {
            libc::open(
                c"/proc".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        require_cloexec(fd.as_raw_fd()).map_err(|error| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            )
        })?;
        let mut filesystem = MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::fstatfs(fd.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        if unsafe { filesystem.assume_init() }.f_type != PROC_SUPER_MAGIC_V1 {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(fd)
    }

    fn verify_proc_self_target(
        proc_root: RawFd,
        pid: libc::pid_t,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let mut target = [0_u8; 32];
        let length = unsafe {
            libc::readlinkat(
                proc_root,
                c"self".as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        if length < 0 {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let length = usize::try_from(length).map_err(|_| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            )
        })?;
        if length == target.len() || !proc_self_target_matches(&target[..length], pid) {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::DedicatedHelper,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(())
    }

    fn proc_self_target_matches(target: &[u8], pid: libc::pid_t) -> bool {
        encode_pid_name(pid).is_some_and(|expected| target == expected.as_bytes())
    }

    fn checked_child_pid(clone_result: libc::c_long) -> Option<libc::pid_t> {
        i32::try_from(clone_result).ok().filter(|pid| *pid > 0)
    }

    fn open_pid_directory_at(
        proc_root: RawFd,
        pid: libc::pid_t,
        stage: IsolationQualificationStageV1,
    ) -> Result<OwnedFd, IsolationQualificationFailureV1> {
        if pid <= 0 {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        let encoded = encode_pid_name(pid).ok_or_else(|| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            )
        })?;
        let how = OpenHowV1 {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH_V1 | RESOLVE_NO_MAGICLINKS_V1 | RESOLVE_NO_XDEV_V1,
        };
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                proc_root,
                encoded.as_c_str().as_ptr(),
                &how,
                std::mem::size_of::<OpenHowV1>(),
            )
        };
        if raw < 0 {
            let errno = last_errno();
            let (code, reason) = match errno {
                Some(libc::ENOSYS) => (
                    RefusalCode::RequiredKernelCapabilityMissing,
                    IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                ),
                Some(libc::EPERM) | Some(libc::EACCES) => (
                    RefusalCode::RequiredKernelCapabilityMissing,
                    IsolationQualificationReasonV1::AdministrativePolicy,
                ),
                Some(libc::EINVAL) | Some(libc::E2BIG) => (
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                ),
                _ => (
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationReasonV1::Io,
                ),
            };
            return Err(failure(code, stage, reason, errno));
        }
        let raw = match i32::try_from(raw) {
            Ok(raw) if raw >= 0 => raw,
            _ => {
                return Err(failure(
                    RefusalCode::IsolationPreflightFailed,
                    stage,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
        };
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        require_cloexec(fd.as_raw_fd()).map_err(|error| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            )
        })?;
        Ok(fd)
    }

    struct EncodedPidNameV1 {
        bytes: [u8; 12],
        length_with_nul: usize,
    }

    impl EncodedPidNameV1 {
        fn as_bytes(&self) -> &[u8] {
            &self.bytes[..self.length_with_nul - 1]
        }

        fn as_c_str(&self) -> &CStr {
            // `encode_pid_name` writes only decimal bytes followed by the
            // zero-initialized terminator included in this exact length.
            unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes[..self.length_with_nul]) }
        }
    }

    fn encode_pid_name(pid: libc::pid_t) -> Option<EncodedPidNameV1> {
        let mut value = u32::try_from(pid).ok().filter(|value| *value > 0)?;
        let mut reversed = [0_u8; 10];
        let mut digits = 0_usize;
        while value != 0 {
            reversed[digits] = b'0' + (value % 10) as u8;
            digits += 1;
            value /= 10;
        }
        let mut bytes = [0_u8; 12];
        for index in 0..digits {
            bytes[index] = reversed[digits - index - 1];
        }
        Some(EncodedPidNameV1 {
            bytes,
            length_with_nul: digits + 1,
        })
    }

    fn open_namespace_at(
        proc_directory: RawFd,
        kind: NamespaceKindV1,
        open_stage: IsolationQualificationStageV1,
    ) -> Result<PinnedNamespaceV1, IsolationQualificationFailureV1> {
        let raw = unsafe {
            libc::openat(
                proc_directory,
                kind.relative_path().as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(namespace_failure(
                open_stage,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        verify_namespace_fd(fd.as_raw_fd(), kind, open_stage)?;
        let identity = namespace_identity(fd.as_raw_fd(), open_stage)?;
        Ok(PinnedNamespaceV1 { fd, identity })
    }

    fn verify_namespace_fd(
        fd: RawFd,
        kind: NamespaceKindV1,
        pin_stage: IsolationQualificationStageV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        require_cloexec(fd).map_err(|error| {
            namespace_failure(
                pin_stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            )
        })?;
        let mut filesystem = MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::fstatfs(fd, filesystem.as_mut_ptr()) } != 0 {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceFilesystem,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        if unsafe { filesystem.assume_init() }.f_type != NSFS_MAGIC_V1 {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceFilesystem,
                IsolationQualificationReasonV1::NamespaceFilesystemMismatch,
                None,
            ));
        }
        let observed_type = unsafe { libc::ioctl(fd, NS_GET_NSTYPE_V1) };
        if observed_type < 0 {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceType,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        if observed_type != kind.clone_flag() {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceType,
                IsolationQualificationReasonV1::NamespaceTypeMismatch,
                None,
            ));
        }
        Ok(())
    }

    fn namespace_identity(
        fd: RawFd,
        pin_stage: IsolationQualificationStageV1,
    ) -> Result<NamespaceIdentityV1, IsolationQualificationFailureV1> {
        let mut status = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
            return Err(namespace_failure(
                pin_stage,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let status = unsafe { status.assume_init() };
        let identity = NamespaceIdentityV1 {
            device: status.st_dev,
            inode: status.st_ino,
        };
        if identity.device == 0 || identity.inode == 0 {
            return Err(namespace_failure(
                pin_stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(identity)
    }

    fn verify_namespace_set(
        parent: &NamespaceFdSetV1,
        child: &NamespaceFdSetV1,
        expected_owner_uid: u32,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let mut child_identities = [NamespaceIdentityV1 {
            device: 0,
            inode: 0,
        }; 6];
        for (index, kind) in NamespaceKindV1::ALL.into_iter().enumerate() {
            let parent_namespace = parent.get(kind);
            let child_namespace = child.get(kind);
            if parent_namespace.identity == child_namespace.identity {
                return Err(namespace_failure(
                    IsolationQualificationStageV1::VerifyNamespaceFreshness,
                    IsolationQualificationReasonV1::NamespaceNotFresh,
                    None,
                ));
            }
            child_identities[index] = child_namespace.identity;
        }
        for (index, identity) in child_identities.iter().enumerate() {
            if child_identities[..index].contains(identity) {
                return Err(namespace_failure(
                    IsolationQualificationStageV1::VerifyNamespaceFreshness,
                    IsolationQualificationReasonV1::NamespaceNotFresh,
                    None,
                ));
            }
        }

        let mut owner_uid = MaybeUninit::<libc::uid_t>::zeroed();
        if unsafe {
            libc::ioctl(
                child.user.fd.as_raw_fd(),
                NS_GET_OWNER_UID_V1,
                owner_uid.as_mut_ptr(),
            )
        } != 0
        {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceOwner,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        if unsafe { owner_uid.assume_init() } != expected_owner_uid {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceOwner,
                IsolationQualificationReasonV1::NamespaceOwnerMismatch,
                None,
            ));
        }

        for kind in NamespaceKindV1::ALL.into_iter().skip(1) {
            verify_namespace_owner(child.get(kind), &child.user)?;
        }
        Ok(())
    }

    fn verify_namespace_owner(
        namespace: &PinnedNamespaceV1,
        expected_user: &PinnedNamespaceV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let owner_raw = unsafe { libc::ioctl(namespace.fd.as_raw_fd(), NS_GET_USERNS_V1) };
        if owner_raw < 0 {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceOwner,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        let owner = unsafe { OwnedFd::from_raw_fd(owner_raw) };
        set_and_require_cloexec(owner.as_raw_fd()).map_err(|error| {
            namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceOwner,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            )
        })?;
        verify_namespace_fd(
            owner.as_raw_fd(),
            NamespaceKindV1::User,
            IsolationQualificationStageV1::VerifyNamespaceOwner,
        )?;
        if namespace_identity(
            owner.as_raw_fd(),
            IsolationQualificationStageV1::VerifyNamespaceOwner,
        )? != expected_user.identity
        {
            return Err(namespace_failure(
                IsolationQualificationStageV1::VerifyNamespaceOwner,
                IsolationQualificationReasonV1::NamespaceOwnerMismatch,
                None,
            ));
        }
        Ok(())
    }

    fn namespace_failure(
        stage: IsolationQualificationStageV1,
        reason: IsolationQualificationReasonV1,
        errno: Option<i32>,
    ) -> IsolationQualificationFailureV1 {
        failure(RefusalCode::RequiredNamespaceFailed, stage, reason, errno)
    }

    fn require_cloexec(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            Err(io::Error::last_os_error())
        } else if flags & libc::FD_CLOEXEC == 0 {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            Ok(())
        }
    }

    fn set_and_require_cloexec(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::FD_CLOEXEC == 0
            && unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        require_cloexec(fd)
    }

    fn write_and_verify_id_map(
        proc_directory: RawFd,
        name: &CStr,
        outside_id: u32,
        write_stage: IsolationQualificationStageV1,
        verify_stage: IsolationQualificationStageV1,
        deadline: MonotonicDeadlineV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        deadline.ensure_open(write_stage)?;
        let line = encode_id_map_line(outside_id);
        write_proc_file_once(proc_directory, name, line.as_slice(), write_stage)?;
        deadline.ensure_open(verify_stage)?;
        let bytes =
            read_bounded_file_at(proc_directory, name, MAX_PROC_MAP_BYTES_V1).map_err(|error| {
                failure(
                    RefusalCode::UserNamespaceUnavailable,
                    verify_stage,
                    IsolationQualificationReasonV1::Io,
                    error.raw_os_error(),
                )
            })?;
        let observed = parse_one_id_map_v1(&bytes).ok_or_else(|| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                verify_stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            )
        })?;
        if observed
            != (IdMapTupleV1 {
                inside: 0,
                outside: outside_id,
                length: 1,
            })
        {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                verify_stage,
                IsolationQualificationReasonV1::MapMismatch,
                None,
            ));
        }
        Ok(())
    }

    struct EncodedMapLineV1 {
        bytes: [u8; 32],
        length: usize,
    }

    impl EncodedMapLineV1 {
        fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.length]
        }
    }

    fn encode_id_map_line(outside_id: u32) -> EncodedMapLineV1 {
        let mut bytes = [0_u8; 32];
        bytes[0] = b'0';
        bytes[1] = b' ';
        let mut reversed = [0_u8; 10];
        let mut value = outside_id;
        let mut digits = 0_usize;
        loop {
            reversed[digits] = b'0' + (value % 10) as u8;
            digits += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for index in 0..digits {
            bytes[2 + index] = reversed[digits - index - 1];
        }
        let suffix = 2 + digits;
        bytes[suffix..suffix + 3].copy_from_slice(b" 1\n");
        EncodedMapLineV1 {
            bytes,
            length: suffix + 3,
        }
    }

    fn write_and_verify_setgroups(
        proc_directory: RawFd,
        deadline: MonotonicDeadlineV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        deadline.ensure_open(IsolationQualificationStageV1::WriteSetgroups)?;
        write_proc_file_once(
            proc_directory,
            c"setgroups",
            b"deny\n",
            IsolationQualificationStageV1::WriteSetgroups,
        )?;
        deadline.ensure_open(IsolationQualificationStageV1::VerifySetgroups)?;
        let bytes = read_bounded_file_at(proc_directory, c"setgroups", MAX_PROC_MAP_BYTES_V1)
            .map_err(|error| {
                failure(
                    RefusalCode::UserNamespaceUnavailable,
                    IsolationQualificationStageV1::VerifySetgroups,
                    IsolationQualificationReasonV1::Io,
                    error.raw_os_error(),
                )
            })?;
        if !parse_setgroups_deny_v1(&bytes) {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::VerifySetgroups,
                IsolationQualificationReasonV1::MapMismatch,
                None,
            ));
        }
        Ok(())
    }

    fn write_proc_file_once(
        proc_directory: RawFd,
        name: &CStr,
        bytes: &[u8],
        stage: IsolationQualificationStageV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let raw = unsafe {
            libc::openat(
                proc_directory,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(map_write_failure(stage, last_errno()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if let Err(error) = require_cloexec(fd.as_raw_fd()) {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                stage,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                error.raw_os_error(),
            ));
        }
        let written = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            return Err(map_write_failure(stage, last_errno()));
        }
        if usize::try_from(written).ok() != Some(bytes.len()) {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                stage,
                IsolationQualificationReasonV1::ShortWrite,
                None,
            ));
        }
        Ok(())
    }

    fn map_write_failure(
        stage: IsolationQualificationStageV1,
        errno: Option<i32>,
    ) -> IsolationQualificationFailureV1 {
        let reason = if matches!(errno, Some(libc::EPERM) | Some(libc::EACCES)) {
            IsolationQualificationReasonV1::AdministrativePolicy
        } else {
            IsolationQualificationReasonV1::Io
        };
        failure(RefusalCode::UserNamespaceUnavailable, stage, reason, errno)
    }

    fn verify_child_groups_and_capabilities(
        proc_directory: RawFd,
        expected_groups: &[u32],
        deadline: MonotonicDeadlineV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        deadline.ensure_open(IsolationQualificationStageV1::VerifyChildGroups)?;
        let status = read_bounded_file_at(proc_directory, c"status", MAX_PROC_STATUS_BYTES_V1)
            .map_err(|error| {
                failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::VerifyChildGroups,
                    IsolationQualificationReasonV1::Io,
                    error.raw_os_error(),
                )
            })?;
        let observed = parse_status_groups(&status)?;
        if observed != expected_groups {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::VerifyChildGroups,
                IsolationQualificationReasonV1::GroupMismatch,
                None,
            ));
        }
        deadline.ensure_open(IsolationQualificationStageV1::VerifyChildCapabilities)?;
        verify_child_sys_admin_capability(&status)?;
        Ok(())
    }

    fn verify_child_sys_admin_capability(
        status: &[u8],
    ) -> Result<(), IsolationQualificationFailureV1> {
        let malformed = || {
            failure(
                RefusalCode::RequiredNamespaceFailed,
                IsolationQualificationStageV1::VerifyChildCapabilities,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            )
        };
        let effective = parse_exact_status_hex(status, b"CapEff:").map_err(|_| malformed())?;
        if effective & CAP_SYS_ADMIN_MASK_V1 == 0 {
            return Err(failure(
                RefusalCode::RequiredNamespaceFailed,
                IsolationQualificationStageV1::VerifyChildCapabilities,
                IsolationQualificationReasonV1::ChildInvariantFailed,
                None,
            ));
        }
        Ok(())
    }

    fn parse_status_groups(status: &[u8]) -> Result<Vec<u32>, IsolationQualificationFailureV1> {
        let row = exact_status_row(status, b"Groups:").map_err(|_| {
            failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::VerifyChildGroups,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            )
        })?;
        let mut parser = AsciiFieldsV1::new(row);
        let mut groups = Vec::new();
        while let Some(field) = parser.next_bytes() {
            if groups.len() == MAX_SUPPLEMENTARY_GROUPS_V1 {
                return Err(failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::VerifyChildGroups,
                    IsolationQualificationReasonV1::BoundExceeded,
                    None,
                ));
            }
            let group = parse_ascii_u32_field_v1(field).ok_or_else(|| {
                failure(
                    RefusalCode::IsolationPreflightFailed,
                    IsolationQualificationStageV1::VerifyChildGroups,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                )
            })?;
            groups.push(group);
        }
        groups.sort_unstable();
        if groups.windows(2).any(|window| window[0] == window[1]) {
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                IsolationQualificationStageV1::VerifyChildGroups,
                IsolationQualificationReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(groups)
    }

    fn read_bounded_file_at(directory: RawFd, name: &CStr, maximum: usize) -> io::Result<Vec<u8>> {
        let raw = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        require_cloexec(fd.as_raw_fd())?;
        read_bounded_fd(fd.as_raw_fd(), maximum)
    }

    fn read_bounded_fd(fd: RawFd, maximum: usize) -> io::Result<Vec<u8>> {
        let capacity = maximum
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let mut bytes = Vec::with_capacity(capacity.min(8192));
        let mut buffer = [0_u8; 4096];
        loop {
            let remaining = capacity.saturating_sub(bytes.len());
            if remaining == 0 {
                return Err(io::Error::from_raw_os_error(libc::E2BIG));
            }
            let requested = remaining.min(buffer.len());
            let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), requested) };
            if read == 0 {
                break;
            }
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            let read =
                usize::try_from(read).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.len() > maximum {
                return Err(io::Error::from_raw_os_error(libc::E2BIG));
            }
        }
        Ok(bytes)
    }

    fn encode_common_frame(
        magic: &[u8; 8],
        phase: u8,
        nonce: &[u8; NONCE_BYTES_V1],
    ) -> [u8; FRAME_BYTES_V1] {
        let mut frame = [0_u8; FRAME_BYTES_V1];
        frame[FRAME_MAGIC_OFFSET_V1..FRAME_VERSION_OFFSET_V1].copy_from_slice(magic);
        frame[FRAME_VERSION_OFFSET_V1..FRAME_PHASE_OFFSET_V1]
            .copy_from_slice(&PROTOCOL_VERSION_V2.to_le_bytes());
        frame[FRAME_PHASE_OFFSET_V1] = phase;
        frame[FRAME_NONCE_OFFSET_V1..FRAME_ERROR_OFFSET_V1].copy_from_slice(nonce);
        frame
    }

    fn verify_common_frame(
        frame: &[u8; FRAME_BYTES_V1],
        magic: &[u8; 8],
        phase: u8,
        nonce: &[u8; NONCE_BYTES_V1],
        stage: IsolationQualificationStageV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let version = u16::from_le_bytes([
            frame[FRAME_VERSION_OFFSET_V1],
            frame[FRAME_VERSION_OFFSET_V1 + 1],
        ]);
        if &frame[FRAME_MAGIC_OFFSET_V1..FRAME_VERSION_OFFSET_V1] != magic
            || version != PROTOCOL_VERSION_V2
            || frame[FRAME_PHASE_OFFSET_V1] != phase
            || frame[FRAME_NONCE_OFFSET_V1..FRAME_ERROR_OFFSET_V1] != nonce[..]
        {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::ProtocolFrameMismatch,
                None,
            ));
        }
        Ok(())
    }

    fn verify_ready_frame(
        frame: &[u8; FRAME_BYTES_V1],
        nonce: &[u8; NONCE_BYTES_V1],
    ) -> Result<(), IsolationQualificationFailureV1> {
        let stage = IsolationQualificationStageV1::VerifyChildReady;
        verify_common_frame(frame, READY_MAGIC_V1, PHASE_READY_V1, nonce, stage)?;
        if frame[FRAME_STATUS_OFFSET_V1] != 0
            || decode_u16(frame, FRAME_FLAGS_OFFSET_V1) != 0
            || frame[FRAME_FLAGS_END_V1..FRAME_NONCE_OFFSET_V1]
                .iter()
                .any(|byte| *byte != 0)
            || frame[FRAME_ERROR_OFFSET_V1..].iter().any(|byte| *byte != 0)
        {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::ProtocolFrameMismatch,
                None,
            ));
        }
        Ok(())
    }

    fn verify_proof_frame(
        frame: &[u8; FRAME_BYTES_V1],
        nonce: &[u8; NONCE_BYTES_V1],
    ) -> Result<(), IsolationQualificationFailureV1> {
        let stage = IsolationQualificationStageV1::VerifyChildProof;
        verify_common_frame(frame, PROOF_MAGIC_V1, PHASE_PROOF_V1, nonce, stage)?;
        if frame[FRAME_FLAGS_END_V1..FRAME_NONCE_OFFSET_V1]
            .iter()
            .any(|byte| *byte != 0)
            || frame[FRAME_RESERVED_OFFSET_V1..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::ProtocolFrameMismatch,
                None,
            ));
        }
        let status = frame[FRAME_STATUS_OFFSET_V1];
        let flags = decode_u16(frame, FRAME_FLAGS_OFFSET_V1);
        let errno = decode_i32(frame, FRAME_ERROR_OFFSET_V1);
        let identity_is_exact = decode_u32(frame, FRAME_PID_OFFSET_V1) == 1
            && decode_u32(frame, FRAME_UID_OFFSET_V1) == 0
            && decode_u32(frame, FRAME_EUID_OFFSET_V1) == 0
            && decode_u32(frame, FRAME_GID_OFFSET_V1) == 0
            && decode_u32(frame, FRAME_EGID_OFFSET_V1) == 0;
        if status == PROOF_STATUS_UTS_CONFIGURATION_V1 {
            if flags != 0 || errno != libc::EPERM || !identity_is_exact {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch,
                    None,
                ));
            }
            return Err(failure(
                RefusalCode::RequiredNamespaceFailed,
                IsolationQualificationStageV1::ChildUtsConfiguration,
                IsolationQualificationReasonV1::AdministrativePolicy,
                Some(errno),
            ));
        }
        if matches!(
            status,
            PROOF_STATUS_MOUNT_ROOT_OS_V1 | PROOF_STATUS_MOUNT_ROOT_INVARIANT_V1
        ) {
            let canonical_errno = match status {
                PROOF_STATUS_MOUNT_ROOT_OS_V1 => (1..=MAX_LINUX_ERRNO_V1).contains(&errno),
                PROOF_STATUS_MOUNT_ROOT_INVARIANT_V1 => errno == 0,
                _ => false,
            };
            if flags != 0 || !canonical_errno || !identity_is_exact {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch,
                    None,
                ));
            }
            return Err(failure(
                RefusalCode::MountRootFailed,
                IsolationQualificationStageV1::ChildMountRoot,
                if status == PROOF_STATUS_MOUNT_ROOT_OS_V1 {
                    IsolationQualificationReasonV1::Io
                } else {
                    IsolationQualificationReasonV1::ChildInvariantFailed
                },
                (errno != 0).then_some(errno),
            ));
        }
        if status == PROOF_STATUS_CLOSE_RANGE_OS_V1 {
            if flags != 0 || !(1..=MAX_LINUX_ERRNO_V1).contains(&errno) || !identity_is_exact {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch,
                    None,
                ));
            }
            let reason = match errno {
                libc::ENOSYS | libc::EINVAL => {
                    IsolationQualificationReasonV1::KernelCapabilityUnavailable
                }
                libc::EPERM | libc::EACCES => IsolationQualificationReasonV1::AdministrativePolicy,
                _ => IsolationQualificationReasonV1::Io,
            };
            return Err(failure(
                RefusalCode::CloseRangeUnavailable,
                IsolationQualificationStageV1::ChildDescriptorScrub,
                reason,
                Some(errno),
            ));
        }
        if matches!(
            status,
            PROOF_STATUS_FD_SCRUB_V1
                | PROOF_STATUS_CAPABILITY_DROP_V1
                | PROOF_STATUS_LANDLOCK_BROKEN_V1
                | PROOF_STATUS_SECCOMP_BROKEN_V1
        ) {
            if flags != 0 || !(0..=MAX_LINUX_ERRNO_V1).contains(&errno) || !identity_is_exact {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch,
                    None,
                ));
            }
            let failure_stage = if status == PROOF_STATUS_FD_SCRUB_V1 {
                IsolationQualificationStageV1::ChildDescriptorScrub
            } else if status == PROOF_STATUS_CAPABILITY_DROP_V1 {
                IsolationQualificationStageV1::ChildCapabilityDrop
            } else if status == PROOF_STATUS_LANDLOCK_BROKEN_V1 {
                IsolationQualificationStageV1::ChildLandlock
            } else {
                IsolationQualificationStageV1::ChildSeccomp
            };
            return Err(failure(
                RefusalCode::IsolationPreflightFailed,
                failure_stage,
                if errno == 0 {
                    IsolationQualificationReasonV1::ChildInvariantFailed
                } else {
                    IsolationQualificationReasonV1::Io
                },
                (errno != 0).then_some(errno),
            ));
        }
        if status == PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1 {
            let canonical_unavailable =
                errno == 0 || matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP);
            if flags != 0 || !canonical_unavailable || !identity_is_exact {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch,
                    None,
                ));
            }
            return Err(failure(
                RefusalCode::LandlockUnavailable,
                IsolationQualificationStageV1::ChildLandlock,
                IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                (errno != 0).then_some(errno),
            ));
        }
        if status == PROOF_STATUS_SECCOMP_UNAVAILABLE_V1 {
            let canonical_unavailable = matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP);
            if flags != 0 || !canonical_unavailable || !identity_is_exact {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch,
                    None,
                ));
            }
            return Err(failure(
                RefusalCode::SeccompUnavailable,
                IsolationQualificationStageV1::ChildSeccomp,
                IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                Some(errno),
            ));
        }
        if status != PROOF_STATUS_SUCCESS_V1 {
            let reason = match status {
                PROOF_STATUS_OS_ERROR_V1 | PROOF_STATUS_INVARIANT_V1 => {
                    IsolationQualificationReasonV1::ChildInvariantFailed
                }
                _ => IsolationQualificationReasonV1::ProtocolFrameMismatch,
            };
            return Err(protocol_failure(
                stage,
                reason,
                (errno != 0).then_some(errno),
            ));
        }
        if flags != PROOF_FLAGS_V1 || errno != 0 || !identity_is_exact {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::ChildInvariantFailed,
                None,
            ));
        }
        Ok(())
    }

    fn decode_u32(frame: &[u8; FRAME_BYTES_V1], offset: usize) -> u32 {
        u32::from_le_bytes([
            frame[offset],
            frame[offset + 1],
            frame[offset + 2],
            frame[offset + 3],
        ])
    }

    fn decode_u16(frame: &[u8; FRAME_BYTES_V1], offset: usize) -> u16 {
        u16::from_le_bytes([frame[offset], frame[offset + 1]])
    }

    fn decode_i32(frame: &[u8; FRAME_BYTES_V1], offset: usize) -> i32 {
        i32::from_le_bytes([
            frame[offset],
            frame[offset + 1],
            frame[offset + 2],
            frame[offset + 3],
        ])
    }

    fn read_parent_frame(
        fd: RawFd,
        pidfd: RawFd,
        deadline: MonotonicDeadlineV1,
        terminal_allowed: bool,
        stage: IsolationQualificationStageV1,
    ) -> Result<[u8; FRAME_BYTES_V1], IsolationQualificationFailureV1> {
        let mut frame = [0_u8; FRAME_BYTES_V1];
        let mut offset = 0_usize;
        while offset < frame.len() {
            deadline.ensure_open(stage)?;
            let read = unsafe {
                libc::read(
                    fd,
                    frame[offset..].as_mut_ptr().cast(),
                    frame.len() - offset,
                )
            };
            if read > 0 {
                let read = usize::try_from(read).map_err(|_| {
                    protocol_failure(
                        stage,
                        IsolationQualificationReasonV1::MalformedKernelResponse,
                        None,
                    )
                })?;
                offset = offset.checked_add(read).ok_or_else(|| {
                    protocol_failure(stage, IsolationQualificationReasonV1::BoundExceeded, None)
                })?;
                if offset > frame.len() {
                    return Err(protocol_failure(
                        stage,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch,
                        None,
                    ));
                }
                continue;
            }
            if read == 0 {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolEofMismatch,
                    None,
                ));
            }
            let errno = last_errno();
            if errno == Some(libc::EINTR) {
                continue;
            }
            if matches!(errno, Some(libc::EAGAIN)) {
                let child_terminal = poll_parent_io(fd, libc::POLLIN, pidfd, deadline, stage)?;
                if child_terminal && !terminal_allowed {
                    return Err(protocol_failure(
                        stage,
                        IsolationQualificationReasonV1::ChildExitMismatch,
                        None,
                    ));
                }
                continue;
            }
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::Io,
                errno,
            ));
        }
        Ok(frame)
    }

    fn verify_no_pending_report_byte(
        fd: RawFd,
        pidfd: RawFd,
        deadline: MonotonicDeadlineV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let stage = IsolationQualificationStageV1::VerifyChildReady;
        deadline.ensure_open(stage)?;
        let mut byte = 0_u8;
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read > 0 {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::ProtocolFrameMismatch,
                None,
            ));
        }
        if read == 0 {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::ProtocolEofMismatch,
                None,
            ));
        }
        let errno = last_errno();
        if errno != Some(libc::EAGAIN) {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::Io,
                errno,
            ));
        }
        let mut child = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut child, 1, 0) };
        if result < 0 {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::Io,
                last_errno(),
            ));
        }
        if result != 0 || child.revents != 0 {
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::ChildExitMismatch,
                None,
            ));
        }
        Ok(())
    }

    fn write_parent_frame(
        fd: RawFd,
        pidfd: RawFd,
        frame: &[u8; FRAME_BYTES_V1],
        deadline: MonotonicDeadlineV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let stage = IsolationQualificationStageV1::SendControl;
        loop {
            deadline.ensure_open(stage)?;
            let written = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
            if written == FRAME_BYTES_V1 as isize {
                return Ok(());
            }
            if written >= 0 {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ShortWrite,
                    None,
                ));
            }
            let errno = last_errno();
            if errno == Some(libc::EINTR) {
                continue;
            }
            if errno == Some(libc::EAGAIN) {
                if poll_parent_io(fd, libc::POLLOUT, pidfd, deadline, stage)? {
                    return Err(protocol_failure(
                        stage,
                        IsolationQualificationReasonV1::ChildExitMismatch,
                        None,
                    ));
                }
                continue;
            }
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::Io,
                errno,
            ));
        }
    }

    fn expect_report_eof(
        fd: RawFd,
        pidfd: RawFd,
        deadline: MonotonicDeadlineV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let stage = IsolationQualificationStageV1::ReceiveChildProof;
        let mut byte = 0_u8;
        loop {
            deadline.ensure_open(stage)?;
            let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            if read == 0 {
                return Ok(());
            }
            if read > 0 {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch,
                    None,
                ));
            }
            let errno = last_errno();
            if errno == Some(libc::EINTR) {
                continue;
            }
            if errno == Some(libc::EAGAIN) {
                poll_parent_io(fd, libc::POLLIN, pidfd, deadline, stage)?;
                continue;
            }
            return Err(protocol_failure(
                stage,
                IsolationQualificationReasonV1::Io,
                errno,
            ));
        }
    }

    fn poll_parent_io(
        fd: RawFd,
        events: i16,
        pidfd: RawFd,
        deadline: MonotonicDeadlineV1,
        stage: IsolationQualificationStageV1,
    ) -> Result<bool, IsolationQualificationFailureV1> {
        loop {
            let timeout = deadline.remaining_milliseconds().map_err(|_| {
                protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolTimeout,
                    Some(libc::ETIMEDOUT),
                )
            })?;
            let mut descriptors = [
                libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: pidfd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, timeout) };
            if result == 0 {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolTimeout,
                    Some(libc::ETIMEDOUT),
                ));
            }
            if result < 0 {
                let errno = last_errno();
                if errno == Some(libc::EINTR) {
                    continue;
                }
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::Io,
                    errno,
                ));
            }
            let invalid = libc::POLLNVAL | libc::POLLERR;
            if descriptors
                .iter()
                .any(|descriptor| descriptor.revents & invalid != 0)
            {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            return Ok(descriptors[1].revents & (libc::POLLIN | libc::POLLHUP) != 0);
        }
    }

    fn wait_pidfd_terminal(
        pidfd: RawFd,
        deadline: MonotonicDeadlineV1,
    ) -> Result<(), IsolationQualificationFailureV1> {
        let stage = IsolationQualificationStageV1::WaitForChild;
        loop {
            let timeout = deadline.remaining_milliseconds().map_err(|_| {
                protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolTimeout,
                    Some(libc::ETIMEDOUT),
                )
            })?;
            let mut descriptor = libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result > 0 {
                if descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    return Ok(());
                }
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            if result == 0 {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::ProtocolTimeout,
                    Some(libc::ETIMEDOUT),
                ));
            }
            let errno = last_errno();
            if errno != Some(libc::EINTR) {
                return Err(protocol_failure(
                    stage,
                    IsolationQualificationReasonV1::WaitFailed,
                    errno,
                ));
            }
        }
    }

    fn protocol_failure(
        stage: IsolationQualificationStageV1,
        reason: IsolationQualificationReasonV1,
        errno: Option<i32>,
    ) -> IsolationQualificationFailureV1 {
        failure(RefusalCode::IsolationPreflightFailed, stage, reason, errno)
    }

    fn clone_failure(errno: Option<i32>) -> IsolationQualificationFailureV1 {
        let (code, reason) = match errno {
            Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => (
                RefusalCode::RequiredKernelCapabilityMissing,
                IsolationQualificationReasonV1::KernelCapabilityUnavailable,
            ),
            Some(libc::EPERM) | Some(libc::EACCES) | Some(libc::ENOSPC) | Some(libc::EUSERS) => (
                RefusalCode::UserNamespaceUnavailable,
                IsolationQualificationReasonV1::AdministrativePolicy,
            ),
            Some(libc::EINVAL) | Some(libc::E2BIG) => (
                RefusalCode::RequiredNamespaceFailed,
                IsolationQualificationReasonV1::MalformedKernelResponse,
            ),
            _ => (
                RefusalCode::RequiredNamespaceFailed,
                IsolationQualificationReasonV1::Io,
            ),
        };
        failure(
            code,
            IsolationQualificationStageV1::CloneNamespaces,
            reason,
            errno,
        )
    }

    fn last_errno() -> Option<i32> {
        io::Error::last_os_error().raw_os_error()
    }

    fn child_entry_v1(
        control_read: RawFd,
        control_write: RawFd,
        report_read: RawFd,
        report_write: RawFd,
        inherited_parent_fds: [RawFd; 8],
        nonce: [u8; NONCE_BYTES_V1],
        deadline: MonotonicDeadlineV1,
    ) -> ! {
        // This branch must never unwind or run Rust destructors. Every exit
        // below reaches the raw `_exit` syscall.
        let control_write_closed = child_close(control_write);
        let report_read_closed = child_close(report_read);
        let mut close_failed = !control_write_closed || !report_read_closed;
        for descriptor in inherited_parent_fds {
            if descriptor < 0
                || descriptor == control_read
                || descriptor == report_write
                || !child_close(descriptor)
            {
                close_failed = true;
            }
        }
        if close_failed {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_INVARIANT_V1,
                libc::EBADF,
                deadline,
            );
        }
        if unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL,
                0_u64,
                0_u64,
                0_u64,
            )
        } != 0
        {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_OS_ERROR_V1,
                child_errno(),
                deadline,
            );
        }

        let ready = child_encode_common_frame(READY_MAGIC_V1, PHASE_READY_V1, &nonce);
        if !child_write_frame(report_write, &ready, deadline) {
            child_exit(CHILD_EXIT_PROOF_FAILED_V1);
        }
        let mut release = [0_u8; FRAME_BYTES_V1];
        if !child_read_frame_and_eof(control_read, &mut release, deadline)
            || !child_verify_release_frame(&release, &nonce)
        {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_PROTOCOL_V1,
                libc::EPROTO,
                deadline,
            );
        }
        if !child_close(control_read) {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_INVARIANT_V1,
                libc::EBADF,
                deadline,
            );
        }

        let pid = unsafe { libc::syscall(libc::SYS_getpid) };
        let mut real_uid = u32::MAX;
        let mut effective_uid = u32::MAX;
        let mut saved_uid = u32::MAX;
        let mut real_gid = u32::MAX;
        let mut effective_gid = u32::MAX;
        let mut saved_gid = u32::MAX;
        let uid_result = unsafe {
            libc::syscall(
                libc::SYS_getresuid,
                &mut real_uid,
                &mut effective_uid,
                &mut saved_uid,
            )
        };
        let gid_result = unsafe {
            libc::syscall(
                libc::SYS_getresgid,
                &mut real_gid,
                &mut effective_gid,
                &mut saved_gid,
            )
        };
        if pid != 1
            || uid_result != 0
            || gid_result != 0
            || real_uid != 0
            || effective_uid != 0
            || saved_uid != 0
            || real_gid != 0
            || effective_gid != 0
            || saved_gid != 0
            || unsafe { libc::syscall(libc::SYS_getuid) } != 0
            || unsafe { libc::syscall(libc::SYS_geteuid) } != 0
            || unsafe { libc::syscall(libc::SYS_getgid) } != 0
            || unsafe { libc::syscall(libc::SYS_getegid) } != 0
        {
            child_fail(report_write, &nonce, PROOF_STATUS_INVARIANT_V1, 0, deadline);
        }

        if unsafe {
            libc::syscall(
                libc::SYS_sethostname,
                HOSTNAME_V1.as_ptr(),
                HOSTNAME_V1.len(),
            )
        } != 0
        {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_UTS_CONFIGURATION_V1,
                child_errno(),
                deadline,
            );
        }
        if unsafe { libc::syscall(libc::SYS_setdomainname, std::ptr::null::<u8>(), 0_usize) } != 0 {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_UTS_CONFIGURATION_V1,
                child_errno(),
                deadline,
            );
        }
        let mut uts = MaybeUninit::<libc::utsname>::zeroed();
        if unsafe { libc::syscall(libc::SYS_uname, uts.as_mut_ptr()) } != 0 {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_OS_ERROR_V1,
                child_errno(),
                deadline,
            );
        }
        let uts = unsafe { uts.assume_init() };
        if !child_c_field_equals(uts.nodename.as_ptr(), uts.nodename.len(), HOSTNAME_V1)
            || unsafe { *uts.domainname.as_ptr() } != 0
        {
            child_fail(report_write, &nonce, PROOF_STATUS_INVARIANT_V1, 0, deadline);
        }
        let mut parent_death_signal = 0_i32;
        if unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_GET_PDEATHSIG,
                &mut parent_death_signal,
                0_u64,
                0_u64,
                0_u64,
            )
        } != 0
        {
            child_fail(
                report_write,
                &nonce,
                PROOF_STATUS_OS_ERROR_V1,
                child_errno(),
                deadline,
            );
        }
        if parent_death_signal != libc::SIGKILL {
            child_fail(report_write, &nonce, PROOF_STATUS_INVARIANT_V1, 0, deadline);
        }

        let private_root = match child_enter_private_tmpfs_root_v1() {
            Ok(evidence) => evidence,
            Err(error) => match error {
                ChildMountRootFailureV1::Os(errno) => child_fail(
                    report_write,
                    &nonce,
                    PROOF_STATUS_MOUNT_ROOT_OS_V1,
                    errno,
                    deadline,
                ),
                ChildMountRootFailureV1::Invariant => child_fail(
                    report_write,
                    &nonce,
                    PROOF_STATUS_MOUNT_ROOT_INVARIANT_V1,
                    0,
                    deadline,
                ),
            },
        };

        if report_write <= libc::STDERR_FILENO {
            child_descriptor_fail_v1(
                report_write,
                &nonce,
                ChildDescriptorFailureV1::Invariant,
                deadline,
            );
        }
        let report_identity = match child_report_descriptor_identity_v1(report_write) {
            Ok(identity) => identity,
            Err(error) => child_descriptor_fail_v1(report_write, &nonce, error, deadline),
        };
        let duplicate = unsafe {
            libc::syscall(
                libc::SYS_dup3,
                report_write,
                REPORT_DESCRIPTOR_V1,
                libc::O_CLOEXEC,
            )
        };
        if duplicate < 0 {
            child_descriptor_fail_v1(
                report_write,
                &nonce,
                child_descriptor_os_failure_v1(),
                deadline,
            );
        }
        if duplicate != libc::c_long::from(REPORT_DESCRIPTOR_V1) {
            child_descriptor_fail_v1(
                report_write,
                &nonce,
                ChildDescriptorFailureV1::Invariant,
                deadline,
            );
        }
        let report_write = REPORT_DESCRIPTOR_V1;
        match child_report_descriptor_identity_v1(report_write) {
            Ok(identity) if identity == report_identity => {}
            Ok(_) => child_descriptor_fail_v1(
                report_write,
                &nonce,
                ChildDescriptorFailureV1::Invariant,
                deadline,
            ),
            Err(error) => child_descriptor_fail_v1(report_write, &nonce, error, deadline),
        }
        if let Err(error) = child_scrub_and_audit_descriptors_v1(&report_identity) {
            child_descriptor_fail_v1(report_write, &nonce, error, deadline);
        }
        let capability = match child_eliminate_capabilities_v1(&report_identity) {
            Ok(evidence) => evidence,
            Err(error) => child_capability_fail_v1(report_write, &nonce, error, deadline),
        };
        if let Err(error) = child_enforce_landlock_v1(&private_root, capability, &report_identity) {
            child_landlock_fail_v1(report_write, &nonce, error, deadline);
        }
        if let Err(error) = child_enforce_seccomp_v1(&report_identity) {
            child_seccomp_fail_v1(report_write, &nonce, error, deadline);
        }

        let proof = child_encode_proof_frame(&nonce, PROOF_STATUS_SUCCESS_V1, PROOF_FLAGS_V1, 0);
        if !child_write_frame(report_write, &proof, deadline) {
            child_exit(CHILD_EXIT_PROOF_FAILED_V1);
        }
        if !child_close(report_write) {
            child_exit(CHILD_EXIT_PROOF_FAILED_V1);
        }
        child_exit(0)
    }

    /// Enter the fixed diagnostic pathname root and mount topology without
    /// accepting a caller path or FD.
    ///
    /// This is diagnostic path-and-mount evidence only. Inherited descriptors
    /// and old executable mappings are deliberately outside this slice, and
    /// this result can never authorize execution.
    fn child_enter_private_tmpfs_root_v1()
    -> Result<ChildPrivateRootEvidenceV1, ChildMountRootFailureV1> {
        let active_pid_namespace = child_pin_active_pid_namespace_v1()?;
        let old_root = child_open_absolute_root_v1()?;
        if unsafe {
            libc::syscall(
                libc::SYS_mount,
                std::ptr::null::<u8>(),
                ROOT_PATH_V1.as_ptr(),
                std::ptr::null::<u8>(),
                (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
                std::ptr::null::<u8>(),
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }

        let old_target = child_open_root_target_at_v1(old_root)?;
        let old_target_identity = child_path_identity_v1(old_target)?;

        if unsafe {
            libc::syscall(
                libc::SYS_mount,
                ROOT_TMPFS_TYPE_V1.as_ptr(),
                TMP_PATH_V1.as_ptr(),
                ROOT_TMPFS_TYPE_V1.as_ptr(),
                (libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong,
                ROOT_TMPFS_OPTIONS_V1.as_ptr(),
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }

        let new_root = child_open_root_target_at_v1(old_root)?;
        let mounted_identity = child_path_identity_v1(new_root)?;
        if mounted_identity.mount_id == old_target_identity.mount_id {
            return Err(ChildMountRootFailureV1::Invariant);
        }

        if unsafe { libc::syscall(libc::SYS_fchdir, new_root) } != 0 {
            return Err(child_mount_os_failure_v1());
        }
        let old_target_closed = child_close_mount_fd_v1(old_target);
        let old_root_closed = child_close_mount_fd_v1(old_root);
        old_target_closed?;
        old_root_closed?;

        if unsafe {
            libc::syscall(
                libc::SYS_mkdirat,
                new_root,
                OLD_ROOT_NAME_V1.as_ptr(),
                0o700_u32,
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }
        if unsafe {
            libc::syscall(
                libc::SYS_pivot_root,
                CURRENT_DIRECTORY_V1.as_ptr(),
                OLD_ROOT_NAME_V1.as_ptr(),
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }
        if unsafe { libc::syscall(libc::SYS_chdir, ROOT_PATH_V1.as_ptr()) } != 0 {
            return Err(child_mount_os_failure_v1());
        }
        if unsafe {
            libc::syscall(
                libc::SYS_umount2,
                OLD_ROOT_PATH_V1.as_ptr(),
                libc::MNT_DETACH,
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }
        if unsafe {
            libc::syscall(
                libc::SYS_unlinkat,
                new_root,
                OLD_ROOT_NAME_V1.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }

        let pivoted_root = child_open_absolute_root_v1()?;
        let pivoted_identity = child_path_identity_v1(pivoted_root)?;
        if pivoted_identity != mounted_identity
            || !child_root_matches_policy_v1(pivoted_root, &pivoted_identity)?
        {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        for name in ABSENT_ROOT_NAMES_V1 {
            child_require_absent_at_v1(pivoted_root, name)?;
        }
        let evidence = child_build_fixed_mount_layout_v1(
            pivoted_root,
            &pivoted_identity,
            &active_pid_namespace,
        )?;
        let retained_root_closed = child_close_mount_fd_v1(new_root);
        let pivoted_root_closed = child_close_mount_fd_v1(pivoted_root);
        let active_pid_namespace_closed = child_close_mount_fd_v1(active_pid_namespace.descriptor);
        retained_root_closed?;
        pivoted_root_closed?;
        active_pid_namespace_closed?;
        Ok(evidence)
    }

    fn child_open_absolute_root_v1() -> Result<RawFd, ChildMountRootFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                ROOT_PATH_V1.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0_u32,
            )
        };
        child_checked_fd_v1(result)
    }

    fn child_open_root_target_at_v1(directory: RawFd) -> Result<RawFd, ChildMountRootFailureV1> {
        let how = OpenHowV1 {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH_V1 | RESOLVE_NO_MAGICLINKS_V1,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory,
                TMP_NAME_V1.as_ptr(),
                &how,
                std::mem::size_of::<OpenHowV1>(),
            )
        };
        child_checked_fd_v1(result)
    }

    fn child_checked_fd_v1(result: libc::c_long) -> Result<RawFd, ChildMountRootFailureV1> {
        if result < 0 {
            return Err(child_mount_os_failure_v1());
        }
        match i32::try_from(result) {
            Ok(fd) if fd >= 0 => Ok(fd),
            _ => Err(ChildMountRootFailureV1::Invariant),
        }
    }

    fn child_path_identity_v1(
        descriptor: RawFd,
    ) -> Result<ChildPathIdentityV1, ChildMountRootFailureV1> {
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        if unsafe {
            libc::syscall(
                libc::SYS_statx,
                descriptor,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW,
                REQUIRED_PATH_STATX_MASK_V1,
                raw.as_mut_ptr(),
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }
        let raw = unsafe { raw.assume_init() };
        if raw.stx_mask & REQUIRED_PATH_STATX_MASK_V1 != REQUIRED_PATH_STATX_MASK_V1
            || raw.stx_mnt_id == 0
            || raw.stx_ino == 0
        {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        Ok(ChildPathIdentityV1 {
            mount_id: raw.stx_mnt_id,
            inode: raw.stx_ino,
            device_major: raw.stx_dev_major,
            device_minor: raw.stx_dev_minor,
            mode: raw.stx_mode,
            uid: raw.stx_uid,
            gid: raw.stx_gid,
        })
    }

    fn child_root_matches_policy_v1(
        descriptor: RawFd,
        identity: &ChildPathIdentityV1,
    ) -> Result<bool, ChildMountRootFailureV1> {
        if u32::from(identity.mode) & libc::S_IFMT != libc::S_IFDIR
            || u32::from(identity.mode) & 0o7777 != 0o755
            || identity.uid != 0
            || identity.gid != 0
        {
            return Ok(false);
        }
        let mut filesystem = MaybeUninit::<libc::statfs64>::zeroed();
        if unsafe { libc::syscall(libc::SYS_fstatfs, descriptor, filesystem.as_mut_ptr()) } != 0 {
            return Err(child_mount_os_failure_v1());
        }
        let filesystem = unsafe { filesystem.assume_init() };
        Ok(child_statfs_matches_policy_v1(&filesystem))
    }

    fn child_statfs_matches_policy_v1(filesystem: &libc::statfs64) -> bool {
        if filesystem.f_bsize <= 0 || filesystem.f_flags < 0 {
            return false;
        }
        let required_flags = libc::ST_NODEV | libc::ST_NOSUID;
        let flags = filesystem.f_flags as u64;
        let bytes = (filesystem.f_bsize as u64).checked_mul(filesystem.f_blocks);
        filesystem.f_type == TMPFS_SUPER_MAGIC_V1
            && flags & required_flags == required_flags
            && bytes.is_some_and(|bytes| bytes > 0 && bytes <= ROOT_TMPFS_BYTES_V1)
            && filesystem.f_files > 0
            && filesystem.f_files <= ROOT_TMPFS_INODES_V1
    }

    fn child_build_fixed_mount_layout_v1(
        root: RawFd,
        root_identity: &ChildPathIdentityV1,
        active_pid_namespace: &ChildPinnedPidNamespaceV1,
    ) -> Result<ChildPrivateRootEvidenceV1, ChildMountRootFailureV1> {
        let _ = unsafe { libc::syscall(libc::SYS_umask, 0_u32) };

        let workspace = child_create_directory_at_v1(root, WORKSPACE_NAME_V1, WORKSPACE_MODE_V1)?;
        let tmp_target = child_create_directory_at_v1(root, TMP_NAME_V1, TMP_MODE_V1)?;
        let run_target = child_create_directory_at_v1(root, RUN_NAME_V1, RUN_MODE_V1)?;
        let home = child_create_directory_at_v1(root, HOME_NAME_V1, HOME_MODE_V1)?;
        let again_home_target =
            child_create_directory_at_v1(home, AGAIN_NAME_V1, AGAIN_HOME_MODE_V1)?;
        let proc_target = child_create_directory_at_v1(root, PROC_NAME_V1, PROC_MODE_V1)?;
        let dev = child_create_directory_at_v1(root, DEV_NAME_V1, DEV_MODE_V1)?;

        let workspace_closed = child_close_mount_fd_v1(workspace);
        let dev_closed = child_close_mount_fd_v1(dev);
        workspace_closed?;
        dev_closed?;

        if unsafe { libc::syscall(libc::SYS_umask, 0o077_u32) } != 0
            || unsafe { libc::syscall(libc::SYS_umask, 0o077_u32) } != 0o077
        {
            return Err(ChildMountRootFailureV1::Invariant);
        }

        let tmp_identity = child_mount_scratch_v1(
            root,
            tmp_target,
            TMP_NAME_V1,
            TMP_PATH_V1,
            TMP_MODE_V1,
            TMP_TMPFS_OPTIONS_V1,
            root_identity,
        )?;
        let run_identity = child_mount_scratch_v1(
            root,
            run_target,
            RUN_NAME_V1,
            RUN_PATH_V1,
            RUN_MODE_V1,
            RUN_TMPFS_OPTIONS_V1,
            root_identity,
        )?;
        let again_home_identity = child_mount_scratch_v1(
            home,
            again_home_target,
            AGAIN_NAME_V1,
            AGAIN_HOME_PATH_V1,
            AGAIN_HOME_MODE_V1,
            AGAIN_HOME_TMPFS_OPTIONS_V1,
            root_identity,
        )?;
        child_close_mount_fd_v1(home)?;
        if !child_scratch_identities_are_independent_v1(
            &tmp_identity,
            &run_identity,
            &again_home_identity,
        ) {
            return Err(ChildMountRootFailureV1::Invariant);
        }

        let proc_identity =
            child_mount_procfs_v1(root, proc_target, root_identity, active_pid_namespace)?;
        child_verify_final_mount_layout_v1(
            root_identity,
            &tmp_identity,
            &run_identity,
            &again_home_identity,
            &proc_identity,
        )?;
        Ok(ChildPrivateRootEvidenceV1 {
            root: *root_identity,
            tmp: tmp_identity,
            run: run_identity,
            proc: proc_identity,
        })
    }

    fn child_create_directory_at_v1(
        parent: RawFd,
        name: &CStr,
        mode: libc::mode_t,
    ) -> Result<RawFd, ChildMountRootFailureV1> {
        if unsafe { libc::syscall(libc::SYS_mkdirat, parent, name.as_ptr(), mode) } != 0 {
            return Err(child_mount_os_failure_v1());
        }
        child_open_same_mount_directory_at_v1(parent, name)
    }

    fn child_open_same_mount_directory_at_v1(
        parent: RawFd,
        name: &CStr,
    ) -> Result<RawFd, ChildMountRootFailureV1> {
        child_open_directory_at_v1(parent, name, true)
    }

    fn child_open_mounted_directory_at_v1(
        parent: RawFd,
        name: &CStr,
    ) -> Result<RawFd, ChildMountRootFailureV1> {
        child_open_directory_at_v1(parent, name, false)
    }

    fn child_open_directory_at_v1(
        parent: RawFd,
        name: &CStr,
        require_same_mount: bool,
    ) -> Result<RawFd, ChildMountRootFailureV1> {
        let mut resolve = RESOLVE_BENEATH_V1 | RESOLVE_NO_MAGICLINKS_V1 | RESOLVE_NO_SYMLINKS_V1;
        if require_same_mount {
            resolve |= RESOLVE_NO_XDEV_V1;
        }
        let how = OpenHowV1 {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent,
                name.as_ptr(),
                &how,
                std::mem::size_of::<OpenHowV1>(),
            )
        };
        child_checked_fd_v1(result)
    }

    fn child_directory_matches_root_v1(
        identity: &ChildPathIdentityV1,
        root_identity: &ChildPathIdentityV1,
        expected_mode: libc::mode_t,
    ) -> bool {
        u32::from(identity.mode) & libc::S_IFMT == libc::S_IFDIR
            && u32::from(identity.mode) & 0o7777 == expected_mode
            && identity.uid == 0
            && identity.gid == 0
            && identity.mount_id == root_identity.mount_id
    }

    fn child_mount_scratch_v1(
        parent: RawFd,
        pre_target: RawFd,
        name: &CStr,
        absolute_path: &CStr,
        mode: libc::mode_t,
        options: &CStr,
        root_identity: &ChildPathIdentityV1,
    ) -> Result<ChildPathIdentityV1, ChildMountRootFailureV1> {
        let pre_identity = child_path_identity_v1(pre_target)?;
        if !child_directory_matches_root_v1(&pre_identity, root_identity, mode) {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        if unsafe {
            libc::syscall(
                libc::SYS_mount,
                ROOT_TMPFS_TYPE_V1.as_ptr(),
                absolute_path.as_ptr(),
                ROOT_TMPFS_TYPE_V1.as_ptr(),
                SCRATCH_MOUNT_FLAGS_V1,
                options.as_ptr(),
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }
        let mounted = child_open_mounted_directory_at_v1(parent, name)?;
        let identity = child_path_identity_v1(mounted)?;
        if identity.mount_id == pre_identity.mount_id
            || child_device_tuple_v1(&identity) == child_device_tuple_v1(&pre_identity)
            || !child_scratch_matches_policy_v1(mounted, &identity, mode)?
        {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        let pre_target_closed = child_close_mount_fd_v1(pre_target);
        let mounted_closed = child_close_mount_fd_v1(mounted);
        pre_target_closed?;
        mounted_closed?;
        Ok(identity)
    }

    fn child_scratch_matches_policy_v1(
        descriptor: RawFd,
        identity: &ChildPathIdentityV1,
        mode: libc::mode_t,
    ) -> Result<bool, ChildMountRootFailureV1> {
        if u32::from(identity.mode) & libc::S_IFMT != libc::S_IFDIR
            || u32::from(identity.mode) & 0o7777 != mode
            || identity.uid != 0
            || identity.gid != 0
        {
            return Ok(false);
        }
        let filesystem = child_filesystem_status_v1(descriptor)?;
        Ok(child_scratch_statfs_matches_policy_v1(&filesystem))
    }

    fn child_scratch_statfs_matches_policy_v1(filesystem: &libc::statfs64) -> bool {
        if filesystem.f_bsize <= 0 || filesystem.f_flags < 0 {
            return false;
        }
        let required_flags = libc::ST_NODEV | libc::ST_NOSUID | libc::ST_NOEXEC;
        let flags = filesystem.f_flags as u64;
        let bytes = (filesystem.f_bsize as u64).checked_mul(filesystem.f_blocks);
        filesystem.f_type == TMPFS_SUPER_MAGIC_V1
            && flags & required_flags == required_flags
            && flags & libc::ST_RDONLY == 0
            && bytes.is_some_and(|bytes| bytes > 0 && bytes <= SCRATCH_TMPFS_BYTES_V1)
            && filesystem.f_files > 0
            && filesystem.f_files <= SCRATCH_TMPFS_INODES_V1
    }

    fn child_scratch_identities_are_independent_v1(
        tmp: &ChildPathIdentityV1,
        run: &ChildPathIdentityV1,
        again_home: &ChildPathIdentityV1,
    ) -> bool {
        let identities = [tmp, run, again_home];
        for (index, identity) in identities.into_iter().enumerate() {
            let device = child_device_tuple_v1(identity);
            if device == (0, 0) {
                return false;
            }
            for previous in identities.into_iter().take(index) {
                if identity.mount_id == previous.mount_id
                    || device == child_device_tuple_v1(previous)
                {
                    return false;
                }
            }
        }
        true
    }

    const fn child_device_tuple_v1(identity: &ChildPathIdentityV1) -> (u32, u32) {
        (identity.device_major, identity.device_minor)
    }

    fn child_mount_procfs_v1(
        root: RawFd,
        pre_target: RawFd,
        root_identity: &ChildPathIdentityV1,
        active_pid_namespace: &ChildPinnedPidNamespaceV1,
    ) -> Result<ChildPathIdentityV1, ChildMountRootFailureV1> {
        let pre_identity = child_path_identity_v1(pre_target)?;
        if !child_directory_matches_root_v1(&pre_identity, root_identity, PROC_MODE_V1) {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        if unsafe {
            libc::syscall(
                libc::SYS_mount,
                PROC_NAME_V1.as_ptr(),
                PROC_PATH_V1.as_ptr(),
                PROC_NAME_V1.as_ptr(),
                PROC_MOUNT_FLAGS_V1,
                PROCFS_OPTIONS_V1.as_ptr(),
            )
        } != 0
        {
            return Err(child_mount_os_failure_v1());
        }
        let proc_directory = child_open_mounted_directory_at_v1(root, PROC_NAME_V1)?;
        let identity = child_path_identity_v1(proc_directory)?;
        if identity.mount_id == pre_identity.mount_id
            || !child_procfs_matches_policy_v1(proc_directory, &identity)?
            || !child_proc_self_is_pid_one_v1(proc_directory)?
        {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        for absent in PROC_SUBSET_ABSENT_NAMES_V1 {
            child_require_absent_at_v1(proc_directory, absent)?;
        }
        let mounted_pid_namespace = child_pin_proc_pid_namespace_v1(proc_directory)?;
        if mounted_pid_namespace.identity != active_pid_namespace.identity {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        let pre_target_closed = child_close_mount_fd_v1(pre_target);
        let proc_directory_closed = child_close_mount_fd_v1(proc_directory);
        let mounted_pid_namespace_closed =
            child_close_mount_fd_v1(mounted_pid_namespace.descriptor);
        pre_target_closed?;
        proc_directory_closed?;
        mounted_pid_namespace_closed?;
        Ok(identity)
    }

    fn child_procfs_matches_policy_v1(
        descriptor: RawFd,
        identity: &ChildPathIdentityV1,
    ) -> Result<bool, ChildMountRootFailureV1> {
        if u32::from(identity.mode) & libc::S_IFMT != libc::S_IFDIR
            || u32::from(identity.mode) & 0o7777 != PROC_MODE_V1
            || identity.uid != 0
            || identity.gid != 0
        {
            return Ok(false);
        }
        let filesystem = child_filesystem_status_v1(descriptor)?;
        Ok(child_procfs_statfs_matches_policy_v1(&filesystem))
    }

    fn child_procfs_statfs_matches_policy_v1(filesystem: &libc::statfs64) -> bool {
        if filesystem.f_flags < 0 {
            return false;
        }
        let required_flags = libc::ST_RDONLY | libc::ST_NODEV | libc::ST_NOSUID | libc::ST_NOEXEC;
        filesystem.f_type == PROC_SUPER_MAGIC_V1
            && (filesystem.f_flags as u64) & required_flags == required_flags
    }

    fn child_filesystem_status_v1(
        descriptor: RawFd,
    ) -> Result<libc::statfs64, ChildMountRootFailureV1> {
        let mut filesystem = MaybeUninit::<libc::statfs64>::zeroed();
        if unsafe { libc::syscall(libc::SYS_fstatfs, descriptor, filesystem.as_mut_ptr()) } != 0 {
            return Err(child_mount_os_failure_v1());
        }
        Ok(unsafe { filesystem.assume_init() })
    }

    fn child_proc_self_is_pid_one_v1(
        proc_directory: RawFd,
    ) -> Result<bool, ChildMountRootFailureV1> {
        let mut target = [0_u8; 2];
        let result = unsafe {
            libc::syscall(
                libc::SYS_readlinkat,
                proc_directory,
                PROC_SELF_NAME_V1.as_ptr(),
                target.as_mut_ptr(),
                target.len(),
            )
        };
        if result < 0 {
            return Err(child_mount_os_failure_v1());
        }
        Ok(result == 1 && target[0] == b'1')
    }

    fn child_pin_active_pid_namespace_v1()
    -> Result<ChildPinnedPidNamespaceV1, ChildMountRootFailureV1> {
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                ACTIVE_PID_NAMESPACE_PATH_V1.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
                0_u32,
            )
        };
        let descriptor = child_checked_fd_v1(raw)?;
        child_verify_pid_namespace_v1(descriptor)
    }

    fn child_pin_proc_pid_namespace_v1(
        proc_directory: RawFd,
    ) -> Result<ChildPinnedPidNamespaceV1, ChildMountRootFailureV1> {
        let pid_one = child_open_same_mount_directory_at_v1(proc_directory, PROC_PID_ONE_NAME_V1)?;
        let namespace_directory =
            child_open_same_mount_directory_at_v1(pid_one, PROC_NAMESPACE_DIRECTORY_NAME_V1)?;
        // This final fixed component is intentionally a procfs namespace magic
        // link. It is accepted only after immediate nsfs/type/identity proof.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat,
                namespace_directory,
                PID_NAMESPACE_NAME_V1.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
                0_u32,
            )
        };
        let descriptor = child_checked_fd_v1(raw)?;
        let namespace = child_verify_pid_namespace_v1(descriptor)?;
        let pid_one_closed = child_close_mount_fd_v1(pid_one);
        let namespace_directory_closed = child_close_mount_fd_v1(namespace_directory);
        pid_one_closed?;
        namespace_directory_closed?;
        Ok(namespace)
    }

    fn child_verify_pid_namespace_v1(
        descriptor: RawFd,
    ) -> Result<ChildPinnedPidNamespaceV1, ChildMountRootFailureV1> {
        let filesystem = child_filesystem_status_v1(descriptor)?;
        if filesystem.f_type != NSFS_MAGIC_V1 {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        let namespace_type =
            unsafe { libc::syscall(libc::SYS_ioctl, descriptor, NS_GET_NSTYPE_V1, 0_u64) };
        if namespace_type < 0 {
            return Err(child_mount_os_failure_v1());
        }
        if namespace_type != i64::from(libc::CLONE_NEWPID) {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        let mut status = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::syscall(libc::SYS_fstat, descriptor, status.as_mut_ptr()) } != 0 {
            return Err(child_mount_os_failure_v1());
        }
        let status = unsafe { status.assume_init() };
        let identity = NamespaceIdentityV1 {
            device: status.st_dev,
            inode: status.st_ino,
        };
        if identity.device == 0 || identity.inode == 0 {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        Ok(ChildPinnedPidNamespaceV1 {
            descriptor,
            identity,
        })
    }

    fn child_verify_final_mount_layout_v1(
        root_identity: &ChildPathIdentityV1,
        tmp_identity: &ChildPathIdentityV1,
        run_identity: &ChildPathIdentityV1,
        again_home_identity: &ChildPathIdentityV1,
        proc_identity: &ChildPathIdentityV1,
    ) -> Result<(), ChildMountRootFailureV1> {
        let root = child_open_absolute_root_v1()?;
        let observed_root_identity = child_path_identity_v1(root)?;
        if &observed_root_identity != root_identity
            || !child_root_matches_policy_v1(root, root_identity)?
        {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        child_verify_base_directory_v1(root, WORKSPACE_NAME_V1, WORKSPACE_MODE_V1, root_identity)?;
        let home = child_open_same_mount_directory_at_v1(root, HOME_NAME_V1)?;
        if !child_directory_matches_root_v1(
            &child_path_identity_v1(home)?,
            root_identity,
            HOME_MODE_V1,
        ) {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        child_verify_base_directory_v1(root, DEV_NAME_V1, DEV_MODE_V1, root_identity)?;
        child_verify_final_scratch_v1(root, TMP_NAME_V1, TMP_MODE_V1, tmp_identity)?;
        child_verify_final_scratch_v1(root, RUN_NAME_V1, RUN_MODE_V1, run_identity)?;
        child_verify_final_scratch_v1(
            home,
            AGAIN_NAME_V1,
            AGAIN_HOME_MODE_V1,
            again_home_identity,
        )?;
        child_verify_final_procfs_v1(root, proc_identity)?;
        child_require_absent_at_v1(root, OLD_ROOT_NAME_V1)?;
        child_require_absent_at_v1(root, SYS_NAME_V1)?;
        let home_closed = child_close_mount_fd_v1(home);
        let root_closed = child_close_mount_fd_v1(root);
        home_closed?;
        root_closed?;
        Ok(())
    }

    fn child_verify_base_directory_v1(
        root: RawFd,
        name: &CStr,
        mode: libc::mode_t,
        root_identity: &ChildPathIdentityV1,
    ) -> Result<(), ChildMountRootFailureV1> {
        let directory = child_open_same_mount_directory_at_v1(root, name)?;
        let matches = child_directory_matches_root_v1(
            &child_path_identity_v1(directory)?,
            root_identity,
            mode,
        );
        child_close_mount_fd_v1(directory)?;
        if matches {
            Ok(())
        } else {
            Err(ChildMountRootFailureV1::Invariant)
        }
    }

    fn child_verify_final_scratch_v1(
        parent: RawFd,
        name: &CStr,
        mode: libc::mode_t,
        expected: &ChildPathIdentityV1,
    ) -> Result<(), ChildMountRootFailureV1> {
        let directory = child_open_mounted_directory_at_v1(parent, name)?;
        let identity = child_path_identity_v1(directory)?;
        let matches =
            &identity == expected && child_scratch_matches_policy_v1(directory, &identity, mode)?;
        child_close_mount_fd_v1(directory)?;
        if matches {
            Ok(())
        } else {
            Err(ChildMountRootFailureV1::Invariant)
        }
    }

    fn child_verify_final_procfs_v1(
        root: RawFd,
        expected: &ChildPathIdentityV1,
    ) -> Result<(), ChildMountRootFailureV1> {
        let proc_directory = child_open_mounted_directory_at_v1(root, PROC_NAME_V1)?;
        let identity = child_path_identity_v1(proc_directory)?;
        let matches = &identity == expected
            && child_procfs_matches_policy_v1(proc_directory, &identity)?
            && child_proc_self_is_pid_one_v1(proc_directory)?;
        if matches {
            for absent in PROC_SUBSET_ABSENT_NAMES_V1 {
                child_require_absent_at_v1(proc_directory, absent)?;
            }
        }
        child_close_mount_fd_v1(proc_directory)?;
        if matches {
            Ok(())
        } else {
            Err(ChildMountRootFailureV1::Invariant)
        }
    }

    fn child_require_absent_at_v1(
        directory: RawFd,
        path: &CStr,
    ) -> Result<(), ChildMountRootFailureV1> {
        let how = OpenHowV1 {
            flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH_V1 | RESOLVE_NO_MAGICLINKS_V1 | RESOLVE_NO_SYMLINKS_V1,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory,
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHowV1>(),
            )
        };
        if result >= 0 {
            if let Ok(fd) = i32::try_from(result) {
                let _ = child_close(fd);
            }
            return Err(ChildMountRootFailureV1::Invariant);
        }
        if child_errno() == libc::ENOENT {
            Ok(())
        } else {
            Err(child_mount_os_failure_v1())
        }
    }

    fn child_mount_os_failure_v1() -> ChildMountRootFailureV1 {
        let errno = child_errno();
        if (1..=MAX_LINUX_ERRNO_V1).contains(&errno) {
            ChildMountRootFailureV1::Os(errno)
        } else {
            ChildMountRootFailureV1::Invariant
        }
    }

    fn child_close_mount_fd_v1(descriptor: RawFd) -> Result<(), ChildMountRootFailureV1> {
        if descriptor < 0 {
            return Err(ChildMountRootFailureV1::Invariant);
        }
        let result = unsafe { libc::syscall(libc::SYS_close, descriptor) };
        if result == 0 || (result < 0 && child_errno() == libc::EINTR) {
            Ok(())
        } else {
            Err(child_mount_os_failure_v1())
        }
    }

    fn child_report_descriptor_identity_v1(
        descriptor: RawFd,
    ) -> Result<ChildReportDescriptorIdentityV1, ChildDescriptorFailureV1> {
        if descriptor < 0 {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        let mut status = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::syscall(libc::SYS_fstat, descriptor, status.as_mut_ptr()) } != 0 {
            return Err(child_descriptor_os_failure_v1());
        }
        let status = unsafe { status.assume_init() };
        let descriptor_flags =
            unsafe { libc::syscall(libc::SYS_fcntl, descriptor, libc::F_GETFD, 0_u64) };
        if descriptor_flags < 0 {
            return Err(child_descriptor_os_failure_v1());
        }
        let status_flags =
            unsafe { libc::syscall(libc::SYS_fcntl, descriptor, libc::F_GETFL, 0_u64) };
        if status_flags < 0 {
            return Err(child_descriptor_os_failure_v1());
        }
        if status.st_dev == 0
            || status.st_ino == 0
            || status.st_mode & libc::S_IFMT != libc::S_IFIFO
            || descriptor_flags != libc::c_long::from(libc::FD_CLOEXEC)
            || status_flags & libc::c_long::from(libc::O_ACCMODE)
                != libc::c_long::from(libc::O_WRONLY)
            || status_flags & libc::c_long::from(libc::O_NONBLOCK) == 0
        {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        Ok(ChildReportDescriptorIdentityV1 {
            device: status.st_dev,
            inode: status.st_ino,
            mode: status.st_mode,
            status_flags,
        })
    }

    fn child_scrub_and_audit_descriptors_v1(
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildDescriptorFailureV1> {
        child_close_range_and_reauthenticate_v1(report_identity)?;

        let audit_descriptor = child_open_fd_audit_v1()?;
        child_verify_and_close_fd_audit_v1(audit_descriptor, report_identity)
    }

    fn child_open_fd_audit_v1() -> Result<RawFd, ChildDescriptorFailureV1> {
        let how = OpenHowV1 {
            flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH_V1 | RESOLVE_NO_MAGICLINKS_V1 | RESOLVE_NO_SYMLINKS_V1,
        };
        let audit_result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                PROC_FD_AUDIT_PATH_V1.as_ptr(),
                &how,
                std::mem::size_of::<OpenHowV1>(),
            )
        };
        if audit_result < 0 {
            return Err(child_descriptor_os_failure_v1());
        }
        if audit_result != libc::c_long::from(FD_AUDIT_DESCRIPTOR_V1) {
            if let Ok(descriptor) = RawFd::try_from(audit_result)
                && descriptor > FD_AUDIT_DESCRIPTOR_V1
            {
                let _ = child_close(descriptor);
            }
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        Ok(FD_AUDIT_DESCRIPTOR_V1)
    }

    fn child_close_range_and_reauthenticate_v1(
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildDescriptorFailureV1> {
        let close_result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                CLOSE_RANGE_FIRST_V1,
                CLOSE_RANGE_LAST_V1,
                libc::CLOSE_RANGE_UNSHARE,
            )
        };
        if close_result < 0 {
            let errno = child_errno();
            return Err(if (1..=MAX_LINUX_ERRNO_V1).contains(&errno) {
                ChildDescriptorFailureV1::CloseRange(errno)
            } else {
                ChildDescriptorFailureV1::Invariant
            });
        }
        if close_result != 0
            || child_report_descriptor_identity_v1(REPORT_DESCRIPTOR_V1)? != *report_identity
        {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        Ok(())
    }

    fn child_verify_and_close_fd_audit_v1(
        audit_descriptor: RawFd,
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildDescriptorFailureV1> {
        child_authenticate_fd_audit_v1(audit_descriptor)?;
        child_finish_fd_audit_v1(audit_descriptor, report_identity)
    }

    fn child_authenticate_fd_audit_v1(
        audit_descriptor: RawFd,
    ) -> Result<(), ChildDescriptorFailureV1> {
        if audit_descriptor != FD_AUDIT_DESCRIPTOR_V1 {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        let descriptor_flags =
            unsafe { libc::syscall(libc::SYS_fcntl, audit_descriptor, libc::F_GETFD, 0_u64) };
        if descriptor_flags < 0 {
            return Err(child_descriptor_os_failure_v1());
        }
        if descriptor_flags != libc::c_long::from(libc::FD_CLOEXEC) {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        let mut status = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::syscall(libc::SYS_fstat, audit_descriptor, status.as_mut_ptr()) } != 0 {
            return Err(child_descriptor_os_failure_v1());
        }
        let status = unsafe { status.assume_init() };
        if status.st_dev == 0
            || status.st_ino == 0
            || status.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        let mut filesystem = MaybeUninit::<libc::statfs64>::zeroed();
        if unsafe { libc::syscall(libc::SYS_fstatfs, audit_descriptor, filesystem.as_mut_ptr()) }
            != 0
        {
            return Err(child_descriptor_os_failure_v1());
        }
        if !child_procfs_statfs_matches_policy_v1(&unsafe { filesystem.assume_init() }) {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        Ok(())
    }

    fn child_finish_fd_audit_v1(
        audit_descriptor: RawFd,
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildDescriptorFailureV1> {
        if audit_descriptor != FD_AUDIT_DESCRIPTOR_V1 {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        let mut buffer = [0_u8; FD_AUDIT_BUFFER_BYTES_V1];
        let mut seen = 0_u8;
        let mut reached_eof = false;
        for _ in 0..FD_AUDIT_MAX_GETDENTS_CALLS_V1 {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    audit_descriptor,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if count == 0 {
                reached_eof = true;
                break;
            }
            if count < 0 {
                let errno = child_errno();
                if errno == libc::EINTR {
                    continue;
                }
                return Err(child_descriptor_failure_from_errno_v1(errno));
            }
            let Ok(count) = usize::try_from(count) else {
                return Err(ChildDescriptorFailureV1::Invariant);
            };
            if count > buffer.len() || !child_parse_fd_audit_dirents_v1(&buffer[..count], &mut seen)
            {
                return Err(ChildDescriptorFailureV1::Invariant);
            }
        }
        if !reached_eof || seen != FD_AUDIT_COMPLETE_MASK_V1 {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        if !child_close(audit_descriptor) {
            return Err(child_descriptor_os_failure_v1());
        }
        let closed =
            unsafe { libc::syscall(libc::SYS_fcntl, audit_descriptor, libc::F_GETFD, 0_u64) };
        if closed >= 0 {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        let errno = child_errno();
        if errno != libc::EBADF {
            return Err(child_descriptor_failure_from_errno_v1(errno));
        }
        if child_report_descriptor_identity_v1(REPORT_DESCRIPTOR_V1)? != *report_identity {
            return Err(ChildDescriptorFailureV1::Invariant);
        }
        Ok(())
    }

    fn child_parse_fd_audit_dirents_v1(bytes: &[u8], seen: &mut u8) -> bool {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            if remaining.len() < DIRENT64_MIN_RECORD_BYTES_V1 {
                return false;
            }
            let record_length = usize::from(u16::from_ne_bytes([remaining[16], remaining[17]]));
            if record_length < DIRENT64_MIN_RECORD_BYTES_V1
                || record_length % DIRENT64_ALIGNMENT_V1 != 0
                || record_length > remaining.len()
            {
                return false;
            }
            let name_field = &remaining[DIRENT64_NAME_OFFSET_V1..record_length];
            let Some(terminator) = name_field.iter().position(|byte| *byte == 0) else {
                return false;
            };
            let bit = match &name_field[..terminator] {
                b"." => FD_AUDIT_DOT_BIT_V1,
                b".." => FD_AUDIT_DOT_DOT_BIT_V1,
                b"0" => FD_AUDIT_ZERO_BIT_V1,
                b"1" => FD_AUDIT_ONE_BIT_V1,
                _ => return false,
            };
            if *seen & bit != 0 {
                return false;
            }
            *seen |= bit;
            let Some(next) = offset.checked_add(record_length) else {
                return false;
            };
            offset = next;
        }
        true
    }

    fn child_eliminate_capabilities_v1(
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<u32, ChildCapabilityFailureV1> {
        let initial_bounding = child_read_bounding_capabilities_v1()?;
        let Some(last_capability) = child_last_capability_v1(&initial_bounding) else {
            return Err(ChildCapabilityFailureV1::Invariant);
        };
        let initial_sets = child_read_capability_sets_v1()?;
        if !child_capability_sets_are_admissible_v1(&initial_sets, last_capability) {
            return Err(ChildCapabilityFailureV1::Invariant);
        }

        child_set_and_verify_securebits_v1()?;
        child_drop_bounding_capabilities_v1(last_capability)?;
        child_clear_ambient_capabilities_v1()?;
        let cleared_ambient = child_read_ambient_capabilities_v1()?;
        if !child_empty_capability_scan_matches_v1(&cleared_ambient, last_capability) {
            return Err(ChildCapabilityFailureV1::Invariant);
        }
        child_clear_capability_sets_v1()?;
        child_set_no_new_privileges_v1()?;

        child_verify_capability_elimination_v1(last_capability, report_identity)?;
        Ok(last_capability)
    }

    fn child_verify_capability_elimination_v1(
        last_capability: u32,
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildCapabilityFailureV1> {
        let final_sets = child_read_capability_sets_v1()?;
        if !child_capability_sets_are_empty_v1(&final_sets) {
            return Err(ChildCapabilityFailureV1::Invariant);
        }
        let final_bounding = child_read_bounding_capabilities_v1()?;
        if !child_empty_capability_scan_matches_v1(&final_bounding, last_capability) {
            return Err(ChildCapabilityFailureV1::Invariant);
        }
        let final_ambient = child_read_ambient_capabilities_v1()?;
        if !child_empty_capability_scan_matches_v1(&final_ambient, last_capability) {
            return Err(ChildCapabilityFailureV1::Invariant);
        }
        child_verify_securebits_v1()?;
        child_verify_no_new_privileges_v1()?;
        child_reauthenticate_capability_report_v1(report_identity)
    }

    fn child_enforce_landlock_v1(
        private_root: &ChildPrivateRootEvidenceV1,
        last_capability: u32,
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let mut tracked = ChildLandlockTrackedFdsV1::new();
        let result = child_enforce_landlock_inner_v1(
            private_root,
            last_capability,
            report_identity,
            &mut tracked,
        );
        let cleanup = child_landlock_cleanup_fds_v1(&mut tracked, report_identity);
        cleanup?;
        result
    }

    fn child_enforce_landlock_inner_v1(
        private_root: &ChildPrivateRootEvidenceV1,
        last_capability: u32,
        report_identity: &ChildReportDescriptorIdentityV1,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let audit_descriptor =
            child_open_fd_audit_v1().map_err(child_landlock_from_descriptor_failure_v1)?;
        tracked.audit_descriptor = audit_descriptor;
        child_authenticate_fd_audit_v1(audit_descriptor)
            .map_err(child_landlock_from_descriptor_failure_v1)?;

        child_landlock_reopen_identity_v1(CURRENT_DIRECTORY_V1, &private_root.root, tracked)?;
        child_landlock_reopen_identity_v1(TMP_NAME_V1, &private_root.tmp, tracked)?;
        child_landlock_reopen_identity_v1(RUN_NAME_V1, &private_root.run, tracked)?;
        child_landlock_reopen_identity_v1(PROC_NAME_V1, &private_root.proc, tracked)?;

        let policy = child_landlock_query_policy_v1()?;
        let restricted_identity = child_landlock_create_fixtures_v1(private_root, tracked)?;
        let ruleset = child_landlock_create_ruleset_v1(tracked)?;
        child_landlock_add_path_rule_v1(
            ruleset,
            TMP_NAME_V1,
            LANDLOCK_TMP_ACCESS_V1,
            &private_root.tmp,
            tracked,
        )?;
        child_landlock_add_path_rule_v1(
            ruleset,
            RUN_RESTRICTED_RELATIVE_PATH_V1,
            LANDLOCK_RESTRICTED_ACCESS_V1,
            &restricted_identity,
            tracked,
        )?;
        child_verify_capability_elimination_v1(last_capability, report_identity)
            .map_err(child_landlock_from_capability_failure_v1)?;
        child_landlock_restrict_self_v1(ruleset, policy)?;
        child_landlock_close_tracked_fd_v1(tracked, ruleset)?;

        child_landlock_run_canaries_v1(tracked)?;
        if tracked
            .descriptors
            .iter()
            .any(|descriptor| *descriptor != -1)
        {
            Err(ChildLandlockFailureV1::Invariant)
        } else {
            Ok(())
        }
    }

    fn child_landlock_query_policy_v1() -> Result<ChildLandlockPolicyV1, ChildLandlockFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<LinuxLandlockRulesetAttrV1>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION_V1,
            )
        };
        let errno = if result == -1 { child_errno() } else { 0 };
        child_landlock_policy_from_version_result_v1(result, errno)
    }

    fn child_landlock_policy_from_version_result_v1(
        result: libc::c_long,
        errno: i32,
    ) -> Result<ChildLandlockPolicyV1, ChildLandlockFailureV1> {
        match result {
            1..=5 if errno == 0 => Err(ChildLandlockFailureV1::Unavailable(0)),
            6 if errno == 0 => Ok(ChildLandlockPolicyV1::Abi6),
            7..=LANDLOCK_ABI_MAX_V1 if errno == 0 => Ok(ChildLandlockPolicyV1::Abi7OrNewer),
            -1 if matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP) => {
                Err(ChildLandlockFailureV1::Unavailable(errno))
            }
            -1 => Err(child_landlock_failure_from_errno_v1(errno)),
            _ => Err(ChildLandlockFailureV1::Invariant),
        }
    }

    const fn child_landlock_restrict_flags_v1(policy: ChildLandlockPolicyV1) -> u32 {
        match policy {
            ChildLandlockPolicyV1::Abi6 => 0,
            ChildLandlockPolicyV1::Abi7OrNewer => LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF_V1,
        }
    }

    fn child_landlock_reopen_identity_v1(
        path: &CStr,
        expected: &ChildPathIdentityV1,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let descriptor = child_landlock_open_fixed_directory_v1(path, tracked)?;
        let observed =
            child_path_identity_v1(descriptor).map_err(child_landlock_from_mount_failure_v1)?;
        if observed != *expected {
            return Err(ChildLandlockFailureV1::Invariant);
        }
        child_landlock_close_tracked_fd_v1(tracked, descriptor)
    }

    fn child_landlock_open_fixed_directory_v1(
        path: &CStr,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<RawFd, ChildLandlockFailureV1> {
        let how = OpenHowV1 {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH_V1 | RESOLVE_NO_MAGICLINKS_V1 | RESOLVE_NO_SYMLINKS_V1,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHowV1>(),
            )
        };
        child_landlock_register_fd_result_v1(tracked, result)
    }

    fn child_landlock_create_fixtures_v1(
        private_root: &ChildPrivateRootEvidenceV1,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<ChildPathIdentityV1, ChildLandlockFailureV1> {
        child_landlock_require_zero_result_v1(unsafe {
            libc::syscall(
                libc::SYS_mkdirat,
                libc::AT_FDCWD,
                RUN_RESTRICTED_PATH_V1.as_ptr(),
                0o700_u32,
            )
        })?;
        for path in [
            c"/tmp/from",
            c"/tmp/to",
            c"/run/restricted/from",
            c"/run/restricted/to",
        ] {
            child_landlock_require_zero_result_v1(unsafe {
                libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, path.as_ptr(), 0o700_u32)
            })?;
        }
        for path in [
            WORKSPACE_FIXTURE_PATH_V1,
            TMP_PREEXISTING_PATH_V1,
            TMP_FROM_ITEM_PATH_V1,
            RUN_RESTRICTED_PREEXISTING_PATH_V1,
            RUN_RESTRICTED_FROM_ITEM_PATH_V1,
        ] {
            child_landlock_create_fixture_file_v1(path, tracked)?;
        }

        let restricted =
            child_landlock_open_fixed_directory_v1(RUN_RESTRICTED_RELATIVE_PATH_V1, tracked)?;
        let identity =
            child_path_identity_v1(restricted).map_err(child_landlock_from_mount_failure_v1)?;
        if u32::from(identity.mode) & libc::S_IFMT != libc::S_IFDIR
            || u32::from(identity.mode) & 0o7777 != 0o700
            || identity.uid != 0
            || identity.gid != 0
            || identity.mount_id != private_root.run.mount_id
            || child_device_tuple_v1(&identity) != child_device_tuple_v1(&private_root.run)
        {
            return Err(ChildLandlockFailureV1::Invariant);
        }
        child_landlock_close_tracked_fd_v1(tracked, restricted)?;
        Ok(identity)
    }

    fn child_landlock_create_fixture_file_v1(
        path: &CStr,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let descriptor = child_landlock_open_tracked_v1(
            path,
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
            tracked,
        )?;
        child_landlock_write_exact_v1(descriptor, LANDLOCK_CANARY_BYTES_V1)?;
        child_landlock_close_tracked_fd_v1(tracked, descriptor)
    }

    fn child_landlock_create_ruleset_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<RawFd, ChildLandlockFailureV1> {
        let attributes = LinuxLandlockRulesetAttrV1 {
            handled_access_fs: LANDLOCK_HANDLED_FS_V1,
            handled_access_net: LANDLOCK_HANDLED_NET_V1,
            scoped: LANDLOCK_SCOPED_V1,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attributes,
                std::mem::size_of::<LinuxLandlockRulesetAttrV1>(),
                0_u32,
            )
        };
        child_landlock_register_fd_result_v1(tracked, result)
    }

    fn child_landlock_add_path_rule_v1(
        ruleset: RawFd,
        path: &CStr,
        allowed_access: u64,
        expected: &ChildPathIdentityV1,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let parent = child_landlock_open_fixed_directory_v1(path, tracked)?;
        let observed =
            child_path_identity_v1(parent).map_err(child_landlock_from_mount_failure_v1)?;
        if observed != *expected {
            return Err(ChildLandlockFailureV1::Invariant);
        }
        let attributes = LinuxLandlockPathBeneathAttrV1 {
            allowed_access,
            parent_fd: parent,
        };
        let add_result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH_V1,
                &attributes,
                0_u32,
            )
        };
        child_landlock_require_zero_result_v1(add_result)?;
        child_landlock_close_tracked_fd_v1(tracked, parent)
    }

    fn child_landlock_restrict_self_v1(
        ruleset: RawFd,
        policy: ChildLandlockPolicyV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                ruleset,
                child_landlock_restrict_flags_v1(policy),
            )
        };
        child_landlock_require_zero_result_v1(result)
    }

    fn child_landlock_run_canaries_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        child_landlock_run_tmp_canaries_v1(tracked)?;
        child_landlock_run_restricted_canaries_v1(tracked)?;
        child_landlock_run_workspace_canaries_v1(tracked)?;
        child_landlock_run_tcp_canaries_v1(tracked)
    }

    fn child_landlock_run_tmp_canaries_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let created = child_landlock_open_tracked_v1(
            TMP_NEW_PATH_V1,
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
            tracked,
        )?;
        child_landlock_write_exact_v1(created, LANDLOCK_CANARY_BYTES_V1)?;
        child_landlock_require_zero_result_v1(unsafe {
            libc::syscall(libc::SYS_ftruncate, created, 1_i64)
        })?;
        child_landlock_close_tracked_fd_v1(tracked, created)?;

        let truncated = child_landlock_open_tracked_v1(
            TMP_PREEXISTING_PATH_V1,
            libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
            tracked,
        )?;
        child_landlock_require_zero_result_v1(unsafe {
            libc::syscall(libc::SYS_ftruncate, truncated, 2_i64)
        })?;
        child_landlock_close_tracked_fd_v1(tracked, truncated)?;

        child_landlock_require_zero_result_v1(unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                TMP_FROM_ITEM_PATH_V1.as_ptr(),
                libc::AT_FDCWD,
                TMP_TO_ITEM_PATH_V1.as_ptr(),
                0_u32,
            )
        })
    }

    fn child_landlock_run_restricted_canaries_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let descriptor = child_landlock_open_tracked_v1(
            RUN_RESTRICTED_PREEXISTING_PATH_V1,
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
            tracked,
        )?;
        child_landlock_require_errno_result_v1(
            unsafe { libc::syscall(libc::SYS_ftruncate, descriptor, 0_i64) },
            libc::EACCES,
        )?;
        child_landlock_close_tracked_fd_v1(tracked, descriptor)?;
        child_landlock_require_errno_result_v1(
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    RUN_RESTRICTED_FROM_ITEM_PATH_V1.as_ptr(),
                    libc::AT_FDCWD,
                    RUN_RESTRICTED_TO_ITEM_PATH_V1.as_ptr(),
                    0_u32,
                )
            },
            libc::EXDEV,
        )
    }

    fn child_landlock_run_workspace_canaries_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        child_landlock_require_open_errno_v1(
            WORKSPACE_FIXTURE_PATH_V1,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            libc::EACCES,
            tracked,
        )?;
        child_landlock_require_open_errno_v1(
            WORKSPACE_PATH_V1,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            libc::EACCES,
            tracked,
        )
    }

    fn child_landlock_run_tcp_canaries_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let bind_socket = child_landlock_open_tcp_socket_v1(tracked)?;
        let bind_address = child_landlock_loopback_address_v1(0);
        child_landlock_require_errno_result_v1(
            unsafe {
                libc::syscall(
                    libc::SYS_bind,
                    bind_socket,
                    &bind_address as *const libc::sockaddr_in,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            },
            libc::EACCES,
        )?;
        child_landlock_close_tracked_fd_v1(tracked, bind_socket)?;

        let connect_socket = child_landlock_open_tcp_socket_v1(tracked)?;
        let connect_address = child_landlock_loopback_address_v1(1);
        child_landlock_require_errno_result_v1(
            unsafe {
                libc::syscall(
                    libc::SYS_connect,
                    connect_socket,
                    &connect_address as *const libc::sockaddr_in,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            },
            libc::EACCES,
        )?;
        child_landlock_close_tracked_fd_v1(tracked, connect_socket)
    }

    fn child_landlock_open_tracked_v1(
        path: &CStr,
        flags: libc::c_int,
        mode: libc::mode_t,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<RawFd, ChildLandlockFailureV1> {
        let result =
            unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path.as_ptr(), flags, mode) };
        child_landlock_register_fd_result_v1(tracked, result)
    }

    fn child_landlock_require_open_errno_v1(
        path: &CStr,
        flags: libc::c_int,
        expected_errno: i32,
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                path.as_ptr(),
                flags,
                0_u32,
            )
        };
        if result == -1 {
            return child_landlock_require_errno_result_v1(result, expected_errno);
        }
        child_landlock_register_fd_result_v1(tracked, result)?;
        Err(ChildLandlockFailureV1::Invariant)
    }

    fn child_landlock_open_tcp_socket_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
    ) -> Result<RawFd, ChildLandlockFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_socket,
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            )
        };
        child_landlock_register_fd_result_v1(tracked, result)
    }

    fn child_landlock_loopback_address_v1(port: u16) -> libc::sockaddr_in {
        let mut address = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        address.sin_port = port.to_be();
        address.sin_addr = libc::in_addr {
            s_addr: u32::from_be(0x7f00_0001),
        };
        address
    }

    fn child_landlock_require_errno_result_v1(
        result: libc::c_long,
        expected_errno: i32,
    ) -> Result<(), ChildLandlockFailureV1> {
        let errno = if result == -1 { child_errno() } else { 0 };
        child_landlock_require_errno_result_with_errno_v1(result, errno, expected_errno)
    }

    fn child_landlock_require_errno_result_with_errno_v1(
        result: libc::c_long,
        errno: i32,
        expected_errno: i32,
    ) -> Result<(), ChildLandlockFailureV1> {
        if !(1..=MAX_LINUX_ERRNO_V1).contains(&expected_errno) {
            return Err(ChildLandlockFailureV1::Invariant);
        }
        match (result, errno) {
            (-1, observed) if observed == expected_errno => Ok(()),
            (-1, observed) => Err(child_landlock_failure_from_errno_v1(observed)),
            _ => Err(ChildLandlockFailureV1::Invariant),
        }
    }

    fn child_landlock_write_exact_v1(
        descriptor: RawFd,
        bytes: &[u8],
    ) -> Result<(), ChildLandlockFailureV1> {
        let result =
            unsafe { libc::syscall(libc::SYS_write, descriptor, bytes.as_ptr(), bytes.len()) };
        if result == bytes.len() as libc::c_long {
            Ok(())
        } else if result == -1 {
            Err(child_landlock_os_failure_v1())
        } else {
            Err(ChildLandlockFailureV1::Invariant)
        }
    }

    fn child_landlock_register_fd_result_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
        result: libc::c_long,
    ) -> Result<RawFd, ChildLandlockFailureV1> {
        if result == -1 {
            return Err(child_landlock_os_failure_v1());
        }
        let Ok(descriptor) = RawFd::try_from(result) else {
            return Err(ChildLandlockFailureV1::Invariant);
        };
        let Some(index) = child_landlock_tracker_next_slot_v1(tracked) else {
            if descriptor >= LANDLOCK_FIRST_TRANSIENT_FD_V1
                && let Some(slot) = tracked.descriptors.iter_mut().find(|slot| **slot == -1)
            {
                *slot = descriptor;
            } else if descriptor >= LANDLOCK_FIRST_TRANSIENT_FD_V1
                && let Err(error) = child_landlock_close_untracked_fd_v1(descriptor)
            {
                return Err(error);
            }
            return Err(ChildLandlockFailureV1::Invariant);
        };
        if index == LANDLOCK_MAX_TRACKED_FDS_V1 {
            return match child_landlock_close_untracked_fd_v1(descriptor) {
                Ok(()) => Err(ChildLandlockFailureV1::Invariant),
                Err(error) => Err(error),
            };
        }
        let expected = LANDLOCK_FIRST_TRANSIENT_FD_V1 + index as RawFd;
        let Some(slot) = tracked.descriptors.get_mut(index) else {
            return Err(ChildLandlockFailureV1::Invariant);
        };
        if descriptor >= LANDLOCK_FIRST_TRANSIENT_FD_V1 {
            *slot = descriptor;
        }
        if descriptor != expected {
            return Err(ChildLandlockFailureV1::Invariant);
        }
        Ok(descriptor)
    }

    fn child_landlock_tracker_next_slot_v1(tracked: &ChildLandlockTrackedFdsV1) -> Option<usize> {
        let mut next = LANDLOCK_MAX_TRACKED_FDS_V1;
        let mut observed_empty = false;
        for (index, descriptor) in tracked.descriptors.iter().copied().enumerate() {
            if descriptor == -1 {
                if !observed_empty {
                    next = index;
                }
                observed_empty = true;
            } else if observed_empty
                || descriptor != LANDLOCK_FIRST_TRANSIENT_FD_V1 + index as RawFd
            {
                return None;
            }
        }
        Some(next)
    }

    fn child_landlock_close_tracked_fd_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
        descriptor: RawFd,
    ) -> Result<(), ChildLandlockFailureV1> {
        let Some(slot) = tracked
            .descriptors
            .iter_mut()
            .find(|slot| **slot == descriptor)
        else {
            return Err(ChildLandlockFailureV1::Invariant);
        };
        let result = child_landlock_close_known_fd_v1(descriptor, false);
        if result.is_ok() {
            *slot = -1;
        }
        result
    }

    fn child_landlock_close_untracked_fd_v1(
        descriptor: RawFd,
    ) -> Result<(), ChildLandlockFailureV1> {
        if descriptor < LANDLOCK_FIRST_TRANSIENT_FD_V1 {
            return Err(ChildLandlockFailureV1::Invariant);
        }
        child_landlock_close_known_fd_v1(descriptor, false)
    }

    fn child_landlock_close_known_fd_v1(
        descriptor: RawFd,
        cleanup: bool,
    ) -> Result<(), ChildLandlockFailureV1> {
        let close_result = unsafe { libc::syscall(libc::SYS_close, descriptor) };
        let close_errno = if close_result == -1 { child_errno() } else { 0 };
        child_landlock_close_result_v1(close_result, close_errno, cleanup)
    }

    fn child_landlock_close_result_v1(
        result: libc::c_long,
        errno: i32,
        cleanup: bool,
    ) -> Result<(), ChildLandlockFailureV1> {
        match (result, errno) {
            (0, _) | (-1, libc::EINTR) => Ok(()),
            (-1, libc::EBADF) if cleanup => Ok(()),
            (-1, errno) => Err(child_landlock_failure_from_errno_v1(errno)),
            _ => Err(ChildLandlockFailureV1::Invariant),
        }
    }

    fn child_landlock_cleanup_fds_v1(
        tracked: &mut ChildLandlockTrackedFdsV1,
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildLandlockFailureV1> {
        let mut first_failure = child_landlock_tracker_next_slot_v1(tracked)
            .is_none()
            .then_some(ChildLandlockFailureV1::Invariant);
        let mut index = 0_usize;
        while index < LANDLOCK_MAX_TRACKED_FDS_V1 {
            let descriptor = tracked.descriptors[index];
            if descriptor >= LANDLOCK_FIRST_TRANSIENT_FD_V1 {
                if let Err(error) = child_landlock_close_known_fd_v1(descriptor, true)
                    && first_failure.is_none()
                {
                    first_failure = Some(error);
                }
            } else if descriptor != -1 && first_failure.is_none() {
                first_failure = Some(ChildLandlockFailureV1::Invariant);
            }
            tracked.descriptors[index] = -1;
            index += 1;
        }
        let exact_audit_ran = tracked.audit_descriptor == FD_AUDIT_DESCRIPTOR_V1;
        if exact_audit_ran {
            if let Err(error) = child_finish_fd_audit_v1(tracked.audit_descriptor, report_identity)
                .map_err(child_landlock_from_descriptor_failure_v1)
            {
                if first_failure.is_none() {
                    first_failure = Some(error);
                }
                if let Err(close_error) =
                    child_landlock_close_known_fd_v1(tracked.audit_descriptor, true)
                    && first_failure.is_none()
                {
                    first_failure = Some(close_error);
                }
            }
        } else if tracked.audit_descriptor > REPORT_DESCRIPTOR_V1 {
            if let Err(error) = child_landlock_close_known_fd_v1(tracked.audit_descriptor, true)
                && first_failure.is_none()
            {
                first_failure = Some(error);
            } else if first_failure.is_none() {
                first_failure = Some(ChildLandlockFailureV1::Invariant);
            }
        } else if tracked.audit_descriptor != -1 && first_failure.is_none() {
            first_failure = Some(ChildLandlockFailureV1::Invariant);
        }
        tracked.audit_descriptor = -1;
        if !exact_audit_ran
            && let Err(error) = child_reauthenticate_capability_report_v1(report_identity)
                .map_err(child_landlock_from_capability_failure_v1)
            && first_failure.is_none()
        {
            first_failure = Some(error);
        }
        match first_failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn child_landlock_require_zero_result_v1(
        result: libc::c_long,
    ) -> Result<(), ChildLandlockFailureV1> {
        let errno = if result == -1 { child_errno() } else { 0 };
        match (result, errno) {
            (0, _) => Ok(()),
            (-1, errno) => Err(child_landlock_failure_from_errno_v1(errno)),
            _ => Err(ChildLandlockFailureV1::Invariant),
        }
    }

    fn child_landlock_from_mount_failure_v1(
        failure: ChildMountRootFailureV1,
    ) -> ChildLandlockFailureV1 {
        match failure {
            ChildMountRootFailureV1::Os(errno) => child_landlock_failure_from_errno_v1(errno),
            ChildMountRootFailureV1::Invariant => ChildLandlockFailureV1::Invariant,
        }
    }

    fn child_landlock_from_descriptor_failure_v1(
        failure: ChildDescriptorFailureV1,
    ) -> ChildLandlockFailureV1 {
        match failure {
            ChildDescriptorFailureV1::CloseRange(errno) | ChildDescriptorFailureV1::Os(errno) => {
                child_landlock_failure_from_errno_v1(errno)
            }
            ChildDescriptorFailureV1::Invariant => ChildLandlockFailureV1::Invariant,
        }
    }

    fn child_landlock_from_capability_failure_v1(
        failure: ChildCapabilityFailureV1,
    ) -> ChildLandlockFailureV1 {
        match failure {
            ChildCapabilityFailureV1::Os(errno) => child_landlock_failure_from_errno_v1(errno),
            ChildCapabilityFailureV1::Invariant => ChildLandlockFailureV1::Invariant,
        }
    }

    fn child_landlock_os_failure_v1() -> ChildLandlockFailureV1 {
        child_landlock_failure_from_errno_v1(child_errno())
    }

    fn child_landlock_failure_from_errno_v1(errno: i32) -> ChildLandlockFailureV1 {
        if (1..=MAX_LINUX_ERRNO_V1).contains(&errno) {
            ChildLandlockFailureV1::Os(errno)
        } else {
            ChildLandlockFailureV1::Invariant
        }
    }

    fn child_enforce_seccomp_v1(
        report_identity: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildSeccompFailureV1> {
        child_reauthenticate_capability_report_v1(report_identity)
            .map_err(child_seccomp_from_capability_failure_v1)?;
        child_verify_no_new_privileges_v1().map_err(child_seccomp_from_capability_failure_v1)?;
        child_seccomp_require_preinstall_mode_v1()?;
        child_seccomp_query_action_v1(SECCOMP_RET_ERRNO_V1)?;
        child_seccomp_query_action_v1(SECCOMP_RET_KILL_PROCESS_V1)?;
        child_seccomp_install_filter_v1()?;
        child_seccomp_require_postinstall_state_v1()?;
        child_seccomp_run_canaries_v1()
    }

    fn child_seccomp_require_preinstall_mode_v1() -> Result<(), ChildSeccompFailureV1> {
        let result = child_seccomp_read_mode_v1();
        let errno = if result == -1 { child_errno() } else { 0 };
        child_seccomp_exact_result_with_errno_v1(result, errno, SECCOMP_MODE_DISABLED_V1)
    }

    fn child_seccomp_query_action_v1(action: u32) -> Result<(), ChildSeccompFailureV1> {
        let mut observed = action;
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_GET_ACTION_AVAIL_V1,
                0_u32,
                &mut observed,
            )
        };
        let errno = if result == -1 { child_errno() } else { 0 };
        child_seccomp_action_query_result_with_errno_v1(result, errno, observed, action)
    }

    fn child_seccomp_action_query_result_with_errno_v1(
        result: libc::c_long,
        errno: i32,
        observed: u32,
        expected: u32,
    ) -> Result<(), ChildSeccompFailureV1> {
        if observed != expected {
            return Err(ChildSeccompFailureV1::Invariant);
        }
        match (result, errno) {
            (0, _) => Ok(()),
            (-1, libc::ENOSYS | libc::EOPNOTSUPP) => Err(ChildSeccompFailureV1::Unavailable(errno)),
            (-1, errno) => Err(child_seccomp_failure_from_errno_v1(errno)),
            _ => Err(ChildSeccompFailureV1::Invariant),
        }
    }

    fn child_seccomp_install_filter_v1() -> Result<(), ChildSeccompFailureV1> {
        let program = LinuxSockFprogV1 {
            length: SECCOMP_FILTER_INSTRUCTION_COUNT_V1 as u16,
            filter: SECCOMP_FILTER_V1.as_ptr(),
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER_V1,
                SECCOMP_FILTER_FLAG_TSYNC_V1,
                &program,
            )
        };
        let errno = if result == -1 { child_errno() } else { 0 };
        child_seccomp_exact_result_with_errno_v1(result, errno, 0)
    }

    fn child_seccomp_require_postinstall_state_v1() -> Result<(), ChildSeccompFailureV1> {
        let mode = child_seccomp_read_mode_v1();
        let mode_errno = if mode == -1 { child_errno() } else { 0 };
        child_seccomp_exact_result_with_errno_v1(mode, mode_errno, SECCOMP_MODE_FILTER_V1)?;
        let no_new_privileges = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                u64::from(libc::PR_GET_NO_NEW_PRIVS as u32),
                0_u64,
                0_u64,
                0_u64,
                0_u64,
            )
        };
        let errno = if no_new_privileges == -1 {
            child_errno()
        } else {
            0
        };
        child_seccomp_exact_result_with_errno_v1(no_new_privileges, errno, 1)
    }

    fn child_seccomp_read_mode_v1() -> libc::c_long {
        unsafe {
            libc::syscall(
                libc::SYS_prctl,
                u64::from(libc::PR_GET_SECCOMP as u32),
                0_u64,
                0_u64,
                0_u64,
                0_u64,
            )
        }
    }

    fn child_seccomp_run_canaries_v1() -> Result<(), ChildSeccompFailureV1> {
        child_seccomp_require_marker_v1(unsafe { libc::syscall(libc::SYS_unshare, 0_u64) })?;
        child_seccomp_require_marker_v1(unsafe { libc::syscall(libc::SYS_setns, -1_i32, 0_u64) })?;
        child_seccomp_require_marker_v1(unsafe {
            libc::syscall(libc::SYS_clone3, std::ptr::null::<CloneArgsV1>(), 0_usize)
        })?;
        child_seccomp_require_marker_v1(unsafe {
            libc::syscall(libc::SYS_socket, -1_i32, 0_i32, 0_i32)
        })?;
        child_seccomp_require_marker_v1(unsafe {
            libc::syscall(libc::SYS_ioctl, -1_i32, 0_u64, 0_u64)
        })?;
        child_seccomp_require_marker_v1(unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                std::ptr::null::<u8>(),
                libc::O_RDONLY | libc::O_CLOEXEC,
                0_u32,
            )
        })
    }

    fn child_seccomp_require_marker_v1(result: libc::c_long) -> Result<(), ChildSeccompFailureV1> {
        let errno = if result == -1 { child_errno() } else { 0 };
        child_seccomp_marker_result_with_errno_v1(result, errno)
    }

    fn child_seccomp_marker_result_with_errno_v1(
        result: libc::c_long,
        errno: i32,
    ) -> Result<(), ChildSeccompFailureV1> {
        match (result, errno) {
            (-1, errno) if errno == i32::from(SECCOMP_ERRNO_MARKER_V1) => Ok(()),
            (-1, errno) => Err(child_seccomp_failure_from_errno_v1(errno)),
            _ => Err(ChildSeccompFailureV1::Invariant),
        }
    }

    fn child_seccomp_exact_result_with_errno_v1(
        result: libc::c_long,
        errno: i32,
        expected: libc::c_long,
    ) -> Result<(), ChildSeccompFailureV1> {
        if result == expected {
            return Ok(());
        }
        if result == -1 {
            return Err(child_seccomp_failure_from_errno_v1(errno));
        }
        Err(ChildSeccompFailureV1::Invariant)
    }

    fn child_seccomp_from_capability_failure_v1(
        failure: ChildCapabilityFailureV1,
    ) -> ChildSeccompFailureV1 {
        match failure {
            ChildCapabilityFailureV1::Os(errno) => child_seccomp_failure_from_errno_v1(errno),
            ChildCapabilityFailureV1::Invariant => ChildSeccompFailureV1::Invariant,
        }
    }

    fn child_seccomp_failure_from_errno_v1(errno: i32) -> ChildSeccompFailureV1 {
        if (1..=MAX_LINUX_ERRNO_V1).contains(&errno) {
            ChildSeccompFailureV1::Os(errno)
        } else {
            ChildSeccompFailureV1::Invariant
        }
    }

    fn child_read_bounding_capabilities_v1()
    -> Result<[i8; CAPABILITY_SCAN_LENGTH_V1], ChildCapabilityFailureV1> {
        let mut scan = [CAPABILITY_SCAN_UNOBSERVED_V1; CAPABILITY_SCAN_LENGTH_V1];
        let mut capability = 0_u32;
        while capability <= CAPABILITY_SCAN_MAX_V1 {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_prctl,
                    libc::PR_CAPBSET_READ,
                    u64::from(capability),
                    0_u64,
                    0_u64,
                    0_u64,
                )
            };
            scan[capability as usize] = child_capability_scan_observation_v1(result)?;
            capability += 1;
        }
        Ok(scan)
    }

    fn child_read_ambient_capabilities_v1()
    -> Result<[i8; CAPABILITY_SCAN_LENGTH_V1], ChildCapabilityFailureV1> {
        let mut scan = [CAPABILITY_SCAN_UNOBSERVED_V1; CAPABILITY_SCAN_LENGTH_V1];
        let mut capability = 0_u32;
        while capability <= CAPABILITY_SCAN_MAX_V1 {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_prctl,
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET,
                    u64::from(capability),
                    0_u64,
                    0_u64,
                )
            };
            scan[capability as usize] = child_capability_scan_observation_v1(result)?;
            capability += 1;
        }
        Ok(scan)
    }

    fn child_capability_scan_observation_v1(
        result: libc::c_long,
    ) -> Result<i8, ChildCapabilityFailureV1> {
        let errno = if result == -1 { child_errno() } else { 0 };
        child_capability_scan_observation_with_errno_v1(result, errno)
    }

    fn child_capability_scan_observation_with_errno_v1(
        result: libc::c_long,
        errno: i32,
    ) -> Result<i8, ChildCapabilityFailureV1> {
        match (result, errno) {
            (0, _) => Ok(CAPABILITY_SCAN_CLEAR_V1),
            (1, _) => Ok(CAPABILITY_SCAN_SET_V1),
            (-1, libc::EINVAL) => Ok(CAPABILITY_SCAN_INVALID_V1),
            (-1, errno) => Err(child_capability_failure_from_errno_v1(errno)),
            _ => Err(ChildCapabilityFailureV1::Invariant),
        }
    }

    fn child_last_capability_v1(scan: &[i8; CAPABILITY_SCAN_LENGTH_V1]) -> Option<u32> {
        let mut first_invalid = None;
        for (index, observation) in scan.iter().copied().enumerate() {
            match observation {
                CAPABILITY_SCAN_CLEAR_V1 | CAPABILITY_SCAN_SET_V1 if first_invalid.is_none() => {}
                CAPABILITY_SCAN_INVALID_V1 => {
                    if first_invalid.is_none() {
                        first_invalid = Some(index);
                    }
                }
                _ => return None,
            }
        }
        let first_invalid = u32::try_from(first_invalid?).ok()?;
        let last = first_invalid.checked_sub(1)?;
        (CAPABILITY_MINIMUM_LAST_V1..CAPABILITY_SCAN_MAX_V1)
            .contains(&last)
            .then_some(last)
    }

    fn child_empty_capability_scan_matches_v1(
        scan: &[i8; CAPABILITY_SCAN_LENGTH_V1],
        expected_last: u32,
    ) -> bool {
        child_last_capability_v1(scan) == Some(expected_last)
            && scan.iter().copied().enumerate().all(|(index, value)| {
                if index <= expected_last as usize {
                    value == CAPABILITY_SCAN_CLEAR_V1
                } else {
                    value == CAPABILITY_SCAN_INVALID_V1
                }
            })
    }

    fn child_read_capability_sets_v1()
    -> Result<[LinuxCapabilityDataV1; 2], ChildCapabilityFailureV1> {
        let mut header = LinuxCapabilityHeaderV1 {
            version: LINUX_CAPABILITY_VERSION_3_V1,
            pid: 0,
        };
        let mut data = [LinuxCapabilityDataV1::default(); 2];
        let result = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
        child_require_exact_zero_capability_result_v1(result)?;
        if !child_capability_header_is_exact_v1(&header) {
            return Err(ChildCapabilityFailureV1::Invariant);
        }
        Ok(data)
    }

    fn child_capability_header_is_exact_v1(header: &LinuxCapabilityHeaderV1) -> bool {
        header.version == LINUX_CAPABILITY_VERSION_3_V1 && header.pid == 0
    }

    fn child_capability_sets_are_admissible_v1(
        data: &[LinuxCapabilityDataV1; 2],
        last_capability: u32,
    ) -> bool {
        let Some(masks) = child_capability_word_masks_v1(last_capability) else {
            return false;
        };
        for (word, allowed) in data.iter().zip(masks) {
            if (word.effective | word.permitted | word.inheritable) & !allowed != 0 {
                return false;
            }
        }
        let setpcap_mask = 1_u32 << CAP_SETPCAP_V1;
        data[0].effective & setpcap_mask != 0 && data[0].permitted & setpcap_mask != 0
    }

    fn child_capability_word_masks_v1(last_capability: u32) -> Option<[u32; 2]> {
        if last_capability > 63 {
            return None;
        }
        let word_mask = |first: u32| {
            if last_capability < first {
                0
            } else if last_capability - first >= 31 {
                u32::MAX
            } else {
                let bit_count = last_capability - first + 1;
                (1_u32 << bit_count) - 1
            }
        };
        Some([word_mask(0), word_mask(32)])
    }

    fn child_capability_sets_are_empty_v1(data: &[LinuxCapabilityDataV1; 2]) -> bool {
        data.iter()
            .all(|word| word.effective == 0 && word.permitted == 0 && word.inheritable == 0)
    }

    fn child_set_and_verify_securebits_v1() -> Result<(), ChildCapabilityFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_SET_SECUREBITS,
                CAPABILITY_SECUREBITS_V1,
                0_u64,
                0_u64,
                0_u64,
            )
        };
        child_require_exact_zero_capability_result_v1(result)?;
        child_verify_securebits_v1()
    }

    fn child_verify_securebits_v1() -> Result<(), ChildCapabilityFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_GET_SECUREBITS,
                0_u64,
                0_u64,
                0_u64,
                0_u64,
            )
        };
        child_require_exact_capability_value_v1(
            result,
            libc::c_long::from(CAPABILITY_SECUREBITS_V1),
        )
    }

    fn child_drop_bounding_capabilities_v1(
        last_capability: u32,
    ) -> Result<(), ChildCapabilityFailureV1> {
        let mut capability = 0_u32;
        while capability <= last_capability {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_prctl,
                    libc::PR_CAPBSET_DROP,
                    u64::from(capability),
                    0_u64,
                    0_u64,
                    0_u64,
                )
            };
            child_require_exact_zero_capability_result_v1(result)?;
            capability += 1;
        }
        Ok(())
    }

    fn child_clear_ambient_capabilities_v1() -> Result<(), ChildCapabilityFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0_u64,
                0_u64,
                0_u64,
            )
        };
        child_require_exact_zero_capability_result_v1(result)
    }

    fn child_clear_capability_sets_v1() -> Result<(), ChildCapabilityFailureV1> {
        let mut header = LinuxCapabilityHeaderV1 {
            version: LINUX_CAPABILITY_VERSION_3_V1,
            pid: 0,
        };
        let data = [LinuxCapabilityDataV1::default(); 2];
        let result = unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) };
        child_require_exact_zero_capability_result_v1(result)?;
        if !child_capability_header_is_exact_v1(&header) {
            return Err(ChildCapabilityFailureV1::Invariant);
        }
        Ok(())
    }

    fn child_set_no_new_privileges_v1() -> Result<(), ChildCapabilityFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_SET_NO_NEW_PRIVS,
                1_u64,
                0_u64,
                0_u64,
                0_u64,
            )
        };
        child_require_exact_zero_capability_result_v1(result)
    }

    fn child_verify_no_new_privileges_v1() -> Result<(), ChildCapabilityFailureV1> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_GET_NO_NEW_PRIVS,
                0_u64,
                0_u64,
                0_u64,
                0_u64,
            )
        };
        child_require_exact_capability_value_v1(result, 1)
    }

    fn child_reauthenticate_capability_report_v1(
        expected: &ChildReportDescriptorIdentityV1,
    ) -> Result<(), ChildCapabilityFailureV1> {
        match child_report_descriptor_identity_v1(REPORT_DESCRIPTOR_V1) {
            Ok(observed) if observed == *expected => Ok(()),
            Ok(_) | Err(ChildDescriptorFailureV1::Invariant) => {
                Err(ChildCapabilityFailureV1::Invariant)
            }
            Err(ChildDescriptorFailureV1::CloseRange(errno))
            | Err(ChildDescriptorFailureV1::Os(errno)) => {
                Err(child_capability_failure_from_errno_v1(errno))
            }
        }
    }

    fn child_require_exact_zero_capability_result_v1(
        result: libc::c_long,
    ) -> Result<(), ChildCapabilityFailureV1> {
        child_require_exact_capability_value_v1(result, 0)
    }

    fn child_require_exact_capability_value_v1(
        result: libc::c_long,
        expected: libc::c_long,
    ) -> Result<(), ChildCapabilityFailureV1> {
        if result == expected {
            return Ok(());
        }
        if result == -1 {
            return Err(child_capability_os_failure_v1());
        }
        Err(ChildCapabilityFailureV1::Invariant)
    }

    fn child_capability_os_failure_v1() -> ChildCapabilityFailureV1 {
        child_capability_failure_from_errno_v1(child_errno())
    }

    fn child_capability_failure_from_errno_v1(errno: i32) -> ChildCapabilityFailureV1 {
        if (1..=MAX_LINUX_ERRNO_V1).contains(&errno) {
            ChildCapabilityFailureV1::Os(errno)
        } else {
            ChildCapabilityFailureV1::Invariant
        }
    }

    fn child_descriptor_os_failure_v1() -> ChildDescriptorFailureV1 {
        child_descriptor_failure_from_errno_v1(child_errno())
    }

    fn child_descriptor_failure_from_errno_v1(errno: i32) -> ChildDescriptorFailureV1 {
        if (1..=MAX_LINUX_ERRNO_V1).contains(&errno) {
            ChildDescriptorFailureV1::Os(errno)
        } else {
            ChildDescriptorFailureV1::Invariant
        }
    }

    fn child_descriptor_fail_v1(
        report_write: RawFd,
        nonce: &[u8; NONCE_BYTES_V1],
        failure: ChildDescriptorFailureV1,
        deadline: MonotonicDeadlineV1,
    ) -> ! {
        let (status, errno) = match failure {
            ChildDescriptorFailureV1::CloseRange(errno) => (PROOF_STATUS_CLOSE_RANGE_OS_V1, errno),
            ChildDescriptorFailureV1::Os(errno) => (PROOF_STATUS_FD_SCRUB_V1, errno),
            ChildDescriptorFailureV1::Invariant => (PROOF_STATUS_FD_SCRUB_V1, 0),
        };
        child_fail(report_write, nonce, status, errno, deadline)
    }

    fn child_capability_fail_v1(
        report_write: RawFd,
        nonce: &[u8; NONCE_BYTES_V1],
        failure: ChildCapabilityFailureV1,
        deadline: MonotonicDeadlineV1,
    ) -> ! {
        let errno = match failure {
            ChildCapabilityFailureV1::Os(errno) => errno,
            ChildCapabilityFailureV1::Invariant => 0,
        };
        child_fail(
            report_write,
            nonce,
            PROOF_STATUS_CAPABILITY_DROP_V1,
            errno,
            deadline,
        )
    }

    fn child_landlock_fail_v1(
        report_write: RawFd,
        nonce: &[u8; NONCE_BYTES_V1],
        failure: ChildLandlockFailureV1,
        deadline: MonotonicDeadlineV1,
    ) -> ! {
        let (status, errno) = match failure {
            ChildLandlockFailureV1::Unavailable(errno) => {
                (PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1, errno)
            }
            ChildLandlockFailureV1::Os(errno) => (PROOF_STATUS_LANDLOCK_BROKEN_V1, errno),
            ChildLandlockFailureV1::Invariant => (PROOF_STATUS_LANDLOCK_BROKEN_V1, 0),
        };
        child_fail(report_write, nonce, status, errno, deadline)
    }

    fn child_seccomp_fail_v1(
        report_write: RawFd,
        nonce: &[u8; NONCE_BYTES_V1],
        failure: ChildSeccompFailureV1,
        deadline: MonotonicDeadlineV1,
    ) -> ! {
        let (status, errno) = match failure {
            ChildSeccompFailureV1::Unavailable(errno) => {
                (PROOF_STATUS_SECCOMP_UNAVAILABLE_V1, errno)
            }
            ChildSeccompFailureV1::Os(errno) => (PROOF_STATUS_SECCOMP_BROKEN_V1, errno),
            ChildSeccompFailureV1::Invariant => (PROOF_STATUS_SECCOMP_BROKEN_V1, 0),
        };
        child_fail(report_write, nonce, status, errno, deadline)
    }

    fn child_fail(
        report_write: RawFd,
        nonce: &[u8; NONCE_BYTES_V1],
        status: u8,
        errno: i32,
        deadline: MonotonicDeadlineV1,
    ) -> ! {
        let proof = child_encode_proof_frame(nonce, status, 0, errno);
        let _ = child_write_frame(report_write, &proof, deadline);
        let _ = child_close(report_write);
        child_exit(CHILD_EXIT_PROOF_FAILED_V1)
    }

    fn child_encode_common_frame(
        magic: &[u8; 8],
        phase: u8,
        nonce: &[u8; NONCE_BYTES_V1],
    ) -> [u8; FRAME_BYTES_V1] {
        let mut frame = [0_u8; FRAME_BYTES_V1];
        unsafe {
            std::ptr::copy_nonoverlapping(
                magic.as_ptr(),
                frame.as_mut_ptr().add(FRAME_MAGIC_OFFSET_V1),
                magic.len(),
            );
            let version = PROTOCOL_VERSION_V2.to_le_bytes();
            std::ptr::copy_nonoverlapping(
                version.as_ptr(),
                frame.as_mut_ptr().add(FRAME_VERSION_OFFSET_V1),
                version.len(),
            );
            *frame.as_mut_ptr().add(FRAME_PHASE_OFFSET_V1) = phase;
            std::ptr::copy_nonoverlapping(
                nonce.as_ptr(),
                frame.as_mut_ptr().add(FRAME_NONCE_OFFSET_V1),
                nonce.len(),
            );
        }
        frame
    }

    fn child_encode_proof_frame(
        nonce: &[u8; NONCE_BYTES_V1],
        status: u8,
        flags: u16,
        errno: i32,
    ) -> [u8; FRAME_BYTES_V1] {
        let mut frame = child_encode_common_frame(PROOF_MAGIC_V1, PHASE_PROOF_V1, nonce);
        unsafe {
            *frame.as_mut_ptr().add(FRAME_STATUS_OFFSET_V1) = status;
            let flags = flags.to_le_bytes();
            std::ptr::copy_nonoverlapping(
                flags.as_ptr(),
                frame.as_mut_ptr().add(FRAME_FLAGS_OFFSET_V1),
                flags.len(),
            );
            let error = errno.to_le_bytes();
            std::ptr::copy_nonoverlapping(
                error.as_ptr(),
                frame.as_mut_ptr().add(FRAME_ERROR_OFFSET_V1),
                error.len(),
            );
            let pid = 1_u32.to_le_bytes();
            std::ptr::copy_nonoverlapping(
                pid.as_ptr(),
                frame.as_mut_ptr().add(FRAME_PID_OFFSET_V1),
                pid.len(),
            );
        }
        frame
    }

    fn child_verify_release_frame(
        frame: &[u8; FRAME_BYTES_V1],
        nonce: &[u8; NONCE_BYTES_V1],
    ) -> bool {
        unsafe {
            child_bytes_equal(
                frame.as_ptr().add(FRAME_MAGIC_OFFSET_V1),
                RELEASE_MAGIC_V1.as_ptr(),
                RELEASE_MAGIC_V1.len(),
            ) && child_bytes_equal(
                frame.as_ptr().add(FRAME_VERSION_OFFSET_V1),
                PROTOCOL_VERSION_V2.to_le_bytes().as_ptr(),
                2,
            ) && *frame.as_ptr().add(FRAME_PHASE_OFFSET_V1) == PHASE_RELEASE_V1
                && *frame.as_ptr().add(FRAME_STATUS_OFFSET_V1) == 0
                && child_all_zero(
                    frame.as_ptr().add(FRAME_FLAGS_OFFSET_V1),
                    FRAME_NONCE_OFFSET_V1 - FRAME_FLAGS_OFFSET_V1,
                )
                && child_bytes_equal(
                    frame.as_ptr().add(FRAME_NONCE_OFFSET_V1),
                    nonce.as_ptr(),
                    NONCE_BYTES_V1,
                )
                && child_all_zero(
                    frame.as_ptr().add(FRAME_ERROR_OFFSET_V1),
                    FRAME_BYTES_V1 - FRAME_ERROR_OFFSET_V1,
                )
        }
    }

    unsafe fn child_bytes_equal(left: *const u8, right: *const u8, length: usize) -> bool {
        let mut offset = 0_usize;
        while offset < length {
            if unsafe { *left.add(offset) != *right.add(offset) } {
                return false;
            }
            offset += 1;
        }
        true
    }

    unsafe fn child_all_zero(bytes: *const u8, length: usize) -> bool {
        let mut offset = 0_usize;
        while offset < length {
            if unsafe { *bytes.add(offset) != 0 } {
                return false;
            }
            offset += 1;
        }
        true
    }

    fn child_c_field_equals(field: *const libc::c_char, length: usize, expected: &[u8]) -> bool {
        if expected.len() >= length {
            return false;
        }
        let mut offset = 0_usize;
        while offset < expected.len() {
            if unsafe { *field.add(offset) as u8 != *expected.get_unchecked(offset) } {
                return false;
            }
            offset += 1;
        }
        unsafe { *field.add(expected.len()) == 0 }
    }

    fn child_read_frame_and_eof(
        fd: RawFd,
        frame: &mut [u8; FRAME_BYTES_V1],
        deadline: MonotonicDeadlineV1,
    ) -> bool {
        let mut offset = 0_usize;
        while offset < FRAME_BYTES_V1 {
            let read = unsafe {
                libc::syscall(
                    libc::SYS_read,
                    fd,
                    frame.as_mut_ptr().add(offset),
                    FRAME_BYTES_V1 - offset,
                )
            };
            if read > 0 {
                let read = read as usize;
                if read > FRAME_BYTES_V1 - offset {
                    return false;
                }
                offset += read;
                continue;
            }
            if read == 0 {
                return false;
            }
            let errno = child_errno();
            if errno == libc::EINTR {
                continue;
            }
            if errno != libc::EAGAIN || !child_poll(fd, libc::POLLIN, deadline) {
                return false;
            }
        }
        let mut extra = 0_u8;
        loop {
            let read = unsafe { libc::syscall(libc::SYS_read, fd, &mut extra as *mut u8, 1_usize) };
            if read == 0 {
                return true;
            }
            if read > 0 {
                return false;
            }
            let errno = child_errno();
            if errno == libc::EINTR {
                continue;
            }
            if errno != libc::EAGAIN || !child_poll(fd, libc::POLLIN | libc::POLLHUP, deadline) {
                return false;
            }
        }
    }

    fn child_write_frame(
        fd: RawFd,
        frame: &[u8; FRAME_BYTES_V1],
        deadline: MonotonicDeadlineV1,
    ) -> bool {
        loop {
            let written = unsafe {
                libc::syscall(
                    libc::SYS_write,
                    u64::from(fd as u32),
                    frame.as_ptr(),
                    FRAME_BYTES_V1 as u64,
                )
            };
            if written == FRAME_BYTES_V1 as libc::c_long {
                return true;
            }
            if written >= 0 {
                return false;
            }
            let errno = child_errno();
            if errno == libc::EINTR {
                continue;
            }
            if errno != libc::EAGAIN || !child_poll(fd, libc::POLLOUT, deadline) {
                return false;
            }
        }
    }

    fn child_poll(fd: RawFd, events: i16, deadline: MonotonicDeadlineV1) -> bool {
        loop {
            let timeout = match child_remaining_milliseconds(deadline) {
                Some(timeout) => timeout,
                None => return false,
            };
            let Ok(timeout) = u32::try_from(timeout) else {
                return false;
            };
            let mut descriptor = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result = unsafe {
                libc::syscall(libc::SYS_poll, &mut descriptor, 1_u64, u64::from(timeout))
            };
            if result > 0 {
                return descriptor.revents & events != 0
                    && descriptor.revents & (libc::POLLERR | libc::POLLNVAL) == 0;
            }
            if result == 0 {
                return false;
            }
            if child_errno() != libc::EINTR {
                return false;
            }
        }
    }

    fn child_remaining_milliseconds(deadline: MonotonicDeadlineV1) -> Option<i32> {
        let mut now = MaybeUninit::<libc::timespec>::zeroed();
        if unsafe {
            libc::syscall(
                libc::SYS_clock_gettime,
                u64::from(libc::CLOCK_MONOTONIC as u32),
                now.as_mut_ptr(),
            )
        } != 0
        {
            return None;
        }
        let now = unsafe { now.assume_init() };
        if now.tv_sec < 0 || !(0..1_000_000_000).contains(&now.tv_nsec) {
            return None;
        }
        deadline.remaining_milliseconds_at(now).ok()
    }

    fn child_close(fd: RawFd) -> bool {
        if fd < 0 {
            return false;
        }
        let result = unsafe { libc::syscall(libc::SYS_close, u64::from(fd as u32)) };
        result == 0 || (result < 0 && child_errno() == libc::EINTR)
    }

    fn child_errno() -> i32 {
        unsafe { *libc::__errno_location() }
    }

    fn child_exit(status: i32) -> ! {
        unsafe { libc::syscall(libc::SYS_exit, u64::from(status as u32)) };
        loop {
            std::hint::spin_loop();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const DISPOSABLE_FD_SCRUB_MAGIC_V1: &[u8; 8] = b"AGNFDT01";
        const DISPOSABLE_FD_SCRUB_COMPLETE_V1: u8 = 1;

        fn seccomp_filter_fingerprint_v1() -> u64 {
            let mut hash = 0xcbf2_9ce4_8422_2325_u64;
            for instruction in &SECCOMP_FILTER_V1 {
                for byte in instruction
                    .code
                    .to_le_bytes()
                    .into_iter()
                    .chain([instruction.jump_true, instruction.jump_false])
                    .chain(instruction.operand.to_le_bytes())
                {
                    hash ^= u64::from(byte);
                    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
            hash
        }

        fn seccomp_filter_is_structurally_valid_v1() -> bool {
            let filter = &SECCOMP_FILTER_V1;
            if filter.is_empty() || filter.len() > usize::from(u16::MAX) {
                return false;
            }
            let mut reachable = vec![false; filter.len()];
            let mut pending = vec![0_usize];
            while let Some(program_counter) = pending.pop() {
                let Some(instruction) = filter.get(program_counter).copied() else {
                    return false;
                };
                if reachable[program_counter] {
                    continue;
                }
                reachable[program_counter] = true;
                match instruction.code {
                    SECCOMP_BPF_LD_W_ABS_V1 => {
                        if instruction.jump_true != 0
                            || instruction.jump_false != 0
                            || instruction.operand % 4 != 0
                            || instruction.operand > 60
                        {
                            return false;
                        }
                        let Some(next) = program_counter.checked_add(1) else {
                            return false;
                        };
                        if next >= filter.len() {
                            return false;
                        }
                        pending.push(next);
                    }
                    SECCOMP_BPF_JMP_JEQ_K_V1
                    | SECCOMP_BPF_JMP_JGT_K_V1
                    | SECCOMP_BPF_JMP_JSET_K_V1 => {
                        for jump in [instruction.jump_true, instruction.jump_false] {
                            let Some(target) = program_counter
                                .checked_add(1)
                                .and_then(|next| next.checked_add(usize::from(jump)))
                            else {
                                return false;
                            };
                            if target >= filter.len() {
                                return false;
                            }
                            pending.push(target);
                        }
                    }
                    SECCOMP_BPF_RET_K_V1 => {
                        if instruction.jump_true != 0
                            || instruction.jump_false != 0
                            || !matches!(
                                instruction.operand,
                                SECCOMP_RET_ALLOW_V1
                                    | SECCOMP_RET_MARKER_V1
                                    | SECCOMP_RET_KILL_PROCESS_V1
                            )
                        {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
            reachable.into_iter().all(|seen| seen)
        }

        fn evaluate_seccomp_filter_v1(
            architecture: u32,
            syscall: u32,
            arguments: [u64; 6],
        ) -> Option<u32> {
            let filter = &SECCOMP_FILTER_V1;
            let mut accumulator = 0_u32;
            let mut program_counter = 0_usize;
            let mut steps = 0_usize;
            while program_counter < filter.len() && steps <= filter.len() {
                let instruction = filter[program_counter];
                steps += 1;
                match instruction.code {
                    SECCOMP_BPF_LD_W_ABS_V1 => {
                        accumulator = match instruction.operand {
                            SECCOMP_DATA_NR_OFFSET_V1 => syscall,
                            SECCOMP_DATA_ARCH_OFFSET_V1 => architecture,
                            offset => {
                                let relative = offset.checked_sub(SECCOMP_DATA_ARGS_OFFSET_V1)?;
                                let argument =
                                    usize::try_from(relative / SECCOMP_DATA_ARG_STRIDE_V1).ok()?;
                                if argument >= arguments.len() {
                                    return None;
                                }
                                let value = *arguments.get(argument)?;
                                if relative % SECCOMP_DATA_ARG_STRIDE_V1 == 0 {
                                    value as u32
                                } else if relative % SECCOMP_DATA_ARG_STRIDE_V1
                                    == SECCOMP_DATA_ARG_HIGH_OFFSET_V1
                                {
                                    (value >> 32) as u32
                                } else {
                                    return None;
                                }
                            }
                        };
                        program_counter += 1;
                    }
                    SECCOMP_BPF_JMP_JEQ_K_V1
                    | SECCOMP_BPF_JMP_JGT_K_V1
                    | SECCOMP_BPF_JMP_JSET_K_V1 => {
                        let predicate = match instruction.code {
                            SECCOMP_BPF_JMP_JEQ_K_V1 => accumulator == instruction.operand,
                            SECCOMP_BPF_JMP_JGT_K_V1 => accumulator > instruction.operand,
                            SECCOMP_BPF_JMP_JSET_K_V1 => accumulator & instruction.operand != 0,
                            _ => return None,
                        };
                        let jump = if predicate {
                            instruction.jump_true
                        } else {
                            instruction.jump_false
                        };
                        program_counter = program_counter.checked_add(1 + usize::from(jump))?;
                    }
                    SECCOMP_BPF_RET_K_V1 => return Some(instruction.operand),
                    _ => return None,
                }
            }
            None
        }

        fn test_pipe() -> (OwnedFd, OwnedFd) {
            create_pipe().unwrap_or_else(|_| panic!("nonblocking pipe fixture failed"))
        }

        fn write_test_payload(fd: RawFd, payload: &[u8]) {
            loop {
                let written = unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) };
                if usize::try_from(written).ok() == Some(payload.len()) {
                    return;
                }
                if written < 0 && last_errno() == Some(libc::EINTR) {
                    continue;
                }
                panic!("pipe fixture write failed");
            }
        }

        fn test_deadline() -> MonotonicDeadlineV1 {
            probe_deadlines()
                .map(|(deadline, _)| deadline)
                .unwrap_or_else(|_| panic!("monotonic deadline fixture failed"))
        }

        fn policy_statfs() -> libc::statfs64 {
            let mut filesystem = unsafe { MaybeUninit::<libc::statfs64>::zeroed().assume_init() };
            filesystem.f_type = TMPFS_SUPER_MAGIC_V1;
            filesystem.f_bsize = 4_096;
            filesystem.f_blocks = ROOT_TMPFS_BYTES_V1 / 4_096;
            filesystem.f_files = ROOT_TMPFS_INODES_V1;
            filesystem.f_flags = (libc::ST_NODEV | libc::ST_NOSUID) as libc::c_long;
            filesystem
        }

        fn scratch_policy_statfs() -> libc::statfs64 {
            let mut filesystem = unsafe { MaybeUninit::<libc::statfs64>::zeroed().assume_init() };
            filesystem.f_type = TMPFS_SUPER_MAGIC_V1;
            filesystem.f_bsize = 4_096;
            filesystem.f_blocks = SCRATCH_TMPFS_BYTES_V1 / 4_096;
            filesystem.f_files = SCRATCH_TMPFS_INODES_V1;
            filesystem.f_flags =
                (libc::ST_NODEV | libc::ST_NOSUID | libc::ST_NOEXEC) as libc::c_long;
            filesystem
        }

        fn proc_policy_statfs() -> libc::statfs64 {
            let mut filesystem = unsafe { MaybeUninit::<libc::statfs64>::zeroed().assume_init() };
            filesystem.f_type = PROC_SUPER_MAGIC_V1;
            filesystem.f_flags =
                (libc::ST_RDONLY | libc::ST_NODEV | libc::ST_NOSUID | libc::ST_NOEXEC)
                    as libc::c_long;
            filesystem
        }

        fn scratch_independence_fixture(mount_ids: [u64; 3], devices: [(u32, u32); 3]) -> bool {
            let identity = |index: usize| ChildPathIdentityV1 {
                mount_id: mount_ids[index],
                inode: 10 + index as u64,
                device_major: devices[index].0,
                device_minor: devices[index].1,
                mode: (libc::S_IFDIR | 0o755) as u16,
                uid: 0,
                gid: 0,
            };
            let tmp = identity(0);
            let run = identity(1);
            let home = identity(2);
            child_scratch_identities_are_independent_v1(&tmp, &run, &home)
        }

        fn fd_audit_dirent(name: &[u8]) -> Vec<u8> {
            let unaligned = DIRENT64_NAME_OFFSET_V1 + name.len() + 1;
            let record_length =
                (unaligned + DIRENT64_ALIGNMENT_V1 - 1) & !(DIRENT64_ALIGNMENT_V1 - 1);
            let mut record = vec![0_u8; record_length];
            record[16..18].copy_from_slice(&(record_length as u16).to_ne_bytes());
            record[18] = libc::DT_LNK;
            record[DIRENT64_NAME_OFFSET_V1..DIRENT64_NAME_OFFSET_V1 + name.len()]
                .copy_from_slice(name);
            record
        }

        fn fd_audit_chunk(names: &[&[u8]]) -> Vec<u8> {
            let mut chunk = Vec::new();
            for name in names {
                chunk.extend_from_slice(&fd_audit_dirent(name));
            }
            chunk
        }

        fn capability_scan_fixture(
            last_capability: u32,
            supported_value: i8,
        ) -> [i8; CAPABILITY_SCAN_LENGTH_V1] {
            let mut scan = [CAPABILITY_SCAN_INVALID_V1; CAPABILITY_SCAN_LENGTH_V1];
            scan[..=last_capability as usize].fill(supported_value);
            scan
        }

        fn admissible_capability_sets() -> [LinuxCapabilityDataV1; 2] {
            let setpcap = 1_u32 << CAP_SETPCAP_V1;
            [
                LinuxCapabilityDataV1 {
                    effective: setpcap,
                    permitted: setpcap,
                    inheritable: 0,
                },
                LinuxCapabilityDataV1::default(),
            ]
        }

        fn disposable_proc_fd_path_v1(pid: libc::pid_t) -> Option<[u8; 32]> {
            let pid = encode_pid_name(pid)?;
            let prefix = b"proc/";
            let suffix = b"/fd";
            let length = prefix.len() + pid.as_bytes().len() + suffix.len();
            let mut path = [0_u8; 32];
            path[..prefix.len()].copy_from_slice(prefix);
            path[prefix.len()..prefix.len() + pid.as_bytes().len()].copy_from_slice(pid.as_bytes());
            path[prefix.len() + pid.as_bytes().len()..length].copy_from_slice(suffix);
            Some(path)
        }

        fn disposable_fd_scrub_evidence_v1(nonce: &[u8; NONCE_BYTES_V1]) -> [u8; FRAME_BYTES_V1] {
            let mut evidence = [0_u8; FRAME_BYTES_V1];
            evidence[..DISPOSABLE_FD_SCRUB_MAGIC_V1.len()]
                .copy_from_slice(DISPOSABLE_FD_SCRUB_MAGIC_V1);
            evidence[8..8 + NONCE_BYTES_V1].copy_from_slice(nonce);
            evidence[8 + NONCE_BYTES_V1] = DISPOSABLE_FD_SCRUB_COMPLETE_V1;
            evidence
        }

        fn disposable_child_fd_audit_v1(
            audit_descriptor: RawFd,
            report_identity: &ChildReportDescriptorIdentityV1,
        ) -> bool {
            let mut filesystem = MaybeUninit::<libc::statfs64>::zeroed();
            if unsafe {
                libc::syscall(libc::SYS_fstatfs, audit_descriptor, filesystem.as_mut_ptr())
            } != 0
                || unsafe { filesystem.assume_init() }.f_type != PROC_SUPER_MAGIC_V1
            {
                return false;
            }
            child_finish_fd_audit_v1(audit_descriptor, report_identity).is_ok()
        }

        fn disposable_fd_scrub_child_v1(
            report_write: RawFd,
            nonce: &[u8; NONCE_BYTES_V1],
            deadline: MonotonicDeadlineV1,
        ) -> ! {
            if report_write <= libc::STDERR_FILENO {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            }
            let Ok(report_identity) = child_report_descriptor_identity_v1(report_write) else {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            };
            let high_descriptor = unsafe {
                libc::syscall(
                    libc::SYS_fcntl,
                    report_write,
                    libc::F_DUPFD_CLOEXEC,
                    127_i32,
                )
            };
            let Ok(high_descriptor) = RawFd::try_from(high_descriptor) else {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            };
            if high_descriptor < 127
                || !matches!(
                    child_report_descriptor_identity_v1(high_descriptor),
                    Ok(identity) if identity == report_identity
                )
            {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            }
            if unsafe {
                libc::syscall(
                    libc::SYS_dup3,
                    report_write,
                    REPORT_DESCRIPTOR_V1,
                    libc::O_CLOEXEC,
                )
            } != libc::c_long::from(REPORT_DESCRIPTOR_V1)
                || !matches!(
                    child_report_descriptor_identity_v1(REPORT_DESCRIPTOR_V1),
                    Ok(identity) if identity == report_identity
                )
                || child_close_range_and_reauthenticate_v1(&report_identity).is_err()
            {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            }
            let high_closed =
                unsafe { libc::syscall(libc::SYS_fcntl, high_descriptor, libc::F_GETFD, 0_u64) };
            if high_closed >= 0 || child_errno() != libc::EBADF {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            }
            if unsafe { libc::syscall(libc::SYS_chdir, ROOT_PATH_V1.as_ptr()) } != 0 {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            }
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            let Ok(pid) = libc::pid_t::try_from(pid) else {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            };
            let Some(path) = disposable_proc_fd_path_v1(pid) else {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            };
            let how = OpenHowV1 {
                flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    as u64,
                mode: 0,
                resolve: RESOLVE_BENEATH_V1 | RESOLVE_NO_MAGICLINKS_V1 | RESOLVE_NO_SYMLINKS_V1,
            };
            let audit_descriptor = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHowV1>(),
                )
            };
            let Ok(audit_descriptor) = RawFd::try_from(audit_descriptor) else {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            };
            if !disposable_child_fd_audit_v1(audit_descriptor, &report_identity) {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            }
            let evidence = disposable_fd_scrub_evidence_v1(nonce);
            if !child_write_frame(REPORT_DESCRIPTOR_V1, &evidence, deadline)
                || !child_close(REPORT_DESCRIPTOR_V1)
            {
                child_exit(CHILD_EXIT_PROOF_FAILED_V1);
            }
            child_exit(0)
        }

        #[test]
        fn map_encoder_covers_zero_and_u32_max() {
            assert_eq!(encode_id_map_line(0).as_slice(), b"0 0 1\n");
            assert_eq!(encode_id_map_line(u32::MAX).as_slice(), b"0 4294967295 1\n");
        }

        #[test]
        fn proc_self_target_is_exact_canonical_decimal() {
            assert!(proc_self_target_matches(b"123", 123));
            for invalid in [
                b"0123".as_slice(),
                b"123/".as_slice(),
                b"123\n".as_slice(),
                b"123\0".as_slice(),
                b"12".as_slice(),
                b"124".as_slice(),
                b"".as_slice(),
            ] {
                assert!(!proc_self_target_matches(invalid, 123));
            }
            assert!(!proc_self_target_matches(b"1", 0));
            assert!(!proc_self_target_matches(b"1", -1));
        }

        #[test]
        fn malformed_clone_pid_never_becomes_signal_target() {
            assert_eq!(checked_child_pid(1), Some(1));
            assert_eq!(checked_child_pid(0), None);
            assert_eq!(checked_child_pid(-1), None);
            assert_eq!(checked_child_pid(i64::from(i32::MAX) + 1), None);
        }

        #[test]
        fn groups_parser_rejects_bad_or_duplicate_fields() {
            assert_eq!(
                parse_status_groups(b"Name:\tx\nGroups:\t9 2 7\n").ok(),
                Some(vec![2, 7, 9])
            );
            for invalid in [
                b"Groups:\t1 x\n".as_slice(),
                b"Groups:\tx 1\n".as_slice(),
                b"Groups:\t1 1\n".as_slice(),
                b"Groups:\t4294967296\n".as_slice(),
                b"Groups:\t1\nGroups:\t2\n".as_slice(),
                b"Groups:\t-1\n".as_slice(),
                b"Groups:\t1\r\n".as_slice(),
            ] {
                assert!(parse_status_groups(invalid).is_err());
            }
        }

        #[test]
        fn child_capability_verification_requires_sys_admin_bit() {
            assert!(
                verify_child_sys_admin_capability(b"Name:\tagain\nCapEff:\t0000000000200001\n")
                    .is_ok()
            );

            let missing = verify_child_sys_admin_capability(b"CapEff:\t00100000\n")
                .expect_err("wrong capability bit was accepted");
            assert_eq!(missing.code, RefusalCode::RequiredNamespaceFailed);
            assert_eq!(
                (missing.stage, missing.reason),
                (
                    IsolationQualificationStageV1::VerifyChildCapabilities,
                    IsolationQualificationReasonV1::ChildInvariantFailed,
                )
            );

            for malformed in [
                b"Name:\tagain\n".as_slice(),
                b"CapEff:\t200000 extra\n".as_slice(),
                b"CapEff:\t10000000000000000\n".as_slice(),
            ] {
                let error = match verify_child_sys_admin_capability(malformed) {
                    Ok(()) => panic!("malformed CapEff row was accepted"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.stage,
                    IsolationQualificationStageV1::VerifyChildCapabilities
                );
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::MalformedKernelResponse
                );
            }
        }

        #[test]
        fn fixed_tmpfs_policy_is_bounded_and_exact() {
            assert_eq!(
                ROOT_TMPFS_OPTIONS_V1.to_bytes_with_nul(),
                b"size=16777216,nr_inodes=4096,mode=0755,noswap\0"
            );
            assert!(child_statfs_matches_policy_v1(&policy_statfs()));

            let mut wrong_type = policy_statfs();
            wrong_type.f_type = 0;
            let mut missing_flag = policy_statfs();
            missing_flag.f_flags &= !(libc::ST_NODEV as libc::c_long);
            let mut too_many_blocks = policy_statfs();
            too_many_blocks.f_blocks += 1;
            let mut too_many_inodes = policy_statfs();
            too_many_inodes.f_files += 1;
            let mut zero_blocks = policy_statfs();
            zero_blocks.f_blocks = 0;
            for filesystem in [
                wrong_type,
                missing_flag,
                too_many_blocks,
                too_many_inodes,
                zero_blocks,
            ] {
                assert!(!child_statfs_matches_policy_v1(&filesystem));
            }
        }

        #[test]
        fn fixed_layout_and_mount_policy_is_frozen() {
            assert_eq!(
                [
                    (WORKSPACE_NAME_V1.to_bytes(), WORKSPACE_MODE_V1),
                    (TMP_NAME_V1.to_bytes(), TMP_MODE_V1),
                    (RUN_NAME_V1.to_bytes(), RUN_MODE_V1),
                    (HOME_NAME_V1.to_bytes(), HOME_MODE_V1),
                    (AGAIN_NAME_V1.to_bytes(), AGAIN_HOME_MODE_V1),
                    (PROC_NAME_V1.to_bytes(), PROC_MODE_V1),
                    (DEV_NAME_V1.to_bytes(), DEV_MODE_V1),
                ],
                [
                    (b"workspace".as_slice(), 0o755),
                    (b"tmp".as_slice(), 0o1777),
                    (b"run".as_slice(), 0o755),
                    (b"home".as_slice(), 0o755),
                    (b"again".as_slice(), 0o700),
                    (b"proc".as_slice(), 0o555),
                    (b"dev".as_slice(), 0o755),
                ],
            );
            assert_eq!(SCRATCH_TMPFS_BYTES_V1, 4_194_304);
            assert_eq!(SCRATCH_TMPFS_INODES_V1, 1_024);
            assert_eq!(
                TMP_TMPFS_OPTIONS_V1.to_bytes_with_nul(),
                b"size=4194304,nr_inodes=1024,mode=1777,noswap\0"
            );
            assert_eq!(
                RUN_TMPFS_OPTIONS_V1.to_bytes_with_nul(),
                b"size=4194304,nr_inodes=1024,mode=0755,noswap\0"
            );
            assert_eq!(
                AGAIN_HOME_TMPFS_OPTIONS_V1.to_bytes_with_nul(),
                b"size=4194304,nr_inodes=1024,mode=0700,noswap\0"
            );
            assert_eq!(PROCFS_OPTIONS_V1.to_bytes_with_nul(), b"subset=pid\0");
            assert_eq!(PROC_FD_AUDIT_PATH_V1.to_bytes_with_nul(), b"proc/1/fd\0");
            assert_eq!(REPORT_DESCRIPTOR_V1, 0);
            assert_eq!(FD_AUDIT_DESCRIPTOR_V1, 1);
            assert_eq!(CLOSE_RANGE_FIRST_V1, 1);
            assert_eq!(CLOSE_RANGE_LAST_V1, u32::MAX);
            assert_eq!(libc::CLOSE_RANGE_UNSHARE, 2);
            assert_eq!(FD_AUDIT_BUFFER_BYTES_V1, 256);
            assert_eq!(FD_AUDIT_MAX_GETDENTS_CALLS_V1, 8);
            assert_eq!(FD_AUDIT_COMPLETE_MASK_V1, 0b1111);
            assert_eq!(PROTOCOL_VERSION_V2, 2);
            assert_eq!(PROOF_FLAGS_V1, 0x01ff);
        }

        #[test]
        fn capability_word_masks_saturate_without_overshifting() {
            assert_eq!(child_capability_word_masks_v1(31), Some([u32::MAX, 0]));
            assert_eq!(child_capability_word_masks_v1(32), Some([u32::MAX, 1]));
            assert_eq!(child_capability_word_masks_v1(40), Some([u32::MAX, 0x1ff]));
            assert_eq!(
                child_capability_word_masks_v1(63),
                Some([u32::MAX, u32::MAX])
            );
            assert_eq!(child_capability_word_masks_v1(64), None);
        }

        #[test]
        fn capability_range_scan_requires_one_bounded_contiguous_prefix() {
            for last_capability in CAPABILITY_MINIMUM_LAST_V1..CAPABILITY_SCAN_MAX_V1 {
                let mut scan = capability_scan_fixture(last_capability, CAPABILITY_SCAN_CLEAR_V1);
                scan[last_capability as usize] = CAPABILITY_SCAN_SET_V1;
                assert_eq!(
                    child_last_capability_v1(&scan),
                    Some(last_capability),
                    "last capability {last_capability}",
                );
            }

            let too_old =
                capability_scan_fixture(CAPABILITY_MINIMUM_LAST_V1 - 1, CAPABILITY_SCAN_CLEAR_V1);
            assert_eq!(child_last_capability_v1(&too_old), None);

            let mut hole =
                capability_scan_fixture(CAPABILITY_MINIMUM_LAST_V1, CAPABILITY_SCAN_CLEAR_V1);
            hole[20] = CAPABILITY_SCAN_INVALID_V1;
            assert_eq!(child_last_capability_v1(&hole), None);

            let mut valid_after_invalid = [CAPABILITY_SCAN_INVALID_V1; CAPABILITY_SCAN_LENGTH_V1];
            valid_after_invalid[0] = CAPABILITY_SCAN_CLEAR_V1;
            valid_after_invalid[1] = CAPABILITY_SCAN_INVALID_V1;
            valid_after_invalid[2] = CAPABILITY_SCAN_SET_V1;
            assert_eq!(child_last_capability_v1(&valid_after_invalid), None);

            let valid_through_64 = [CAPABILITY_SCAN_CLEAR_V1; CAPABILITY_SCAN_LENGTH_V1];
            assert_eq!(child_last_capability_v1(&valid_through_64), None);

            for malformed in [CAPABILITY_SCAN_UNOBSERVED_V1, 2, i8::MAX] {
                let mut scan =
                    capability_scan_fixture(CAPABILITY_MINIMUM_LAST_V1, CAPABILITY_SCAN_CLEAR_V1);
                scan[10] = malformed;
                assert_eq!(child_last_capability_v1(&scan), None);
            }
        }

        #[test]
        fn capability_scan_syscall_results_and_errno_are_canonical() {
            assert_eq!(
                child_capability_scan_observation_with_errno_v1(0, MAX_LINUX_ERRNO_V1 + 1),
                Ok(CAPABILITY_SCAN_CLEAR_V1),
            );
            assert_eq!(
                child_capability_scan_observation_with_errno_v1(1, MAX_LINUX_ERRNO_V1 + 1),
                Ok(CAPABILITY_SCAN_SET_V1),
            );
            for errno in 1..=MAX_LINUX_ERRNO_V1 {
                let observed = child_capability_scan_observation_with_errno_v1(-1, errno);
                if errno == libc::EINVAL {
                    assert_eq!(observed, Ok(CAPABILITY_SCAN_INVALID_V1));
                } else {
                    assert_eq!(observed, Err(ChildCapabilityFailureV1::Os(errno)));
                }
            }
            for errno in [-1, 0, MAX_LINUX_ERRNO_V1 + 1] {
                assert_eq!(
                    child_capability_scan_observation_with_errno_v1(-1, errno),
                    Err(ChildCapabilityFailureV1::Invariant),
                );
            }
            for result in [-2, 2, libc::c_long::MAX] {
                assert_eq!(
                    child_capability_scan_observation_with_errno_v1(result, libc::EINVAL),
                    Err(ChildCapabilityFailureV1::Invariant),
                );
            }
        }

        #[test]
        fn empty_capability_scan_requires_zero_supported_bits_and_same_boundary() {
            for last_capability in [CAPABILITY_MINIMUM_LAST_V1, 63] {
                let scan = capability_scan_fixture(last_capability, CAPABILITY_SCAN_CLEAR_V1);
                assert!(child_empty_capability_scan_matches_v1(
                    &scan,
                    last_capability
                ));

                let mut set = scan;
                set[last_capability as usize] = CAPABILITY_SCAN_SET_V1;
                assert!(!child_empty_capability_scan_matches_v1(
                    &set,
                    last_capability
                ));

                let mut hole = scan;
                hole[0] = CAPABILITY_SCAN_INVALID_V1;
                assert!(!child_empty_capability_scan_matches_v1(
                    &hole,
                    last_capability
                ));

                let mut changed_boundary = scan;
                changed_boundary[last_capability as usize + 1] = CAPABILITY_SCAN_CLEAR_V1;
                assert!(!child_empty_capability_scan_matches_v1(
                    &changed_boundary,
                    last_capability
                ));
            }
        }

        #[test]
        fn capability_v3_headers_and_initial_sets_are_exact() {
            assert_eq!(std::mem::size_of::<LinuxCapabilityHeaderV1>(), 8);
            assert_eq!(std::mem::size_of::<LinuxCapabilityDataV1>(), 12);
            assert_eq!(std::mem::size_of::<[LinuxCapabilityDataV1; 2]>(), 24);
            let exact_header = LinuxCapabilityHeaderV1 {
                version: LINUX_CAPABILITY_VERSION_3_V1,
                pid: 0,
            };
            assert!(child_capability_header_is_exact_v1(&exact_header));
            assert!(!child_capability_header_is_exact_v1(
                &LinuxCapabilityHeaderV1 {
                    version: LINUX_CAPABILITY_VERSION_3_V1 ^ 1,
                    ..exact_header
                }
            ));
            assert!(!child_capability_header_is_exact_v1(
                &LinuxCapabilityHeaderV1 {
                    pid: 1,
                    ..exact_header
                }
            ));

            let exact = admissible_capability_sets();
            assert!(child_capability_sets_are_admissible_v1(
                &exact,
                CAPABILITY_MINIMUM_LAST_V1
            ));
            assert!(child_capability_sets_are_admissible_v1(&exact, 63));

            let mut missing_effective = exact;
            missing_effective[0].effective = 0;
            assert!(!child_capability_sets_are_admissible_v1(
                &missing_effective,
                CAPABILITY_MINIMUM_LAST_V1
            ));
            let mut missing_permitted = exact;
            missing_permitted[0].permitted = 0;
            assert!(!child_capability_sets_are_admissible_v1(
                &missing_permitted,
                CAPABILITY_MINIMUM_LAST_V1
            ));

            for field in 0..3 {
                let mut above_last = exact;
                let forbidden = 1_u32 << (CAPABILITY_MINIMUM_LAST_V1 + 1 - 32);
                match field {
                    0 => above_last[1].effective |= forbidden,
                    1 => above_last[1].permitted |= forbidden,
                    2 => above_last[1].inheritable |= forbidden,
                    _ => unreachable!(),
                }
                assert!(!child_capability_sets_are_admissible_v1(
                    &above_last,
                    CAPABILITY_MINIMUM_LAST_V1,
                ));
            }
            assert!(!child_capability_sets_are_admissible_v1(&exact, 64));
        }

        #[test]
        fn final_capability_sets_require_all_six_words_zero() {
            let empty = [LinuxCapabilityDataV1::default(); 2];
            assert!(child_capability_sets_are_empty_v1(&empty));
            for field in 0..6 {
                let mut nonempty = empty;
                match field {
                    0 => nonempty[0].effective = 1,
                    1 => nonempty[0].permitted = 1,
                    2 => nonempty[0].inheritable = 1,
                    3 => nonempty[1].effective = 1,
                    4 => nonempty[1].permitted = 1,
                    5 => nonempty[1].inheritable = 1,
                    _ => unreachable!(),
                }
                assert!(!child_capability_sets_are_empty_v1(&nonempty));
            }
        }

        #[test]
        fn securebits_and_no_new_privileges_values_are_frozen() {
            assert_eq!(CAPABILITY_SECUREBITS_V1, 0xef);
            for bit in [
                libc::SECBIT_NOROOT,
                libc::SECBIT_NOROOT_LOCKED,
                libc::SECBIT_NO_SETUID_FIXUP,
                libc::SECBIT_NO_SETUID_FIXUP_LOCKED,
                libc::SECBIT_KEEP_CAPS_LOCKED,
                libc::SECBIT_NO_CAP_AMBIENT_RAISE,
                libc::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
            ] {
                assert_ne!(CAPABILITY_SECUREBITS_V1 & bit, 0);
                assert_eq!(
                    child_require_exact_capability_value_v1(
                        libc::c_long::from(CAPABILITY_SECUREBITS_V1 & !bit),
                        libc::c_long::from(CAPABILITY_SECUREBITS_V1),
                    ),
                    Err(ChildCapabilityFailureV1::Invariant),
                );
            }
            assert_eq!(CAPABILITY_SECUREBITS_V1 & libc::SECBIT_KEEP_CAPS, 0);
            assert_eq!(
                child_require_exact_capability_value_v1(
                    libc::c_long::from(CAPABILITY_SECUREBITS_V1),
                    libc::c_long::from(CAPABILITY_SECUREBITS_V1),
                ),
                Ok(()),
            );
            for wrong in [
                0,
                libc::c_long::from(CAPABILITY_SECUREBITS_V1 ^ libc::SECBIT_NOROOT),
                libc::c_long::from(CAPABILITY_SECUREBITS_V1 | libc::SECBIT_KEEP_CAPS),
                libc::c_long::from(CAPABILITY_SECUREBITS_V1 | libc::SECBIT_EXEC_RESTRICT_FILE),
            ] {
                assert_eq!(
                    child_require_exact_capability_value_v1(
                        wrong,
                        libc::c_long::from(CAPABILITY_SECUREBITS_V1),
                    ),
                    Err(ChildCapabilityFailureV1::Invariant),
                );
            }
            assert_eq!(child_require_exact_capability_value_v1(1, 1), Ok(()));
            for wrong in [0, 2, libc::c_long::MAX] {
                assert_eq!(
                    child_require_exact_capability_value_v1(wrong, 1),
                    Err(ChildCapabilityFailureV1::Invariant),
                );
            }
        }

        #[test]
        fn landlock_uapi_layout_and_policy_constants_are_exact() {
            assert_eq!(std::mem::size_of::<LinuxLandlockRulesetAttrV1>(), 24);
            assert_eq!(std::mem::align_of::<LinuxLandlockRulesetAttrV1>(), 8);
            assert_eq!(
                std::mem::offset_of!(LinuxLandlockRulesetAttrV1, handled_access_fs),
                0
            );
            assert_eq!(
                std::mem::offset_of!(LinuxLandlockRulesetAttrV1, handled_access_net),
                8
            );
            assert_eq!(std::mem::offset_of!(LinuxLandlockRulesetAttrV1, scoped), 16);
            assert_eq!(std::mem::size_of::<LinuxLandlockPathBeneathAttrV1>(), 12);
            assert_eq!(std::mem::align_of::<LinuxLandlockPathBeneathAttrV1>(), 1);
            assert_eq!(
                std::mem::offset_of!(LinuxLandlockPathBeneathAttrV1, allowed_access),
                0,
            );
            assert_eq!(
                std::mem::offset_of!(LinuxLandlockPathBeneathAttrV1, parent_fd),
                8,
            );

            let ruleset = LinuxLandlockRulesetAttrV1 {
                handled_access_fs: LANDLOCK_HANDLED_FS_V1,
                handled_access_net: LANDLOCK_HANDLED_NET_V1,
                scoped: LANDLOCK_SCOPED_V1,
            };
            assert_eq!(ruleset.handled_access_fs, 0xffff);
            assert_eq!(ruleset.handled_access_net, 0x3);
            assert_eq!(ruleset.scoped, 0x3);
            assert_eq!(LANDLOCK_CREATE_RULESET_VERSION_V1, 1);
            assert_eq!(LANDLOCK_RULE_PATH_BENEATH_V1, 1);
            assert_eq!(LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF_V1, 1);
            assert_eq!(
                [
                    (TMP_NAME_V1.to_bytes(), LANDLOCK_TMP_ACCESS_V1),
                    (
                        RUN_RESTRICTED_RELATIVE_PATH_V1.to_bytes(),
                        LANDLOCK_RESTRICTED_ACCESS_V1,
                    ),
                ],
                [
                    (b"tmp".as_slice(), 0x77be),
                    (b"run/restricted".as_slice(), 0x17be),
                ],
            );
            assert_eq!(LANDLOCK_MAX_TRACKED_FDS_V1, 2);
            assert_eq!(LANDLOCK_FIRST_TRANSIENT_FD_V1, 2);

            let address = child_landlock_loopback_address_v1(0x1234);
            assert_eq!(address.sin_family, libc::AF_INET as libc::sa_family_t);
            assert_eq!(address.sin_port, 0x1234_u16.to_be());
            assert_eq!(address.sin_addr.s_addr, u32::from_be(0x7f00_0001));
            let port_bytes = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!(address.sin_port).cast::<u8>(),
                    std::mem::size_of::<u16>(),
                )
            };
            let address_bytes = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!(address.sin_addr.s_addr).cast::<u8>(),
                    std::mem::size_of::<u32>(),
                )
            };
            assert_eq!(port_bytes, [0x12, 0x34]);
            assert_eq!(address_bytes, [127, 0, 0, 1]);
            for port in [0, 1] {
                let address = child_landlock_loopback_address_v1(port);
                assert_eq!(u16::from_be(address.sin_port), port);
                assert_eq!(u32::from_be(address.sin_addr.s_addr), 0x7f00_0001);
            }
        }

        #[test]
        fn seccomp_uapi_program_and_syscall_contract_are_exact() {
            assert_eq!(std::mem::size_of::<LinuxSockFilterV1>(), 8);
            assert_eq!(std::mem::align_of::<LinuxSockFilterV1>(), 4);
            assert_eq!(std::mem::offset_of!(LinuxSockFilterV1, code), 0);
            assert_eq!(std::mem::offset_of!(LinuxSockFilterV1, jump_true), 2);
            assert_eq!(std::mem::offset_of!(LinuxSockFilterV1, jump_false), 3);
            assert_eq!(std::mem::offset_of!(LinuxSockFilterV1, operand), 4);
            assert_eq!(std::mem::size_of::<LinuxSockFprogV1>(), 16);
            assert_eq!(std::mem::align_of::<LinuxSockFprogV1>(), 8);
            assert_eq!(std::mem::offset_of!(LinuxSockFprogV1, length), 0);
            assert_eq!(std::mem::offset_of!(LinuxSockFprogV1, filter), 8);
            assert_eq!(std::mem::size_of::<LinuxSeccompDataV1>(), 64);
            assert_eq!(std::mem::align_of::<LinuxSeccompDataV1>(), 8);
            assert_eq!(std::mem::offset_of!(LinuxSeccompDataV1, syscall), 0);
            assert_eq!(std::mem::offset_of!(LinuxSeccompDataV1, architecture), 4);
            assert_eq!(
                std::mem::offset_of!(LinuxSeccompDataV1, instruction_pointer),
                8
            );
            assert_eq!(std::mem::offset_of!(LinuxSeccompDataV1, arguments), 16);
            assert_eq!(SECCOMP_FILTER_INSTRUCTION_COUNT_V1, 93);
            assert_eq!(SECCOMP_SET_MODE_FILTER_V1, 1);
            assert_eq!(SECCOMP_GET_ACTION_AVAIL_V1, 2);
            assert_eq!(SECCOMP_FILTER_FLAG_TSYNC_V1, 1);
            assert_eq!(SECCOMP_RET_KILL_PROCESS_V1, 0x8000_0000);
            assert_eq!(SECCOMP_RET_ERRNO_V1, 0x0005_0000);
            assert_eq!(SECCOMP_RET_ALLOW_V1, 0x7fff_0000);
            assert_eq!(SECCOMP_ERRNO_MARKER_V1, 0x05a5);
            assert_eq!(SECCOMP_RET_MARKER_V1, 0x0005_05a5);
            assert_eq!(AUDIT_ARCH_X86_64_V1, 0xc000_003e);
            assert_eq!(X32_SYSCALL_BIT_V1, 0x4000_0000);
            assert_eq!(SECCOMP_DATA_NR_OFFSET_V1, 0);
            assert_eq!(SECCOMP_DATA_ARCH_OFFSET_V1, 4);
            assert_eq!(SECCOMP_DATA_ARGS_OFFSET_V1, 16);
            assert_eq!(SECCOMP_DATA_ARG_STRIDE_V1, 8);
            assert_eq!(SECCOMP_DATA_ARG_HIGH_OFFSET_V1, 4);
            assert_eq!(SECCOMP_MAX_POLL_MILLISECONDS_V1, 8_000);
            assert_eq!(SECCOMP_PR_GET_SECCOMP_V1, libc::PR_GET_SECCOMP as u32);
            assert_eq!(
                SECCOMP_PR_GET_NO_NEW_PRIVS_V1,
                libc::PR_GET_NO_NEW_PRIVS as u32
            );
            for (frozen, libc_number) in [
                (SECCOMP_SYSCALL_WRITE_V1, libc::SYS_write),
                (SECCOMP_SYSCALL_CLOSE_V1, libc::SYS_close),
                (SECCOMP_SYSCALL_POLL_V1, libc::SYS_poll),
                (SECCOMP_SYSCALL_IOCTL_V1, libc::SYS_ioctl),
                (SECCOMP_SYSCALL_SOCKET_V1, libc::SYS_socket),
                (SECCOMP_SYSCALL_EXIT_V1, libc::SYS_exit),
                (SECCOMP_SYSCALL_PRCTL_V1, libc::SYS_prctl),
                (SECCOMP_SYSCALL_CLOCK_GETTIME_V1, libc::SYS_clock_gettime),
                (SECCOMP_SYSCALL_OPENAT_V1, libc::SYS_openat),
                (SECCOMP_SYSCALL_UNSHARE_V1, libc::SYS_unshare),
                (SECCOMP_SYSCALL_SETNS_V1, libc::SYS_setns),
                (SECCOMP_SYSCALL_CLONE3_V1, libc::SYS_clone3),
            ] {
                assert_eq!(u64::from(frozen), libc_number as u64);
            }
            assert_eq!(SECCOMP_EXIT_SUCCESS_V1, 0);
            assert_eq!(SECCOMP_EXIT_FAILURE_V1, 125);
        }

        #[test]
        fn seccomp_filter_has_one_frozen_byte_sequence() {
            assert_eq!(seccomp_filter_fingerprint_v1(), 0x1858_59bb_c152_5aac);
            assert!(seccomp_filter_is_structurally_valid_v1());
        }

        #[test]
        fn seccomp_filter_allows_only_the_terminal_proof_surface() {
            let evaluate = |syscall, arguments| {
                evaluate_seccomp_filter_v1(AUDIT_ARCH_X86_64_V1, syscall, arguments)
                    .expect("fixed filter did not terminate")
            };

            let mut write = [0_u64; 6];
            write[1] = 0x1234_5678_9abc_def0;
            write[2] = FRAME_BYTES_V1 as u64;
            assert_eq!(
                evaluate(SECCOMP_SYSCALL_WRITE_V1, write),
                SECCOMP_RET_ALLOW_V1
            );
            for (argument, value) in [
                (0, 1),
                (0, 1_u64 << 32),
                (2, 63),
                (2, (FRAME_BYTES_V1 as u64) | (1_u64 << 32)),
            ] {
                let mut changed = write;
                changed[argument] = value;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_WRITE_V1, changed),
                    SECCOMP_RET_MARKER_V1
                );
            }

            let mut poll = [0_u64; 6];
            poll[0] = u64::MAX;
            poll[1] = 1;
            for timeout in [0, 1, SECCOMP_MAX_POLL_MILLISECONDS_V1 as u64] {
                poll[2] = timeout;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_POLL_V1, poll),
                    SECCOMP_RET_ALLOW_V1
                );
            }
            for (argument, value) in [
                (1, 0),
                (1, 2),
                (1, 1 | (1_u64 << 32)),
                (2, u64::from(SECCOMP_MAX_POLL_MILLISECONDS_V1) + 1),
                (2, 1_u64 << 32),
            ] {
                let mut changed = poll;
                changed[argument] = value;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_POLL_V1, changed),
                    SECCOMP_RET_MARKER_V1
                );
            }

            let mut clock = [0_u64; 6];
            clock[0] = libc::CLOCK_MONOTONIC as u64;
            clock[1] = u64::MAX;
            assert_eq!(
                evaluate(SECCOMP_SYSCALL_CLOCK_GETTIME_V1, clock),
                SECCOMP_RET_ALLOW_V1
            );
            for clock_id in [0, 2, (libc::CLOCK_MONOTONIC as u64) | (1_u64 << 32)] {
                clock[0] = clock_id;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_CLOCK_GETTIME_V1, clock),
                    SECCOMP_RET_MARKER_V1
                );
            }

            for option in [SECCOMP_PR_GET_SECCOMP_V1, SECCOMP_PR_GET_NO_NEW_PRIVS_V1] {
                let mut arguments = [0_u64; 6];
                arguments[0] = u64::from(option);
                arguments[5] = u64::MAX;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_PRCTL_V1, arguments),
                    SECCOMP_RET_ALLOW_V1
                );
                for argument in 1..=4 {
                    for value in [1, 1_u64 << 32] {
                        let mut changed = arguments;
                        changed[argument] = value;
                        assert_eq!(
                            evaluate(SECCOMP_SYSCALL_PRCTL_V1, changed),
                            SECCOMP_RET_MARKER_V1
                        );
                    }
                }
            }
            for option in [0, 1, u64::from(SECCOMP_PR_GET_SECCOMP_V1) | (1_u64 << 32)] {
                let mut arguments = [0_u64; 6];
                arguments[0] = option;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_PRCTL_V1, arguments),
                    SECCOMP_RET_MARKER_V1
                );
            }

            assert_eq!(
                evaluate(SECCOMP_SYSCALL_CLOSE_V1, [0; 6]),
                SECCOMP_RET_ALLOW_V1
            );
            for descriptor in [1, 1_u64 << 32] {
                let mut arguments = [0_u64; 6];
                arguments[0] = descriptor;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_CLOSE_V1, arguments),
                    SECCOMP_RET_MARKER_V1
                );
            }

            for status in [SECCOMP_EXIT_SUCCESS_V1, SECCOMP_EXIT_FAILURE_V1] {
                let mut arguments = [0_u64; 6];
                arguments[0] = u64::from(status);
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_EXIT_V1, arguments),
                    SECCOMP_RET_ALLOW_V1
                );
            }
            for status in [1, 124, 126, 1_u64 << 32] {
                let mut arguments = [0_u64; 6];
                arguments[0] = status;
                assert_eq!(
                    evaluate(SECCOMP_SYSCALL_EXIT_V1, arguments),
                    SECCOMP_RET_MARKER_V1
                );
            }
        }

        #[test]
        fn seccomp_filter_kills_wrong_abi_and_marks_every_canary() {
            let evaluate = |architecture, syscall| {
                evaluate_seccomp_filter_v1(architecture, syscall, [0_u64; 6])
                    .expect("fixed filter did not terminate")
            };
            assert_eq!(
                evaluate(AUDIT_ARCH_X86_64_V1 ^ 1, SECCOMP_SYSCALL_WRITE_V1),
                SECCOMP_RET_KILL_PROCESS_V1
            );
            assert_eq!(
                evaluate(
                    AUDIT_ARCH_X86_64_V1,
                    SECCOMP_SYSCALL_WRITE_V1 | X32_SYSCALL_BIT_V1,
                ),
                SECCOMP_RET_KILL_PROCESS_V1
            );
            for syscall in [
                SECCOMP_SYSCALL_UNSHARE_V1,
                SECCOMP_SYSCALL_SETNS_V1,
                SECCOMP_SYSCALL_CLONE3_V1,
                SECCOMP_SYSCALL_SOCKET_V1,
                SECCOMP_SYSCALL_IOCTL_V1,
                SECCOMP_SYSCALL_OPENAT_V1,
                0,
                u32::MAX & !X32_SYSCALL_BIT_V1,
            ] {
                assert_eq!(
                    evaluate(AUDIT_ARCH_X86_64_V1, syscall),
                    SECCOMP_RET_MARKER_V1,
                    "syscall {syscall}",
                );
            }
        }

        #[test]
        fn seccomp_result_classifiers_are_exact_and_do_not_launder_errors() {
            for action in [SECCOMP_RET_ERRNO_V1, SECCOMP_RET_KILL_PROCESS_V1] {
                assert_eq!(
                    child_seccomp_action_query_result_with_errno_v1(0, libc::EIO, action, action),
                    Ok(())
                );
                assert_eq!(
                    child_seccomp_action_query_result_with_errno_v1(0, 0, action ^ 1, action),
                    Err(ChildSeccompFailureV1::Invariant)
                );
                for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
                    assert_eq!(
                        child_seccomp_action_query_result_with_errno_v1(-1, errno, action, action,),
                        Err(ChildSeccompFailureV1::Unavailable(errno))
                    );
                }
                for errno in [libc::EINVAL, libc::EPERM, libc::EACCES, MAX_LINUX_ERRNO_V1] {
                    assert_eq!(
                        child_seccomp_action_query_result_with_errno_v1(-1, errno, action, action,),
                        Err(ChildSeccompFailureV1::Os(errno))
                    );
                }
                for (result, errno, observed) in [
                    (1, 0, action),
                    (-2, 0, action),
                    (-1, 0, action),
                    (-1, -1, action),
                    (-1, MAX_LINUX_ERRNO_V1 + 1, action),
                    (-1, libc::ENOSYS, action ^ 1),
                ] {
                    assert_eq!(
                        child_seccomp_action_query_result_with_errno_v1(
                            result, errno, observed, action,
                        ),
                        Err(ChildSeccompFailureV1::Invariant)
                    );
                }
            }

            for expected in [SECCOMP_MODE_DISABLED_V1, SECCOMP_MODE_FILTER_V1, 1] {
                assert_eq!(
                    child_seccomp_exact_result_with_errno_v1(expected, libc::EIO, expected),
                    Ok(())
                );
                for positive in [1, 2, 42, libc::c_long::MAX] {
                    if positive != expected {
                        assert_eq!(
                            child_seccomp_exact_result_with_errno_v1(positive, 0, expected),
                            Err(ChildSeccompFailureV1::Invariant)
                        );
                    }
                }
                for errno in [
                    libc::ENOSYS,
                    libc::EOPNOTSUPP,
                    libc::EINVAL,
                    libc::EPERM,
                    libc::EACCES,
                ] {
                    assert_eq!(
                        child_seccomp_exact_result_with_errno_v1(-1, errno, expected),
                        Err(ChildSeccompFailureV1::Os(errno))
                    );
                }
            }

            assert_eq!(
                child_seccomp_marker_result_with_errno_v1(-1, i32::from(SECCOMP_ERRNO_MARKER_V1),),
                Ok(())
            );
            for errno in [libc::EPERM, libc::EACCES, libc::EINVAL, MAX_LINUX_ERRNO_V1] {
                assert_eq!(
                    child_seccomp_marker_result_with_errno_v1(-1, errno),
                    Err(ChildSeccompFailureV1::Os(errno))
                );
            }
            for (result, errno) in [
                (0, i32::from(SECCOMP_ERRNO_MARKER_V1)),
                (1, i32::from(SECCOMP_ERRNO_MARKER_V1)),
                (-2, i32::from(SECCOMP_ERRNO_MARKER_V1)),
                (-1, 0),
                (-1, -1),
                (-1, MAX_LINUX_ERRNO_V1 + 1),
            ] {
                assert_eq!(
                    child_seccomp_marker_result_with_errno_v1(result, errno),
                    Err(ChildSeccompFailureV1::Invariant)
                );
            }
        }

        #[test]
        fn landlock_version_results_accept_abi_six_and_compatible_newer_prefixes() {
            for version in 1..=5 {
                assert_eq!(
                    child_landlock_policy_from_version_result_v1(version, 0),
                    Err(ChildLandlockFailureV1::Unavailable(0)),
                );
            }
            assert_eq!(
                child_landlock_policy_from_version_result_v1(6, 0),
                Ok(ChildLandlockPolicyV1::Abi6),
            );
            assert_eq!(
                child_landlock_policy_from_version_result_v1(7, 0),
                Ok(ChildLandlockPolicyV1::Abi7OrNewer),
            );
            for version in [8, 9, 10, LANDLOCK_ABI_MAX_V1] {
                assert_eq!(
                    child_landlock_policy_from_version_result_v1(version, 0),
                    Ok(ChildLandlockPolicyV1::Abi7OrNewer),
                );
            }
            assert_eq!(
                child_landlock_policy_from_version_result_v1(libc::c_long::MAX, 0),
                Err(ChildLandlockFailureV1::Invariant),
            );
            assert_eq!(
                child_landlock_restrict_flags_v1(ChildLandlockPolicyV1::Abi6),
                0
            );
            assert_eq!(
                child_landlock_restrict_flags_v1(ChildLandlockPolicyV1::Abi7OrNewer),
                1
            );

            for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
                assert_eq!(
                    child_landlock_policy_from_version_result_v1(-1, errno),
                    Err(ChildLandlockFailureV1::Unavailable(errno)),
                );
            }
            for errno in [libc::EINVAL, libc::EPERM, libc::EACCES, MAX_LINUX_ERRNO_V1] {
                assert_eq!(
                    child_landlock_policy_from_version_result_v1(-1, errno),
                    Err(ChildLandlockFailureV1::Os(errno)),
                );
            }
            for (result, errno) in [
                (0, 0),
                (6, libc::EIO),
                (7, libc::EIO),
                (-2, 0),
                (-1, 0),
                (-1, -1),
                (-1, MAX_LINUX_ERRNO_V1 + 1),
            ] {
                assert_eq!(
                    child_landlock_policy_from_version_result_v1(result, errno),
                    Err(ChildLandlockFailureV1::Invariant),
                );
            }
        }

        #[test]
        fn landlock_tracker_accepts_only_exact_contiguous_fd_slots() {
            for (descriptors, next) in [([-1, -1], Some(0)), ([2, -1], Some(1)), ([2, 3], Some(2))]
            {
                let tracked = ChildLandlockTrackedFdsV1 {
                    audit_descriptor: FD_AUDIT_DESCRIPTOR_V1,
                    descriptors,
                };
                assert_eq!(child_landlock_tracker_next_slot_v1(&tracked), next);
            }
            for descriptors in [
                [-2, -1],
                [0, -1],
                [1, -1],
                [3, -1],
                [-1, 3],
                [2, 2],
                [3, 2],
                [2, 4],
            ] {
                let tracked = ChildLandlockTrackedFdsV1 {
                    audit_descriptor: FD_AUDIT_DESCRIPTOR_V1,
                    descriptors,
                };
                assert_eq!(child_landlock_tracker_next_slot_v1(&tracked), None);
            }
        }

        #[test]
        fn landlock_syscall_result_classifiers_are_exact() {
            assert_eq!(
                child_landlock_require_errno_result_with_errno_v1(-1, libc::EACCES, libc::EACCES),
                Ok(()),
            );
            assert_eq!(
                child_landlock_require_errno_result_with_errno_v1(-1, libc::EPERM, libc::EACCES),
                Err(ChildLandlockFailureV1::Os(libc::EPERM)),
            );
            for (result, errno) in [(0, 0), (1, 0), (-2, libc::EACCES)] {
                assert_eq!(
                    child_landlock_require_errno_result_with_errno_v1(result, errno, libc::EACCES,),
                    Err(ChildLandlockFailureV1::Invariant),
                );
            }
            for errno in [-1, 0, MAX_LINUX_ERRNO_V1 + 1] {
                assert_eq!(
                    child_landlock_require_errno_result_with_errno_v1(-1, errno, libc::EACCES),
                    Err(ChildLandlockFailureV1::Invariant),
                );
            }
            for expected in [-1, 0, MAX_LINUX_ERRNO_V1 + 1] {
                assert_eq!(
                    child_landlock_require_errno_result_with_errno_v1(-1, expected, expected),
                    Err(ChildLandlockFailureV1::Invariant),
                );
            }

            assert_eq!(child_landlock_close_result_v1(0, libc::EIO, false), Ok(()));
            assert_eq!(
                child_landlock_close_result_v1(-1, libc::EINTR, false),
                Ok(()),
            );
            assert_eq!(
                child_landlock_close_result_v1(-1, libc::EBADF, false),
                Err(ChildLandlockFailureV1::Os(libc::EBADF)),
            );
            assert_eq!(
                child_landlock_close_result_v1(-1, libc::EBADF, true),
                Ok(()),
            );
            assert_eq!(
                child_landlock_close_result_v1(-1, libc::EIO, true),
                Err(ChildLandlockFailureV1::Os(libc::EIO)),
            );
            for (result, errno) in [(1, 0), (-2, 0), (-1, 0), (-1, 4096)] {
                assert_eq!(
                    child_landlock_close_result_v1(result, errno, false),
                    Err(ChildLandlockFailureV1::Invariant),
                );
            }
        }

        #[test]
        fn fd_audit_dirent_parser_accepts_only_exact_bounded_inventory() {
            let first = fd_audit_chunk(&[b"1", b"."]);
            let second = fd_audit_chunk(&[b"0", b".."]);
            let mut seen = 0_u8;
            assert!(child_parse_fd_audit_dirents_v1(&first, &mut seen));
            assert_ne!(seen, FD_AUDIT_COMPLETE_MASK_V1);
            assert!(child_parse_fd_audit_dirents_v1(&second, &mut seen));
            assert_eq!(seen, FD_AUDIT_COMPLETE_MASK_V1);

            for name in [
                b"2".as_slice(),
                b"x".as_slice(),
                b"00".as_slice(),
                b"01".as_slice(),
                b"".as_slice(),
            ] {
                assert!(!child_parse_fd_audit_dirents_v1(
                    &fd_audit_dirent(name),
                    &mut 0_u8,
                ));
            }
            for duplicate in [b".".as_slice(), b"..".as_slice(), b"0".as_slice(), b"1"] {
                assert!(!child_parse_fd_audit_dirents_v1(
                    &fd_audit_chunk(&[duplicate, duplicate]),
                    &mut 0_u8,
                ));
            }

            let valid = fd_audit_dirent(b"0");
            let mut empty_seen = FD_AUDIT_ONE_BIT_V1;
            assert!(child_parse_fd_audit_dirents_v1(&[], &mut empty_seen));
            assert_eq!(empty_seen, FD_AUDIT_ONE_BIT_V1);
            for header_length in 1..DIRENT64_MIN_RECORD_BYTES_V1 {
                assert!(!child_parse_fd_audit_dirents_v1(
                    &valid[..header_length],
                    &mut 0_u8,
                ));
            }
            let mut zero_record = valid.clone();
            zero_record[16..18].copy_from_slice(&0_u16.to_ne_bytes());
            let mut short_record = valid.clone();
            short_record[16..18]
                .copy_from_slice(&((DIRENT64_MIN_RECORD_BYTES_V1 - 1) as u16).to_ne_bytes());
            let mut unaligned_record = valid.clone();
            unaligned_record.resize(DIRENT64_MIN_RECORD_BYTES_V1 + DIRENT64_ALIGNMENT_V1, 0);
            unaligned_record[16..18]
                .copy_from_slice(&((DIRENT64_MIN_RECORD_BYTES_V1 + 1) as u16).to_ne_bytes());
            let mut out_of_bounds_record = valid.clone();
            out_of_bounds_record[16..18]
                .copy_from_slice(&((valid.len() + DIRENT64_ALIGNMENT_V1) as u16).to_ne_bytes());
            let mut unterminated_record = fd_audit_dirent(b"0");
            unterminated_record[DIRENT64_NAME_OFFSET_V1..].fill(b'x');
            let mut trailing_partial = fd_audit_dirent(b"0");
            trailing_partial.push(0);
            for malformed in [
                zero_record,
                short_record,
                unaligned_record,
                out_of_bounds_record,
                unterminated_record,
                trailing_partial,
            ] {
                assert!(!child_parse_fd_audit_dirents_v1(&malformed, &mut 0_u8,));
            }

            for missing in [
                [b"..".as_slice(), b"0".as_slice(), b"1".as_slice()],
                [b".".as_slice(), b"0".as_slice(), b"1".as_slice()],
                [b".".as_slice(), b"..".as_slice(), b"1".as_slice()],
                [b".".as_slice(), b"..".as_slice(), b"0".as_slice()],
            ] {
                let mut seen = 0_u8;
                assert!(child_parse_fd_audit_dirents_v1(
                    &fd_audit_chunk(&missing),
                    &mut seen,
                ));
                assert_ne!(seen, FD_AUDIT_COMPLETE_MASK_V1);
            }

            let mut unknown_type = fd_audit_dirent(b"0");
            unknown_type[18] = libc::DT_UNKNOWN;
            let mut seen = 0_u8;
            assert!(child_parse_fd_audit_dirents_v1(&unknown_type, &mut seen,));
            assert_eq!(seen, FD_AUDIT_ZERO_BIT_V1);
        }

        #[test]
        fn disposable_child_range_closes_sparse_fds_and_reports_exact_inventory() {
            let (read, write) = test_pipe();
            let report_write = unsafe {
                libc::fcntl(
                    write.as_raw_fd(),
                    libc::F_DUPFD_CLOEXEC,
                    libc::STDERR_FILENO + 1,
                )
            };
            assert!(report_write > libc::STDERR_FILENO);
            let report_write = unsafe { OwnedFd::from_raw_fd(report_write) };
            drop(write);

            let nonce = [0x9b_u8; NONCE_BYTES_V1];
            let (deadline, hard_deadline) = probe_deadlines()
                .unwrap_or_else(|_| panic!("disposable child deadlines were unavailable"));
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                disposable_fd_scrub_child_v1(report_write.as_raw_fd(), &nonce, deadline);
            }
            assert!(pid > 0, "fork for disposable descriptor child failed");
            let mut child_guard = ProbeChildGuardV1 {
                pid: Some(pid),
                pidfd: None,
                control_write: None,
                report_read: None,
                proc_directory: None,
                child_namespaces: None,
                deadline: hard_deadline,
                reaped: false,
            };
            let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
            let pidfd_errno = (pidfd < 0).then(last_errno).flatten();
            let Some(pidfd) = RawFd::try_from(pidfd).ok().filter(|pidfd| *pidfd >= 0) else {
                let cleanup = child_guard.kill_and_reap();
                assert!(cleanup.is_ok(), "pidfd failure also left cleanup uncertain");
                panic!("pidfd_open failed for disposable child: {pidfd_errno:?}");
            };
            child_guard.pidfd = Some(unsafe { OwnedFd::from_raw_fd(pidfd) });
            drop(report_write);

            let mut frame = [0_u8; FRAME_BYTES_V1];
            let received = child_read_frame_and_eof(read.as_raw_fd(), &mut frame, deadline);
            if !received {
                let cleanup = child_guard.kill_and_reap();
                assert!(cleanup.is_ok(), "failed child cleanup was uncertain");
                panic!("disposable descriptor child sent no exact test evidence");
            }
            if let Err(error) = child_guard.reap_success(deadline) {
                let cleanup = child_guard.kill_and_reap();
                assert!(cleanup.is_ok(), "terminal child cleanup was uncertain");
                panic!(
                    "disposable descriptor child was not a clean exit: {}/{}",
                    error.stage(),
                    error.reason(),
                );
            }
            assert!(child_guard.reaped);
            assert_eq!(frame, disposable_fd_scrub_evidence_v1(&nonce));
        }

        #[test]
        fn scratch_policy_rejects_unbounded_or_weakened_mounts() {
            assert!(child_scratch_statfs_matches_policy_v1(
                &scratch_policy_statfs()
            ));

            let mut wrong_type = scratch_policy_statfs();
            wrong_type.f_type = 0;
            let mut missing_nodev = scratch_policy_statfs();
            missing_nodev.f_flags &= !(libc::ST_NODEV as libc::c_long);
            let mut missing_nosuid = scratch_policy_statfs();
            missing_nosuid.f_flags &= !(libc::ST_NOSUID as libc::c_long);
            let mut missing_noexec = scratch_policy_statfs();
            missing_noexec.f_flags &= !(libc::ST_NOEXEC as libc::c_long);
            let mut read_only = scratch_policy_statfs();
            read_only.f_flags |= libc::ST_RDONLY as libc::c_long;
            let mut too_many_blocks = scratch_policy_statfs();
            too_many_blocks.f_blocks += 1;
            let mut zero_blocks = scratch_policy_statfs();
            zero_blocks.f_blocks = 0;
            let mut too_many_inodes = scratch_policy_statfs();
            too_many_inodes.f_files += 1;
            let mut zero_inodes = scratch_policy_statfs();
            zero_inodes.f_files = 0;
            for filesystem in [
                wrong_type,
                missing_nodev,
                missing_nosuid,
                missing_noexec,
                read_only,
                too_many_blocks,
                zero_blocks,
                too_many_inodes,
                zero_inodes,
            ] {
                assert!(!child_scratch_statfs_matches_policy_v1(&filesystem));
            }
        }

        #[test]
        fn scratch_mount_identity_requires_every_pair_to_be_independent() {
            assert!(scratch_independence_fixture(
                [2, 3, 4],
                [(0, 2), (0, 3), (0, 4)]
            ));
            for mount_ids in [[2, 2, 4], [2, 3, 2], [2, 3, 3]] {
                assert!(!scratch_independence_fixture(
                    mount_ids,
                    [(0, 2), (0, 3), (0, 4)]
                ));
            }
            for devices in [
                [(0, 0), (0, 3), (0, 4)],
                [(0, 2), (0, 0), (0, 4)],
                [(0, 2), (0, 3), (0, 0)],
                [(0, 2), (0, 2), (0, 4)],
                [(0, 2), (0, 3), (0, 2)],
                [(0, 2), (0, 3), (0, 3)],
            ] {
                assert!(!scratch_independence_fixture([2, 3, 4], devices));
            }
        }

        #[test]
        fn procfs_policy_requires_readonly_and_all_security_flags() {
            assert!(child_procfs_statfs_matches_policy_v1(&proc_policy_statfs()));
            let mut wrong_type = proc_policy_statfs();
            wrong_type.f_type = 0;
            assert!(!child_procfs_statfs_matches_policy_v1(&wrong_type));
            for flag in [
                libc::ST_RDONLY,
                libc::ST_NODEV,
                libc::ST_NOSUID,
                libc::ST_NOEXEC,
            ] {
                let mut missing = proc_policy_statfs();
                missing.f_flags &= !(flag as libc::c_long);
                assert!(!child_procfs_statfs_matches_policy_v1(&missing));
            }
        }

        #[test]
        fn ready_frame_commits_phase_nonce_and_reserved_bytes() {
            let nonce = [0x5a_u8; NONCE_BYTES_V1];
            let frame = child_encode_common_frame(READY_MAGIC_V1, PHASE_READY_V1, &nonce);
            assert!(verify_ready_frame(&frame, &nonce).is_ok());

            for offset in [
                0,
                FRAME_VERSION_OFFSET_V1,
                FRAME_PHASE_OFFSET_V1,
                FRAME_STATUS_OFFSET_V1,
                FRAME_FLAGS_OFFSET_V1,
                13,
                14,
                15,
                31,
                63,
            ] {
                let mut changed = frame;
                changed[offset] ^= 1;
                assert!(verify_ready_frame(&changed, &nonce).is_err());
            }
            let other_nonce = [0xa5_u8; NONCE_BYTES_V1];
            assert!(verify_ready_frame(&frame, &other_nonce).is_err());
        }

        #[test]
        fn release_frame_requires_exact_full_zeroed_shape() {
            let nonce = [7_u8; NONCE_BYTES_V1];
            let frame = encode_common_frame(RELEASE_MAGIC_V1, PHASE_RELEASE_V1, &nonce);
            assert!(child_verify_release_frame(&frame, &nonce));
            for offset in [
                0,
                FRAME_VERSION_OFFSET_V1,
                FRAME_PHASE_OFFSET_V1,
                FRAME_STATUS_OFFSET_V1,
                FRAME_FLAGS_OFFSET_V1,
                13,
                14,
                15,
                32,
                63,
            ] {
                let mut changed = frame;
                changed[offset] ^= 1;
                assert!(!child_verify_release_frame(&changed, &nonce));
            }
        }

        #[test]
        fn completed_frame_eof_wait_accepts_hup_only_then_requires_eof() {
            let (read, write) = test_pipe();
            let payload = [0x5a_u8; FRAME_BYTES_V1];
            write_test_payload(write.as_raw_fd(), &payload);

            let mut frame = [0_u8; FRAME_BYTES_V1];
            let received =
                unsafe { libc::read(read.as_raw_fd(), frame.as_mut_ptr().cast(), frame.len()) };
            assert_eq!(received, FRAME_BYTES_V1 as isize);
            assert_eq!(frame, payload);

            let mut extra = 0_u8;
            assert_eq!(
                unsafe { libc::read(read.as_raw_fd(), (&mut extra as *mut u8).cast(), 1) },
                -1
            );
            assert_eq!(last_errno(), Some(libc::EAGAIN));
            drop(write);

            assert!(!child_poll(read.as_raw_fd(), libc::POLLIN, test_deadline()));
            assert!(child_poll(
                read.as_raw_fd(),
                libc::POLLIN | libc::POLLHUP,
                test_deadline(),
            ));
            assert_eq!(
                unsafe { libc::read(read.as_raw_fd(), (&mut extra as *mut u8).cast(), 1) },
                0
            );
        }

        #[test]
        fn release_reader_accepts_exactly_one_complete_frame() {
            let payload = [0x3c_u8; FRAME_BYTES_V1 + 1];
            for (length, accepted) in [
                (FRAME_BYTES_V1 - 1, false),
                (FRAME_BYTES_V1, true),
                (FRAME_BYTES_V1 + 1, false),
            ] {
                let (read, write) = test_pipe();
                write_test_payload(write.as_raw_fd(), &payload[..length]);
                drop(write);
                let mut frame = [0_u8; FRAME_BYTES_V1];
                assert_eq!(
                    child_read_frame_and_eof(read.as_raw_fd(), &mut frame, test_deadline()),
                    accepted,
                    "payload length {length}",
                );
            }
        }

        #[test]
        fn proof_frame_accepts_only_fixed_success_invariants() {
            let nonce = [3_u8; NONCE_BYTES_V1];
            let frame =
                child_encode_proof_frame(&nonce, PROOF_STATUS_SUCCESS_V1, PROOF_FLAGS_V1, 0);
            assert!(verify_proof_frame(&frame, &nonce).is_ok());
            assert_eq!(
                &frame[FRAME_FLAGS_OFFSET_V1..FRAME_FLAGS_END_V1],
                &PROOF_FLAGS_V1.to_le_bytes(),
            );
            assert_eq!(&frame[FRAME_FLAGS_END_V1..FRAME_NONCE_OFFSET_V1], &[0, 0]);
            let mut protocol_v1 = frame;
            protocol_v1[FRAME_VERSION_OFFSET_V1..FRAME_PHASE_OFFSET_V1]
                .copy_from_slice(&1_u16.to_le_bytes());
            assert!(verify_proof_frame(&protocol_v1, &nonce).is_err());
            for stale_flags in [0x000f, 0x001f, 0x003f, 0x007f, 0x00ff, 0x03ff, u16::MAX] {
                let stale =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_SUCCESS_V1, stale_flags, 0);
                assert!(verify_proof_frame(&stale, &nonce).is_err());
            }

            for offset in [
                FRAME_STATUS_OFFSET_V1,
                FRAME_FLAGS_OFFSET_V1,
                13,
                14,
                15,
                FRAME_PID_OFFSET_V1,
                FRAME_UID_OFFSET_V1,
                FRAME_RESERVED_OFFSET_V1,
            ] {
                let mut changed = frame;
                changed[offset] ^= 1;
                assert!(verify_proof_frame(&changed, &nonce).is_err());
            }

            let failed = child_encode_proof_frame(&nonce, PROOF_STATUS_OS_ERROR_V1, 0, libc::EPERM);
            let error = match verify_proof_frame(&failed, &nonce) {
                Ok(()) => panic!("failure proof was accepted"),
                Err(error) => error,
            };
            assert_eq!(
                error.reason,
                IsolationQualificationReasonV1::ChildInvariantFailed
            );
            assert_eq!(error.errno, Some(libc::EPERM));
            assert!(!error.is_expected_unavailable());

            let valid_uts =
                child_encode_proof_frame(&nonce, PROOF_STATUS_UTS_CONFIGURATION_V1, 0, libc::EPERM);
            let uts_error =
                verify_proof_frame(&valid_uts, &nonce).expect_err("UTS failure proof was accepted");
            assert_eq!(
                (
                    uts_error.code,
                    uts_error.stage,
                    uts_error.reason,
                    uts_error.errno
                ),
                (
                    RefusalCode::RequiredNamespaceFailed,
                    IsolationQualificationStageV1::ChildUtsConfiguration,
                    IsolationQualificationReasonV1::AdministrativePolicy,
                    Some(libc::EPERM),
                )
            );
            assert!(uts_error.is_expected_unavailable());

            let mut identity = valid_uts;
            identity[FRAME_PID_OFFSET_V1] = 2;
            for frame in [
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_UTS_CONFIGURATION_V1,
                    PROOF_FLAGS_V1,
                    libc::EPERM,
                ),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_UTS_CONFIGURATION_V1,
                    0,
                    libc::EACCES,
                ),
                child_encode_proof_frame(&nonce, 0xff, 0, libc::EPERM),
                identity,
            ] {
                let error = match verify_proof_frame(&frame, &nonce) {
                    Ok(()) => panic!("noncanonical UTS proof was accepted"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
                assert!(!error.is_expected_unavailable());
            }
        }

        #[test]
        fn mount_root_failure_proofs_are_closed_and_never_expected() {
            let nonce = [0x42_u8; NONCE_BYTES_V1];
            for (status, errno, reason) in [
                (
                    PROOF_STATUS_MOUNT_ROOT_OS_V1,
                    libc::EPERM,
                    IsolationQualificationReasonV1::Io,
                ),
                (
                    PROOF_STATUS_MOUNT_ROOT_OS_V1,
                    MAX_LINUX_ERRNO_V1,
                    IsolationQualificationReasonV1::Io,
                ),
                (
                    PROOF_STATUS_MOUNT_ROOT_INVARIANT_V1,
                    0,
                    IsolationQualificationReasonV1::ChildInvariantFailed,
                ),
            ] {
                let frame = child_encode_proof_frame(&nonce, status, 0, errno);
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("mount-root failure proof was accepted as success");
                assert_eq!(error.code, RefusalCode::MountRootFailed);
                assert_eq!(error.stage, IsolationQualificationStageV1::ChildMountRoot);
                assert_eq!(error.reason, reason);
                assert_eq!(error.errno, (errno != 0).then_some(errno));
                assert!(!error.is_expected_unavailable());
            }

            let mut wrong_identity =
                child_encode_proof_frame(&nonce, PROOF_STATUS_MOUNT_ROOT_OS_V1, 0, libc::EPERM);
            wrong_identity[FRAME_PID_OFFSET_V1] = 2;
            for frame in [
                child_encode_proof_frame(&nonce, PROOF_STATUS_MOUNT_ROOT_OS_V1, 0, 0),
                child_encode_proof_frame(&nonce, PROOF_STATUS_MOUNT_ROOT_OS_V1, 0, -1),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_MOUNT_ROOT_OS_V1,
                    0,
                    MAX_LINUX_ERRNO_V1 + 1,
                ),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_MOUNT_ROOT_INVARIANT_V1,
                    0,
                    libc::EPERM,
                ),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_MOUNT_ROOT_OS_V1,
                    PROOF_FLAGS_V1,
                    libc::EPERM,
                ),
                wrong_identity,
            ] {
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("noncanonical mount-root proof was accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
                assert!(!error.is_expected_unavailable());
            }
        }

        #[test]
        fn descriptor_scrub_failure_proofs_are_exact_and_fail_closed() {
            let nonce = [0x6d_u8; NONCE_BYTES_V1];
            for (errno, reason, expected_unavailable) in [
                (
                    libc::ENOSYS,
                    IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                    true,
                ),
                (libc::EOPNOTSUPP, IsolationQualificationReasonV1::Io, false),
                (
                    libc::EINVAL,
                    IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                    true,
                ),
                (
                    libc::EPERM,
                    IsolationQualificationReasonV1::AdministrativePolicy,
                    true,
                ),
                (
                    libc::EACCES,
                    IsolationQualificationReasonV1::AdministrativePolicy,
                    true,
                ),
                (libc::EMFILE, IsolationQualificationReasonV1::Io, false),
                (libc::ENOMEM, IsolationQualificationReasonV1::Io, false),
                (
                    MAX_LINUX_ERRNO_V1,
                    IsolationQualificationReasonV1::Io,
                    false,
                ),
            ] {
                let frame =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_CLOSE_RANGE_OS_V1, 0, errno);
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("close-range failure proof was accepted as success");
                assert_eq!(
                    (error.code, error.stage, error.reason, error.errno),
                    (
                        RefusalCode::CloseRangeUnavailable,
                        IsolationQualificationStageV1::ChildDescriptorScrub,
                        reason,
                        Some(errno),
                    )
                );
                assert_eq!(error.is_expected_unavailable(), expected_unavailable);
            }

            for (errno, reason) in [
                (0, IsolationQualificationReasonV1::ChildInvariantFailed),
                (libc::EIO, IsolationQualificationReasonV1::Io),
                (MAX_LINUX_ERRNO_V1, IsolationQualificationReasonV1::Io),
            ] {
                let frame = child_encode_proof_frame(&nonce, PROOF_STATUS_FD_SCRUB_V1, 0, errno);
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("descriptor-scrub failure proof was accepted as success");
                assert_eq!(
                    (error.code, error.stage, error.reason, error.errno),
                    (
                        RefusalCode::IsolationPreflightFailed,
                        IsolationQualificationStageV1::ChildDescriptorScrub,
                        reason,
                        (errno != 0).then_some(errno),
                    )
                );
                assert!(!error.is_expected_unavailable());
            }

            for frame in [
                child_encode_proof_frame(&nonce, PROOF_STATUS_CLOSE_RANGE_OS_V1, 0, 0),
                child_encode_proof_frame(&nonce, PROOF_STATUS_CLOSE_RANGE_OS_V1, 0, -1),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_CLOSE_RANGE_OS_V1,
                    0,
                    MAX_LINUX_ERRNO_V1 + 1,
                ),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_CLOSE_RANGE_OS_V1,
                    PROOF_FLAGS_V1,
                    libc::ENOSYS,
                ),
                child_encode_proof_frame(&nonce, PROOF_STATUS_FD_SCRUB_V1, 0, -1),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_FD_SCRUB_V1,
                    0,
                    MAX_LINUX_ERRNO_V1 + 1,
                ),
                child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_FD_SCRUB_V1,
                    PROOF_FLAGS_V1,
                    libc::EIO,
                ),
            ] {
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("noncanonical descriptor failure proof was accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
                assert!(!error.is_expected_unavailable());
            }

            for (status, errno) in [
                (PROOF_STATUS_CLOSE_RANGE_OS_V1, libc::ENOSYS),
                (PROOF_STATUS_FD_SCRUB_V1, libc::EIO),
            ] {
                for offset in [
                    FRAME_PID_OFFSET_V1,
                    FRAME_UID_OFFSET_V1,
                    FRAME_EUID_OFFSET_V1,
                    FRAME_GID_OFFSET_V1,
                    FRAME_EGID_OFFSET_V1,
                ] {
                    let mut wrong_identity = child_encode_proof_frame(&nonce, status, 0, errno);
                    wrong_identity[offset] ^= 1;
                    let error = verify_proof_frame(&wrong_identity, &nonce)
                        .expect_err("descriptor failure accepted a noncanonical identity");
                    assert_eq!(
                        error.reason,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch
                    );
                    assert!(!error.is_expected_unavailable());
                }
            }
        }

        #[test]
        fn capability_drop_failure_proofs_are_exact_and_never_expected() {
            let nonce = [0xa7_u8; NONCE_BYTES_V1];
            for (errno, reason) in [
                (0, IsolationQualificationReasonV1::ChildInvariantFailed),
                (libc::EPERM, IsolationQualificationReasonV1::Io),
                (libc::ENOSYS, IsolationQualificationReasonV1::Io),
                (MAX_LINUX_ERRNO_V1, IsolationQualificationReasonV1::Io),
            ] {
                let frame =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_CAPABILITY_DROP_V1, 0, errno);
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("capability-drop failure proof was accepted as success");
                assert_eq!(
                    (error.code, error.stage, error.reason, error.errno),
                    (
                        RefusalCode::IsolationPreflightFailed,
                        IsolationQualificationStageV1::ChildCapabilityDrop,
                        reason,
                        (errno != 0).then_some(errno),
                    )
                );
                assert!(!error.is_expected_unavailable());
            }

            for errno in [-1, MAX_LINUX_ERRNO_V1 + 1] {
                let malformed =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_CAPABILITY_DROP_V1, 0, errno);
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("noncanonical capability errno was accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
                assert!(!error.is_expected_unavailable());
            }

            for flags in [1, PROOF_FLAGS_V1, u16::MAX] {
                let malformed = child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_CAPABILITY_DROP_V1,
                    flags,
                    libc::EIO,
                );
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("nonzero capability failure flags were accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
            }

            for offset in [
                FRAME_PID_OFFSET_V1,
                FRAME_UID_OFFSET_V1,
                FRAME_EUID_OFFSET_V1,
                FRAME_GID_OFFSET_V1,
                FRAME_EGID_OFFSET_V1,
            ] {
                let mut malformed =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_CAPABILITY_DROP_V1, 0, libc::EIO);
                malformed[offset] ^= 1;
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("capability failure accepted a wrong identity");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
            }

            for offset in FRAME_RESERVED_OFFSET_V1..FRAME_BYTES_V1 {
                let mut malformed =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_CAPABILITY_DROP_V1, 0, libc::EIO);
                malformed[offset] = 1;
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("capability failure accepted reserved data");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
            }

            let cleanup = IsolationQualificationFailureV1::cleanup_uncertain(Some(libc::EIO));
            assert_eq!(cleanup.stage, IsolationQualificationStageV1::Cleanup);
            assert_eq!(
                cleanup.reason,
                IsolationQualificationReasonV1::CleanupUncertain
            );
            assert!(!cleanup.is_expected_unavailable());
        }

        #[test]
        fn landlock_failure_proofs_distinguish_unavailable_from_broken() {
            let nonce = [0x4c_u8; NONCE_BYTES_V1];
            for errno in [0, libc::ENOSYS, libc::EOPNOTSUPP] {
                let frame = child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1,
                    0,
                    errno,
                );
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("Landlock-unavailable proof was accepted as success");
                assert_eq!(
                    (error.code, error.stage, error.reason, error.errno),
                    (
                        RefusalCode::LandlockUnavailable,
                        IsolationQualificationStageV1::ChildLandlock,
                        IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                        (errno != 0).then_some(errno),
                    )
                );
                assert!(error.is_expected_unavailable());
            }

            for errno in [
                0,
                libc::ENOSYS,
                libc::EOPNOTSUPP,
                libc::EPERM,
                libc::EACCES,
                libc::EIO,
                MAX_LINUX_ERRNO_V1,
            ] {
                let frame =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_LANDLOCK_BROKEN_V1, 0, errno);
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("broken Landlock proof was accepted as success");
                assert_eq!(
                    (error.code, error.stage, error.reason, error.errno),
                    (
                        RefusalCode::IsolationPreflightFailed,
                        IsolationQualificationStageV1::ChildLandlock,
                        if errno == 0 {
                            IsolationQualificationReasonV1::ChildInvariantFailed
                        } else {
                            IsolationQualificationReasonV1::Io
                        },
                        (errno != 0).then_some(errno),
                    )
                );
                assert!(!error.is_expected_unavailable());
            }

            for errno in [
                libc::EINVAL,
                libc::EPERM,
                libc::EACCES,
                libc::EIO,
                MAX_LINUX_ERRNO_V1,
                -1,
                MAX_LINUX_ERRNO_V1 + 1,
            ] {
                let malformed = child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1,
                    0,
                    errno,
                );
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("noncanonical Landlock-unavailable errno was accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
                assert!(!error.is_expected_unavailable());
            }
            for errno in [-1, MAX_LINUX_ERRNO_V1 + 1] {
                let malformed =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_LANDLOCK_BROKEN_V1, 0, errno);
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("noncanonical broken-Landlock errno was accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
            }

            for status in [
                PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1,
                PROOF_STATUS_LANDLOCK_BROKEN_V1,
            ] {
                let errno = if status == PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1 {
                    libc::ENOSYS
                } else {
                    libc::EIO
                };
                for flags in [1_u16, 0x0100, u16::MAX] {
                    let malformed = child_encode_proof_frame(&nonce, status, flags, errno);
                    let error = verify_proof_frame(&malformed, &nonce)
                        .expect_err("Landlock failure accepted nonzero u16 flags");
                    assert_eq!(
                        error.reason,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch
                    );
                }
                for offset in [
                    FRAME_PID_OFFSET_V1,
                    FRAME_UID_OFFSET_V1,
                    FRAME_EUID_OFFSET_V1,
                    FRAME_GID_OFFSET_V1,
                    FRAME_EGID_OFFSET_V1,
                ] {
                    let mut malformed = child_encode_proof_frame(&nonce, status, 0, errno);
                    malformed[offset] ^= 1;
                    let error = verify_proof_frame(&malformed, &nonce)
                        .expect_err("Landlock failure accepted a wrong identity");
                    assert_eq!(
                        error.reason,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch
                    );
                }
                for offset in [14, 15, FRAME_RESERVED_OFFSET_V1, FRAME_BYTES_V1 - 1] {
                    let mut malformed = child_encode_proof_frame(&nonce, status, 0, errno);
                    malformed[offset] = 1;
                    let error = verify_proof_frame(&malformed, &nonce)
                        .expect_err("Landlock failure accepted reserved data");
                    assert_eq!(
                        error.reason,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch
                    );
                }
            }

            let mut cleanup_overrides = verify_proof_frame(
                &child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_LANDLOCK_UNAVAILABLE_V1,
                    0,
                    libc::ENOSYS,
                ),
                &nonce,
            )
            .expect_err("Landlock-unavailable proof was accepted as success");
            cleanup_overrides.cleanup_complete = false;
            assert!(!cleanup_overrides.is_expected_unavailable());
        }

        #[test]
        fn seccomp_failure_proofs_distinguish_only_action_unavailability() {
            let nonce = [0x5c_u8; NONCE_BYTES_V1];
            for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
                let frame =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_SECCOMP_UNAVAILABLE_V1, 0, errno);
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("seccomp-unavailable proof was accepted as success");
                assert_eq!(
                    (error.code, error.stage, error.reason, error.errno),
                    (
                        RefusalCode::SeccompUnavailable,
                        IsolationQualificationStageV1::ChildSeccomp,
                        IsolationQualificationReasonV1::KernelCapabilityUnavailable,
                        Some(errno),
                    )
                );
                assert!(error.is_expected_unavailable());
            }

            for errno in [
                0,
                libc::ENOSYS,
                libc::EOPNOTSUPP,
                libc::EINVAL,
                libc::EPERM,
                libc::EACCES,
                libc::EIO,
                MAX_LINUX_ERRNO_V1,
            ] {
                let frame =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_SECCOMP_BROKEN_V1, 0, errno);
                let error = verify_proof_frame(&frame, &nonce)
                    .expect_err("broken-seccomp proof was accepted as success");
                assert_eq!(
                    (error.code, error.stage, error.reason, error.errno),
                    (
                        RefusalCode::IsolationPreflightFailed,
                        IsolationQualificationStageV1::ChildSeccomp,
                        if errno == 0 {
                            IsolationQualificationReasonV1::ChildInvariantFailed
                        } else {
                            IsolationQualificationReasonV1::Io
                        },
                        (errno != 0).then_some(errno),
                    )
                );
                assert!(!error.is_expected_unavailable());
            }

            for errno in [
                0,
                libc::EINVAL,
                libc::EPERM,
                libc::EACCES,
                libc::EIO,
                MAX_LINUX_ERRNO_V1,
                -1,
                MAX_LINUX_ERRNO_V1 + 1,
            ] {
                let malformed =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_SECCOMP_UNAVAILABLE_V1, 0, errno);
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("noncanonical seccomp-unavailable errno was accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
                assert!(!error.is_expected_unavailable());
            }
            for errno in [-1, MAX_LINUX_ERRNO_V1 + 1] {
                let malformed =
                    child_encode_proof_frame(&nonce, PROOF_STATUS_SECCOMP_BROKEN_V1, 0, errno);
                let error = verify_proof_frame(&malformed, &nonce)
                    .expect_err("noncanonical broken-seccomp errno was accepted");
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::ProtocolFrameMismatch
                );
            }

            for status in [
                PROOF_STATUS_SECCOMP_UNAVAILABLE_V1,
                PROOF_STATUS_SECCOMP_BROKEN_V1,
            ] {
                let errno = if status == PROOF_STATUS_SECCOMP_UNAVAILABLE_V1 {
                    libc::ENOSYS
                } else {
                    libc::EIO
                };
                for flags in [1_u16, 0x0100, PROOF_FLAGS_V1, u16::MAX] {
                    let malformed = child_encode_proof_frame(&nonce, status, flags, errno);
                    let error = verify_proof_frame(&malformed, &nonce)
                        .expect_err("seccomp failure accepted nonzero u16 flags");
                    assert_eq!(
                        error.reason,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch
                    );
                }
                for offset in [
                    FRAME_PID_OFFSET_V1,
                    FRAME_UID_OFFSET_V1,
                    FRAME_EUID_OFFSET_V1,
                    FRAME_GID_OFFSET_V1,
                    FRAME_EGID_OFFSET_V1,
                ] {
                    let mut malformed = child_encode_proof_frame(&nonce, status, 0, errno);
                    malformed[offset] ^= 1;
                    let error = verify_proof_frame(&malformed, &nonce)
                        .expect_err("seccomp failure accepted a wrong identity");
                    assert_eq!(
                        error.reason,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch
                    );
                }
                for offset in [14, 15, FRAME_RESERVED_OFFSET_V1, FRAME_BYTES_V1 - 1] {
                    let mut malformed = child_encode_proof_frame(&nonce, status, 0, errno);
                    malformed[offset] = 1;
                    let error = verify_proof_frame(&malformed, &nonce)
                        .expect_err("seccomp failure accepted reserved data");
                    assert_eq!(
                        error.reason,
                        IsolationQualificationReasonV1::ProtocolFrameMismatch
                    );
                }
            }

            let mut cleanup_overrides = verify_proof_frame(
                &child_encode_proof_frame(
                    &nonce,
                    PROOF_STATUS_SECCOMP_UNAVAILABLE_V1,
                    0,
                    libc::ENOSYS,
                ),
                &nonce,
            )
            .expect_err("seccomp-unavailable proof was accepted as success");
            cleanup_overrides.cleanup_complete = false;
            assert!(!cleanup_overrides.is_expected_unavailable());
        }

        #[test]
        fn clone_failure_classification_does_not_launder_abi_errors() {
            for errno in [libc::ENOSYS, libc::EOPNOTSUPP] {
                let error = clone_failure(Some(errno));
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::KernelCapabilityUnavailable
                );
                assert!(error.is_expected_unavailable());
            }
            for errno in [libc::EINVAL, libc::E2BIG] {
                let error = clone_failure(Some(errno));
                assert_eq!(
                    error.reason,
                    IsolationQualificationReasonV1::MalformedKernelResponse
                );
                assert!(!error.is_expected_unavailable());
            }
        }

        #[test]
        fn expired_deadline_is_terminal_without_sleeping() {
            let deadline = MonotonicDeadlineV1 {
                seconds: 0,
                nanoseconds: 0,
            };
            assert!(deadline.remaining_milliseconds().is_err());
            assert!(child_remaining_milliseconds(deadline).is_none());
        }

        #[test]
        fn protocol_timeout_preserves_reserved_cleanup_budget() {
            let start = libc::timespec {
                tv_sec: 100,
                tv_nsec: 123_456_789,
            };
            let Ok(protocol) = MonotonicDeadlineV1::from_start(start, PROBE_PROTOCOL_SECONDS_V1)
            else {
                panic!("fixed protocol deadline was not representable");
            };
            let Ok(hard) = MonotonicDeadlineV1::from_start(start, PROBE_HARD_SECONDS_V1) else {
                panic!("fixed hard deadline was not representable");
            };
            let at_protocol_timeout = libc::timespec {
                tv_sec: protocol.seconds,
                tv_nsec: protocol.nanoseconds,
            };
            assert!(
                protocol
                    .remaining_milliseconds_at(at_protocol_timeout)
                    .is_err()
            );
            assert_eq!(
                hard.remaining_milliseconds_at(at_protocol_timeout),
                Ok(2_000)
            );

            let across_second_boundary = libc::timespec {
                tv_sec: protocol.seconds - 1,
                tv_nsec: protocol.nanoseconds + 500_000_000,
            };
            assert_eq!(
                protocol.remaining_milliseconds_at(across_second_boundary),
                Ok(500)
            );
        }

        #[test]
        fn cleanup_fallback_and_terminal_merge_are_fail_closed() {
            assert!(pid_signal_fallback_required(false, None));
            for errno in [libc::EBADF, libc::EPERM, libc::ESRCH] {
                assert!(pid_signal_fallback_required(true, Some(errno)));
            }
            assert!(!pid_signal_fallback_required(true, None));
            assert_eq!(positive_direct_pid(Some(42)), Some(42));
            assert_eq!(positive_direct_pid(Some(0)), None);
            assert_eq!(positive_direct_pid(Some(-42)), None);
            assert_eq!(merge_cleanup_results(Some(libc::EBADF), Ok(())), Ok(()));
            assert_eq!(
                merge_cleanup_results(Some(libc::EBADF), Err(Some(libc::ETIMEDOUT))),
                Err(Some(libc::ETIMEDOUT))
            );
            assert_eq!(
                merge_reap_fallback(Some(libc::EBADF), Some(libc::EINVAL), Ok(())),
                Ok(())
            );
            assert_eq!(
                merge_reap_fallback(
                    Some(libc::EBADF),
                    Some(libc::EINVAL),
                    Err(Some(libc::ETIMEDOUT)),
                ),
                Err(Some(libc::ETIMEDOUT))
            );
        }

        #[test]
        fn wait_status_decoder_accepts_only_terminal_exact_status() {
            let exited = decode_wait_status(23 << 8).expect("exit status is terminal");
            assert_eq!(exited.code, libc::CLD_EXITED);
            assert_eq!(exited.status, 23);

            let signaled = decode_wait_status(libc::SIGKILL).expect("signal status is terminal");
            assert_eq!(signaled.code, libc::CLD_KILLED);
            assert_eq!(signaled.status, libc::SIGKILL);
            assert!(decode_wait_status(0x7f).is_none());
        }
    }
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
mod platform {
    use super::*;

    pub(super) struct BlockedRootlessNamespaceBootstrapV1 {
        _private: (),
    }

    pub(super) fn begin_blocked_rootless_namespace_bootstrap_v1()
    -> Result<BlockedRootlessNamespaceBootstrapV1, IsolationQualificationFailureV1> {
        Err(IsolationQualificationFailureV1::new(
            RefusalCode::UnsupportedArchitecture,
            IsolationQualificationStageV1::Platform,
            IsolationQualificationReasonV1::UnsupportedArchitecture,
            None,
        ))
    }

    pub(super) fn qualify_rootless_namespace_tuple_v1()
    -> Result<CompletedRootlessNamespaceProbeV1, IsolationQualificationFailureV1> {
        Err(IsolationQualificationFailureV1::new(
            RefusalCode::UnsupportedArchitecture,
            IsolationQualificationStageV1::Platform,
            IsolationQualificationReasonV1::UnsupportedArchitecture,
            None,
        ))
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(all(target_env = "gnu", target_pointer_width = "64"))
))]
mod platform {
    use super::*;

    pub(super) struct BlockedRootlessNamespaceBootstrapV1 {
        _private: (),
    }

    pub(super) fn begin_blocked_rootless_namespace_bootstrap_v1()
    -> Result<BlockedRootlessNamespaceBootstrapV1, IsolationQualificationFailureV1> {
        Err(IsolationQualificationFailureV1::new(
            RefusalCode::RequiredKernelCapabilityMissing,
            IsolationQualificationStageV1::Platform,
            IsolationQualificationReasonV1::UnsupportedEnvironment,
            None,
        ))
    }

    pub(super) fn qualify_rootless_namespace_tuple_v1()
    -> Result<CompletedRootlessNamespaceProbeV1, IsolationQualificationFailureV1> {
        Err(IsolationQualificationFailureV1::new(
            RefusalCode::RequiredKernelCapabilityMissing,
            IsolationQualificationStageV1::Platform,
            IsolationQualificationReasonV1::UnsupportedEnvironment,
            None,
        ))
    }
}
