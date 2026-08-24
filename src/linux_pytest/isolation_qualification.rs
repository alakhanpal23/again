//! Fixed rootless-namespace diagnostic for `linux-pytest-v1`.
//!
//! This module does not accept a program, arguments, caller-supplied
//! environment parameter, path, callback, descriptor, or output sink. Its
//! Linux leaf creates only one fixed child running a raw-syscall protocol; it
//! never executes caller code. The leaf verifies the namespace bootstrap. A
//! completed marker is returned only after that direct child has exited and
//! been reaped; a cleanup-uncertain failure remains possible.
//! The result is not an execution, snapshot, isolation-session, or reuse
//! authority.

use super::RefusalCode;

const PROTOCOL_VERSION_V1: u16 = 1;

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
    const PROOF_FLAGS_V1: u8 = 0b0000_0111;
    const CHILD_EXIT_PROOF_FAILED_V1: i32 = 125;
    const FRAME_MAGIC_OFFSET_V1: usize = 0;
    const FRAME_VERSION_OFFSET_V1: usize = 8;
    const FRAME_PHASE_OFFSET_V1: usize = 10;
    const FRAME_STATUS_OFFSET_V1: usize = 11;
    const FRAME_FLAGS_OFFSET_V1: usize = 12;
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
    const RESOLVE_BENEATH_V1: u64 = 0x08;
    const NS_GET_USERNS_V1: libc::c_ulong = 0xb701;
    const NS_GET_NSTYPE_V1: libc::c_ulong = 0xb703;
    const NS_GET_OWNER_UID_V1: libc::c_ulong = 0xb704;
    const CLONE_CLEAR_SIGHAND_V1: u64 = 0x1_0000_0000;
    const CAP_SYS_ADMIN_MASK_V1: u64 = 1_u64 << 21;
    const HOSTNAME_V1: &[u8] = b"again";

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

    pub(super) fn qualify_rootless_namespace_tuple_v1()
    -> Result<CompletedRootlessNamespaceProbeV1, IsolationQualificationFailureV1> {
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

        let release = encode_common_frame(RELEASE_MAGIC_V1, PHASE_RELEASE_V1, &nonce);
        let control_fd = guarded!(retained_fd(
            &guard.control_write,
            IsolationQualificationStageV1::SendControl,
        ));
        guarded!(write_parent_frame(
            control_fd,
            child_pidfd,
            &release,
            deadline,
        ));
        guard.control_write.take();

        let proof = guarded!(read_parent_frame(
            report_fd,
            child_pidfd,
            deadline,
            true,
            IsolationQualificationStageV1::ReceiveChildProof,
        ));
        guarded!(expect_report_eof(report_fd, child_pidfd, deadline,));
        guard.report_read.take();
        guarded!(verify_proof_frame(&proof, &nonce));
        if let Err(error) = guard.reap_success(deadline) {
            return Err(guard.refuse(error));
        }

        Ok(CompletedRootlessNamespaceProbeV1 { _private: () })
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
            .copy_from_slice(&PROTOCOL_VERSION_V1.to_le_bytes());
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
            || version != PROTOCOL_VERSION_V1
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
            || frame[FRAME_FLAGS_OFFSET_V1] != 0
            || frame[13..FRAME_NONCE_OFFSET_V1]
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
        if frame[13..FRAME_NONCE_OFFSET_V1]
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
        let errno = decode_i32(frame, FRAME_ERROR_OFFSET_V1);
        let identity_is_exact = decode_u32(frame, FRAME_PID_OFFSET_V1) == 1
            && decode_u32(frame, FRAME_UID_OFFSET_V1) == 0
            && decode_u32(frame, FRAME_EUID_OFFSET_V1) == 0
            && decode_u32(frame, FRAME_GID_OFFSET_V1) == 0
            && decode_u32(frame, FRAME_EGID_OFFSET_V1) == 0;
        if status == PROOF_STATUS_UTS_CONFIGURATION_V1 {
            if frame[FRAME_FLAGS_OFFSET_V1] != 0 || errno != libc::EPERM || !identity_is_exact {
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
        if frame[FRAME_FLAGS_OFFSET_V1] != PROOF_FLAGS_V1 || errno != 0 || !identity_is_exact {
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

        let proof = child_encode_proof_frame(&nonce, PROOF_STATUS_SUCCESS_V1, PROOF_FLAGS_V1, 0);
        if !child_write_frame(report_write, &proof, deadline) {
            child_exit(CHILD_EXIT_PROOF_FAILED_V1);
        }
        let _ = child_close(report_write);
        child_exit(0)
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
            let version = PROTOCOL_VERSION_V1.to_le_bytes();
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
        flags: u8,
        errno: i32,
    ) -> [u8; FRAME_BYTES_V1] {
        let mut frame = child_encode_common_frame(PROOF_MAGIC_V1, PHASE_PROOF_V1, nonce);
        unsafe {
            *frame.as_mut_ptr().add(FRAME_STATUS_OFFSET_V1) = status;
            *frame.as_mut_ptr().add(FRAME_FLAGS_OFFSET_V1) = flags;
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
                PROTOCOL_VERSION_V1.to_le_bytes().as_ptr(),
                2,
            ) && *frame.as_ptr().add(FRAME_PHASE_OFFSET_V1) == PHASE_RELEASE_V1
                && *frame.as_ptr().add(FRAME_STATUS_OFFSET_V1) == 0
                && *frame.as_ptr().add(FRAME_FLAGS_OFFSET_V1) == 0
                && child_all_zero(frame.as_ptr().add(13), FRAME_NONCE_OFFSET_V1 - 13)
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
            let written =
                unsafe { libc::syscall(libc::SYS_write, fd, frame.as_ptr(), FRAME_BYTES_V1) };
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
            let mut descriptor = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result =
                unsafe { libc::syscall(libc::SYS_poll, &mut descriptor, 1_usize, timeout) };
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
                libc::CLOCK_MONOTONIC,
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
        let result = unsafe { libc::syscall(libc::SYS_close, fd) };
        result == 0 || (result < 0 && child_errno() == libc::EINTR)
    }

    fn child_errno() -> i32 {
        unsafe { *libc::__errno_location() }
    }

    fn child_exit(status: i32) -> ! {
        unsafe { libc::syscall(libc::SYS_exit, status) };
        loop {
            std::hint::spin_loop();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
        fn ready_frame_commits_phase_nonce_and_reserved_bytes() {
            let nonce = [0x5a_u8; NONCE_BYTES_V1];
            let frame = child_encode_common_frame(READY_MAGIC_V1, PHASE_READY_V1, &nonce);
            assert!(verify_ready_frame(&frame, &nonce).is_ok());

            for offset in [
                0,
                FRAME_VERSION_OFFSET_V1,
                FRAME_PHASE_OFFSET_V1,
                13,
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
                13,
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

            for offset in [
                FRAME_STATUS_OFFSET_V1,
                FRAME_FLAGS_OFFSET_V1,
                13,
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
