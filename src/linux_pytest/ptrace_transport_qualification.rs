//! Fixed no-command ptrace/seccomp transport diagnostic.
//!
//! The only Linux leaf in this module creates one child, observes exactly two
//! seccomp stops, one ptrace exit event, and one terminal reap, then returns the
//! protocol checker's opaque completed value. It accepts no command, path,
//! environment, callback, descriptor, or event slice. It never executes a
//! workload and cannot grant EffectIR, execution, or reuse authority.

use super::RefusalCode;
use super::trace_protocol::CompletedFixedPtraceTransportProbeV1;

/// Single-use construction permit for the pure transport recorder.
///
/// The private field prevents sibling modules from safely fabricating the
/// permit even though the protocol sibling must be able to name its type.
pub(super) struct FixedPtraceTransportRecorderPermitV1(());

impl FixedPtraceTransportRecorderPermitV1 {
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    fn issue() -> Self {
        Self(())
    }
}

// Each target compiles exactly one platform module, so some typed failure
// variants are necessarily constructed only on the other target family.
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum PtraceTransportStageV1 {
    Platform,
    DedicatedHelper,
    SeccompActions,
    SignalChannel,
    ReleaseChannel,
    CloneChild,
    PtraceSeize,
    ReleaseChild,
    WaitEvent,
    ReadEventMessage,
    ReadSyscallInfo,
    ContinueChild,
    TraceProtocol,
    TerminalReap,
    Cleanup,
}

impl PtraceTransportStageV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::DedicatedHelper => "dedicated_helper",
            Self::SeccompActions => "seccomp_actions",
            Self::SignalChannel => "signal_channel",
            Self::ReleaseChannel => "release_channel",
            Self::CloneChild => "clone_child",
            Self::PtraceSeize => "ptrace_seize",
            Self::ReleaseChild => "release_child",
            Self::WaitEvent => "wait_event",
            Self::ReadEventMessage => "read_event_message",
            Self::ReadSyscallInfo => "read_syscall_info",
            Self::ContinueChild => "continue_child",
            Self::TraceProtocol => "trace_protocol",
            Self::TerminalReap => "terminal_reap",
            Self::Cleanup => "cleanup",
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum PtraceTransportReasonV1 {
    UnsupportedPlatform,
    UnsupportedArchitecture,
    UnsupportedEnvironment,
    MultipleTasks,
    SignalDisposition,
    LoaderInjectionEnvironment,
    KernelCapabilityUnavailable,
    AdministrativePolicy,
    BoundExceeded,
    Io,
    ShortIo,
    MalformedKernelResponse,
    UnexpectedLifecycleEvent,
    ProtocolMismatch,
    CleanupUncertain,
}

impl PtraceTransportReasonV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsupportedArchitecture => "unsupported_architecture",
            Self::UnsupportedEnvironment => "unsupported_environment",
            Self::MultipleTasks => "multiple_tasks",
            Self::SignalDisposition => "signal_disposition",
            Self::LoaderInjectionEnvironment => "loader_injection_environment",
            Self::KernelCapabilityUnavailable => "kernel_capability_unavailable",
            Self::AdministrativePolicy => "administrative_policy",
            Self::BoundExceeded => "bound_exceeded",
            Self::Io => "io",
            Self::ShortIo => "short_io",
            Self::MalformedKernelResponse => "malformed_kernel_response",
            Self::UnexpectedLifecycleEvent => "unexpected_lifecycle_event",
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::CleanupUncertain => "cleanup_uncertain",
        }
    }
}

/// Typed refusal from the fixed transport diagnostic.
///
/// Private fields prevent callers from manufacturing a successful transport
/// proof. A failure contains classification only; no child or descriptor is
/// ever returned.
pub(super) struct PtraceTransportQualificationFailureV1 {
    code: RefusalCode,
    stage: PtraceTransportStageV1,
    reason: PtraceTransportReasonV1,
    errno: Option<i32>,
    cleanup_complete: bool,
}

impl PtraceTransportQualificationFailureV1 {
    const fn new(
        code: RefusalCode,
        stage: PtraceTransportStageV1,
        reason: PtraceTransportReasonV1,
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

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    const fn cleanup_uncertain(errno: Option<i32>) -> Self {
        Self {
            code: RefusalCode::IsolationPreflightFailed,
            stage: PtraceTransportStageV1::Cleanup,
            reason: PtraceTransportReasonV1::CleanupUncertain,
            errno,
            cleanup_complete: false,
        }
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    const fn with_cleanup_complete(mut self, cleanup_complete: bool) -> Self {
        self.cleanup_complete = cleanup_complete;
        self
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
        self.cleanup_complete
            && matches!(
                (self.code, self.stage, self.reason, self.errno),
                (
                    RefusalCode::UnsupportedOs,
                    PtraceTransportStageV1::Platform,
                    PtraceTransportReasonV1::UnsupportedPlatform,
                    None,
                ) | (
                    RefusalCode::UnsupportedArchitecture,
                    PtraceTransportStageV1::Platform,
                    PtraceTransportReasonV1::UnsupportedArchitecture
                        | PtraceTransportReasonV1::UnsupportedEnvironment,
                    None,
                ) | (
                    RefusalCode::SeccompUnavailable,
                    PtraceTransportStageV1::SeccompActions,
                    PtraceTransportReasonV1::KernelCapabilityUnavailable,
                    Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP),
                ) | (
                    RefusalCode::PtraceUnavailable,
                    PtraceTransportStageV1::CloneChild,
                    PtraceTransportReasonV1::KernelCapabilityUnavailable,
                    Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP),
                ) | (
                    RefusalCode::PtraceUnavailable,
                    PtraceTransportStageV1::PtraceSeize,
                    PtraceTransportReasonV1::KernelCapabilityUnavailable,
                    Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP),
                ) | (
                    RefusalCode::PtraceUnavailable,
                    PtraceTransportStageV1::PtraceSeize,
                    PtraceTransportReasonV1::AdministrativePolicy,
                    Some(libc::EPERM) | Some(libc::EACCES),
                )
            )
    }
}

/// Run the fixed four-event transport diagnostic.
///
/// The function has deliberately no parameter. Its successful value is the
/// protocol module's opaque, redacted diagnostic completion, not execution or
/// trace-record authority.
pub(super) fn qualify_fixed_ptrace_transport_v1()
-> Result<CompletedFixedPtraceTransportProbeV1, PtraceTransportQualificationFailureV1> {
    platform::qualify_fixed_ptrace_transport_v1()
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
)))]
mod platform {
    use super::*;

    pub(super) fn qualify_fixed_ptrace_transport_v1()
    -> Result<CompletedFixedPtraceTransportProbeV1, PtraceTransportQualificationFailureV1> {
        let (code, reason) = if cfg!(target_os = "linux") {
            (
                RefusalCode::UnsupportedArchitecture,
                if cfg!(all(target_arch = "x86_64", target_pointer_width = "64")) {
                    PtraceTransportReasonV1::UnsupportedEnvironment
                } else {
                    PtraceTransportReasonV1::UnsupportedArchitecture
                },
            )
        } else {
            (
                RefusalCode::UnsupportedOs,
                PtraceTransportReasonV1::UnsupportedPlatform,
            )
        };
        Err(PtraceTransportQualificationFailureV1::new(
            code,
            PtraceTransportStageV1::Platform,
            reason,
            None,
        ))
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
mod platform {
    use std::fs;
    use std::io::{self, Read};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;

    use super::super::RawLinuxWaitStatusV1;
    use super::super::trace_protocol::{
        FixedPtraceTransportEventV1, FixedPtraceTransportProbeRecorderV1,
        FixedPtraceTransportProtocolErrorV1, PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
        PTRACE_TRANSPORT_GETPID_COOKIE_V1, PTRACE_TRANSPORT_GETPID_NR_X86_64_V1,
        PTRACE_TRANSPORT_GETPPID_COOKIE_V1, PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1,
    };
    use super::*;

    const TRANSPORT_SECONDS_V1: i64 = 8;
    const CLEANUP_SECONDS_V1: i64 = 2;
    const MAX_SIGNAL_READ_ATTEMPTS_V1: usize = 16;
    const MAX_WAIT_ATTEMPTS_V1: usize = 64;
    const MAX_CHILD_IO_ATTEMPTS_V1: usize = 16;
    const MAX_ENVIRONMENT_BYTES_V1: usize = 1024 * 1024;
    const RELEASE_BYTE_V1: u8 = 0xa6;
    const CHILD_FAILURE_EXIT_V1: u32 = 125;
    const CLONE_PIDFD_V1: u64 = 0x0000_1000;
    const PTRACE_SEIZE_V1: u64 = 0x4206;
    const PTRACE_CONT_V1: u64 = 7;
    const PTRACE_GETEVENTMSG_V1: u64 = 0x4201;
    const PTRACE_GET_SYSCALL_INFO_V1: u64 = 0x420e;
    const PTRACE_EVENT_EXIT_V1: u32 = 6;
    const PTRACE_EVENT_SECCOMP_V1: u32 = 7;
    const PTRACE_O_TRACESYSGOOD_V1: u64 = 0x0000_0001;
    const PTRACE_O_TRACEFORK_V1: u64 = 0x0000_0002;
    const PTRACE_O_TRACEVFORK_V1: u64 = 0x0000_0004;
    const PTRACE_O_TRACECLONE_V1: u64 = 0x0000_0008;
    const PTRACE_O_TRACEEXEC_V1: u64 = 0x0000_0010;
    const PTRACE_O_TRACEEXIT_V1: u64 = 0x0000_0040;
    const PTRACE_O_TRACESECCOMP_V1: u64 = 0x0000_0080;
    const PTRACE_O_EXITKILL_V1: u64 = 0x0010_0000;
    const PTRACE_OPTIONS_V1: u64 = PTRACE_O_TRACESYSGOOD_V1
        | PTRACE_O_TRACEFORK_V1
        | PTRACE_O_TRACEVFORK_V1
        | PTRACE_O_TRACECLONE_V1
        | PTRACE_O_TRACEEXEC_V1
        | PTRACE_O_TRACEEXIT_V1
        | PTRACE_O_TRACESECCOMP_V1
        | PTRACE_O_EXITKILL_V1;
    const PTRACE_SYSCALL_INFO_SECCOMP_V1: u8 = 3;
    const PTRACE_SECCOMP_INFO_BYTES_V1: libc::c_long = 84;
    const WAIT_WALL_V1: libc::c_int = 0x4000_0000;
    const X32_SYSCALL_BIT_V1: u32 = 0x4000_0000;
    const SECCOMP_SET_MODE_FILTER_V1: u32 = 1;
    const SECCOMP_GET_ACTION_AVAIL_V1: u32 = 2;
    const SECCOMP_FILTER_FLAG_TSYNC_V1: u32 = 1;
    const SECCOMP_RET_KILL_PROCESS_V1: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO_V1: u32 = 0x0005_0000;
    const SECCOMP_RET_TRACE_V1: u32 = 0x7ff0_0000;
    const SECCOMP_RET_ALLOW_V1: u32 = 0x7fff_0000;
    const SECCOMP_ERRNO_MARKER_V1: u16 = 0x05a7;
    const SECCOMP_RET_MARKER_V1: u32 = SECCOMP_RET_ERRNO_V1 | SECCOMP_ERRNO_MARKER_V1 as u32;
    const SECCOMP_DATA_NR_OFFSET_V1: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET_V1: u32 = 4;
    const SECCOMP_DATA_ARGS_OFFSET_V1: u32 = 16;
    const SECCOMP_DATA_ARG_STRIDE_V1: u32 = 8;
    const SECCOMP_DATA_ARG_HIGH_OFFSET_V1: u32 = 4;
    const SECCOMP_BPF_LD_W_ABS_V1: u16 = 0x20;
    const SECCOMP_BPF_JMP_JEQ_K_V1: u16 = 0x15;
    const SECCOMP_BPF_JMP_JSET_K_V1: u16 = 0x45;
    const SECCOMP_BPF_RET_K_V1: u16 = 0x06;
    const FILTER_DISPATCH_INSTRUCTIONS_V1: usize = 10;
    const FILTER_ZERO_ARGUMENT_BLOCK_INSTRUCTIONS_V1: usize = 37;
    const FILTER_EXIT_BLOCK_INSTRUCTIONS_V1: usize = 38;
    const SECCOMP_FILTER_INSTRUCTION_COUNT_V1: usize = FILTER_DISPATCH_INSTRUCTIONS_V1
        + 2 * FILTER_ZERO_ARGUMENT_BLOCK_INSTRUCTIONS_V1
        + FILTER_EXIT_BLOCK_INSTRUCTIONS_V1;
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
    #[derive(Clone, Copy)]
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

    #[repr(C)]
    struct LinuxPtraceSyscallInfoSeccompV1 {
        operation: u8,
        reserved: u8,
        flags: u16,
        architecture: u32,
        instruction_pointer: u64,
        stack_pointer: u64,
        syscall_number: u64,
        arguments: [u64; 6],
        return_data: u32,
        reserved2: u32,
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

    const fn append_zero_argument_checks_v1(
        mut filter: [LinuxSockFilterV1; SECCOMP_FILTER_INSTRUCTION_COUNT_V1],
        mut cursor: usize,
    ) -> (
        [LinuxSockFilterV1; SECCOMP_FILTER_INSTRUCTION_COUNT_V1],
        usize,
    ) {
        let mut argument = 0_u32;
        while argument < 6 {
            filter[cursor] =
                seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(argument));
            filter[cursor + 1] = seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0);
            filter[cursor + 2] = seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1);
            filter[cursor + 3] = seccomp_statement_v1(
                SECCOMP_BPF_LD_W_ABS_V1,
                seccomp_arg_high_offset_v1(argument),
            );
            filter[cursor + 4] = seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0);
            filter[cursor + 5] = seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1);
            cursor += 6;
            argument += 1;
        }
        (filter, cursor)
    }

    const fn build_seccomp_filter_v1() -> [LinuxSockFilterV1; SECCOMP_FILTER_INSTRUCTION_COUNT_V1] {
        let marker = seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_MARKER_V1);
        let mut filter = [marker; SECCOMP_FILTER_INSTRUCTION_COUNT_V1];

        filter[0] = seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, SECCOMP_DATA_ARCH_OFFSET_V1);
        filter[1] = seccomp_jump_v1(
            SECCOMP_BPF_JMP_JEQ_K_V1,
            PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
            1,
            0,
        );
        filter[2] = seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_KILL_PROCESS_V1);
        filter[3] = seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, SECCOMP_DATA_NR_OFFSET_V1);
        filter[4] = seccomp_jump_v1(SECCOMP_BPF_JMP_JSET_K_V1, X32_SYSCALL_BIT_V1, 0, 1);
        filter[5] = seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_KILL_PROCESS_V1);

        let getpid_start = FILTER_DISPATCH_INSTRUCTIONS_V1;
        let getppid_start = getpid_start + FILTER_ZERO_ARGUMENT_BLOCK_INSTRUCTIONS_V1;
        let exit_start = getppid_start + FILTER_ZERO_ARGUMENT_BLOCK_INSTRUCTIONS_V1;
        filter[6] = seccomp_jump_v1(
            SECCOMP_BPF_JMP_JEQ_K_V1,
            PTRACE_TRANSPORT_GETPID_NR_X86_64_V1 as u32,
            (getpid_start - 7) as u8,
            0,
        );
        filter[7] = seccomp_jump_v1(
            SECCOMP_BPF_JMP_JEQ_K_V1,
            PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1 as u32,
            (getppid_start - 8) as u8,
            0,
        );
        filter[8] = seccomp_jump_v1(
            SECCOMP_BPF_JMP_JEQ_K_V1,
            libc::SYS_exit as u32,
            (exit_start - 9) as u8,
            0,
        );
        filter[9] = marker;

        let (mut filter, cursor) = append_zero_argument_checks_v1(filter, getpid_start);
        filter[cursor] = seccomp_statement_v1(
            SECCOMP_BPF_RET_K_V1,
            SECCOMP_RET_TRACE_V1 | PTRACE_TRANSPORT_GETPID_COOKIE_V1 as u32,
        );
        let (mut filter, cursor) = append_zero_argument_checks_v1(filter, cursor + 1);
        filter[cursor] = seccomp_statement_v1(
            SECCOMP_BPF_RET_K_V1,
            SECCOMP_RET_TRACE_V1 | PTRACE_TRANSPORT_GETPPID_COOKIE_V1 as u32,
        );

        let mut cursor = cursor + 1;
        filter[cursor] =
            seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(0));
        filter[cursor + 1] = seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 2, 0);
        filter[cursor + 2] = seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, CHILD_FAILURE_EXIT_V1, 1, 0);
        filter[cursor + 3] = marker;
        cursor += 4;
        filter[cursor] =
            seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_high_offset_v1(0));
        filter[cursor + 1] = seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0);
        filter[cursor + 2] = marker;
        cursor += 3;

        let mut argument = 1_u32;
        while argument < 6 {
            filter[cursor] =
                seccomp_statement_v1(SECCOMP_BPF_LD_W_ABS_V1, seccomp_arg_low_offset_v1(argument));
            filter[cursor + 1] = seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0);
            filter[cursor + 2] = marker;
            filter[cursor + 3] = seccomp_statement_v1(
                SECCOMP_BPF_LD_W_ABS_V1,
                seccomp_arg_high_offset_v1(argument),
            );
            filter[cursor + 4] = seccomp_jump_v1(SECCOMP_BPF_JMP_JEQ_K_V1, 0, 1, 0);
            filter[cursor + 5] = marker;
            cursor += 6;
            argument += 1;
        }
        filter[cursor] = seccomp_statement_v1(SECCOMP_BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1);
        filter
    }

    const SECCOMP_FILTER_V1: [LinuxSockFilterV1; SECCOMP_FILTER_INSTRUCTION_COUNT_V1] =
        build_seccomp_filter_v1();

    struct ReleaseChannelV1 {
        read: OwnedFd,
        write: OwnedFd,
    }

    impl ReleaseChannelV1 {
        fn create() -> Result<Self, PtraceTransportQualificationFailureV1> {
            let mut descriptors = [-1_i32; 2];
            let result = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            };
            if result != 0 {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::ReleaseChannel,
                    PtraceTransportReasonV1::Io,
                    Some(last_errno_v1()),
                ));
            }
            if descriptors[0] < 0 || descriptors[1] < 0 || descriptors[0] == descriptors[1] {
                if descriptors[0] >= 0 {
                    let _ = unsafe { libc::close(descriptors[0]) };
                }
                if descriptors[1] >= 0 && descriptors[1] != descriptors[0] {
                    let _ = unsafe { libc::close(descriptors[1]) };
                }
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::ReleaseChannel,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            let channel = Self {
                read: unsafe { OwnedFd::from_raw_fd(descriptors[0]) },
                write: unsafe { OwnedFd::from_raw_fd(descriptors[1]) },
            };
            for descriptor in [channel.read.as_raw_fd(), channel.write.as_raw_fd()] {
                let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
                if flags < 0 {
                    return Err(transport_failure_v1(
                        PtraceTransportStageV1::ReleaseChannel,
                        PtraceTransportReasonV1::Io,
                        Some(last_errno_v1()),
                    ));
                }
                if flags != libc::FD_CLOEXEC {
                    return Err(transport_failure_v1(
                        PtraceTransportStageV1::ReleaseChannel,
                        PtraceTransportReasonV1::MalformedKernelResponse,
                        None,
                    ));
                }
            }
            Ok(channel)
        }
    }

    struct FixedChildGuardV1 {
        pid: Option<libc::pid_t>,
        pidfd: Option<OwnedFd>,
        pidfd_kill_attempted: bool,
        ptrace_stop: Option<(i32, u32)>,
        reaped: bool,
        echild_proven: bool,
    }

    impl FixedChildGuardV1 {
        fn wait_event(
            &mut self,
            signal_channel: &SignalChannelV1,
            deadline: MonotonicDeadlineV1,
            stage: PtraceTransportStageV1,
        ) -> Result<i32, PtraceTransportQualificationFailureV1> {
            let pid = self.pid.ok_or_else(|| {
                transport_failure_v1(
                    stage,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                )
            })?;
            let status = wait_child_event_v1(signal_channel, pid, deadline, stage)?;
            match decode_wait_event_v1(status) {
                Some(DecodedWaitEventV1::PtraceStop { signal, event }) => {
                    self.ptrace_stop = Some((signal, event));
                }
                Some(DecodedWaitEventV1::Exited { .. })
                | Some(DecodedWaitEventV1::Signaled { .. }) => {
                    self.ptrace_stop = None;
                    self.reaped = true;
                }
                Some(DecodedWaitEventV1::Continued) => self.ptrace_stop = None,
                None => {}
            }
            Ok(status)
        }

        fn continue_child(
            &mut self,
            signal: i32,
        ) -> Result<(), PtraceTransportQualificationFailureV1> {
            let pid = self.pid.ok_or_else(|| {
                transport_failure_v1(
                    PtraceTransportStageV1::ContinueChild,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                )
            })?;
            ptrace_continue_v1(pid, signal)?;
            self.ptrace_stop = None;
            Ok(())
        }

        fn refuse(
            mut self,
            signal_channel: &mut SignalChannelV1,
            failure: PtraceTransportQualificationFailureV1,
        ) -> PtraceTransportQualificationFailureV1 {
            match self.kill_and_reap(signal_channel) {
                Ok(()) => failure,
                Err(errno) => PtraceTransportQualificationFailureV1::cleanup_uncertain(errno),
            }
        }

        fn finish(
            self,
            completed: CompletedFixedPtraceTransportProbeV1,
        ) -> Result<CompletedFixedPtraceTransportProbeV1, PtraceTransportQualificationFailureV1>
        {
            if self.ptrace_stop.is_none() && self.reaped && self.echild_proven {
                Ok(completed)
            } else {
                Err(PtraceTransportQualificationFailureV1::cleanup_uncertain(
                    None,
                ))
            }
        }

        fn kill_and_reap(
            &mut self,
            signal_channel: &mut SignalChannelV1,
        ) -> Result<(), Option<i32>> {
            let pidfd = self.pidfd.as_ref().map(AsRawFd::as_raw_fd);
            let mut signal_errno = None;
            if let Some(pidfd) = pidfd {
                self.pidfd_kill_attempted = true;
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd,
                        libc::SIGKILL,
                        ptr::null::<libc::siginfo_t>(),
                        0_u32,
                    )
                };
                if result != 0 {
                    let errno = last_errno_v1();
                    if !(errno == libc::ESRCH && self.reaped && self.echild_proven) {
                        signal_errno = Some(errno);
                    }
                }
            } else {
                signal_errno = Some(libc::EBADF);
            }

            if !self.reaped && self.pid.is_none() {
                let deadline = MonotonicDeadlineV1::after(CLEANUP_SECONDS_V1)
                    .map_err(|failure| failure.errno())?;
                self.reap_pidfd_only_v1(signal_channel, deadline)?;
            }

            if !self.reaped && signal_errno.is_some() {
                let Some(pid) = self.pid else {
                    return Err(signal_errno);
                };
                if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
                    let errno = last_errno_v1();
                    if errno != libc::ESRCH {
                        signal_errno = Some(errno);
                    }
                }
            }
            if !self.reaped {
                if let Some((signal, event)) = self.ptrace_stop {
                    let delivery_signal = if event == 0 && signal == libc::SIGKILL {
                        libc::SIGKILL
                    } else {
                        0
                    };
                    self.continue_child(delivery_signal)
                        .map_err(|failure| failure.errno())?;
                }
            }
            if !self.reaped {
                let deadline = MonotonicDeadlineV1::after(CLEANUP_SECONDS_V1)
                    .map_err(|failure| failure.errno())?;
                self.reap_after_kill_v1(signal_channel, deadline)?;
            }
            self.prove_echild_v1()?;
            if !cleanup_proof_complete_v1(
                self.pidfd_kill_attempted,
                self.reaped,
                self.echild_proven,
            ) {
                return Err(signal_errno.or(Some(libc::EBADF)));
            }
            Ok(())
        }

        fn reap_pidfd_only_v1(
            &mut self,
            signal_channel: &mut SignalChannelV1,
            deadline: MonotonicDeadlineV1,
        ) -> Result<(), Option<i32>> {
            let pidfd = self
                .pidfd
                .as_ref()
                .map(AsRawFd::as_raw_fd)
                .ok_or(Some(libc::EBADF))?;
            let mut attempts = 0_usize;
            while attempts < MAX_WAIT_ATTEMPTS_V1 {
                attempts += 1;
                let timeout = deadline
                    .remaining_milliseconds()
                    .map_err(|()| Some(libc::ETIMEDOUT))?;
                let mut descriptor = libc::pollfd {
                    fd: pidfd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let poll_result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
                if poll_result < 0 {
                    let errno = last_errno_v1();
                    if errno == libc::EINTR {
                        continue;
                    }
                    return Err(Some(errno));
                }
                if poll_result == 0 {
                    return Err(Some(libc::ETIMEDOUT));
                }
                if poll_result != 1
                    || descriptor.revents & libc::POLLIN == 0
                    || descriptor.revents & !libc::POLLIN != 0
                {
                    return Err(Some(libc::EPROTO));
                }

                let mut information = MaybeUninit::<libc::siginfo_t>::zeroed();
                let wait_result = unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        pidfd as libc::id_t,
                        information.as_mut_ptr(),
                        libc::WEXITED | libc::WNOHANG,
                    )
                };
                if wait_result < 0 {
                    let errno = last_errno_v1();
                    if errno == libc::EINTR {
                        continue;
                    }
                    return Err(Some(errno));
                }
                if wait_result != 0 {
                    return Err(Some(libc::EPROTO));
                }
                let information = unsafe { information.assume_init() };
                let child_pid = unsafe { information.si_pid() };
                if child_pid == 0 {
                    continue;
                }
                if child_pid < 0
                    || information.si_signo != libc::SIGCHLD
                    || !matches!(
                        information.si_code,
                        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                    )
                {
                    return Err(Some(libc::EPROTO));
                }
                signal_channel
                    .register_child(child_pid)
                    .map_err(|failure| failure.errno())?;
                self.pid = Some(child_pid);
                self.reaped = true;
                self.prove_pidfd_echild_v1()?;
                return Ok(());
            }
            Err(Some(libc::ETIMEDOUT))
        }

        fn prove_pidfd_echild_v1(&mut self) -> Result<(), Option<i32>> {
            let pidfd = self
                .pidfd
                .as_ref()
                .map(AsRawFd::as_raw_fd)
                .ok_or(Some(libc::EBADF))?;
            let mut attempts = 0_usize;
            while attempts < MAX_WAIT_ATTEMPTS_V1 {
                attempts += 1;
                let mut information = MaybeUninit::<libc::siginfo_t>::zeroed();
                let result = unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        pidfd as libc::id_t,
                        information.as_mut_ptr(),
                        libc::WEXITED | libc::WNOHANG,
                    )
                };
                if result < 0 {
                    let errno = last_errno_v1();
                    if errno == libc::EINTR {
                        continue;
                    }
                    if errno == libc::ECHILD {
                        self.echild_proven = true;
                        return Ok(());
                    }
                    return Err(Some(errno));
                }
                return Err(Some(libc::EPROTO));
            }
            Err(Some(libc::ETIMEDOUT))
        }

        fn reap_after_kill_v1(
            &mut self,
            signal_channel: &SignalChannelV1,
            deadline: MonotonicDeadlineV1,
        ) -> Result<(), Option<i32>> {
            let Some(pid) = self.pid else {
                return Err(Some(libc::EINVAL));
            };
            let mut attempts = 0_usize;
            loop {
                if attempts >= MAX_WAIT_ATTEMPTS_V1 {
                    return Err(Some(libc::ETIMEDOUT));
                }
                attempts += 1;
                let status = wait_child_event_v1(
                    signal_channel,
                    pid,
                    deadline,
                    PtraceTransportStageV1::Cleanup,
                )
                .map_err(|failure| failure.errno())?;
                match cleanup_wait_action_v1(status) {
                    Some(CleanupWaitActionV1::Resume { signal }) => {
                        self.continue_child(signal)
                            .map_err(|failure| failure.errno())?;
                    }
                    Some(CleanupWaitActionV1::Reaped) => {
                        self.reaped = true;
                        return Ok(());
                    }
                    Some(CleanupWaitActionV1::Continue) => {}
                    None => return Err(Some(libc::EPROTO)),
                }
            }
        }

        fn prove_echild_v1(&mut self) -> Result<(), Option<i32>> {
            if self.echild_proven {
                return Ok(());
            }
            let Some(pid) = self.pid else {
                return Err(Some(libc::EINVAL));
            };
            let mut attempts = 0_usize;
            while attempts < MAX_WAIT_ATTEMPTS_V1 {
                attempts += 1;
                let mut status = 0_i32;
                let result =
                    unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | WAIT_WALL_V1) };
                if result < 0 {
                    let errno = last_errno_v1();
                    if errno == libc::EINTR {
                        continue;
                    }
                    if errno == libc::ECHILD {
                        self.echild_proven = true;
                        return Ok(());
                    }
                    return Err(Some(errno));
                }
                return Err(Some(libc::EPROTO));
            }
            Err(Some(libc::ETIMEDOUT))
        }
    }

    impl Drop for FixedChildGuardV1 {
        fn drop(&mut self) {
            if !self.reaped || !self.echild_proven {
                if let Some(pidfd) = self.pidfd.as_ref() {
                    let _ = unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            pidfd.as_raw_fd(),
                            libc::SIGKILL,
                            ptr::null::<libc::siginfo_t>(),
                            0_u32,
                        )
                    };
                }
            }
        }
    }

    fn clone_fixed_child_v1(
        release_read: RawFd,
        release_write: RawFd,
        signal_descriptor: RawFd,
    ) -> Result<FixedChildGuardV1, PtraceTransportQualificationFailureV1> {
        let mut pidfd = -1_i32;
        let mut arguments = CloneArgsV1 {
            flags: CLONE_PIDFD_V1,
            pidfd: (&mut pidfd as *mut i32) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgsV1::default()
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut arguments,
                std::mem::size_of::<CloneArgsV1>(),
            )
        };
        if result == 0 {
            unsafe { child_entry_v1(release_read, release_write, signal_descriptor) };
        }
        if result < 0 {
            return Err(clone_failure_v1(last_errno_v1()));
        }

        let pid = i32::try_from(result).ok().filter(|value| *value > 0);
        let pidfd = (pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd) });
        Ok(FixedChildGuardV1 {
            pid,
            pidfd,
            pidfd_kill_attempted: false,
            ptrace_stop: None,
            reaped: false,
            echild_proven: false,
        })
    }

    fn validate_pidfd_v1(
        guard: &FixedChildGuardV1,
    ) -> Result<(), PtraceTransportQualificationFailureV1> {
        let pidfd = guard.pidfd.as_ref().ok_or_else(|| {
            transport_failure_v1(
                PtraceTransportStageV1::CloneChild,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            )
        })?;
        let flags = unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::CloneChild,
                PtraceTransportReasonV1::Io,
                Some(last_errno_v1()),
            ));
        }
        if flags != libc::FD_CLOEXEC {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::CloneChild,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(())
    }

    fn seize_child_v1(child_pid: libc::pid_t) -> Result<(), PtraceTransportQualificationFailureV1> {
        match ptrace_call_v1(PTRACE_SEIZE_V1, child_pid, 0, PTRACE_OPTIONS_V1) {
            Ok(0) => Ok(()),
            Ok(_) => Err(transport_failure_v1(
                PtraceTransportStageV1::PtraceSeize,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            )),
            Err(errno) => Err(ptrace_seize_failure_v1(errno)),
        }
    }

    fn release_child_v1(descriptor: OwnedFd) -> Result<(), PtraceTransportQualificationFailureV1> {
        let mut attempts = 0_usize;
        loop {
            let byte = RELEASE_BYTE_V1;
            let result = unsafe {
                libc::send(
                    descriptor.as_raw_fd(),
                    (&byte as *const u8).cast(),
                    1,
                    libc::MSG_NOSIGNAL,
                )
            };
            if result == 1 {
                return Ok(());
            }
            if result < 0 && last_errno_v1() == libc::EINTR {
                attempts += 1;
                if attempts < MAX_CHILD_IO_ATTEMPTS_V1 {
                    continue;
                }
            }
            return Err(transport_failure_v1(
                PtraceTransportStageV1::ReleaseChild,
                if result == 0 {
                    PtraceTransportReasonV1::ShortIo
                } else {
                    PtraceTransportReasonV1::Io
                },
                (result < 0).then(last_errno_v1),
            ));
        }
    }

    unsafe fn child_entry_v1(
        release_read: RawFd,
        release_write: RawFd,
        signal_descriptor: RawFd,
    ) -> ! {
        unsafe {
            if raw_syscall6_v1(libc::SYS_close, i64::from(release_write), 0, 0, 0, 0, 0) != 0
                || raw_syscall6_v1(libc::SYS_close, i64::from(signal_descriptor), 0, 0, 0, 0, 0)
                    != 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }

            let mut release = 0_u8;
            if child_read_bounded_v1(release_read, &mut release) != 1 {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            if release != RELEASE_BYTE_V1 {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            let eof = child_read_bounded_v1(release_read, &mut release);
            if eof != 0
                || raw_syscall6_v1(libc::SYS_close, i64::from(release_read), 0, 0, 0, 0, 0) != 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }

            if raw_syscall6_v1(
                libc::SYS_prctl,
                libc::PR_SET_NO_NEW_PRIVS.into(),
                1,
                0,
                0,
                0,
                0,
            ) != 0
                || raw_syscall6_v1(
                    libc::SYS_prctl,
                    libc::PR_GET_NO_NEW_PRIVS.into(),
                    0,
                    0,
                    0,
                    0,
                    0,
                ) != 1
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            let program = LinuxSockFprogV1 {
                length: SECCOMP_FILTER_INSTRUCTION_COUNT_V1 as u16,
                filter: SECCOMP_FILTER_V1.as_ptr(),
            };
            if raw_syscall6_v1(
                libc::SYS_seccomp,
                i64::from(SECCOMP_SET_MODE_FILTER_V1),
                i64::from(SECCOMP_FILTER_FLAG_TSYNC_V1),
                (&program as *const LinuxSockFprogV1) as i64,
                0,
                0,
                0,
            ) != 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }

            if raw_syscall6_v1(libc::SYS_getpid, 0, 0, 0, 0, 0, 0) <= 0
                || raw_syscall6_v1(libc::SYS_getppid, 0, 0, 0, 0, 0, 0) <= 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            child_exit_v1(0)
        }
    }

    unsafe fn child_read_bounded_v1(descriptor: RawFd, byte: &mut u8) -> i64 {
        let mut attempts = 0_usize;
        loop {
            let result = unsafe {
                raw_syscall6_v1(
                    libc::SYS_read,
                    i64::from(descriptor),
                    (byte as *mut u8) as i64,
                    1,
                    0,
                    0,
                    0,
                )
            };
            if result != -i64::from(libc::EINTR) {
                return result;
            }
            attempts += 1;
            if attempts >= MAX_CHILD_IO_ATTEMPTS_V1 {
                return result;
            }
        }
    }

    unsafe fn child_exit_v1(status: u32) -> ! {
        unsafe {
            let _ = raw_syscall6_v1(libc::SYS_exit, i64::from(status), 0, 0, 0, 0, 0);
            core::arch::asm!("ud2", options(noreturn, nostack));
        }
    }

    unsafe fn raw_syscall6_v1(
        syscall_number: libc::c_long,
        argument0: i64,
        argument1: i64,
        argument2: i64,
        argument3: i64,
        argument4: i64,
        argument5: i64,
    ) -> i64 {
        let mut result = syscall_number;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") result,
                in("rdi") argument0,
                in("rsi") argument1,
                in("rdx") argument2,
                in("r10") argument3,
                in("r8") argument4,
                in("r9") argument5,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        result
    }

    #[derive(Clone, Copy)]
    struct MonotonicDeadlineV1 {
        seconds: i64,
        nanoseconds: i64,
    }

    impl MonotonicDeadlineV1 {
        fn after(seconds: i64) -> Result<Self, PtraceTransportQualificationFailureV1> {
            let now = monotonic_now_v1().map_err(|errno| {
                transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::Io,
                    Some(errno),
                )
            })?;
            let seconds = now.tv_sec.checked_add(seconds).ok_or_else(|| {
                transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::BoundExceeded,
                    None,
                )
            })?;
            Ok(Self {
                seconds,
                nanoseconds: now.tv_nsec,
            })
        }

        fn remaining_milliseconds(self) -> Result<libc::c_int, ()> {
            let now = monotonic_now_v1().map_err(|_| ())?;
            let mut seconds = self.seconds.checked_sub(now.tv_sec).ok_or(())?;
            let mut nanoseconds = self.nanoseconds - now.tv_nsec;
            if nanoseconds < 0 {
                seconds = seconds.checked_sub(1).ok_or(())?;
                nanoseconds += 1_000_000_000;
            }
            if seconds < 0 || (seconds == 0 && nanoseconds <= 0) {
                return Err(());
            }
            let milliseconds = seconds
                .checked_mul(1_000)
                .and_then(|value| value.checked_add((nanoseconds + 999_999) / 1_000_000))
                .ok_or(())?;
            libc::c_int::try_from(milliseconds.min(i64::from(libc::c_int::MAX))).map_err(|_| ())
        }
    }

    #[derive(Debug, PartialEq)]
    enum DecodedWaitEventV1 {
        PtraceStop { signal: i32, event: u32 },
        Exited { code: u8 },
        Signaled { signal: u8, core_dumped: bool },
        Continued,
    }

    #[derive(Debug, PartialEq)]
    enum CleanupWaitActionV1 {
        Resume { signal: i32 },
        Reaped,
        Continue,
    }

    fn decode_wait_event_v1(status: i32) -> Option<DecodedWaitEventV1> {
        let raw = u32::try_from(status).ok()?;
        if raw & 0xff == 0x7f {
            return Some(DecodedWaitEventV1::PtraceStop {
                signal: ((raw >> 8) & 0xff) as i32,
                event: raw >> 16,
            });
        }
        if raw == 0xffff {
            return Some(DecodedWaitEventV1::Continued);
        }
        if raw > u16::MAX as u32 {
            return None;
        }
        if raw & 0x7f == 0 {
            return Some(DecodedWaitEventV1::Exited {
                code: ((raw >> 8) & 0xff) as u8,
            });
        }
        let signal = (raw & 0x7f) as u8;
        if signal == 0 || signal > 64 {
            return None;
        }
        Some(DecodedWaitEventV1::Signaled {
            signal,
            core_dumped: raw & 0x80 != 0,
        })
    }

    fn cleanup_wait_action_v1(status: i32) -> Option<CleanupWaitActionV1> {
        match decode_wait_event_v1(status)? {
            DecodedWaitEventV1::PtraceStop { signal, event } => Some(CleanupWaitActionV1::Resume {
                signal: if event == 0 && signal == libc::SIGKILL {
                    libc::SIGKILL
                } else {
                    0
                },
            }),
            DecodedWaitEventV1::Exited { .. } | DecodedWaitEventV1::Signaled { .. } => {
                Some(CleanupWaitActionV1::Reaped)
            }
            DecodedWaitEventV1::Continued => Some(CleanupWaitActionV1::Continue),
        }
    }

    fn wait_child_event_v1(
        signal_channel: &SignalChannelV1,
        child_pid: libc::pid_t,
        deadline: MonotonicDeadlineV1,
        stage: PtraceTransportStageV1,
    ) -> Result<i32, PtraceTransportQualificationFailureV1> {
        let mut attempts = 0_usize;
        loop {
            if attempts >= MAX_WAIT_ATTEMPTS_V1 {
                return Err(transport_failure_v1(
                    stage,
                    PtraceTransportReasonV1::BoundExceeded,
                    None,
                ));
            }
            attempts += 1;
            let mut status = 0_i32;
            let wait_result =
                unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG | WAIT_WALL_V1) };
            if wait_result == child_pid {
                if decode_wait_event_v1(status).is_none() {
                    return Err(transport_failure_v1(
                        stage,
                        PtraceTransportReasonV1::MalformedKernelResponse,
                        None,
                    ));
                }
                return Ok(status);
            }
            if wait_result < 0 {
                let errno = last_errno_v1();
                if errno == libc::EINTR {
                    continue;
                }
                return Err(transport_failure_v1(
                    stage,
                    PtraceTransportReasonV1::Io,
                    Some(errno),
                ));
            }
            if wait_result != 0 {
                return Err(transport_failure_v1(
                    stage,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                ));
            }

            let timeout = deadline.remaining_milliseconds().map_err(|()| {
                transport_failure_v1(stage, PtraceTransportReasonV1::BoundExceeded, None)
            })?;
            let mut poll_descriptor = libc::pollfd {
                fd: signal_channel.descriptor.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_result = unsafe { libc::poll(&mut poll_descriptor, 1, timeout) };
            if poll_result < 0 {
                let errno = last_errno_v1();
                if errno == libc::EINTR {
                    continue;
                }
                return Err(transport_failure_v1(
                    stage,
                    PtraceTransportReasonV1::Io,
                    Some(errno),
                ));
            }
            if poll_result == 0 {
                return Err(transport_failure_v1(
                    stage,
                    PtraceTransportReasonV1::BoundExceeded,
                    None,
                ));
            }
            if poll_result != 1
                || poll_descriptor.revents & !libc::POLLIN != 0
                || poll_descriptor.revents & libc::POLLIN == 0
            {
                return Err(transport_failure_v1(
                    stage,
                    PtraceTransportReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            signal_channel.read_notification()?;
        }
    }

    fn require_ptrace_stop_v1(
        status: i32,
        expected_event: u32,
    ) -> Result<(), PtraceTransportQualificationFailureV1> {
        match decode_wait_event_v1(status) {
            Some(DecodedWaitEventV1::PtraceStop { signal, event })
                if signal == libc::SIGTRAP && event == expected_event =>
            {
                Ok(())
            }
            _ => Err(transport_failure_v1(
                PtraceTransportStageV1::WaitEvent,
                PtraceTransportReasonV1::UnexpectedLifecycleEvent,
                None,
            )),
        }
    }

    fn ptrace_call_v1(
        request: u64,
        child_pid: libc::pid_t,
        address: u64,
        data: u64,
    ) -> Result<libc::c_long, i32> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_ptrace,
                request,
                child_pid,
                address,
                data,
                0_u64,
                0_u64,
            )
        };
        if result < 0 {
            Err(last_errno_v1())
        } else {
            Ok(result)
        }
    }

    fn ptrace_continue_v1(
        child_pid: libc::pid_t,
        signal: i32,
    ) -> Result<(), PtraceTransportQualificationFailureV1> {
        let result =
            ptrace_call_v1(PTRACE_CONT_V1, child_pid, 0, signal as u64).map_err(|errno| {
                transport_failure_v1(
                    PtraceTransportStageV1::ContinueChild,
                    PtraceTransportReasonV1::Io,
                    Some(errno),
                )
            })?;
        if result != 0 {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::ContinueChild,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(())
    }

    fn ptrace_event_message_v1(
        child_pid: libc::pid_t,
    ) -> Result<u64, PtraceTransportQualificationFailureV1> {
        let mut message = u64::MAX;
        let result = ptrace_call_v1(
            PTRACE_GETEVENTMSG_V1,
            child_pid,
            0,
            (&mut message as *mut u64) as u64,
        )
        .map_err(|errno| {
            transport_failure_v1(
                PtraceTransportStageV1::ReadEventMessage,
                PtraceTransportReasonV1::Io,
                Some(errno),
            )
        })?;
        if result != 0 {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::ReadEventMessage,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(message)
    }

    fn read_seccomp_syscall_info_v1(
        child_pid: libc::pid_t,
        expected_syscall_number: i64,
        expected_cookie: u16,
    ) -> Result<FixedPtraceTransportEventV1, PtraceTransportQualificationFailureV1> {
        const TRAILING_CANARY_V1: u32 = 0xa5a5_a5a5;
        let mut information = LinuxPtraceSyscallInfoSeccompV1 {
            operation: 0xa5,
            reserved: 0xa5,
            flags: 0xa5a5,
            architecture: 0xa5a5_a5a5,
            instruction_pointer: u64::MAX,
            stack_pointer: u64::MAX,
            syscall_number: u64::MAX,
            arguments: [u64::MAX; 6],
            return_data: u32::MAX,
            reserved2: TRAILING_CANARY_V1,
        };
        let result = ptrace_call_v1(
            PTRACE_GET_SYSCALL_INFO_V1,
            child_pid,
            std::mem::size_of::<LinuxPtraceSyscallInfoSeccompV1>() as u64,
            (&mut information as *mut LinuxPtraceSyscallInfoSeccompV1) as u64,
        )
        .map_err(|errno| {
            transport_failure_v1(
                PtraceTransportStageV1::ReadSyscallInfo,
                PtraceTransportReasonV1::Io,
                Some(errno),
            )
        })?;
        if result != PTRACE_SECCOMP_INFO_BYTES_V1
            || information.operation != PTRACE_SYSCALL_INFO_SECCOMP_V1
            || information.reserved != 0
            || information.flags != 0
            || information.architecture != PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1
            || information.syscall_number != expected_syscall_number as u64
            || information.arguments != [0; 6]
            || information.return_data != u32::from(expected_cookie)
            || information.reserved2 != TRAILING_CANARY_V1
        {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::ReadSyscallInfo,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(FixedPtraceTransportEventV1::SeccompStop {
            raw_tid: child_pid,
            architecture: information.architecture,
            syscall_number: expected_syscall_number,
            arguments: information.arguments,
            cookie: expected_cookie,
        })
    }

    fn observe_seccomp_stop_v1(
        signal_channel: &SignalChannelV1,
        deadline: MonotonicDeadlineV1,
        child: &mut FixedChildGuardV1,
        expected_syscall_number: i64,
        expected_cookie: u16,
        recorder: FixedPtraceTransportProbeRecorderV1,
    ) -> Result<FixedPtraceTransportProbeRecorderV1, PtraceTransportQualificationFailureV1> {
        let child_pid = child.pid.ok_or_else(|| {
            transport_failure_v1(
                PtraceTransportStageV1::WaitEvent,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            )
        })?;
        let status =
            child.wait_event(signal_channel, deadline, PtraceTransportStageV1::WaitEvent)?;
        require_ptrace_stop_v1(status, PTRACE_EVENT_SECCOMP_V1)?;
        let message = ptrace_event_message_v1(child_pid)?;
        if message != u64::from(expected_cookie) {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::ReadEventMessage,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        let event =
            read_seccomp_syscall_info_v1(child_pid, expected_syscall_number, expected_cookie)?;
        let recorder = recorder.observe(event).map_err(protocol_failure_v1)?;
        child.continue_child(0)?;
        Ok(recorder)
    }

    pub(super) fn qualify_fixed_ptrace_transport_v1()
    -> Result<CompletedFixedPtraceTransportProbeV1, PtraceTransportQualificationFailureV1> {
        require_dedicated_single_task_v1()?;
        require_no_loader_injection_environment_v1()?;
        require_seccomp_actions_v1()?;
        let mut signal_channel = SignalChannelV1::create()?;
        let outcome = qualify_with_signal_channel_v1(&mut signal_channel);
        let drain_result = signal_channel.drain_before_restore();
        let restore_result = signal_channel.restore();
        if let Err(errno) = restore_result {
            return Err(PtraceTransportQualificationFailureV1::cleanup_uncertain(
                Some(errno),
            ));
        }
        if let Err(failure) = drain_result {
            return Err(failure.with_cleanup_complete(false));
        }
        outcome
    }

    fn qualify_with_signal_channel_v1(
        signal_channel: &mut SignalChannelV1,
    ) -> Result<CompletedFixedPtraceTransportProbeV1, PtraceTransportQualificationFailureV1> {
        let deadline = MonotonicDeadlineV1::after(TRANSPORT_SECONDS_V1)?;
        let release_channel = ReleaseChannelV1::create()?;
        require_dedicated_single_task_v1()?;
        let mut child = clone_fixed_child_v1(
            release_channel.read.as_raw_fd(),
            release_channel.write.as_raw_fd(),
            signal_channel.descriptor.as_raw_fd(),
        )?;
        drop(release_channel.read);
        let mut release_write = Some(release_channel.write);

        let outcome = (|| {
            let child_pid = child.pid.ok_or_else(|| {
                transport_failure_v1(
                    PtraceTransportStageV1::CloneChild,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                )
            })?;
            signal_channel.register_child(child_pid)?;
            validate_pidfd_v1(&child)?;
            seize_child_v1(child_pid)?;
            let release_descriptor = release_write.take().ok_or_else(|| {
                transport_failure_v1(
                    PtraceTransportStageV1::ReleaseChild,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                )
            })?;
            release_child_v1(release_descriptor)?;

            let recorder = observe_seccomp_stop_v1(
                signal_channel,
                deadline,
                &mut child,
                PTRACE_TRANSPORT_GETPID_NR_X86_64_V1,
                PTRACE_TRANSPORT_GETPID_COOKIE_V1,
                FixedPtraceTransportProbeRecorderV1::new(
                    FixedPtraceTransportRecorderPermitV1::issue(),
                ),
            )?;
            let recorder = observe_seccomp_stop_v1(
                signal_channel,
                deadline,
                &mut child,
                PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1,
                PTRACE_TRANSPORT_GETPPID_COOKIE_V1,
                recorder,
            )?;

            let exit_status =
                child.wait_event(signal_channel, deadline, PtraceTransportStageV1::WaitEvent)?;
            require_ptrace_stop_v1(exit_status, PTRACE_EVENT_EXIT_V1)?;
            let exit_message = ptrace_event_message_v1(child_pid)?;
            require_zero_exit_event_message_v1(exit_message)?;
            let recorder = recorder
                .observe(FixedPtraceTransportEventV1::PtraceExitEvent {
                    raw_tid: child_pid,
                    status: exit_message,
                })
                .map_err(protocol_failure_v1)?;
            child.continue_child(0)?;

            let terminal_status = child.wait_event(
                signal_channel,
                deadline,
                PtraceTransportStageV1::TerminalReap,
            )?;
            if decode_wait_event_v1(terminal_status) != Some(DecodedWaitEventV1::Exited { code: 0 })
            {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::TerminalReap,
                    PtraceTransportReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            let wait_status =
                RawLinuxWaitStatusV1(u32::try_from(terminal_status).map_err(|_| {
                    transport_failure_v1(
                        PtraceTransportStageV1::TerminalReap,
                        PtraceTransportReasonV1::MalformedKernelResponse,
                        None,
                    )
                })?);
            let recorder = recorder
                .observe(FixedPtraceTransportEventV1::TerminalReap {
                    raw_tid: child_pid,
                    wait_status,
                })
                .map_err(protocol_failure_v1)?;
            child.prove_echild_v1().map_err(|errno| {
                transport_failure_v1(
                    PtraceTransportStageV1::TerminalReap,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    errno,
                )
            })?;
            recorder.complete().map_err(protocol_failure_v1)
        })();

        drop(release_write);
        match outcome {
            Ok(completed) => child.finish(completed),
            Err(failure) => Err(child.refuse(signal_channel, failure)),
        }
    }

    fn monotonic_now_v1() -> Result<libc::timespec, i32> {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) };
        if result == 0 {
            let value = unsafe { value.assume_init() };
            if value.tv_nsec < 0 || value.tv_nsec >= 1_000_000_000 {
                return Err(0);
            }
            Ok(value)
        } else {
            Err(last_errno_v1())
        }
    }

    struct SignalChannelV1 {
        descriptor: OwnedFd,
        prior_mask: libc::sigset_t,
        expected_child: Option<libc::pid_t>,
        restored: bool,
    }

    impl SignalChannelV1 {
        fn create() -> Result<Self, PtraceTransportQualificationFailureV1> {
            let mut signal_set = MaybeUninit::<libc::sigset_t>::uninit();
            let empty_result = unsafe { libc::sigemptyset(signal_set.as_mut_ptr()) };
            if empty_result != 0 {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    Some(last_errno_v1()),
                ));
            }
            let mut signal_set = unsafe { signal_set.assume_init() };
            if unsafe { libc::sigaddset(&mut signal_set, libc::SIGCHLD) } != 0 {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    Some(last_errno_v1()),
                ));
            }

            let mut prior_mask = MaybeUninit::<libc::sigset_t>::uninit();
            let mask_result = unsafe {
                libc::pthread_sigmask(libc::SIG_BLOCK, &signal_set, prior_mask.as_mut_ptr())
            };
            if mask_result != 0 {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::Io,
                    Some(mask_result),
                ));
            }
            let prior_mask = unsafe { prior_mask.assume_init() };
            let prior_membership = unsafe { libc::sigismember(&prior_mask, libc::SIGCHLD) };
            if prior_membership != 0 {
                let membership_errno = (prior_membership < 0).then(last_errno_v1);
                let restore_result = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &prior_mask, ptr::null_mut())
                };
                return Err(if restore_result != 0 {
                    PtraceTransportQualificationFailureV1::cleanup_uncertain(Some(restore_result))
                } else if prior_membership < 0 {
                    transport_failure_v1(
                        PtraceTransportStageV1::SignalChannel,
                        PtraceTransportReasonV1::MalformedKernelResponse,
                        membership_errno,
                    )
                } else {
                    transport_failure_v1(
                        PtraceTransportStageV1::SignalChannel,
                        PtraceTransportReasonV1::SignalDisposition,
                        None,
                    )
                });
            }

            let mut pending = MaybeUninit::<libc::sigset_t>::uninit();
            let pending_result = unsafe { libc::sigpending(pending.as_mut_ptr()) };
            let pending_membership = if pending_result == 0 {
                let pending = unsafe { pending.assume_init() };
                unsafe { libc::sigismember(&pending, libc::SIGCHLD) }
            } else {
                -1
            };
            if pending_result != 0 || pending_membership != 0 {
                let errno = (pending_result != 0 || pending_membership < 0).then(last_errno_v1);
                let restore_result = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &prior_mask, ptr::null_mut())
                };
                return Err(if restore_result == 0 {
                    transport_failure_v1(
                        PtraceTransportStageV1::SignalChannel,
                        if pending_membership > 0 {
                            PtraceTransportReasonV1::UnexpectedLifecycleEvent
                        } else {
                            PtraceTransportReasonV1::MalformedKernelResponse
                        },
                        errno,
                    )
                } else {
                    PtraceTransportQualificationFailureV1::cleanup_uncertain(Some(restore_result))
                });
            }
            let descriptor =
                unsafe { libc::signalfd(-1, &signal_set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
            if descriptor < 0 {
                let errno = last_errno_v1();
                let restore_result = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &prior_mask, ptr::null_mut())
                };
                return Err(if restore_result == 0 {
                    transport_failure_v1(
                        PtraceTransportStageV1::SignalChannel,
                        PtraceTransportReasonV1::Io,
                        Some(errno),
                    )
                } else {
                    PtraceTransportQualificationFailureV1::cleanup_uncertain(Some(restore_result))
                });
            }
            let channel = Self {
                descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) },
                prior_mask,
                expected_child: None,
                restored: false,
            };
            if let Err(failure) = channel.validate_descriptor() {
                return Err(match channel.restore() {
                    Ok(()) => failure,
                    Err(errno) => {
                        PtraceTransportQualificationFailureV1::cleanup_uncertain(Some(errno))
                    }
                });
            }
            Ok(channel)
        }

        fn validate_descriptor(&self) -> Result<(), PtraceTransportQualificationFailureV1> {
            let descriptor_flags =
                unsafe { libc::fcntl(self.descriptor.as_raw_fd(), libc::F_GETFD) };
            if descriptor_flags < 0 {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::Io,
                    Some(last_errno_v1()),
                ));
            }
            let status_flags = unsafe { libc::fcntl(self.descriptor.as_raw_fd(), libc::F_GETFL) };
            if status_flags < 0 {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::Io,
                    Some(last_errno_v1()),
                ));
            }
            if descriptor_flags != libc::FD_CLOEXEC || status_flags & libc::O_NONBLOCK == 0 {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            Ok(())
        }

        fn register_child(
            &mut self,
            child_pid: libc::pid_t,
        ) -> Result<(), PtraceTransportQualificationFailureV1> {
            if child_pid <= 0 || self.expected_child.replace(child_pid).is_some() {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            Ok(())
        }

        fn read_notification(&self) -> Result<bool, PtraceTransportQualificationFailureV1> {
            let mut information = MaybeUninit::<libc::signalfd_siginfo>::uninit();
            let result = unsafe {
                libc::read(
                    self.descriptor.as_raw_fd(),
                    information.as_mut_ptr().cast(),
                    std::mem::size_of::<libc::signalfd_siginfo>(),
                )
            };
            if result < 0 {
                let errno = last_errno_v1();
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    return Ok(false);
                }
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::Io,
                    Some(errno),
                ));
            }
            if usize::try_from(result).ok() != Some(std::mem::size_of::<libc::signalfd_siginfo>()) {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::ShortIo,
                    None,
                ));
            }
            let information = unsafe { information.assume_init() };
            self.validate_notification(&information)?;
            Ok(true)
        }

        fn validate_notification(
            &self,
            information: &libc::signalfd_siginfo,
        ) -> Result<(), PtraceTransportQualificationFailureV1> {
            let expected_pid = self.expected_child.and_then(|pid| u32::try_from(pid).ok());
            if information.ssi_signo != libc::SIGCHLD as u32
                || expected_pid != Some(information.ssi_pid)
                || !matches!(
                    information.ssi_code,
                    libc::CLD_EXITED
                        | libc::CLD_KILLED
                        | libc::CLD_DUMPED
                        | libc::CLD_TRAPPED
                        | libc::CLD_STOPPED
                        | libc::CLD_CONTINUED
                )
            {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SignalChannel,
                    PtraceTransportReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            Ok(())
        }

        fn drain_before_restore(&self) -> Result<(), PtraceTransportQualificationFailureV1> {
            let mut attempts = 0_usize;
            loop {
                if attempts >= MAX_SIGNAL_READ_ATTEMPTS_V1 {
                    return Err(transport_failure_v1(
                        PtraceTransportStageV1::SignalChannel,
                        PtraceTransportReasonV1::BoundExceeded,
                        None,
                    ));
                }
                if self.read_notification()? {
                    attempts += 1;
                } else {
                    return Ok(());
                }
            }
        }

        fn restore(mut self) -> Result<(), i32> {
            let result = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.prior_mask, ptr::null_mut())
            };
            if result != 0 {
                return Err(result);
            }
            verify_signal_mask_v1(&self.prior_mask)?;
            self.restored = true;
            Ok(())
        }
    }

    fn verify_signal_mask_v1(expected: &libc::sigset_t) -> Result<(), i32> {
        let mut observed = MaybeUninit::<libc::sigset_t>::uninit();
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, ptr::null(), observed.as_mut_ptr()) };
        if result != 0 {
            return Err(result);
        }
        let observed = unsafe { observed.assume_init() };
        let mut signal = 1;
        while signal <= 64 {
            let expected_member = unsafe { libc::sigismember(expected, signal) };
            let observed_member = unsafe { libc::sigismember(&observed, signal) };
            if expected_member < 0 || observed_member < 0 {
                return Err(last_errno_v1());
            }
            if expected_member != observed_member {
                return Err(libc::EPROTO);
            }
            signal += 1;
        }
        Ok(())
    }

    impl Drop for SignalChannelV1 {
        fn drop(&mut self) {
            if !self.restored {
                let _ = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &self.prior_mask, ptr::null_mut())
                };
            }
        }
    }

    fn require_dedicated_single_task_v1() -> Result<(), PtraceTransportQualificationFailureV1> {
        let process_id = unsafe { libc::getpid() };
        let task_id = unsafe { libc::syscall(libc::SYS_gettid) };
        if process_id <= 0 || task_id != libc::c_long::from(process_id) {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::MultipleTasks,
                None,
            ));
        }
        let expected_name = process_id.to_string();
        let mut count = 0_usize;
        let entries = fs::read_dir("/proc/self/task").map_err(|error| {
            transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                transport_failure_v1(
                    PtraceTransportStageV1::DedicatedHelper,
                    PtraceTransportReasonV1::Io,
                    error.raw_os_error(),
                )
            })?;
            let name = entry.file_name();
            let bytes = name.as_bytes();
            if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::DedicatedHelper,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            count = count.checked_add(1).ok_or_else(|| {
                transport_failure_v1(
                    PtraceTransportStageV1::DedicatedHelper,
                    PtraceTransportReasonV1::BoundExceeded,
                    None,
                )
            })?;
            if count > 1 || bytes != expected_name.as_bytes() {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::DedicatedHelper,
                    PtraceTransportReasonV1::MultipleTasks,
                    None,
                ));
            }
        }
        if count != 1 {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        require_no_existing_children_v1(process_id)?;
        require_sigchld_disposition_v1()
    }

    fn require_no_existing_children_v1(
        process_id: libc::pid_t,
    ) -> Result<(), PtraceTransportQualificationFailureV1> {
        let path = format!("/proc/self/task/{process_id}/children");
        let children = fs::read(path).map_err(|error| {
            transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        if !children.is_empty() {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::UnexpectedLifecycleEvent,
                None,
            ));
        }
        Ok(())
    }

    fn require_no_loader_injection_environment_v1()
    -> Result<(), PtraceTransportQualificationFailureV1> {
        let environment = fs::File::open("/proc/self/environ").map_err(|error| {
            transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        let mut bounded = environment.take((MAX_ENVIRONMENT_BYTES_V1 + 1) as u64);
        let mut bytes = Vec::new();
        bounded.read_to_end(&mut bytes).map_err(|error| {
            transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        if bytes.len() > MAX_ENVIRONMENT_BYTES_V1 {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::BoundExceeded,
                None,
            ));
        }
        validate_environment_bytes_v1(&bytes)
    }

    fn validate_environment_bytes_v1(
        bytes: &[u8],
    ) -> Result<(), PtraceTransportQualificationFailureV1> {
        if bytes.is_empty() {
            return Ok(());
        }
        if bytes.last() != Some(&0) {
            return Err(malformed_environment_failure_v1());
        }
        let entries = &bytes[..bytes.len() - 1];
        if entries.is_empty() {
            return Err(malformed_environment_failure_v1());
        }
        for entry in entries.split(|byte| *byte == 0) {
            let Some(separator) = entry.iter().position(|byte| *byte == b'=') else {
                return Err(malformed_environment_failure_v1());
            };
            if separator == 0 {
                return Err(malformed_environment_failure_v1());
            }
            let name = &entry[..separator];
            if loader_injection_name_v1(name) {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::DedicatedHelper,
                    PtraceTransportReasonV1::LoaderInjectionEnvironment,
                    None,
                ));
            }
        }
        Ok(())
    }

    fn loader_injection_name_v1(name: &[u8]) -> bool {
        name.starts_with(b"LD_")
            || name.starts_with(b"DYLD_")
            || name.starts_with(b"MALLOC_")
            || matches!(
                name,
                b"GLIBC_TUNABLES" | b"GCONV_PATH" | b"LOCPATH" | b"NLSPATH"
            )
    }

    fn malformed_environment_failure_v1() -> PtraceTransportQualificationFailureV1 {
        transport_failure_v1(
            PtraceTransportStageV1::DedicatedHelper,
            PtraceTransportReasonV1::MalformedKernelResponse,
            None,
        )
    }

    fn require_sigchld_disposition_v1() -> Result<(), PtraceTransportQualificationFailureV1> {
        let mut action = MaybeUninit::<libc::sigaction>::uninit();
        let result = unsafe { libc::sigaction(libc::SIGCHLD, ptr::null(), action.as_mut_ptr()) };
        if result != 0 {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::Io,
                Some(last_errno_v1()),
            ));
        }
        let action = unsafe { action.assume_init() };
        if action.sa_sigaction != libc::SIG_DFL
            || action.sa_flags & (libc::SA_NOCLDWAIT | libc::SA_NOCLDSTOP) != 0
        {
            return Err(transport_failure_v1(
                PtraceTransportStageV1::DedicatedHelper,
                PtraceTransportReasonV1::SignalDisposition,
                None,
            ));
        }
        Ok(())
    }

    fn require_seccomp_actions_v1() -> Result<(), PtraceTransportQualificationFailureV1> {
        for expected_action in [
            SECCOMP_RET_TRACE_V1,
            SECCOMP_RET_KILL_PROCESS_V1,
            SECCOMP_RET_ERRNO_V1,
        ] {
            let mut action = expected_action;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_GET_ACTION_AVAIL_V1,
                    0_u32,
                    &mut action,
                )
            };
            if action != expected_action {
                return Err(transport_failure_v1(
                    PtraceTransportStageV1::SeccompActions,
                    PtraceTransportReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            if result == 0 {
                continue;
            }
            if result < 0 {
                let errno = last_errno_v1();
                return Err(seccomp_action_failure_v1(errno));
            }
            return Err(transport_failure_v1(
                PtraceTransportStageV1::SeccompActions,
                PtraceTransportReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(())
    }

    fn seccomp_action_failure_v1(errno: i32) -> PtraceTransportQualificationFailureV1 {
        if matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP) {
            return PtraceTransportQualificationFailureV1::new(
                RefusalCode::SeccompUnavailable,
                PtraceTransportStageV1::SeccompActions,
                PtraceTransportReasonV1::KernelCapabilityUnavailable,
                Some(errno),
            );
        }
        transport_failure_v1(
            PtraceTransportStageV1::SeccompActions,
            if valid_errno_v1(errno) {
                PtraceTransportReasonV1::Io
            } else {
                PtraceTransportReasonV1::MalformedKernelResponse
            },
            valid_errno_v1(errno).then_some(errno),
        )
    }

    fn clone_failure_v1(errno: i32) -> PtraceTransportQualificationFailureV1 {
        if matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP) {
            return PtraceTransportQualificationFailureV1::new(
                RefusalCode::PtraceUnavailable,
                PtraceTransportStageV1::CloneChild,
                PtraceTransportReasonV1::KernelCapabilityUnavailable,
                Some(errno),
            );
        }
        transport_failure_v1(
            PtraceTransportStageV1::CloneChild,
            if valid_errno_v1(errno) {
                PtraceTransportReasonV1::Io
            } else {
                PtraceTransportReasonV1::MalformedKernelResponse
            },
            valid_errno_v1(errno).then_some(errno),
        )
    }

    const fn cleanup_proof_complete_v1(
        pidfd_kill_attempted: bool,
        reaped: bool,
        echild_proven: bool,
    ) -> bool {
        pidfd_kill_attempted && reaped && echild_proven
    }

    fn require_zero_exit_event_message_v1(
        message: u64,
    ) -> Result<(), PtraceTransportQualificationFailureV1> {
        if message == u64::from(RawLinuxWaitStatusV1::exited(0).0) {
            Ok(())
        } else {
            Err(transport_failure_v1(
                PtraceTransportStageV1::ReadEventMessage,
                PtraceTransportReasonV1::UnexpectedLifecycleEvent,
                None,
            ))
        }
    }

    fn ptrace_seize_failure_v1(errno: i32) -> PtraceTransportQualificationFailureV1 {
        let reason = if matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP) {
            Some(PtraceTransportReasonV1::KernelCapabilityUnavailable)
        } else if matches!(errno, libc::EPERM | libc::EACCES) {
            Some(PtraceTransportReasonV1::AdministrativePolicy)
        } else {
            None
        };
        if let Some(reason) = reason {
            return PtraceTransportQualificationFailureV1::new(
                RefusalCode::PtraceUnavailable,
                PtraceTransportStageV1::PtraceSeize,
                reason,
                Some(errno),
            );
        }
        transport_failure_v1(
            PtraceTransportStageV1::PtraceSeize,
            if valid_errno_v1(errno) {
                PtraceTransportReasonV1::Io
            } else {
                PtraceTransportReasonV1::MalformedKernelResponse
            },
            valid_errno_v1(errno).then_some(errno),
        )
    }

    fn transport_failure_v1(
        stage: PtraceTransportStageV1,
        reason: PtraceTransportReasonV1,
        errno: Option<i32>,
    ) -> PtraceTransportQualificationFailureV1 {
        PtraceTransportQualificationFailureV1::new(
            RefusalCode::IsolationPreflightFailed,
            stage,
            reason,
            errno,
        )
    }

    fn protocol_failure_v1(
        _error: FixedPtraceTransportProtocolErrorV1,
    ) -> PtraceTransportQualificationFailureV1 {
        transport_failure_v1(
            PtraceTransportStageV1::TraceProtocol,
            PtraceTransportReasonV1::ProtocolMismatch,
            None,
        )
    }

    fn last_errno_v1() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn valid_errno_v1(errno: i32) -> bool {
        (1..=MAX_LINUX_ERRNO_V1).contains(&errno)
    }

    #[cfg(test)]
    mod tests {
        // These tests are intentionally pure. The live qualifier must run in a
        // fresh product process; Rust's parallel test harness cannot satisfy
        // the exact single-task precondition for blocking SIGCHLD.
        use super::*;

        const FILTER_FINGERPRINT_DOMAIN_V1: &[u8] = b"again fixed ptrace transport filter v1";
        const FILTER_FINGERPRINT_V1: u64 = 0xe689_6c98_7224_e00d;
        const FNV1A64_OFFSET_BASIS_V1: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV1A64_PRIME_V1: u64 = 0x0000_0100_0000_01b3;
        const _: () = assert!(filter_fingerprint_v1() == FILTER_FINGERPRINT_V1);

        #[test]
        fn uapi_layout_and_constants_are_frozen() {
            assert_eq!(std::mem::size_of::<CloneArgsV1>(), 88);
            assert_eq!(std::mem::align_of::<CloneArgsV1>(), 8);
            assert_eq!(std::mem::offset_of!(CloneArgsV1, flags), 0);
            assert_eq!(std::mem::offset_of!(CloneArgsV1, pidfd), 8);
            assert_eq!(std::mem::offset_of!(CloneArgsV1, exit_signal), 32);
            assert_eq!(std::mem::offset_of!(CloneArgsV1, cgroup), 80);

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

            assert_eq!(std::mem::size_of::<LinuxPtraceSyscallInfoSeccompV1>(), 88);
            assert_eq!(std::mem::align_of::<LinuxPtraceSyscallInfoSeccompV1>(), 8);
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, operation),
                0
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, reserved),
                1
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, flags),
                2
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, architecture),
                4
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, instruction_pointer),
                8
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, stack_pointer),
                16
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, syscall_number),
                24
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, arguments),
                32
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, return_data),
                80
            );
            assert_eq!(
                std::mem::offset_of!(LinuxPtraceSyscallInfoSeccompV1, reserved2),
                84
            );
            assert_eq!(PTRACE_SECCOMP_INFO_BYTES_V1, 84);
            assert_eq!(std::mem::size_of::<libc::signalfd_siginfo>(), 128);

            assert_eq!(CLONE_PIDFD_V1, libc::CLONE_PIDFD as u64);
            assert_eq!(PTRACE_TRANSPORT_GETPID_NR_X86_64_V1, libc::SYS_getpid);
            assert_eq!(PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1, libc::SYS_getppid);
            assert_eq!(libc::SYS_exit, 60);
            assert_eq!(PTRACE_OPTIONS_V1, 0x0010_00df);
            assert_eq!(SECCOMP_FILTER_INSTRUCTION_COUNT_V1, 122);
            assert!(u32::from(SECCOMP_ERRNO_MARKER_V1) <= MAX_LINUX_ERRNO_V1 as u32);
        }

        #[test]
        fn frozen_filter_has_closed_forward_control_flow_and_exact_fingerprint() {
            let mut reachable = [false; SECCOMP_FILTER_INSTRUCTION_COUNT_V1];
            let mut pending = vec![0_usize];
            while let Some(program_counter) = pending.pop() {
                assert!(program_counter < SECCOMP_FILTER_V1.len());
                if reachable[program_counter] {
                    continue;
                }
                reachable[program_counter] = true;
                let instruction = SECCOMP_FILTER_V1[program_counter];
                match instruction.code {
                    SECCOMP_BPF_LD_W_ABS_V1 => pending.push(program_counter + 1),
                    SECCOMP_BPF_JMP_JEQ_K_V1 | SECCOMP_BPF_JMP_JSET_K_V1 => {
                        pending.push(program_counter + 1 + usize::from(instruction.jump_true));
                        pending.push(program_counter + 1 + usize::from(instruction.jump_false));
                    }
                    SECCOMP_BPF_RET_K_V1 => {}
                    other => panic!("unexpected cBPF opcode {other:#x}"),
                }
            }
            assert!(reachable.into_iter().all(|entry| entry));
            assert_eq!(filter_fingerprint_v1(), FILTER_FINGERPRINT_V1);
        }

        #[test]
        fn filter_admits_only_exact_fixed_syscalls() {
            let zero_arguments = [0_u64; 6];
            assert_eq!(
                evaluate_filter_v1(
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1 ^ 1,
                    PTRACE_TRANSPORT_GETPID_NR_X86_64_V1 as u32,
                    zero_arguments,
                ),
                SECCOMP_RET_KILL_PROCESS_V1
            );
            assert_eq!(
                evaluate_filter_v1(
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                    X32_SYSCALL_BIT_V1 | PTRACE_TRANSPORT_GETPID_NR_X86_64_V1 as u32,
                    zero_arguments,
                ),
                SECCOMP_RET_KILL_PROCESS_V1
            );
            assert_eq!(
                evaluate_filter_v1(
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                    PTRACE_TRANSPORT_GETPID_NR_X86_64_V1 as u32,
                    zero_arguments,
                ),
                SECCOMP_RET_TRACE_V1 | u32::from(PTRACE_TRANSPORT_GETPID_COOKIE_V1)
            );
            assert_eq!(
                evaluate_filter_v1(
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                    PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1 as u32,
                    zero_arguments,
                ),
                SECCOMP_RET_TRACE_V1 | u32::from(PTRACE_TRANSPORT_GETPPID_COOKIE_V1)
            );

            for syscall_number in [
                PTRACE_TRANSPORT_GETPID_NR_X86_64_V1 as u32,
                PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1 as u32,
            ] {
                for argument in 0..6 {
                    for mutation in [1_u64, 1_u64 << 32] {
                        let mut arguments = zero_arguments;
                        arguments[argument] = mutation;
                        assert_eq!(
                            evaluate_filter_v1(
                                PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                                syscall_number,
                                arguments,
                            ),
                            SECCOMP_RET_MARKER_V1
                        );
                    }
                }
            }

            for status in [0_u64, u64::from(CHILD_FAILURE_EXIT_V1)] {
                let mut arguments = zero_arguments;
                arguments[0] = status;
                assert_eq!(
                    evaluate_filter_v1(
                        PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                        libc::SYS_exit as u32,
                        arguments,
                    ),
                    SECCOMP_RET_ALLOW_V1
                );
            }
            for status in [1_u64, 124, 126, 1_u64 << 32] {
                let mut arguments = zero_arguments;
                arguments[0] = status;
                assert_eq!(
                    evaluate_filter_v1(
                        PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                        libc::SYS_exit as u32,
                        arguments,
                    ),
                    SECCOMP_RET_MARKER_V1
                );
            }
            for argument in 1..6 {
                let mut arguments = zero_arguments;
                arguments[argument] = 1;
                assert_eq!(
                    evaluate_filter_v1(
                        PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                        libc::SYS_exit as u32,
                        arguments,
                    ),
                    SECCOMP_RET_MARKER_V1
                );
            }
            assert_eq!(
                evaluate_filter_v1(
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                    libc::SYS_write as u32,
                    zero_arguments,
                ),
                SECCOMP_RET_MARKER_V1
            );
        }

        #[test]
        fn wait_exit_and_cleanup_classifiers_fail_closed() {
            let seccomp_stop = ptrace_stop_status_v1(PTRACE_EVENT_SECCOMP_V1, libc::SIGTRAP);
            assert_eq!(
                decode_wait_event_v1(seccomp_stop),
                Some(DecodedWaitEventV1::PtraceStop {
                    signal: libc::SIGTRAP,
                    event: PTRACE_EVENT_SECCOMP_V1,
                })
            );
            assert_eq!(
                cleanup_wait_action_v1(seccomp_stop),
                Some(CleanupWaitActionV1::Resume { signal: 0 })
            );
            assert_eq!(
                cleanup_wait_action_v1(ptrace_stop_status_v1(0, libc::SIGKILL)),
                Some(CleanupWaitActionV1::Resume {
                    signal: libc::SIGKILL,
                })
            );
            assert_eq!(
                cleanup_wait_action_v1(RawLinuxWaitStatusV1::exited(0).0 as i32),
                Some(CleanupWaitActionV1::Reaped)
            );
            assert_eq!(
                cleanup_wait_action_v1(libc::SIGKILL),
                Some(CleanupWaitActionV1::Reaped)
            );
            assert_eq!(
                cleanup_wait_action_v1(0xffff),
                Some(CleanupWaitActionV1::Continue)
            );
            assert_eq!(decode_wait_event_v1(-1), None);

            assert!(require_zero_exit_event_message_v1(0).is_ok());
            for wrong in [
                1_u64,
                u64::from(RawLinuxWaitStatusV1::exited(CHILD_FAILURE_EXIT_V1 as u8).0),
            ] {
                let failure = require_zero_exit_event_message_v1(wrong).unwrap_err();
                assert_eq!(failure.stage(), "read_event_message");
                assert_eq!(failure.reason(), "unexpected_lifecycle_event");
            }
        }

        #[test]
        fn cleanup_requires_pidfd_kill_terminal_reap_and_echild() {
            for pidfd_kill_attempted in [false, true] {
                for reaped in [false, true] {
                    for echild_proven in [false, true] {
                        assert_eq!(
                            cleanup_proof_complete_v1(pidfd_kill_attempted, reaped, echild_proven,),
                            pidfd_kill_attempted && reaped && echild_proven
                        );
                    }
                }
            }
        }

        #[test]
        fn only_narrow_kernel_and_policy_errors_are_expected_unavailability() {
            for failure in [
                clone_failure_v1(libc::ENOSYS),
                clone_failure_v1(libc::EOPNOTSUPP),
                seccomp_action_failure_v1(libc::ENOSYS),
                seccomp_action_failure_v1(libc::EOPNOTSUPP),
                ptrace_seize_failure_v1(libc::ENOSYS),
                ptrace_seize_failure_v1(libc::EOPNOTSUPP),
                ptrace_seize_failure_v1(libc::EPERM),
                ptrace_seize_failure_v1(libc::EACCES),
            ] {
                assert!(failure.is_expected_unavailable());
                assert!(failure.cleanup_complete());
            }
            for failure in [
                clone_failure_v1(libc::EINVAL),
                seccomp_action_failure_v1(libc::EINVAL),
                ptrace_seize_failure_v1(libc::EINVAL),
                PtraceTransportQualificationFailureV1::cleanup_uncertain(Some(libc::EIO)),
            ] {
                assert!(!failure.is_expected_unavailable());
            }
        }

        #[test]
        fn loader_injection_environment_names_fail_closed_without_values() {
            for name in [
                b"LD_PRELOAD".as_slice(),
                b"LD_LIBRARY_PATH",
                b"DYLD_INSERT_LIBRARIES",
                b"MALLOC_CHECK_",
                b"GLIBC_TUNABLES",
                b"GCONV_PATH",
                b"LOCPATH",
                b"NLSPATH",
            ] {
                let mut environment = name.to_vec();
                environment.extend_from_slice(b"=/secret/value\0");
                let failure = validate_environment_bytes_v1(&environment).unwrap_err();
                assert_eq!(failure.code(), RefusalCode::IsolationPreflightFailed);
                assert_eq!(failure.stage(), "dedicated_helper");
                assert_eq!(failure.reason(), "loader_injection_environment");
                assert_eq!(failure.errno(), None);
                assert!(failure.cleanup_complete());
                assert!(!failure.is_expected_unavailable());
            }

            assert!(
                validate_environment_bytes_v1(
                    b"SAFE=LD_PRELOAD=/not-a-name\0XLD_LIBRARY_PATH=value\0"
                )
                .is_ok()
            );
            assert_eq!(MAX_ENVIRONMENT_BYTES_V1, 1024 * 1024);
        }

        #[test]
        fn malformed_environment_records_fail_closed() {
            for malformed in [
                b"MISSING_TERMINATOR=value".as_slice(),
                b"NO_SEPARATOR\0",
                b"=empty-name\0",
                b"A=1\0\0",
                b"\0",
            ] {
                let failure = validate_environment_bytes_v1(malformed).unwrap_err();
                assert_eq!(failure.stage(), "dedicated_helper");
                assert_eq!(failure.reason(), "malformed_kernel_response");
                assert!(failure.cleanup_complete());
            }
            assert!(validate_environment_bytes_v1(b"").is_ok());
            assert!(validate_environment_bytes_v1(b"A=\0B=x=y\0").is_ok());
        }

        fn ptrace_stop_status_v1(event: u32, signal: i32) -> i32 {
            ((event << 16) | ((signal as u32) << 8) | 0x7f) as i32
        }

        fn evaluate_filter_v1(architecture: u32, syscall_number: u32, arguments: [u64; 6]) -> u32 {
            let mut accumulator = 0_u32;
            let mut program_counter = 0_usize;
            let mut steps = 0_usize;
            loop {
                assert!(steps < SECCOMP_FILTER_V1.len());
                steps += 1;
                let instruction = SECCOMP_FILTER_V1[program_counter];
                match instruction.code {
                    SECCOMP_BPF_LD_W_ABS_V1 => {
                        accumulator = seccomp_word_v1(
                            instruction.operand,
                            architecture,
                            syscall_number,
                            arguments,
                        );
                        program_counter += 1;
                    }
                    SECCOMP_BPF_JMP_JEQ_K_V1 => {
                        let jump = if accumulator == instruction.operand {
                            instruction.jump_true
                        } else {
                            instruction.jump_false
                        };
                        program_counter += 1 + usize::from(jump);
                    }
                    SECCOMP_BPF_JMP_JSET_K_V1 => {
                        let jump = if accumulator & instruction.operand != 0 {
                            instruction.jump_true
                        } else {
                            instruction.jump_false
                        };
                        program_counter += 1 + usize::from(jump);
                    }
                    SECCOMP_BPF_RET_K_V1 => return instruction.operand,
                    other => panic!("unexpected cBPF opcode {other:#x}"),
                }
            }
        }

        fn seccomp_word_v1(
            offset: u32,
            architecture: u32,
            syscall_number: u32,
            arguments: [u64; 6],
        ) -> u32 {
            match offset {
                SECCOMP_DATA_NR_OFFSET_V1 => syscall_number,
                SECCOMP_DATA_ARCH_OFFSET_V1 => architecture,
                offset if offset >= SECCOMP_DATA_ARGS_OFFSET_V1 => {
                    let relative = offset - SECCOMP_DATA_ARGS_OFFSET_V1;
                    let argument = usize::try_from(relative / SECCOMP_DATA_ARG_STRIDE_V1).unwrap();
                    assert!(argument < arguments.len());
                    match relative % SECCOMP_DATA_ARG_STRIDE_V1 {
                        0 => arguments[argument] as u32,
                        SECCOMP_DATA_ARG_HIGH_OFFSET_V1 => (arguments[argument] >> 32) as u32,
                        other => panic!("unaligned seccomp_data offset {other}"),
                    }
                }
                other => panic!("unknown seccomp_data offset {other}"),
            }
        }

        const fn filter_fingerprint_v1() -> u64 {
            let mut fingerprint = FNV1A64_OFFSET_BASIS_V1;
            let mut domain_index = 0_usize;
            while domain_index < FILTER_FINGERPRINT_DOMAIN_V1.len() {
                fingerprint =
                    fingerprint_byte_v1(fingerprint, FILTER_FINGERPRINT_DOMAIN_V1[domain_index]);
                domain_index += 1;
            }
            let mut instruction_index = 0_usize;
            while instruction_index < SECCOMP_FILTER_V1.len() {
                let instruction = SECCOMP_FILTER_V1[instruction_index];
                fingerprint = fingerprint_byte_v1(fingerprint, instruction.code as u8);
                fingerprint = fingerprint_byte_v1(fingerprint, (instruction.code >> 8) as u8);
                fingerprint = fingerprint_byte_v1(fingerprint, instruction.jump_true);
                fingerprint = fingerprint_byte_v1(fingerprint, instruction.jump_false);
                let mut byte_index = 0_u32;
                while byte_index < 4 {
                    fingerprint = fingerprint_byte_v1(
                        fingerprint,
                        (instruction.operand >> (byte_index * 8)) as u8,
                    );
                    byte_index += 1;
                }
                instruction_index += 1;
            }
            fingerprint
        }

        const fn fingerprint_byte_v1(fingerprint: u64, byte: u8) -> u64 {
            (fingerprint ^ byte as u64).wrapping_mul(FNV1A64_PRIME_V1)
        }
    }
}
