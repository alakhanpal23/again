//! Kernel-owned connector for the fixed two-task supervisor diagnostic.
//!
//! This module is a child of `tracer_seccomp`, so it can borrow the frozen
//! filter only through the sealed connector permit. It accepts no command,
//! path, descriptor, callback, or event transcript. Its output is redacted and
//! grants no profile, EffectIR, execution, candidate, or reuse authority.

use super::super::RefusalCode;

/// Single-use authority to start the pure supervisor from the reviewed kernel
/// connector. The field is private to this module.
pub(in crate::linux_pytest) struct TracerSupervisorIssuerPermitV1(());

/// Single-use evidence that final `ECHILD`, signal-state preservation and
/// drain, and connector resource cleanup all completed.
pub(in crate::linux_pytest) struct TracerSupervisorCleanupCompletionPermitV1(());

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::linux_pytest) enum FixedTwoTaskForkDeliveryOrderV1 {
    ParentEventFirst,
    ChildStopFirst,
}

impl FixedTwoTaskForkDeliveryOrderV1 {
    pub(in crate::linux_pytest) const fn as_str(self) -> &'static str {
        match self {
            Self::ParentEventFirst => "parent_event_first",
            Self::ChildStopFirst => "child_stop_first",
        }
    }
}

/// Opaque success for the fixed no-command two-task probe.
pub(in crate::linux_pytest) struct CompletedFixedTwoTaskSupervisorProbeV1 {
    fork_delivery_order: FixedTwoTaskForkDeliveryOrderV1,
    task_count: u16,
    accepted_transition_count: u64,
    fork_birth_count: u64,
    seccomp_entry_count: u64,
    syscall_exit_count: u64,
    no_return_resolution_count: u64,
    ptrace_exit_event_count: u64,
    terminal_reap_count: u64,
}

impl CompletedFixedTwoTaskSupervisorProbeV1 {
    pub(in crate::linux_pytest) const fn fork_delivery_order(&self) -> &'static str {
        self.fork_delivery_order.as_str()
    }

    pub(in crate::linux_pytest) const fn task_count(&self) -> u16 {
        self.task_count
    }

    pub(in crate::linux_pytest) const fn accepted_transition_count(&self) -> u64 {
        self.accepted_transition_count
    }

    pub(in crate::linux_pytest) const fn fork_birth_count(&self) -> u64 {
        self.fork_birth_count
    }

    pub(in crate::linux_pytest) const fn seccomp_entry_count(&self) -> u64 {
        self.seccomp_entry_count
    }

    pub(in crate::linux_pytest) const fn syscall_exit_count(&self) -> u64 {
        self.syscall_exit_count
    }

    pub(in crate::linux_pytest) const fn no_return_resolution_count(&self) -> u64 {
        self.no_return_resolution_count
    }

    pub(in crate::linux_pytest) const fn ptrace_exit_event_count(&self) -> u64 {
        self.ptrace_exit_event_count
    }

    pub(in crate::linux_pytest) const fn terminal_reap_count(&self) -> u64 {
        self.terminal_reap_count
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum FixedTwoTaskSupervisorStageV1 {
    Platform,
    DedicatedHelper,
    SeccompActions,
    SignalState,
    ReleaseChannel,
    CloneRoot,
    PtraceSeize,
    ReleaseRoot,
    WaitEvent,
    FilterWitness,
    EventMessage,
    SyscallInfo,
    Quiescence,
    ProcessMemory,
    Resume,
    Planner,
    TerminalEchild,
    Cleanup,
}

impl FixedTwoTaskSupervisorStageV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::DedicatedHelper => "dedicated_helper",
            Self::SeccompActions => "seccomp_actions",
            Self::SignalState => "signal_state",
            Self::ReleaseChannel => "release_channel",
            Self::CloneRoot => "clone_root",
            Self::PtraceSeize => "ptrace_seize",
            Self::ReleaseRoot => "release_root",
            Self::WaitEvent => "wait_event",
            Self::FilterWitness => "filter_witness",
            Self::EventMessage => "event_message",
            Self::SyscallInfo => "syscall_info",
            Self::Quiescence => "quiescence",
            Self::ProcessMemory => "process_memory",
            Self::Resume => "resume",
            Self::Planner => "planner",
            Self::TerminalEchild => "terminal_echild",
            Self::Cleanup => "cleanup",
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum FixedTwoTaskSupervisorReasonV1 {
    UnsupportedPlatform,
    UnsupportedArchitecture,
    MultipleTasks,
    ExistingChildren,
    LoaderInjectionEnvironment,
    KernelCapabilityUnavailable,
    AdministrativePolicy,
    BoundExceeded,
    Io,
    ShortIo,
    MalformedKernelResponse,
    UnexpectedLifecycleEvent,
    FilterMismatch,
    QuiescenceUnproven,
    PrivateRangeUnproven,
    SupervisorRejected(&'static str),
    ForkDeliveryOrderMissing,
    PlannerSummaryMismatch,
    CleanupUncertain,
}

impl FixedTwoTaskSupervisorReasonV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsupportedArchitecture => "unsupported_architecture",
            Self::MultipleTasks => "multiple_tasks",
            Self::ExistingChildren => "existing_children",
            Self::LoaderInjectionEnvironment => "loader_injection_environment",
            Self::KernelCapabilityUnavailable => "kernel_capability_unavailable",
            Self::AdministrativePolicy => "administrative_policy",
            Self::BoundExceeded => "bound_exceeded",
            Self::Io => "io",
            Self::ShortIo => "short_io",
            Self::MalformedKernelResponse => "malformed_kernel_response",
            Self::UnexpectedLifecycleEvent => "unexpected_lifecycle_event",
            Self::FilterMismatch => "filter_mismatch",
            Self::QuiescenceUnproven => "quiescence_unproven",
            Self::PrivateRangeUnproven => "private_range_unproven",
            Self::SupervisorRejected(reason) => reason,
            Self::ForkDeliveryOrderMissing => "fork_delivery_order_missing",
            Self::PlannerSummaryMismatch => "planner_summary_mismatch",
            Self::CleanupUncertain => "cleanup_uncertain",
        }
    }
}

/// Typed, redacted refusal. No raw kernel identity or resource escapes.
pub(in crate::linux_pytest) struct FixedTwoTaskSupervisorFailureV1 {
    code: RefusalCode,
    stage: FixedTwoTaskSupervisorStageV1,
    reason: FixedTwoTaskSupervisorReasonV1,
    errno: Option<i32>,
    cleanup_complete: bool,
    cleanup_errno: Option<i32>,
}

impl FixedTwoTaskSupervisorFailureV1 {
    const fn new(
        code: RefusalCode,
        stage: FixedTwoTaskSupervisorStageV1,
        reason: FixedTwoTaskSupervisorReasonV1,
        errno: Option<i32>,
        cleanup_complete: bool,
    ) -> Self {
        Self {
            code,
            stage,
            reason,
            errno,
            cleanup_complete,
            cleanup_errno: None,
        }
    }

    pub(in crate::linux_pytest) const fn code(&self) -> RefusalCode {
        self.code
    }

    pub(in crate::linux_pytest) const fn stage(&self) -> &'static str {
        self.stage.as_str()
    }

    pub(in crate::linux_pytest) const fn reason(&self) -> &'static str {
        self.reason.as_str()
    }

    pub(in crate::linux_pytest) const fn errno(&self) -> Option<i32> {
        self.errno
    }

    pub(in crate::linux_pytest) const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }

    pub(in crate::linux_pytest) const fn cleanup_errno(&self) -> Option<i32> {
        self.cleanup_errno
    }

    pub(in crate::linux_pytest) const fn is_expected_unavailable(&self) -> bool {
        self.cleanup_complete
            && matches!(
                (self.code, self.stage, self.reason, self.errno),
                (
                    RefusalCode::UnsupportedOs,
                    FixedTwoTaskSupervisorStageV1::Platform,
                    FixedTwoTaskSupervisorReasonV1::UnsupportedPlatform,
                    None,
                ) | (
                    RefusalCode::UnsupportedArchitecture,
                    FixedTwoTaskSupervisorStageV1::Platform,
                    FixedTwoTaskSupervisorReasonV1::UnsupportedArchitecture,
                    None,
                ) | (
                    RefusalCode::SeccompUnavailable,
                    FixedTwoTaskSupervisorStageV1::SeccompActions,
                    FixedTwoTaskSupervisorReasonV1::KernelCapabilityUnavailable,
                    Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP),
                ) | (
                    RefusalCode::PtraceUnavailable,
                    FixedTwoTaskSupervisorStageV1::CloneRoot,
                    FixedTwoTaskSupervisorReasonV1::KernelCapabilityUnavailable,
                    Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP),
                ) | (
                    RefusalCode::PtraceUnavailable,
                    FixedTwoTaskSupervisorStageV1::PtraceSeize
                        | FixedTwoTaskSupervisorStageV1::FilterWitness
                        | FixedTwoTaskSupervisorStageV1::ProcessMemory,
                    FixedTwoTaskSupervisorReasonV1::AdministrativePolicy,
                    Some(libc::EPERM) | Some(libc::EACCES),
                )
            )
    }

    const fn with_cleanup(mut self, cleanup_complete: bool, cleanup_errno: Option<i32>) -> Self {
        if !cleanup_complete {
            self.cleanup_complete = false;
            if self.cleanup_errno.is_none() {
                self.cleanup_errno = cleanup_errno;
            }
        }
        self
    }
}

/// Run the fixed no-command connector and erase every live capability.
pub(in crate::linux_pytest) fn qualify_fixed_two_task_supervisor_v1()
-> Result<CompletedFixedTwoTaskSupervisorProbeV1, FixedTwoTaskSupervisorFailureV1> {
    platform::qualify_fixed_two_task_supervisor_v1()
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
)))]
mod platform {
    use super::*;

    pub(super) fn qualify_fixed_two_task_supervisor_v1()
    -> Result<CompletedFixedTwoTaskSupervisorProbeV1, FixedTwoTaskSupervisorFailureV1> {
        let (code, reason) = if cfg!(target_os = "linux") {
            (
                RefusalCode::UnsupportedArchitecture,
                FixedTwoTaskSupervisorReasonV1::UnsupportedArchitecture,
            )
        } else {
            (
                RefusalCode::UnsupportedOs,
                FixedTwoTaskSupervisorReasonV1::UnsupportedPlatform,
            )
        };
        Err(FixedTwoTaskSupervisorFailureV1::new(
            code,
            FixedTwoTaskSupervisorStageV1::Platform,
            reason,
            None,
            true,
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
    use std::ffi::OsStr;
    use std::fs;
    use std::io::Read;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;

    use super::super::super::tracer_fork_decode::{
        CLONE3_ARGS_BUFFER_BYTES_V1, Clone3ArgsCaptureV1,
    };
    use super::super::super::tracer_supervisor_state::{
        CompletedTracerSupervisorStateV1, TracerSupervisorExecuteOnlyReasonV1,
        TracerSupervisorIntentV1, TracerSupervisorResumeRequestV1, TracerSupervisorStateV1,
    };
    use super::super::super::tracer_task_state::{
        NormalizedTracerTaskEventSinkV1, NormalizedTracerTaskEventV1,
    };
    use super::super::super::tracer_wait_status::LinuxPtraceEventV1;
    use super::super::{
        FutureTracerSeccompConnectorPermitV1, LinuxSockFilterV1,
        trace_all_native_seccomp_program_v1,
    };
    use super::*;

    const RUN_SECONDS_V1: i64 = 8;
    const CLEANUP_SECONDS_V1: i64 = 2;
    const MAX_WAIT_ATTEMPTS_V1: usize = 2_000_000;
    const MAX_DRIVER_STEPS_V1: usize = 128;
    const MAX_ENVIRONMENT_BYTES_V1: usize = 1024 * 1024;
    const MAX_PROC_TEXT_BYTES_V1: usize = 1024 * 1024;
    const WAIT_BACKOFF_NANOSECONDS_V1: i64 = 50_000;
    const RELEASE_BYTE_V1: u8 = 0x5a;
    const CHILD_FAILURE_EXIT_V1: u32 = 125;
    const KERNEL_SIGNAL_SET_BYTES_V1: i64 = 8;
    const SIGCHLD_MASK_V1: u64 = 1_u64 << (libc::SIGCHLD - 1);
    const CLONE_PIDFD_V1: u64 = 0x0000_1000;
    const WAIT_WALL_V1: libc::c_int = 0x4000_0000;

    const PTRACE_CONT_V1: u64 = 7;
    const PTRACE_SYSCALL_V1: u64 = 24;
    const PTRACE_SEIZE_V1: u64 = 0x4206;
    const PTRACE_GETSIGMASK_V1: u64 = 0x420a;
    const PTRACE_SETSIGMASK_V1: u64 = 0x420b;
    const PTRACE_GETEVENTMSG_V1: u64 = 0x4201;
    const PTRACE_SECCOMP_GET_FILTER_V1: u64 = 0x420c;
    const PTRACE_GET_SYSCALL_INFO_V1: u64 = 0x420e;
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

    const SECCOMP_SET_MODE_FILTER_V1: u32 = 1;
    const SECCOMP_GET_ACTION_AVAIL_V1: u32 = 2;
    const SECCOMP_FILTER_FLAG_TSYNC_V1: u32 = 1;
    const SECCOMP_RET_KILL_PROCESS_V1: u32 = 0x8000_0000;
    const SECCOMP_RET_TRACE_V1: u32 = 0x7ff0_0000;
    const PR_SET_NO_NEW_PRIVS_V1: i64 = 38;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ConnectorKernelOperationV1 {
        WaitRun,
        WaitCleanup,
        PtraceSeize,
        OwnershipTransfer,
        SeccompInstall,
        PtraceFilterCount,
        PtraceFilterRead,
        PtraceEventMessage,
        PtraceSignalMaskRead,
        PtraceSignalMaskWrite,
        PtraceSignalMaskVerify,
        PtraceSyscallInfo,
        PtraceResumeContinue,
        PtraceResumeSyscall,
        PtraceCleanupResume,
        ProcessMemoryRead,
        KillPidfd,
        KillTid,
        SignalMaskRead,
        SignalActionRead,
        SignalPendingRead,
    }

    #[derive(Clone, Copy)]
    enum InjectedKernelResultV1 {
        Return(i64),
        Errno(i32),
    }

    trait ConnectorFaultInjectorV1 {
        fn take(&mut self, operation: ConnectorKernelOperationV1)
        -> Option<InjectedKernelResultV1>;
    }

    struct NoConnectorFaultsV1;

    impl ConnectorFaultInjectorV1 for NoConnectorFaultsV1 {
        fn take(
            &mut self,
            _operation: ConnectorKernelOperationV1,
        ) -> Option<InjectedKernelResultV1> {
            None
        }
    }

    fn connector_kernel_call_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        operation: ConnectorKernelOperationV1,
        call: impl FnOnce() -> i64,
    ) -> Result<i64, i32> {
        match faults.take(operation) {
            Some(InjectedKernelResultV1::Return(value)) => Ok(value),
            Some(InjectedKernelResultV1::Errno(errno)) => Err(errno),
            None => {
                let result = call();
                if result < 0 {
                    Err(last_errno_v1())
                } else {
                    Ok(result)
                }
            }
        }
    }

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
    struct LinuxSockFprogV1 {
        length: u16,
        filter: *const LinuxSockFilterV1,
    }

    struct FixedEventSinkV1 {
        events: [Option<NormalizedTracerTaskEventV1>; 16],
        length: usize,
    }

    impl FixedEventSinkV1 {
        const fn new() -> Self {
            Self {
                events: [None; 16],
                length: 0,
            }
        }
    }

    impl NormalizedTracerTaskEventSinkV1 for FixedEventSinkV1 {
        fn emit(&mut self, event: NormalizedTracerTaskEventV1) -> Result<(), ()> {
            if self.length == self.events.len() {
                return Err(());
            }
            self.events[self.length] = Some(event);
            self.length += 1;
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct MonotonicDeadlineV1 {
        seconds: i64,
        nanoseconds: i64,
    }

    impl MonotonicDeadlineV1 {
        fn after(seconds: i64) -> Result<Self, FixedTwoTaskSupervisorFailureV1> {
            let now = monotonic_now_v1().map_err(|errno| {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    Some(errno),
                )
            })?;
            Ok(Self {
                seconds: now.tv_sec.checked_add(seconds).ok_or_else(|| {
                    failure_v1(
                        FixedTwoTaskSupervisorStageV1::WaitEvent,
                        FixedTwoTaskSupervisorReasonV1::BoundExceeded,
                        None,
                    )
                })?,
                nanoseconds: now.tv_nsec,
            })
        }

        fn expired(self) -> Result<bool, i32> {
            let now = monotonic_now_v1()?;
            Ok(now.tv_sec > self.seconds
                || (now.tv_sec == self.seconds && now.tv_nsec >= self.nanoseconds))
        }
    }

    struct SignalStateSnapshotV1 {
        mask: libc::sigset_t,
        action: libc::sigaction,
    }

    impl SignalStateSnapshotV1 {
        fn capture(
            faults: &mut impl ConnectorFaultInjectorV1,
        ) -> Result<Self, FixedTwoTaskSupervisorFailureV1> {
            let mask = current_signal_mask_v1(faults)?;
            let blocked = unsafe { libc::sigismember(&mask, libc::SIGCHLD) };
            if blocked != 0 {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::SignalState,
                    if blocked < 0 {
                        FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse
                    } else {
                        FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent
                    },
                    (blocked < 0).then(last_errno_v1),
                ));
            }
            require_no_pending_sigchld_v1(faults)?;
            let mut action = MaybeUninit::<libc::sigaction>::zeroed();
            if let Err(errno) = connector_kernel_call_v1(
                faults,
                ConnectorKernelOperationV1::SignalActionRead,
                || unsafe {
                    i64::from(libc::sigaction(
                        libc::SIGCHLD,
                        ptr::null(),
                        action.as_mut_ptr(),
                    ))
                },
            ) {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::SignalState,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    Some(errno),
                ));
            }
            let action = unsafe { action.assume_init() };
            if action.sa_sigaction != libc::SIG_DFL
                || action.sa_flags & (libc::SA_NOCLDWAIT | libc::SA_NOCLDSTOP) != 0
            {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::SignalState,
                    FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            Ok(Self { mask, action })
        }

        fn verify(
            &self,
            faults: &mut impl ConnectorFaultInjectorV1,
        ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
            let observed_mask = current_signal_mask_v1(faults)?;
            for signal in 1..=64 {
                let expected = unsafe { libc::sigismember(&self.mask, signal) };
                let observed = unsafe { libc::sigismember(&observed_mask, signal) };
                if expected < 0 || observed < 0 || expected != observed {
                    return Err(failure_v1(
                        FixedTwoTaskSupervisorStageV1::SignalState,
                        FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                        (expected < 0 || observed < 0).then(last_errno_v1),
                    ));
                }
            }
            let mut observed_action = MaybeUninit::<libc::sigaction>::zeroed();
            if let Err(errno) = connector_kernel_call_v1(
                faults,
                ConnectorKernelOperationV1::SignalActionRead,
                || unsafe {
                    i64::from(libc::sigaction(
                        libc::SIGCHLD,
                        ptr::null(),
                        observed_action.as_mut_ptr(),
                    ))
                },
            ) {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::SignalState,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    Some(errno),
                ));
            }
            let observed_action = unsafe { observed_action.assume_init() };
            if self.action.sa_sigaction != observed_action.sa_sigaction
                || self.action.sa_flags != observed_action.sa_flags
                || self.action.sa_restorer.map(|restorer| restorer as usize)
                    != observed_action
                        .sa_restorer
                        .map(|restorer| restorer as usize)
                || !signal_sets_equal_v1(&self.action.sa_mask, &observed_action.sa_mask)?
            {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::SignalState,
                    FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            require_no_pending_sigchld_v1(faults)
        }
    }

    struct ReleaseChannelV1 {
        read: OwnedFd,
        write: OwnedFd,
    }

    impl ReleaseChannelV1 {
        fn create() -> Result<Self, FixedTwoTaskSupervisorFailureV1> {
            let mut descriptors = [-1_i32; 2];
            if unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            } != 0
            {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::ReleaseChannel,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    Some(last_errno_v1()),
                ));
            }
            if descriptors[0] < 0 || descriptors[1] < 0 || descriptors[0] == descriptors[1] {
                for descriptor in descriptors {
                    if descriptor >= 0 {
                        let _ = unsafe { libc::close(descriptor) };
                    }
                }
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::ReleaseChannel,
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            Ok(Self {
                read: unsafe { OwnedFd::from_raw_fd(descriptors[0]) },
                write: unsafe { OwnedFd::from_raw_fd(descriptors[1]) },
            })
        }
    }

    struct TaskTreeGuardV1 {
        root_tid: i32,
        root_pidfd: Option<OwnedFd>,
        nested_announced_tid: Option<i32>,
        pending_nested_stop_tid: Option<i32>,
        nested_tid: Option<i32>,
        fork_delivery_order: Option<FixedTwoTaskForkDeliveryOrderV1>,
        nested_pidfd: Option<OwnedFd>,
        root_reaped: bool,
        nested_reaped: bool,
        final_echild: bool,
        disarmed: bool,
    }

    /// Linear proof that the connector successfully seized the fixed root
    /// while the child was still blocked on its private release channel.
    /// There is no constructor other than the checked `PTRACE_SEIZE` leaf and
    /// no raw-identity accessor.
    struct SupervisorOwnedRootV1 {
        raw_tid: i32,
    }

    /// The same ownership after the private one-byte release was consumed.
    /// Only this state may enter the wait/filter-readback driver, so the child
    /// cannot install `SECCOMP_RET_TRACE` before supervisor ownership.
    struct SupervisorReleasedRootV1 {
        raw_tid: i32,
    }

    impl TaskTreeGuardV1 {
        fn record_nested_announcement(
            &mut self,
            raw_tid: i32,
        ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
            if raw_tid <= 0
                || raw_tid == self.root_tid
                || self.nested_announced_tid.is_some()
                || self
                    .pending_nested_stop_tid
                    .is_some_and(|stopped| stopped != raw_tid)
            {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::EventMessage,
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            self.record_fork_delivery_order(if self.pending_nested_stop_tid == Some(raw_tid) {
                FixedTwoTaskForkDeliveryOrderV1::ChildStopFirst
            } else {
                FixedTwoTaskForkDeliveryOrderV1::ParentEventFirst
            })?;
            self.nested_announced_tid = Some(raw_tid);
            if self.pending_nested_stop_tid == Some(raw_tid) {
                self.bind_nested_tid(raw_tid)?;
            }
            Ok(())
        }

        fn record_ptrace_stop(
            &mut self,
            raw_tid: i32,
        ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
            if raw_tid == self.root_tid || self.nested_tid == Some(raw_tid) {
                return Ok(());
            }
            if raw_tid <= 0 {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            if self.pending_nested_stop_tid.is_none() {
                // The successful wait is lifetime authority for this exact
                // stopped tracee. Retain it before validating the separately
                // obtained event message so cleanup cannot lose a stop that
                // waitpid has already consumed.
                self.pending_nested_stop_tid = Some(raw_tid);
            }
            self.record_fork_delivery_order(if self.nested_announced_tid == Some(raw_tid) {
                FixedTwoTaskForkDeliveryOrderV1::ParentEventFirst
            } else {
                FixedTwoTaskForkDeliveryOrderV1::ChildStopFirst
            })?;
            if self.pending_nested_stop_tid != Some(raw_tid)
                || self
                    .nested_announced_tid
                    .is_some_and(|announced| announced != raw_tid)
            {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            if self.nested_announced_tid == Some(raw_tid) {
                self.bind_nested_tid(raw_tid)?;
            }
            Ok(())
        }

        fn record_fork_delivery_order(
            &mut self,
            observed: FixedTwoTaskForkDeliveryOrderV1,
        ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
            match self.fork_delivery_order {
                None => {
                    self.fork_delivery_order = Some(observed);
                    Ok(())
                }
                Some(existing) if existing == observed => Ok(()),
                Some(_) => Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                    None,
                )),
            }
        }

        fn bind_nested_tid(&mut self, raw_tid: i32) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
            if self.nested_tid.is_some()
                || self.nested_announced_tid != Some(raw_tid)
                || self.pending_nested_stop_tid != Some(raw_tid)
            {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::EventMessage,
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                    None,
                ));
            }
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, raw_tid, 0_u32) };
            if descriptor < 0 {
                return Err(ptrace_failure_v1(
                    FixedTwoTaskSupervisorStageV1::EventMessage,
                    last_errno_v1(),
                ));
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) };
            require_cloexec_v1(&descriptor, FixedTwoTaskSupervisorStageV1::EventMessage)?;
            self.nested_tid = Some(raw_tid);
            self.pending_nested_stop_tid = None;
            self.nested_pidfd = Some(descriptor);
            Ok(())
        }

        fn record_reap(&mut self, raw_tid: i32) {
            if raw_tid == self.root_tid {
                self.root_reaped = true;
            }
            if self.nested_tid == Some(raw_tid) {
                self.nested_reaped = true;
            }
            if self.pending_nested_stop_tid == Some(raw_tid) {
                // A wait-proven but not yet event-message-correlated child is
                // still cleanup authority for that exact lifetime. Retire the
                // raw identity only after consuming its terminal wait so a
                // later cleanup pass cannot target a reused TID.
                self.pending_nested_stop_tid = None;
            }
        }

        fn prove_final_echild(&mut self) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
            if !self.root_reaped || self.nested_tid.is_none() || !self.nested_reaped {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::TerminalEchild,
                    FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                    None,
                ));
            }
            self.final_echild = true;
            Ok(())
        }

        fn close_success(&mut self) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
            if !self.root_reaped || !self.nested_reaped || !self.final_echild {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::Cleanup,
                    FixedTwoTaskSupervisorReasonV1::CleanupUncertain,
                    None,
                ));
            }
            drop(self.root_pidfd.take());
            drop(self.nested_pidfd.take());
            self.disarmed = true;
            Ok(())
        }

        fn cleanup(&mut self, faults: &mut impl ConnectorFaultInjectorV1) -> (bool, Option<i32>) {
            let deadline = match MonotonicDeadlineV1::after(CLEANUP_SECONDS_V1) {
                Ok(deadline) => deadline,
                Err(failure) => return (false, failure.errno()),
            };
            let mut first_errno = None;
            self.kill_known(&mut first_errno, faults);
            let mut attempts = 0_usize;
            loop {
                if attempts >= MAX_WAIT_ATTEMPTS_V1 {
                    return (false, first_errno.or(Some(libc::ETIMEDOUT)));
                }
                attempts += 1;
                let mut status = 0_i32;
                let result = match connector_kernel_call_v1(
                    faults,
                    ConnectorKernelOperationV1::WaitCleanup,
                    || unsafe {
                        i64::from(libc::waitpid(-1, &mut status, libc::WNOHANG | WAIT_WALL_V1))
                    },
                ) {
                    Ok(result) => result,
                    Err(errno) => -i64::from(errno),
                };
                if result > 0 {
                    let Ok(raw_tid) = i32::try_from(result) else {
                        first_errno.get_or_insert(libc::EPROTO);
                        return (false, first_errno);
                    };
                    if wait_status_is_ptrace_stop_v1(status) {
                        if let Err(errno) = kill_tid_v1(faults, raw_tid) {
                            if errno != libc::ESRCH {
                                first_errno.get_or_insert(errno);
                            }
                        }
                        if let Err(errno) = ptrace_call_v1(
                            faults,
                            ConnectorKernelOperationV1::PtraceCleanupResume,
                            PTRACE_CONT_V1,
                            raw_tid,
                            0,
                            libc::SIGKILL as u64,
                        ) {
                            if !matches!(errno, libc::ESRCH | libc::ECHILD) {
                                first_errno.get_or_insert(errno);
                            }
                        }
                    } else if wait_status_is_final_v1(status) {
                        self.record_reap(raw_tid);
                    } else {
                        first_errno.get_or_insert(libc::EPROTO);
                    }
                    self.kill_known(&mut first_errno, faults);
                    continue;
                }
                if result < 0 {
                    let errno = i32::try_from(-result).unwrap_or(libc::EIO);
                    if errno == libc::EINTR {
                        continue;
                    }
                    if errno == libc::ECHILD {
                        self.final_echild = true;
                        drop(self.root_pidfd.take());
                        drop(self.nested_pidfd.take());
                        self.disarmed = true;
                        return (first_errno.is_none(), first_errno);
                    }
                    first_errno.get_or_insert(errno);
                    return (false, first_errno);
                }
                match deadline.expired() {
                    Ok(false) => {
                        // Keep retrying every lifetime-bound task while the
                        // bounded drain is live. In particular, child-stop-first
                        // cleanup must not discard its only safe identity after
                        // one failed kill/resume pair.
                        self.kill_known(&mut first_errno, faults);
                        if let Err(errno) = wait_backoff_v1() {
                            return (false, first_errno.or(Some(errno)));
                        }
                    }
                    Ok(true) => return (false, first_errno.or(Some(libc::ETIMEDOUT))),
                    Err(errno) => return (false, first_errno.or(Some(errno))),
                };
            }
        }

        fn kill_known(
            &mut self,
            first_errno: &mut Option<i32>,
            faults: &mut impl ConnectorFaultInjectorV1,
        ) {
            self.kill_bound_task(
                self.root_tid,
                self.root_pidfd.as_ref(),
                self.root_reaped,
                first_errno,
                faults,
            );
            if let Some(raw_tid) = self.nested_tid {
                self.kill_bound_task(
                    raw_tid,
                    self.nested_pidfd.as_ref(),
                    self.nested_reaped,
                    first_errno,
                    faults,
                );
            }
            if let Some(raw_tid) = self.pending_nested_stop_tid {
                if let Err(errno) = kill_tid_v1(faults, raw_tid) {
                    if errno != libc::ESRCH {
                        first_errno.get_or_insert(errno);
                    }
                }
                if let Err(errno) = ptrace_call_v1(
                    faults,
                    ConnectorKernelOperationV1::PtraceCleanupResume,
                    PTRACE_CONT_V1,
                    raw_tid,
                    0,
                    libc::SIGKILL as u64,
                ) {
                    if !matches!(errno, libc::ESRCH | libc::ECHILD) {
                        first_errno.get_or_insert(errno);
                    }
                }
            }
        }

        fn kill_bound_task(
            &self,
            raw_tid: i32,
            descriptor: Option<&OwnedFd>,
            reaped: bool,
            first_errno: &mut Option<i32>,
            faults: &mut impl ConnectorFaultInjectorV1,
        ) {
            if reaped {
                return;
            }
            if let Some(descriptor) = descriptor {
                if let Err(errno) = pidfd_kill_v1(faults, descriptor) {
                    if !matches!(errno, libc::ESRCH | libc::ECHILD) {
                        first_errno.get_or_insert(errno);
                    }
                }
                return;
            }
            if let Err(errno) = kill_tid_v1(faults, raw_tid) {
                if errno != libc::ESRCH {
                    first_errno.get_or_insert(errno);
                }
            }
        }
    }

    // Emergency unwind protection only. Normal paths call `cleanup` or
    // `close_success`, which also reap and prove final ECHILD. Drop can only
    // send termination signals and therefore grants no cleanup-completion
    // evidence.
    impl Drop for TaskTreeGuardV1 {
        fn drop(&mut self) {
            if !self.disarmed {
                let mut ignored = None;
                self.kill_known(&mut ignored, &mut NoConnectorFaultsV1);
            }
        }
    }

    pub(super) fn qualify_fixed_two_task_supervisor_v1()
    -> Result<CompletedFixedTwoTaskSupervisorProbeV1, FixedTwoTaskSupervisorFailureV1> {
        qualify_fixed_two_task_supervisor_with_faults_v1(&mut NoConnectorFaultsV1)
    }

    fn qualify_fixed_two_task_supervisor_with_faults_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
    ) -> Result<CompletedFixedTwoTaskSupervisorProbeV1, FixedTwoTaskSupervisorFailureV1> {
        require_dedicated_helper_v1()?;
        require_no_loader_injection_v1()?;
        require_seccomp_actions_v1()?;
        let signal_state = SignalStateSnapshotV1::capture(faults)?;
        let release = ReleaseChannelV1::create()?;
        let mut tree = clone_root_v1(faults, release.read.as_raw_fd(), release.write.as_raw_fd())?;
        drop(release.read);
        let mut release_write = Some(release.write);

        let outcome = (|| {
            let owned_root = seize_root_v1(faults, tree.root_tid)?;
            let released_root = release_root_v1(
                faults,
                owned_root,
                release_write.take().ok_or_else(|| {
                    failure_v1(
                        FixedTwoTaskSupervisorStageV1::ReleaseRoot,
                        FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                        None,
                    )
                })?,
            )?;
            let deadline = MonotonicDeadlineV1::after(RUN_SECONDS_V1)?;
            drive_supervisor_v1(faults, released_root, &mut tree, deadline)
        })();
        drop(release_write);

        let supervisor = match outcome {
            Ok(supervisor) => supervisor,
            Err(first) => {
                return Err(finish_failed_run_v1(
                    first,
                    &mut tree,
                    &signal_state,
                    faults,
                ));
            }
        };

        let fork_delivery_order = match tree.fork_delivery_order {
            Some(order) => order,
            None => {
                return Err(finish_failed_run_v1(
                    failure_v1(
                        FixedTwoTaskSupervisorStageV1::Planner,
                        FixedTwoTaskSupervisorReasonV1::ForkDeliveryOrderMissing,
                        None,
                    ),
                    &mut tree,
                    &signal_state,
                    faults,
                ));
            }
        };
        if let Err(first) = tree.close_success() {
            return Err(finish_failed_run_v1(
                first,
                &mut tree,
                &signal_state,
                faults,
            ));
        }
        signal_state
            .verify(faults)
            .map_err(|failure| failure.with_cleanup(false, None))?;
        let completed = supervisor
            .complete(TracerSupervisorCleanupCompletionPermitV1(()))
            .map_err(planner_failure_v1)?;
        fixed_completion_v1(completed, fork_delivery_order)
    }

    fn finish_failed_run_v1(
        first: FixedTwoTaskSupervisorFailureV1,
        tree: &mut TaskTreeGuardV1,
        signal_state: &SignalStateSnapshotV1,
        faults: &mut impl ConnectorFaultInjectorV1,
    ) -> FixedTwoTaskSupervisorFailureV1 {
        let (tree_clean, cleanup_errno) = tree.cleanup(faults);
        let signal_failure = signal_state.verify(faults).err();
        let signal_clean = signal_failure.is_none();
        let cleanup_errno =
            cleanup_errno.or_else(|| signal_failure.as_ref().and_then(|failure| failure.errno()));
        first.with_cleanup(tree_clean && signal_clean, cleanup_errno)
    }

    fn drive_supervisor_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        released_root: SupervisorReleasedRootV1,
        tree: &mut TaskTreeGuardV1,
        deadline: MonotonicDeadlineV1,
    ) -> Result<TracerSupervisorStateV1, FixedTwoTaskSupervisorFailureV1> {
        if released_root.raw_tid != tree.root_tid {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::PtraceSeize,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        let (initial_tid, initial_status) = wait_any_v1(faults, deadline)?.ok_or_else(|| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::WaitEvent,
                FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                Some(libc::ECHILD),
            )
        })?;
        if initial_tid != tree.root_tid {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::WaitEvent,
                FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                None,
            ));
        }
        prove_installed_filter_v1(faults, released_root.raw_tid)?;
        let mut sink = FixedEventSinkV1::new();
        let mut supervisor = TracerSupervisorStateV1::begin(
            TracerSupervisorIssuerPermitV1(()),
            released_root.raw_tid,
            &mut sink,
        )
        .map_err(planner_failure_v1)?;
        let mut intent = supervisor
            .observe_wait(initial_tid, initial_status, &mut sink)
            .map_err(planner_failure_v1)?;

        for _ in 0..MAX_DRIVER_STEPS_V1 {
            intent = match intent {
                TracerSupervisorIntentV1::ReadEventMessage(token) => {
                    let event = token.event();
                    let message = read_event_message_v1(faults, token.raw_tid())?;
                    if event == LinuxPtraceEventV1::Fork {
                        let child_tid = i32::try_from(message)
                            .ok()
                            .filter(|tid| *tid > 0)
                            .ok_or_else(|| {
                                failure_v1(
                                    FixedTwoTaskSupervisorStageV1::EventMessage,
                                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                                    None,
                                )
                            })?;
                        block_tracee_sigchld_v1(faults, tree.root_tid)?;
                        tree.record_nested_announcement(child_tid)?;
                    }
                    supervisor
                        .accept_event_message(token, &message.to_le_bytes(), &mut sink)
                        .map_err(planner_failure_v1)?
                }
                TracerSupervisorIntentV1::ReadSyscallInfo(token) => {
                    let mut buffer = [0_u8; 84];
                    let count = read_syscall_info_v1(faults, token.raw_tid(), &mut buffer)?;
                    supervisor
                        .accept_syscall_info(token, count, &buffer, &mut sink)
                        .map_err(planner_failure_v1)?
                }
                TracerSupervisorIntentV1::HoldStoppedSeccompTask(permit) => supervisor
                    .consume_stopped_seccomp_permit(permit, &mut sink)
                    .map_err(planner_failure_v1)?,
                TracerSupervisorIntentV1::ReadClone3Args(token) => {
                    prove_clone3_quiescence_v1(
                        tree,
                        token.raw_tid(),
                        token.address(),
                        token.byte_count(),
                    )?;
                    let mut buffer = [0_u8; CLONE3_ARGS_BUFFER_BYTES_V1];
                    let copied = read_process_memory_v1(
                        faults,
                        token.raw_tid(),
                        token.address(),
                        token.byte_count(),
                        &mut buffer,
                    )?;
                    supervisor
                        .accept_clone3_args_read(
                            token,
                            Clone3ArgsCaptureV1::Exact {
                                copied_byte_count: copied,
                                buffer: &buffer,
                            },
                            &mut sink,
                        )
                        .map_err(planner_failure_v1)?
                }
                TracerSupervisorIntentV1::Resume(resume) => {
                    resume_task_v1(faults, resume.raw_tid(), resume.request())?;
                    supervisor
                        .confirm_resume_succeeded(resume)
                        .map_err(planner_failure_v1)?
                }
                TracerSupervisorIntentV1::WaitForNextStop => match wait_any_v1(faults, deadline)? {
                    Some((raw_tid, status)) => {
                        if wait_status_is_ptrace_stop_v1(status) {
                            tree.record_ptrace_stop(raw_tid)?;
                        }
                        if wait_status_is_final_v1(status) {
                            tree.record_reap(raw_tid);
                        }
                        supervisor
                            .observe_wait(raw_tid, status, &mut sink)
                            .map_err(planner_failure_v1)?
                    }
                    None => {
                        tree.prove_final_echild()?;
                        return Ok(supervisor);
                    }
                },
            };
        }
        Err(failure_v1(
            FixedTwoTaskSupervisorStageV1::Planner,
            FixedTwoTaskSupervisorReasonV1::BoundExceeded,
            None,
        ))
    }

    fn fixed_completion_v1(
        completed: CompletedTracerSupervisorStateV1,
        fork_delivery_order: FixedTwoTaskForkDeliveryOrderV1,
    ) -> Result<CompletedFixedTwoTaskSupervisorProbeV1, FixedTwoTaskSupervisorFailureV1> {
        let summary = completed.summary();
        if summary.task_count != 2
            || summary.accepted_transition_count != 11
            || summary.initial_birth_count != 1
            || summary.child_announcement_count != 1
            || summary.child_ready_count != 1
            || summary.fork_birth_count != 1
            || summary.vfork_birth_count != 0
            || summary.clone_birth_count != 0
            || summary.exec_count != 0
            || summary.seccomp_entry_count != 3
            || summary.syscall_exit_count != 1
            || summary.no_return_resolution_count != 2
            || summary.ptrace_exit_event_count != 2
            || summary.terminal_reap_count != 2
        {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::Planner,
                FixedTwoTaskSupervisorReasonV1::PlannerSummaryMismatch,
                None,
            ));
        }
        Ok(CompletedFixedTwoTaskSupervisorProbeV1 {
            fork_delivery_order,
            task_count: summary.task_count,
            accepted_transition_count: summary.accepted_transition_count,
            fork_birth_count: summary.fork_birth_count,
            seccomp_entry_count: summary.seccomp_entry_count,
            syscall_exit_count: summary.syscall_exit_count,
            no_return_resolution_count: summary.no_return_resolution_count,
            ptrace_exit_event_count: summary.ptrace_exit_event_count,
            terminal_reap_count: summary.terminal_reap_count,
        })
    }

    fn clone_root_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        release_read: RawFd,
        release_write: RawFd,
    ) -> Result<TaskTreeGuardV1, FixedTwoTaskSupervisorFailureV1> {
        let child_faults = FixedRootFaultPlanV1 {
            seccomp_install: faults
                .take(ConnectorKernelOperationV1::SeccompInstall)
                .is_some(),
        };
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
            unsafe { fixed_root_entry_v1(release_read, release_write, child_faults) };
        }
        if result < 0 {
            let errno = last_errno_v1();
            return Err(if matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP) {
                FixedTwoTaskSupervisorFailureV1::new(
                    RefusalCode::PtraceUnavailable,
                    FixedTwoTaskSupervisorStageV1::CloneRoot,
                    FixedTwoTaskSupervisorReasonV1::KernelCapabilityUnavailable,
                    Some(errno),
                    true,
                )
            } else {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::CloneRoot,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    valid_errno_v1(errno).then_some(errno),
                )
            });
        }
        let root_tid = i32::try_from(result)
            .ok()
            .filter(|tid| *tid > 0)
            .ok_or_else(|| {
                let first = failure_v1(
                    FixedTwoTaskSupervisorStageV1::CloneRoot,
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                    None,
                );
                let (cleanup_complete, cleanup_errno) = cleanup_unidentified_root_v1(faults, pidfd);
                first.with_cleanup(cleanup_complete, cleanup_errno)
            })?;
        let root_pidfd = (pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd) });
        let mut tree = TaskTreeGuardV1 {
            root_tid,
            root_pidfd,
            nested_announced_tid: None,
            pending_nested_stop_tid: None,
            nested_tid: None,
            fork_delivery_order: None,
            nested_pidfd: None,
            root_reaped: false,
            nested_reaped: false,
            final_echild: false,
            disarmed: false,
        };
        let validation = (|| {
            let descriptor = tree.root_pidfd.as_ref().ok_or_else(|| {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::CloneRoot,
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                    None,
                )
            })?;
            require_cloexec_v1(descriptor, FixedTwoTaskSupervisorStageV1::CloneRoot)
        })();
        match validation {
            Ok(()) => Ok(tree),
            Err(first) => {
                let (cleanup_complete, cleanup_errno) = tree.cleanup(faults);
                Err(first.with_cleanup(cleanup_complete, cleanup_errno))
            }
        }
    }

    fn cleanup_unidentified_root_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        pidfd: RawFd,
    ) -> (bool, Option<i32>) {
        if pidfd < 0 {
            return (false, None);
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(pidfd) };
        if let Err(errno) = pidfd_kill_v1(faults, &descriptor) {
            if errno != libc::ESRCH {
                return (false, Some(errno));
            }
        }
        let deadline = match MonotonicDeadlineV1::after(CLEANUP_SECONDS_V1) {
            Ok(deadline) => deadline,
            Err(failure) => return (false, failure.errno()),
        };
        for _ in 0..MAX_WAIT_ATTEMPTS_V1 {
            let mut status = 0_i32;
            let waited = match connector_kernel_call_v1(
                faults,
                ConnectorKernelOperationV1::WaitCleanup,
                || unsafe {
                    i64::from(libc::waitpid(-1, &mut status, libc::WNOHANG | WAIT_WALL_V1))
                },
            ) {
                Ok(result) => result,
                Err(errno) => -i64::from(errno),
            };
            if waited > 0 {
                continue;
            }
            if waited < 0 {
                let errno = i32::try_from(-waited).unwrap_or(libc::EIO);
                if errno == libc::EINTR {
                    continue;
                }
                return if errno == libc::ECHILD {
                    (true, None)
                } else {
                    (false, Some(errno))
                };
            }
            match deadline.expired() {
                Ok(false) => {
                    if let Err(errno) = wait_backoff_v1() {
                        return (false, Some(errno));
                    }
                }
                Ok(true) => return (false, Some(libc::ETIMEDOUT)),
                Err(errno) => return (false, Some(errno)),
            }
        }
        (false, Some(libc::ETIMEDOUT))
    }

    #[derive(Clone, Copy, Default)]
    struct FixedRootFaultPlanV1 {
        seccomp_install: bool,
    }

    unsafe fn fixed_root_entry_v1(
        release_read: RawFd,
        release_write: RawFd,
        faults: FixedRootFaultPlanV1,
    ) -> ! {
        unsafe {
            if raw_syscall6_v1(libc::SYS_close, i64::from(release_write), 0, 0, 0, 0, 0) != 0 {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            if release_read > 0
                && raw_syscall6_v1(
                    libc::SYS_close_range,
                    0,
                    i64::from(release_read - 1),
                    0,
                    0,
                    0,
                    0,
                ) != 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            if raw_syscall6_v1(
                libc::SYS_close_range,
                i64::from(release_read) + 1,
                i64::from(u32::MAX),
                0,
                0,
                0,
                0,
            ) != 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            let mut release = 0_u8;
            let mut attempts = 0_u8;
            loop {
                let read = raw_syscall6_v1(
                    libc::SYS_read,
                    i64::from(release_read),
                    (&mut release as *mut u8) as i64,
                    1,
                    0,
                    0,
                    0,
                );
                if read == 1 {
                    break;
                }
                if read == -i64::from(libc::EINTR) && attempts < 8 {
                    attempts += 1;
                    continue;
                }
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            if release != RELEASE_BYTE_V1
                || raw_syscall6_v1(libc::SYS_close, i64::from(release_read), 0, 0, 0, 0, 0) != 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }

            let mapping = raw_syscall6_v1(
                libc::SYS_mmap,
                0,
                4096,
                i64::from(libc::PROT_READ | libc::PROT_WRITE),
                i64::from(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS),
                -1,
                0,
            );
            if mapping < 0 {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            let clone_args = mapping as *mut CloneArgsV1;
            ptr::write(
                clone_args,
                CloneArgsV1 {
                    exit_signal: libc::SIGCHLD as u64,
                    ..CloneArgsV1::default()
                },
            );

            let program =
                trace_all_native_seccomp_program_v1(FutureTracerSeccompConnectorPermitV1(()));
            let filter = program.instructions();
            let descriptor = LinuxSockFprogV1 {
                length: filter.len() as u16,
                filter: filter.as_ptr(),
            };
            if raw_syscall6_v1(libc::SYS_prctl, PR_SET_NO_NEW_PRIVS_V1, 1, 0, 0, 0, 0) != 0 {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            if faults.seccomp_install
                || raw_syscall6_v1(
                    libc::SYS_seccomp,
                    i64::from(SECCOMP_SET_MODE_FILTER_V1),
                    i64::from(SECCOMP_FILTER_FLAG_TSYNC_V1),
                    (&descriptor as *const LinuxSockFprogV1) as i64,
                    0,
                    0,
                    0,
                ) != 0
            {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }

            let nested = raw_syscall6_v1(
                libc::SYS_clone3,
                clone_args as i64,
                CLONE3_ARGS_BUFFER_BYTES_V1 as i64,
                0,
                0,
                0,
                0,
            );
            if nested < 0 {
                child_exit_v1(CHILD_FAILURE_EXIT_V1);
            }
            child_exit_v1(0);
        }
    }

    unsafe fn child_exit_v1(code: u32) -> ! {
        unsafe {
            let _ = raw_syscall6_v1(libc::SYS_exit, i64::from(code), 0, 0, 0, 0, 0);
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

    fn seize_root_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        root_tid: i32,
    ) -> Result<SupervisorOwnedRootV1, FixedTwoTaskSupervisorFailureV1> {
        match ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceSeize,
            PTRACE_SEIZE_V1,
            root_tid,
            0,
            PTRACE_OPTIONS_V1,
        ) {
            Ok(0) => Ok(SupervisorOwnedRootV1 { raw_tid: root_tid }),
            Ok(_) => Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::PtraceSeize,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            )),
            Err(errno) => Err(ptrace_failure_v1(
                FixedTwoTaskSupervisorStageV1::PtraceSeize,
                errno,
            )),
        }
    }

    fn release_root_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        owned_root: SupervisorOwnedRootV1,
        descriptor: OwnedFd,
    ) -> Result<SupervisorReleasedRootV1, FixedTwoTaskSupervisorFailureV1> {
        let byte = RELEASE_BYTE_V1;
        let result = connector_kernel_call_v1(
            faults,
            ConnectorKernelOperationV1::OwnershipTransfer,
            || unsafe {
                libc::send(
                    descriptor.as_raw_fd(),
                    (&byte as *const u8).cast(),
                    1,
                    libc::MSG_NOSIGNAL,
                ) as i64
            },
        );
        if result == Ok(1) {
            Ok(SupervisorReleasedRootV1 {
                raw_tid: owned_root.raw_tid,
            })
        } else {
            Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::ReleaseRoot,
                if result == Ok(0) {
                    FixedTwoTaskSupervisorReasonV1::ShortIo
                } else {
                    FixedTwoTaskSupervisorReasonV1::Io
                },
                result.err(),
            ))
        }
    }

    fn wait_any_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        deadline: MonotonicDeadlineV1,
    ) -> Result<Option<(i32, i32)>, FixedTwoTaskSupervisorFailureV1> {
        let mut attempts = 0_usize;
        loop {
            if attempts >= MAX_WAIT_ATTEMPTS_V1 {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::BoundExceeded,
                    None,
                ));
            }
            attempts += 1;
            let mut status = 0_i32;
            let result = match connector_kernel_call_v1(
                faults,
                ConnectorKernelOperationV1::WaitRun,
                || unsafe {
                    i64::from(libc::waitpid(-1, &mut status, libc::WNOHANG | WAIT_WALL_V1))
                },
            ) {
                Ok(result) => result,
                Err(errno) => -i64::from(errno),
            };
            if result > 0 {
                return Ok(Some((
                    i32::try_from(result).map_err(|_| {
                        failure_v1(
                            FixedTwoTaskSupervisorStageV1::WaitEvent,
                            FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                            None,
                        )
                    })?,
                    status,
                )));
            }
            if result < 0 {
                let errno = i32::try_from(-result).unwrap_or(libc::EIO);
                if errno == libc::EINTR {
                    continue;
                }
                if errno == libc::ECHILD {
                    return Ok(None);
                }
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    Some(errno),
                ));
            }
            if deadline.expired().map_err(|errno| {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    Some(errno),
                )
            })? {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::BoundExceeded,
                    None,
                ));
            }
            wait_backoff_v1().map_err(|errno| {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::WaitEvent,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    Some(errno),
                )
            })?;
        }
    }

    fn prove_installed_filter_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        raw_tid: i32,
    ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let program = trace_all_native_seccomp_program_v1(FutureTracerSeccompConnectorPermitV1(()));
        let expected = program.instructions();
        let count = ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceFilterCount,
            PTRACE_SECCOMP_GET_FILTER_V1,
            raw_tid,
            0,
            0,
        )
        .map_err(|errno| ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::FilterWitness, errno))?;
        if usize::try_from(count).ok() != Some(expected.len()) {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::FilterWitness,
                FixedTwoTaskSupervisorReasonV1::FilterMismatch,
                None,
            ));
        }
        let mut observed = [LinuxSockFilterV1 {
            code: 0,
            jump_true: 0,
            jump_false: 0,
            operand: 0,
        }; super::super::TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1];
        let read = ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceFilterRead,
            PTRACE_SECCOMP_GET_FILTER_V1,
            raw_tid,
            0,
            observed.as_mut_ptr() as u64,
        )
        .map_err(|errno| ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::FilterWitness, errno))?;
        if usize::try_from(read).ok() != Some(expected.len()) || observed != *expected {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::FilterWitness,
                FixedTwoTaskSupervisorReasonV1::FilterMismatch,
                None,
            ));
        }
        Ok(())
    }

    fn read_event_message_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        raw_tid: i32,
    ) -> Result<u64, FixedTwoTaskSupervisorFailureV1> {
        let mut message = u64::MAX;
        let result = ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceEventMessage,
            PTRACE_GETEVENTMSG_V1,
            raw_tid,
            0,
            (&mut message as *mut u64) as u64,
        )
        .map_err(|errno| ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::EventMessage, errno))?;
        if result != 0 {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::EventMessage,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(message)
    }

    /// Block `SIGCHLD` only after Linux has produced the fork event.
    ///
    /// The root tracee is stopped for the event throughout this operation, so
    /// its mask cannot race the read-modify-write. Delaying the mask change
    /// until this point preserves the kernel's real parent-event/child-stop
    /// delivery order while preventing a later child-exit signal from adding
    /// an event outside the fixed transcript.
    fn block_tracee_sigchld_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        raw_tid: i32,
    ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let mut observed = 0_u64;
        let read = ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceSignalMaskRead,
            PTRACE_GETSIGMASK_V1,
            raw_tid,
            KERNEL_SIGNAL_SET_BYTES_V1 as u64,
            (&mut observed as *mut u64) as u64,
        )
        .map_err(|errno| ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::SignalState, errno))?;
        if read != 0 || observed & SIGCHLD_MASK_V1 != 0 {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::SignalState,
                FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
                None,
            ));
        }

        let blocked = observed | SIGCHLD_MASK_V1;
        let written = ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceSignalMaskWrite,
            PTRACE_SETSIGMASK_V1,
            raw_tid,
            KERNEL_SIGNAL_SET_BYTES_V1 as u64,
            (&blocked as *const u64) as u64,
        )
        .map_err(|errno| ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::SignalState, errno))?;
        if written != 0 {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::SignalState,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            ));
        }

        let mut verified = 0_u64;
        let reread = ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceSignalMaskVerify,
            PTRACE_GETSIGMASK_V1,
            raw_tid,
            KERNEL_SIGNAL_SET_BYTES_V1 as u64,
            (&mut verified as *mut u64) as u64,
        )
        .map_err(|errno| ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::SignalState, errno))?;
        if reread != 0 || verified != blocked {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::SignalState,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(())
    }

    fn read_syscall_info_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        raw_tid: i32,
        buffer: &mut [u8; 84],
    ) -> Result<usize, FixedTwoTaskSupervisorFailureV1> {
        let result = ptrace_call_v1(
            faults,
            ConnectorKernelOperationV1::PtraceSyscallInfo,
            PTRACE_GET_SYSCALL_INFO_V1,
            raw_tid,
            buffer.len() as u64,
            buffer.as_mut_ptr() as u64,
        )
        .map_err(|errno| ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::SyscallInfo, errno))?;
        usize::try_from(result).map_err(|_| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::SyscallInfo,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            )
        })
    }

    fn resume_task_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        raw_tid: i32,
        request: TracerSupervisorResumeRequestV1,
    ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let (operation, request) = match request {
            TracerSupervisorResumeRequestV1::Continue => (
                ConnectorKernelOperationV1::PtraceResumeContinue,
                PTRACE_CONT_V1,
            ),
            TracerSupervisorResumeRequestV1::Syscall => (
                ConnectorKernelOperationV1::PtraceResumeSyscall,
                PTRACE_SYSCALL_V1,
            ),
        };
        match ptrace_call_v1(faults, operation, request, raw_tid, 0, 0) {
            Ok(0) => Ok(()),
            Ok(_) => Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::Resume,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            )),
            Err(errno) => Err(ptrace_failure_v1(
                FixedTwoTaskSupervisorStageV1::Resume,
                errno,
            )),
        }
    }

    fn prove_clone3_quiescence_v1(
        tree: &TaskTreeGuardV1,
        raw_tid: i32,
        address: u64,
        byte_count: usize,
    ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        if raw_tid != tree.root_tid
            || tree.nested_tid.is_some()
            || byte_count != CLONE3_ARGS_BUFFER_BYTES_V1
            || count_exact_task_v1(raw_tid)? != 1
        {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::QuiescenceUnproven,
                None,
            ));
        }
        prove_private_anonymous_range_v1(raw_tid, address, byte_count)
    }

    fn count_exact_task_v1(raw_tid: i32) -> Result<usize, FixedTwoTaskSupervisorFailureV1> {
        let path = format!("/proc/{raw_tid}/task");
        let expected = raw_tid.to_string();
        let mut count = 0_usize;
        for entry in fs::read_dir(path).map_err(|error| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::Io,
                error.raw_os_error(),
            )
        })? {
            let entry = entry.map_err(|error| {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::Quiescence,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    error.raw_os_error(),
                )
            })?;
            if entry.file_name() != OsStr::new(&expected) {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::Quiescence,
                    FixedTwoTaskSupervisorReasonV1::QuiescenceUnproven,
                    None,
                ));
            }
            count += 1;
        }
        Ok(count)
    }

    fn prove_private_anonymous_range_v1(
        raw_tid: i32,
        address: u64,
        byte_count: usize,
    ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let end = address.checked_add(byte_count as u64).ok_or_else(|| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::PrivateRangeUnproven,
                None,
            )
        })?;
        let file = fs::File::open(format!("/proc/{raw_tid}/maps")).map_err(|error| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        let mut bounded = file.take((MAX_PROC_TEXT_BYTES_V1 + 1) as u64);
        let mut bytes = Vec::new();
        bounded.read_to_end(&mut bytes).map_err(|error| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        if bytes.len() > MAX_PROC_TEXT_BYTES_V1 || bytes.contains(&0) {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::PrivateRangeUnproven,
                None,
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::PrivateRangeUnproven,
                None,
            )
        })?;
        let mut matched = false;
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let Some(range) = fields.next() else { continue };
            let Some(perms) = fields.next() else { continue };
            let Some(offset) = fields.next() else {
                continue;
            };
            let Some(device) = fields.next() else {
                continue;
            };
            let Some(inode) = fields.next() else { continue };
            let pathname = fields.next();
            if fields.next().is_some() {
                continue;
            }
            let Some((start_text, end_text)) = range.split_once('-') else {
                continue;
            };
            let Ok(start) = u64::from_str_radix(start_text, 16) else {
                continue;
            };
            let Ok(mapping_end) = u64::from_str_radix(end_text, 16) else {
                continue;
            };
            if start <= address && end <= mapping_end {
                if matched
                    || perms != "rw-p"
                    || offset != "00000000"
                    || device != "00:00"
                    || inode != "0"
                    || pathname.is_some()
                {
                    return Err(failure_v1(
                        FixedTwoTaskSupervisorStageV1::Quiescence,
                        FixedTwoTaskSupervisorReasonV1::PrivateRangeUnproven,
                        None,
                    ));
                }
                matched = true;
            }
        }
        if matched {
            Ok(())
        } else {
            Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::Quiescence,
                FixedTwoTaskSupervisorReasonV1::PrivateRangeUnproven,
                None,
            ))
        }
    }

    fn read_process_memory_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        raw_tid: i32,
        address: u64,
        byte_count: usize,
        buffer: &mut [u8; CLONE3_ARGS_BUFFER_BYTES_V1],
    ) -> Result<usize, FixedTwoTaskSupervisorFailureV1> {
        let mut local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: byte_count,
        };
        let mut remote = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: byte_count,
        };
        let result = connector_kernel_call_v1(
            faults,
            ConnectorKernelOperationV1::ProcessMemoryRead,
            || unsafe {
                libc::syscall(
                    libc::SYS_process_vm_readv,
                    raw_tid,
                    &mut local,
                    1_u64,
                    &mut remote,
                    1_u64,
                    0_u64,
                )
            },
        )
        .map_err(process_memory_failure_v1)?;
        let copied = usize::try_from(result).map_err(|_| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::ProcessMemory,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            )
        })?;
        if copied != byte_count {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::ProcessMemory,
                FixedTwoTaskSupervisorReasonV1::ShortIo,
                None,
            ));
        }
        Ok(copied)
    }

    fn ptrace_call_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        operation: ConnectorKernelOperationV1,
        request: u64,
        raw_tid: i32,
        address: u64,
        data: u64,
    ) -> Result<libc::c_long, i32> {
        connector_kernel_call_v1(faults, operation, || unsafe {
            libc::syscall(
                libc::SYS_ptrace,
                request,
                raw_tid,
                address,
                data,
                0_u64,
                0_u64,
            )
        })
        .map(|result| result as libc::c_long)
    }

    fn pidfd_kill_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
        descriptor: &OwnedFd,
    ) -> Result<(), i32> {
        connector_kernel_call_v1(faults, ConnectorKernelOperationV1::KillPidfd, || unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                descriptor.as_raw_fd(),
                libc::SIGKILL,
                ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        })
        .and_then(|result| (result == 0).then_some(()).ok_or(libc::EPROTO))
    }

    fn kill_tid_v1(faults: &mut impl ConnectorFaultInjectorV1, raw_tid: i32) -> Result<(), i32> {
        connector_kernel_call_v1(faults, ConnectorKernelOperationV1::KillTid, || unsafe {
            i64::from(libc::kill(raw_tid, libc::SIGKILL))
        })
        .and_then(|result| (result == 0).then_some(()).ok_or(libc::EPROTO))
    }

    fn require_dedicated_helper_v1() -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let pid = unsafe { libc::getpid() };
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        if pid <= 0 || tid != libc::c_long::from(pid) || count_exact_self_task_v1(pid)? != 1 {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                FixedTwoTaskSupervisorReasonV1::MultipleTasks,
                None,
            ));
        }
        let children =
            fs::File::open(format!("/proc/self/task/{pid}/children")).map_err(|error| {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    error.raw_os_error(),
                )
            })?;
        let mut bounded = children.take(1);
        let mut observed = [0_u8; 1];
        let count = bounded.read(&mut observed).map_err(|error| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                FixedTwoTaskSupervisorReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        if count == 0 {
            Ok(())
        } else {
            Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                FixedTwoTaskSupervisorReasonV1::ExistingChildren,
                None,
            ))
        }
    }

    fn count_exact_self_task_v1(pid: i32) -> Result<usize, FixedTwoTaskSupervisorFailureV1> {
        let expected = pid.to_string();
        let mut count = 0_usize;
        for entry in fs::read_dir("/proc/self/task").map_err(|error| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                FixedTwoTaskSupervisorReasonV1::Io,
                error.raw_os_error(),
            )
        })? {
            let entry = entry.map_err(|error| {
                failure_v1(
                    FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    error.raw_os_error(),
                )
            })?;
            if entry.file_name().as_bytes() != expected.as_bytes() {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                    FixedTwoTaskSupervisorReasonV1::MultipleTasks,
                    None,
                ));
            }
            count += 1;
        }
        Ok(count)
    }

    fn require_no_loader_injection_v1() -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let environment = fs::File::open("/proc/self/environ").map_err(|error| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                FixedTwoTaskSupervisorReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        let mut bounded = environment.take((MAX_ENVIRONMENT_BYTES_V1 + 1) as u64);
        let mut bytes = Vec::new();
        bounded.read_to_end(&mut bytes).map_err(|error| {
            failure_v1(
                FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                FixedTwoTaskSupervisorReasonV1::Io,
                error.raw_os_error(),
            )
        })?;
        if bytes.len() > MAX_ENVIRONMENT_BYTES_V1 {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                FixedTwoTaskSupervisorReasonV1::BoundExceeded,
                None,
            ));
        }
        validate_environment_bytes_v1(&bytes)
    }

    fn validate_environment_bytes_v1(bytes: &[u8]) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
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
            if loader_injection_name_v1(&entry[..separator]) {
                return Err(FixedTwoTaskSupervisorFailureV1::new(
                    RefusalCode::LoaderInjectionEnvironment,
                    FixedTwoTaskSupervisorStageV1::DedicatedHelper,
                    FixedTwoTaskSupervisorReasonV1::LoaderInjectionEnvironment,
                    None,
                    true,
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
                b"GLIBC_TUNABLES"
                    | b"GCONV_PATH"
                    | b"LOCPATH"
                    | b"NLSPATH"
                    | b"ASAN_OPTIONS"
                    | b"LSAN_OPTIONS"
                    | b"MSAN_OPTIONS"
                    | b"TSAN_OPTIONS"
                    | b"UBSAN_OPTIONS"
            )
    }

    fn malformed_environment_failure_v1() -> FixedTwoTaskSupervisorFailureV1 {
        failure_v1(
            FixedTwoTaskSupervisorStageV1::DedicatedHelper,
            FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
            None,
        )
    }

    fn require_seccomp_actions_v1() -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        for expected in [SECCOMP_RET_TRACE_V1, SECCOMP_RET_KILL_PROCESS_V1] {
            let mut action = expected;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_GET_ACTION_AVAIL_V1,
                    0_u32,
                    &mut action,
                )
            };
            if result == 0 && action == expected {
                continue;
            }
            if result < 0 {
                let errno = last_errno_v1();
                if matches!(errno, libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP) {
                    return Err(FixedTwoTaskSupervisorFailureV1::new(
                        RefusalCode::SeccompUnavailable,
                        FixedTwoTaskSupervisorStageV1::SeccompActions,
                        FixedTwoTaskSupervisorReasonV1::KernelCapabilityUnavailable,
                        Some(errno),
                        true,
                    ));
                }
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::SeccompActions,
                    FixedTwoTaskSupervisorReasonV1::Io,
                    valid_errno_v1(errno).then_some(errno),
                ));
            }
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::SeccompActions,
                FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                None,
            ));
        }
        Ok(())
    }

    fn current_signal_mask_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
    ) -> Result<libc::sigset_t, FixedTwoTaskSupervisorFailureV1> {
        let mut mask = MaybeUninit::<libc::sigset_t>::zeroed();
        let result = match faults.take(ConnectorKernelOperationV1::SignalMaskRead) {
            Some(InjectedKernelResultV1::Return(value)) => {
                i32::try_from(value).unwrap_or(libc::EIO)
            }
            Some(InjectedKernelResultV1::Errno(errno)) => errno,
            None => unsafe {
                libc::pthread_sigmask(libc::SIG_BLOCK, ptr::null(), mask.as_mut_ptr())
            },
        };
        if result != 0 {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::SignalState,
                FixedTwoTaskSupervisorReasonV1::Io,
                Some(result),
            ));
        }
        Ok(unsafe { mask.assume_init() })
    }

    fn signal_sets_equal_v1(
        expected: &libc::sigset_t,
        observed: &libc::sigset_t,
    ) -> Result<bool, FixedTwoTaskSupervisorFailureV1> {
        for signal in 1..=64 {
            let expected_member = unsafe { libc::sigismember(expected, signal) };
            let observed_member = unsafe { libc::sigismember(observed, signal) };
            if expected_member < 0 || observed_member < 0 {
                return Err(failure_v1(
                    FixedTwoTaskSupervisorStageV1::SignalState,
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
                    Some(last_errno_v1()),
                ));
            }
            if expected_member != observed_member {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn require_no_pending_sigchld_v1(
        faults: &mut impl ConnectorFaultInjectorV1,
    ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let mut pending = MaybeUninit::<libc::sigset_t>::zeroed();
        if let Err(errno) = connector_kernel_call_v1(
            faults,
            ConnectorKernelOperationV1::SignalPendingRead,
            || unsafe { i64::from(libc::sigpending(pending.as_mut_ptr())) },
        ) {
            return Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::SignalState,
                FixedTwoTaskSupervisorReasonV1::Io,
                Some(errno),
            ));
        }
        let pending = unsafe { pending.assume_init() };
        let member = unsafe { libc::sigismember(&pending, libc::SIGCHLD) };
        if member == 0 {
            Ok(())
        } else {
            Err(failure_v1(
                FixedTwoTaskSupervisorStageV1::SignalState,
                if member < 0 {
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse
                } else {
                    FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent
                },
                (member < 0).then(last_errno_v1),
            ))
        }
    }

    fn require_cloexec_v1(
        descriptor: &OwnedFd,
        stage: FixedTwoTaskSupervisorStageV1,
    ) -> Result<(), FixedTwoTaskSupervisorFailureV1> {
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        if flags == libc::FD_CLOEXEC {
            Ok(())
        } else {
            Err(failure_v1(
                stage,
                if flags < 0 {
                    FixedTwoTaskSupervisorReasonV1::Io
                } else {
                    FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse
                },
                (flags < 0).then(last_errno_v1),
            ))
        }
    }

    fn wait_status_is_ptrace_stop_v1(status: i32) -> bool {
        u32::try_from(status).is_ok_and(|raw| raw & 0xff == 0x7f)
    }

    fn wait_status_is_final_v1(status: i32) -> bool {
        u32::try_from(status)
            .is_ok_and(|raw| raw <= u16::MAX as u32 && raw & 0xff != 0x7f && raw != 0xffff)
    }

    fn monotonic_now_v1() -> Result<libc::timespec, i32> {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
            return Err(last_errno_v1());
        }
        let value = unsafe { value.assume_init() };
        if value.tv_nsec < 0 || value.tv_nsec >= 1_000_000_000 {
            Err(libc::EPROTO)
        } else {
            Ok(value)
        }
    }

    fn wait_backoff_v1() -> Result<(), i32> {
        let mut remaining = libc::timespec {
            tv_sec: 0,
            tv_nsec: WAIT_BACKOFF_NANOSECONDS_V1,
        };
        loop {
            let requested = remaining;
            if unsafe { libc::nanosleep(&requested, &mut remaining) } == 0 {
                return Ok(());
            }
            let errno = last_errno_v1();
            if errno != libc::EINTR {
                return Err(errno);
            }
        }
    }

    fn planner_failure_v1(
        reason: TracerSupervisorExecuteOnlyReasonV1,
    ) -> FixedTwoTaskSupervisorFailureV1 {
        failure_v1(
            FixedTwoTaskSupervisorStageV1::Planner,
            FixedTwoTaskSupervisorReasonV1::SupervisorRejected(reason.as_str()),
            None,
        )
    }

    fn ptrace_failure_v1(
        stage: FixedTwoTaskSupervisorStageV1,
        errno: i32,
    ) -> FixedTwoTaskSupervisorFailureV1 {
        if matches!(errno, libc::EPERM | libc::EACCES)
            && matches!(
                stage,
                FixedTwoTaskSupervisorStageV1::PtraceSeize
                    | FixedTwoTaskSupervisorStageV1::FilterWitness
                    | FixedTwoTaskSupervisorStageV1::ProcessMemory
            )
        {
            return FixedTwoTaskSupervisorFailureV1::new(
                RefusalCode::PtraceUnavailable,
                stage,
                FixedTwoTaskSupervisorReasonV1::AdministrativePolicy,
                Some(errno),
                true,
            );
        }
        failure_v1(
            stage,
            FixedTwoTaskSupervisorReasonV1::Io,
            valid_errno_v1(errno).then_some(errno),
        )
    }

    fn process_memory_failure_v1(errno: i32) -> FixedTwoTaskSupervisorFailureV1 {
        let reason = match errno {
            libc::EFAULT => FixedTwoTaskSupervisorReasonV1::PrivateRangeUnproven,
            libc::EINVAL => FixedTwoTaskSupervisorReasonV1::MalformedKernelResponse,
            libc::ESRCH => FixedTwoTaskSupervisorReasonV1::UnexpectedLifecycleEvent,
            _ => return ptrace_failure_v1(FixedTwoTaskSupervisorStageV1::ProcessMemory, errno),
        };
        failure_v1(
            FixedTwoTaskSupervisorStageV1::ProcessMemory,
            reason,
            valid_errno_v1(errno).then_some(errno),
        )
    }

    fn failure_v1(
        stage: FixedTwoTaskSupervisorStageV1,
        reason: FixedTwoTaskSupervisorReasonV1,
        errno: Option<i32>,
    ) -> FixedTwoTaskSupervisorFailureV1 {
        FixedTwoTaskSupervisorFailureV1::new(
            RefusalCode::IsolationPreflightFailed,
            stage,
            reason,
            errno,
            true,
        )
    }

    const fn valid_errno_v1(errno: i32) -> bool {
        errno > 0 && errno <= 4_095
    }

    fn last_errno_v1() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fixed_tracee_signal_mask_contract_is_exact() {
            assert_eq!(KERNEL_SIGNAL_SET_BYTES_V1, 8);
            assert_eq!(SIGCHLD_MASK_V1.count_ones(), 1);
            assert_ne!(SIGCHLD_MASK_V1 & (1_u64 << (libc::SIGCHLD - 1)), 0);
            assert_eq!(PTRACE_GETSIGMASK_V1, 0x420a);
            assert_eq!(PTRACE_SETSIGMASK_V1, 0x420b);
        }

        #[test]
        fn planner_failure_preserves_the_exact_redacted_supervisor_reason() {
            let failure = planner_failure_v1(
                TracerSupervisorExecuteOnlyReasonV1::EventMessageCorrelationMismatch,
            );
            assert_eq!(failure.stage(), "planner");
            assert_eq!(
                failure.reason(),
                "supervisor_event_message_correlation_mismatch"
            );
            assert_eq!(failure.errno(), None);
        }

        struct ScriptedFaultsV1 {
            script: Vec<(ConnectorKernelOperationV1, InjectedKernelResultV1)>,
            cursor: usize,
        }

        impl ScriptedFaultsV1 {
            fn one(operation: ConnectorKernelOperationV1, result: InjectedKernelResultV1) -> Self {
                Self {
                    script: vec![(operation, result)],
                    cursor: 0,
                }
            }

            fn new(script: Vec<(ConnectorKernelOperationV1, InjectedKernelResultV1)>) -> Self {
                Self { script, cursor: 0 }
            }

            fn assert_consumed(&self) {
                assert_eq!(self.cursor, self.script.len());
            }
        }

        impl ConnectorFaultInjectorV1 for ScriptedFaultsV1 {
            fn take(
                &mut self,
                operation: ConnectorKernelOperationV1,
            ) -> Option<InjectedKernelResultV1> {
                let (expected, result) = *self.script.get(self.cursor)?;
                if expected != operation {
                    return None;
                }
                self.cursor += 1;
                Some(result)
            }
        }

        fn inert_tree_v1() -> TaskTreeGuardV1 {
            TaskTreeGuardV1 {
                root_tid: 10,
                root_pidfd: None,
                nested_announced_tid: None,
                pending_nested_stop_tid: None,
                nested_tid: None,
                fork_delivery_order: None,
                nested_pidfd: None,
                root_reaped: false,
                nested_reaped: false,
                final_echild: false,
                disarmed: true,
            }
        }

        fn assert_forward_failure_cleans_tree_v1(first: FixedTwoTaskSupervisorFailureV1) {
            let expected = (first.stage(), first.reason(), first.errno());
            let signal_state = SignalStateSnapshotV1::capture(&mut NoConnectorFaultsV1)
                .ok()
                .expect("signal snapshot");
            let mut tree = inert_tree_v1();
            tree.disarmed = false;
            let mut cleanup = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Errno(libc::ECHILD),
                ),
            ]);
            let completed = finish_failed_run_v1(first, &mut tree, &signal_state, &mut cleanup);
            assert_eq!(
                (completed.stage(), completed.reason(), completed.errno()),
                expected
            );
            assert!(completed.cleanup_complete());
            assert_eq!(completed.cleanup_errno(), None);
            assert!(tree.final_echild);
            assert!(tree.disarmed);
            cleanup.assert_consumed();
        }

        #[test]
        fn mismatched_event_message_cannot_discard_a_wait_proven_stop() {
            let mut tree = inert_tree_v1();
            assert!(tree.record_nested_announcement(20).is_ok());

            let failure = tree.record_ptrace_stop(21).unwrap_err();

            assert_eq!(failure.stage(), "wait_event");
            assert_eq!(failure.reason(), "unexpected_lifecycle_event");
            assert_eq!(tree.nested_announced_tid, Some(20));
            assert_eq!(tree.pending_nested_stop_tid, Some(21));
            assert!(tree.nested_tid.is_none());
        }

        #[test]
        fn both_fork_delivery_orders_are_classified_without_kernel_identity() {
            let mut parent_first = inert_tree_v1();
            assert!(parent_first.record_nested_announcement(20).is_ok());
            assert_eq!(
                parent_first
                    .fork_delivery_order
                    .map(FixedTwoTaskForkDeliveryOrderV1::as_str),
                Some("parent_event_first")
            );

            let mut child_first = inert_tree_v1();
            assert!(child_first.record_ptrace_stop(20).is_ok());
            assert_eq!(
                child_first
                    .fork_delivery_order
                    .map(FixedTwoTaskForkDeliveryOrderV1::as_str),
                Some("child_stop_first")
            );
        }

        #[test]
        fn loader_environment_parser_matches_the_profile_injection_set() {
            for name in [
                b"LD_PRELOAD".as_slice(),
                b"DYLD_INSERT_LIBRARIES",
                b"MALLOC_CHECK_",
                b"GLIBC_TUNABLES",
                b"GCONV_PATH",
                b"LOCPATH",
                b"NLSPATH",
                b"ASAN_OPTIONS",
                b"LSAN_OPTIONS",
                b"MSAN_OPTIONS",
                b"TSAN_OPTIONS",
                b"UBSAN_OPTIONS",
            ] {
                let mut environment = name.to_vec();
                environment.extend_from_slice(b"=value\0");
                let failure = validate_environment_bytes_v1(&environment).unwrap_err();
                assert_eq!(failure.code(), RefusalCode::LoaderInjectionEnvironment);
                assert_eq!(failure.reason(), "loader_injection_environment");
            }
            assert!(validate_environment_bytes_v1(b"PATH=/usr/bin\0LANG=C\0").is_ok());
        }

        #[test]
        fn malformed_environment_and_process_memory_errors_are_typed() {
            for bytes in [b"NO_EQUALS\0".as_slice(), b"=value\0", b"PATH=/bin"] {
                let failure = validate_environment_bytes_v1(bytes).unwrap_err();
                assert_eq!(failure.reason(), "malformed_kernel_response");
            }

            for (errno, reason) in [
                (libc::EFAULT, "private_range_unproven"),
                (libc::EINVAL, "malformed_kernel_response"),
                (libc::ESRCH, "unexpected_lifecycle_event"),
            ] {
                let failure = process_memory_failure_v1(errno);
                assert_eq!(failure.stage(), "process_memory");
                assert_eq!(failure.reason(), reason);
                assert_eq!(failure.errno(), Some(errno));
            }
        }

        #[test]
        fn every_forward_kernel_operation_has_an_injected_failure_boundary() {
            let deadline = MonotonicDeadlineV1::after(1)
                .ok()
                .expect("monotonic deadline");
            let mut wait = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::WaitRun,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            let failure = wait_any_v1(&mut wait, deadline).unwrap_err();
            assert_eq!((failure.stage(), failure.reason()), ("wait_event", "io"));
            wait.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);

            let mut seize = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::PtraceSeize,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            let failure = seize_root_v1(&mut seize, 1)
                .err()
                .expect("injected seize failure");
            assert_eq!((failure.stage(), failure.reason()), ("ptrace_seize", "io"));
            seize.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);

            let mut filter_count = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::PtraceFilterCount,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            let failure = prove_installed_filter_v1(&mut filter_count, 1).unwrap_err();
            assert_eq!(
                (failure.stage(), failure.reason()),
                ("filter_witness", "io")
            );
            filter_count.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);

            let mut filter_read = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::PtraceFilterCount,
                    InjectedKernelResultV1::Return(
                        super::super::super::TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1 as i64,
                    ),
                ),
                (
                    ConnectorKernelOperationV1::PtraceFilterRead,
                    InjectedKernelResultV1::Errno(libc::EIO),
                ),
            ]);
            let failure = prove_installed_filter_v1(&mut filter_read, 1).unwrap_err();
            assert_eq!(
                (failure.stage(), failure.reason()),
                ("filter_witness", "io")
            );
            filter_read.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);

            let mut filter_mismatch = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::PtraceFilterCount,
                    InjectedKernelResultV1::Return(
                        super::super::super::TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1 as i64,
                    ),
                ),
                (
                    ConnectorKernelOperationV1::PtraceFilterRead,
                    InjectedKernelResultV1::Return(
                        super::super::super::TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1 as i64,
                    ),
                ),
            ]);
            let failure = prove_installed_filter_v1(&mut filter_mismatch, 1).unwrap_err();
            assert_eq!(
                (failure.stage(), failure.reason()),
                ("filter_witness", "filter_mismatch")
            );
            filter_mismatch.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);

            let mut event = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::PtraceEventMessage,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            let failure = read_event_message_v1(&mut event, 1).unwrap_err();
            assert_eq!((failure.stage(), failure.reason()), ("event_message", "io"));
            event.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);

            for script in [
                vec![(
                    ConnectorKernelOperationV1::PtraceSignalMaskRead,
                    InjectedKernelResultV1::Errno(libc::EIO),
                )],
                vec![
                    (
                        ConnectorKernelOperationV1::PtraceSignalMaskRead,
                        InjectedKernelResultV1::Return(0),
                    ),
                    (
                        ConnectorKernelOperationV1::PtraceSignalMaskWrite,
                        InjectedKernelResultV1::Errno(libc::EIO),
                    ),
                ],
                vec![
                    (
                        ConnectorKernelOperationV1::PtraceSignalMaskRead,
                        InjectedKernelResultV1::Return(0),
                    ),
                    (
                        ConnectorKernelOperationV1::PtraceSignalMaskWrite,
                        InjectedKernelResultV1::Return(0),
                    ),
                    (
                        ConnectorKernelOperationV1::PtraceSignalMaskVerify,
                        InjectedKernelResultV1::Errno(libc::EIO),
                    ),
                ],
            ] {
                let mut signal_mask = ScriptedFaultsV1::new(script);
                let failure = block_tracee_sigchld_v1(&mut signal_mask, 1).unwrap_err();
                assert_eq!((failure.stage(), failure.reason()), ("signal_state", "io"));
                signal_mask.assert_consumed();
                assert_forward_failure_cleans_tree_v1(failure);
            }

            let mut syscall = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::PtraceSyscallInfo,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            let failure = read_syscall_info_v1(&mut syscall, 1, &mut [0_u8; 84]).unwrap_err();
            assert_eq!((failure.stage(), failure.reason()), ("syscall_info", "io"));
            syscall.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);

            for (request, operation) in [
                (
                    TracerSupervisorResumeRequestV1::Continue,
                    ConnectorKernelOperationV1::PtraceResumeContinue,
                ),
                (
                    TracerSupervisorResumeRequestV1::Syscall,
                    ConnectorKernelOperationV1::PtraceResumeSyscall,
                ),
            ] {
                let mut resume =
                    ScriptedFaultsV1::one(operation, InjectedKernelResultV1::Errno(libc::EIO));
                let failure = resume_task_v1(&mut resume, 1, request).unwrap_err();
                assert_eq!((failure.stage(), failure.reason()), ("resume", "io"));
                resume.assert_consumed();
                assert_forward_failure_cleans_tree_v1(failure);
            }

            let mut memory = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::ProcessMemoryRead,
                InjectedKernelResultV1::Errno(libc::EFAULT),
            );
            let failure = read_process_memory_v1(
                &mut memory,
                1,
                1,
                CLONE3_ARGS_BUFFER_BYTES_V1,
                &mut [0_u8; CLONE3_ARGS_BUFFER_BYTES_V1],
            )
            .unwrap_err();
            assert_eq!(
                (failure.stage(), failure.reason()),
                ("process_memory", "private_range_unproven")
            );
            memory.assert_consumed();
            assert_forward_failure_cleans_tree_v1(failure);
        }

        #[test]
        fn cleanup_fault_matrix_drains_or_reports_uncertainty_without_losing_first_error() {
            let mut tree = inert_tree_v1();
            tree.disarmed = false;
            tree.nested_tid = Some(20);
            let root_pidfd: OwnedFd = fs::File::open("/dev/null").unwrap().into();
            let nested_pidfd: OwnedFd = fs::File::open("/dev/null").unwrap().into();
            let root_descriptor = root_pidfd.as_raw_fd();
            let nested_descriptor = nested_pidfd.as_raw_fd();
            tree.root_pidfd = Some(root_pidfd);
            tree.nested_pidfd = Some(nested_pidfd);
            let mut clean = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::KillPidfd,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::KillPidfd,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Errno(libc::ECHILD),
                ),
            ]);
            assert_eq!(tree.cleanup(&mut clean), (true, None));
            assert!(tree.final_echild);
            assert!(tree.disarmed);
            assert!(tree.root_pidfd.is_none());
            assert!(tree.nested_pidfd.is_none());
            assert_eq!(unsafe { libc::fcntl(root_descriptor, libc::F_GETFD) }, -1);
            assert_eq!(last_errno_v1(), libc::EBADF);
            assert_eq!(unsafe { libc::fcntl(nested_descriptor, libc::F_GETFD) }, -1);
            assert_eq!(last_errno_v1(), libc::EBADF);
            clean.assert_consumed();

            let mut uncertain_tree = inert_tree_v1();
            uncertain_tree.nested_tid = Some(20);
            let mut kill_failure = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Errno(libc::EIO),
                ),
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Errno(libc::ECHILD),
                ),
            ]);
            assert_eq!(
                uncertain_tree.cleanup(&mut kill_failure),
                (false, Some(libc::EIO))
            );
            assert!(uncertain_tree.final_echild);
            kill_failure.assert_consumed();

            let first = failure_v1(
                FixedTwoTaskSupervisorStageV1::ProcessMemory,
                FixedTwoTaskSupervisorReasonV1::ShortIo,
                Some(libc::EFAULT),
            )
            .with_cleanup(false, Some(libc::EIO));
            assert_eq!(first.stage(), "process_memory");
            assert_eq!(first.reason(), "short_io");
            assert_eq!(first.errno(), Some(libc::EFAULT));
            assert_eq!(first.cleanup_errno(), Some(libc::EIO));
        }

        #[test]
        fn child_stop_first_cleanup_retries_without_discarding_wait_authority() {
            let mut tree = inert_tree_v1();
            tree.disarmed = false;
            tree.pending_nested_stop_tid = Some(20);
            let mut faults = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Errno(libc::EIO),
                ),
                (
                    ConnectorKernelOperationV1::PtraceCleanupResume,
                    InjectedKernelResultV1::Errno(libc::EIO),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::PtraceCleanupResume,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Errno(libc::ECHILD),
                ),
            ]);

            assert_eq!(tree.cleanup(&mut faults), (false, Some(libc::EIO)));
            assert!(tree.final_echild);
            assert!(tree.disarmed);
            faults.assert_consumed();
        }

        #[test]
        fn child_stop_first_terminal_wait_retires_raw_cleanup_identity() {
            let mut tree = inert_tree_v1();
            tree.disarmed = false;
            tree.pending_nested_stop_tid = Some(20);
            let mut faults = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::PtraceCleanupResume,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Return(20),
                ),
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Errno(libc::ECHILD),
                ),
            ]);

            assert_eq!(tree.cleanup(&mut faults), (true, None));
            assert!(tree.pending_nested_stop_tid.is_none());
            assert!(tree.final_echild);
            assert!(tree.disarmed);
            faults.assert_consumed();
        }

        #[test]
        fn every_cleanup_kernel_operation_has_an_injected_failure_boundary() {
            let descriptor: OwnedFd = fs::File::open("/dev/null").unwrap().into();
            let mut pidfd_failure = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::KillPidfd,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            assert_eq!(
                pidfd_kill_v1(&mut pidfd_failure, &descriptor),
                Err(libc::EIO)
            );
            pidfd_failure.assert_consumed();

            let mut tid_failure = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::KillTid,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            assert_eq!(kill_tid_v1(&mut tid_failure, 1), Err(libc::EIO));
            tid_failure.assert_consumed();

            let mut cleanup_resume_failure = ScriptedFaultsV1::one(
                ConnectorKernelOperationV1::PtraceCleanupResume,
                InjectedKernelResultV1::Errno(libc::EIO),
            );
            assert_eq!(
                ptrace_call_v1(
                    &mut cleanup_resume_failure,
                    ConnectorKernelOperationV1::PtraceCleanupResume,
                    PTRACE_CONT_V1,
                    1,
                    0,
                    libc::SIGKILL as u64,
                ),
                Err(libc::EIO)
            );
            cleanup_resume_failure.assert_consumed();

            let mut tree = inert_tree_v1();
            let mut reap_failure = ScriptedFaultsV1::new(vec![
                (
                    ConnectorKernelOperationV1::KillTid,
                    InjectedKernelResultV1::Return(0),
                ),
                (
                    ConnectorKernelOperationV1::WaitCleanup,
                    InjectedKernelResultV1::Errno(libc::EIO),
                ),
            ]);
            assert_eq!(tree.cleanup(&mut reap_failure), (false, Some(libc::EIO)));
            assert!(!tree.final_echild);
            reap_failure.assert_consumed();
        }

        #[test]
        fn signal_preservation_checks_have_independent_fault_boundaries() {
            let snapshot = SignalStateSnapshotV1::capture(&mut NoConnectorFaultsV1)
                .ok()
                .expect("signal snapshot");
            for operation in [
                ConnectorKernelOperationV1::SignalMaskRead,
                ConnectorKernelOperationV1::SignalActionRead,
                ConnectorKernelOperationV1::SignalPendingRead,
            ] {
                let mut faults =
                    ScriptedFaultsV1::one(operation, InjectedKernelResultV1::Errno(libc::EIO));
                let failure = snapshot.verify(&mut faults).unwrap_err();
                assert_eq!((failure.stage(), failure.reason()), ("signal_state", "io"));
                assert_eq!(failure.errno(), Some(libc::EIO));
                faults.assert_consumed();
            }
        }

        #[test]
        fn authority_witnesses_and_child_fault_plan_are_linear_non_evidence() {
            trait AmbiguousIfClone<A> {
                fn probe() {}
            }
            impl<T: ?Sized> AmbiguousIfClone<()> for T {}
            impl<T: Clone> AmbiguousIfClone<u8> for T {}
            trait AmbiguousIfCopy<A> {
                fn probe() {}
            }
            impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
            impl<T: Copy> AmbiguousIfCopy<u8> for T {}

            <SupervisorOwnedRootV1 as AmbiguousIfClone<_>>::probe();
            <SupervisorOwnedRootV1 as AmbiguousIfCopy<_>>::probe();
            <SupervisorReleasedRootV1 as AmbiguousIfClone<_>>::probe();
            <SupervisorReleasedRootV1 as AmbiguousIfCopy<_>>::probe();
            assert!(!FixedRootFaultPlanV1::default().seccomp_install);
            assert!(
                FixedRootFaultPlanV1 {
                    seccomp_install: true,
                }
                .seccomp_install
            );
        }

        #[test]
        #[ignore = "requires the provisioned supervisor kernel contract and isolated single-thread execution"]
        fn provisioned_live_post_seize_faults_cleanup_the_complete_tree() {
            for operation in [
                ConnectorKernelOperationV1::OwnershipTransfer,
                ConnectorKernelOperationV1::SeccompInstall,
            ] {
                let helper = unsafe { libc::fork() };
                assert!(helper >= 0, "fork failed for {operation:?}");
                if helper == 0 {
                    let mut faults =
                        ScriptedFaultsV1::one(operation, InjectedKernelResultV1::Errno(libc::EIO));
                    let accepted = qualify_fixed_two_task_supervisor_with_faults_v1(&mut faults)
                        .is_err_and(|failure| failure.cleanup_complete());
                    let consumed = faults.cursor == faults.script.len();
                    unsafe { libc::_exit(i32::from(!(accepted && consumed))) };
                }
                let mut status = 0_i32;
                assert_eq!(unsafe { libc::waitpid(helper, &mut status, 0) }, helper);
                assert!(libc::WIFEXITED(status), "helper was not reaped normally");
                assert_eq!(
                    libc::WEXITSTATUS(status),
                    0,
                    "fault did not clean: {operation:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_failure_never_replaces_the_first_failure() {
        let first = FixedTwoTaskSupervisorFailureV1::new(
            RefusalCode::IsolationPreflightFailed,
            FixedTwoTaskSupervisorStageV1::ProcessMemory,
            FixedTwoTaskSupervisorReasonV1::ShortIo,
            Some(libc::EIO),
            true,
        )
        .with_cleanup(false, Some(libc::ETIMEDOUT));

        assert_eq!(first.code(), RefusalCode::IsolationPreflightFailed);
        assert_eq!(first.stage(), "process_memory");
        assert_eq!(first.reason(), "short_io");
        assert_eq!(first.errno(), Some(libc::EIO));
        assert!(!first.cleanup_complete());
        assert_eq!(first.cleanup_errno(), Some(libc::ETIMEDOUT));
        assert!(!first.is_expected_unavailable());
    }

    #[test]
    fn later_cleanup_annotation_never_replaces_the_first_cleanup_errno() {
        let first = FixedTwoTaskSupervisorFailureV1::new(
            RefusalCode::IsolationPreflightFailed,
            FixedTwoTaskSupervisorStageV1::ProcessMemory,
            FixedTwoTaskSupervisorReasonV1::ShortIo,
            Some(libc::EFAULT),
            true,
        )
        .with_cleanup(false, Some(libc::EIO))
        .with_cleanup(false, Some(libc::ETIMEDOUT));

        assert_eq!(first.stage(), "process_memory");
        assert_eq!(first.errno(), Some(libc::EFAULT));
        assert_eq!(first.cleanup_errno(), Some(libc::EIO));
    }

    #[test]
    fn unsupported_seccomp_operation_is_expected_unavailability() {
        for errno in [libc::ENOSYS, libc::EINVAL, libc::EOPNOTSUPP] {
            let failure = FixedTwoTaskSupervisorFailureV1::new(
                RefusalCode::SeccompUnavailable,
                FixedTwoTaskSupervisorStageV1::SeccompActions,
                FixedTwoTaskSupervisorReasonV1::KernelCapabilityUnavailable,
                Some(errno),
                true,
            );
            assert!(failure.is_expected_unavailable());
        }
    }

    #[test]
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    )))]
    fn unsupported_platform_refusal_is_exact_and_non_authoritative() {
        let failure = qualify_fixed_two_task_supervisor_v1()
            .err()
            .expect("unsupported target must refuse");
        let expected_code = if cfg!(target_os = "linux") {
            RefusalCode::UnsupportedArchitecture
        } else {
            RefusalCode::UnsupportedOs
        };
        assert_eq!(failure.code(), expected_code);
        assert_eq!(failure.stage(), "platform");
        assert_eq!(failure.errno(), None);
        assert!(failure.cleanup_complete());
        assert!(failure.is_expected_unavailable());
    }
}
