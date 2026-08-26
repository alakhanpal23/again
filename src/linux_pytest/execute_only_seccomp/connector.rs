//! Stopped-child installer/readback checkpoint for the frozen workload filter.
//!
//! The live entry point creates only a disposable diagnostic child. The child
//! never accepts or executes a command. A witness is returned only after exact
//! kernel readback, terminal reap, final `ECHILD`, and signal-mask restoration.

use core::fmt;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux_pytest) enum WorkloadSeccompConnectorStageV1 {
    SignalBlock,
    SpawnChild,
    WaitInitialStop,
    VerifySingleTask,
    PtracePrepare,
    ReadNoNewPrivileges,
    ReadInitialSeccompMode,
    ResumeForInstall,
    WaitInstalledStop,
    InstallTsyncFilter,
    ReadInstalledSeccompMode,
    PtraceReadbackCount,
    PtraceReadbackInstructions,
    VerifyReadback,
    ResumeWithKill,
    ReapChild,
    ProveFinalEchild,
    SignalRestore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux_pytest) enum WorkloadSeccompConnectorReasonV1 {
    UnsupportedTarget,
    UnsupportedKernelPolicy,
    KernelOperation,
    UnexpectedObservation,
    FilterMismatch,
}

/// Stable failure with the first operational stage kept independently from
/// cleanup completeness. It carries no PID, descriptor, filter bytes, or path.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::linux_pytest) struct WorkloadSeccompConnectorFailureV1 {
    stage: WorkloadSeccompConnectorStageV1,
    reason: WorkloadSeccompConnectorReasonV1,
    cleanup_complete: bool,
}

impl WorkloadSeccompConnectorFailureV1 {
    const fn new(
        stage: WorkloadSeccompConnectorStageV1,
        reason: WorkloadSeccompConnectorReasonV1,
    ) -> Self {
        Self {
            stage,
            reason,
            cleanup_complete: true,
        }
    }

    const fn with_cleanup(mut self, cleanup_complete: bool) -> Self {
        self.cleanup_complete = cleanup_complete;
        self
    }

    pub(in crate::linux_pytest) const fn stage(&self) -> WorkloadSeccompConnectorStageV1 {
        self.stage
    }

    pub(in crate::linux_pytest) const fn reason(&self) -> WorkloadSeccompConnectorReasonV1 {
        self.reason
    }

    pub(in crate::linux_pytest) const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }

    pub(in crate::linux_pytest) const fn execution_authority(&self) -> bool {
        false
    }
}

impl fmt::Debug for WorkloadSeccompConnectorFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadSeccompConnectorFailureV1")
            .field("stage", &self.stage)
            .field("reason", &self.reason)
            .field("cleanup_complete", &self.cleanup_complete)
            .field("kernel_payload", &"<redacted>")
            .field("execution_authority", &false)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectorOperationV1 {
    SignalBlock,
    SpawnChild,
    WaitInitialStop,
    VerifySingleTask,
    PtracePrepare,
    ReadNoNewPrivileges,
    ReadInitialSeccompMode,
    ResumeForInstall,
    WaitInstalledStop,
    InstallTsyncFilter,
    ReadInstalledSeccompMode,
    PtraceReadbackCount,
    PtraceReadbackInstructions,
    ResumeWithKill,
    ReapChild,
    ProveFinalEchild,
    SignalRestore,
    CleanupKill,
    CleanupReap,
    CleanupFinalEchild,
    CleanupSignalRestore,
}

const FORWARD_OPERATIONS_V1: [ConnectorOperationV1; 17] = [
    ConnectorOperationV1::SignalBlock,
    ConnectorOperationV1::SpawnChild,
    ConnectorOperationV1::WaitInitialStop,
    ConnectorOperationV1::VerifySingleTask,
    ConnectorOperationV1::PtracePrepare,
    ConnectorOperationV1::ReadNoNewPrivileges,
    ConnectorOperationV1::ReadInitialSeccompMode,
    ConnectorOperationV1::ResumeForInstall,
    ConnectorOperationV1::WaitInstalledStop,
    ConnectorOperationV1::InstallTsyncFilter,
    ConnectorOperationV1::ReadInstalledSeccompMode,
    ConnectorOperationV1::PtraceReadbackCount,
    ConnectorOperationV1::PtraceReadbackInstructions,
    ConnectorOperationV1::ResumeWithKill,
    ConnectorOperationV1::ReapChild,
    ConnectorOperationV1::ProveFinalEchild,
    ConnectorOperationV1::SignalRestore,
];

const CLEANUP_OPERATIONS_V1: [ConnectorOperationV1; 4] = [
    ConnectorOperationV1::CleanupKill,
    ConnectorOperationV1::CleanupReap,
    ConnectorOperationV1::CleanupFinalEchild,
    ConnectorOperationV1::CleanupSignalRestore,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationErrorV1 {
    Unsupported,
    Failed,
}

trait StoppedChildOperationsV1 {
    fn perform(
        &mut self,
        operation: ConnectorOperationV1,
        readback: Option<&mut [WorkloadSockFilterV1]>,
    ) -> Result<i64, OperationErrorV1>;
}

struct StoppedChildPermitV1 {
    _seal: StoppedChildPermitSealV1,
}

struct StoppedChildPermitSealV1;

fn stage_for_operation_v1(operation: ConnectorOperationV1) -> WorkloadSeccompConnectorStageV1 {
    match operation {
        ConnectorOperationV1::SignalBlock => WorkloadSeccompConnectorStageV1::SignalBlock,
        ConnectorOperationV1::SpawnChild => WorkloadSeccompConnectorStageV1::SpawnChild,
        ConnectorOperationV1::WaitInitialStop => WorkloadSeccompConnectorStageV1::WaitInitialStop,
        ConnectorOperationV1::VerifySingleTask => WorkloadSeccompConnectorStageV1::VerifySingleTask,
        ConnectorOperationV1::PtracePrepare => WorkloadSeccompConnectorStageV1::PtracePrepare,
        ConnectorOperationV1::ReadNoNewPrivileges => {
            WorkloadSeccompConnectorStageV1::ReadNoNewPrivileges
        }
        ConnectorOperationV1::ReadInitialSeccompMode => {
            WorkloadSeccompConnectorStageV1::ReadInitialSeccompMode
        }
        ConnectorOperationV1::ResumeForInstall => WorkloadSeccompConnectorStageV1::ResumeForInstall,
        ConnectorOperationV1::WaitInstalledStop => {
            WorkloadSeccompConnectorStageV1::WaitInstalledStop
        }
        ConnectorOperationV1::InstallTsyncFilter => {
            WorkloadSeccompConnectorStageV1::InstallTsyncFilter
        }
        ConnectorOperationV1::ReadInstalledSeccompMode => {
            WorkloadSeccompConnectorStageV1::ReadInstalledSeccompMode
        }
        ConnectorOperationV1::PtraceReadbackCount => {
            WorkloadSeccompConnectorStageV1::PtraceReadbackCount
        }
        ConnectorOperationV1::PtraceReadbackInstructions => {
            WorkloadSeccompConnectorStageV1::PtraceReadbackInstructions
        }
        ConnectorOperationV1::ResumeWithKill => WorkloadSeccompConnectorStageV1::ResumeWithKill,
        ConnectorOperationV1::ReapChild | ConnectorOperationV1::CleanupReap => {
            WorkloadSeccompConnectorStageV1::ReapChild
        }
        ConnectorOperationV1::ProveFinalEchild | ConnectorOperationV1::CleanupFinalEchild => {
            WorkloadSeccompConnectorStageV1::ProveFinalEchild
        }
        ConnectorOperationV1::SignalRestore | ConnectorOperationV1::CleanupSignalRestore => {
            WorkloadSeccompConnectorStageV1::SignalRestore
        }
        ConnectorOperationV1::CleanupKill => WorkloadSeccompConnectorStageV1::ResumeWithKill,
    }
}

fn operation_failure_v1(
    operation: ConnectorOperationV1,
    error: OperationErrorV1,
) -> WorkloadSeccompConnectorFailureV1 {
    WorkloadSeccompConnectorFailureV1::new(
        stage_for_operation_v1(operation),
        match error {
            OperationErrorV1::Unsupported => {
                WorkloadSeccompConnectorReasonV1::UnsupportedKernelPolicy
            }
            OperationErrorV1::Failed => WorkloadSeccompConnectorReasonV1::KernelOperation,
        },
    )
}

fn cleanup_after_failure_v1(operations: &mut impl StoppedChildOperationsV1) -> bool {
    let mut complete = true;
    for operation in CLEANUP_OPERATIONS_V1 {
        if operations.perform(operation, None).is_err() {
            complete = false;
        }
    }
    complete
}

fn observe_exact_v1(
    operations: &mut impl StoppedChildOperationsV1,
    operation: ConnectorOperationV1,
    expected: i64,
) -> Result<(), WorkloadSeccompConnectorFailureV1> {
    let observed = operations
        .perform(operation, None)
        .map_err(|error| operation_failure_v1(operation, error))?;
    if observed != expected {
        let reason = if matches!(
            operation,
            ConnectorOperationV1::ReadNoNewPrivileges
                | ConnectorOperationV1::ReadInitialSeccompMode
                | ConnectorOperationV1::InstallTsyncFilter
                | ConnectorOperationV1::ReadInstalledSeccompMode
        ) {
            WorkloadSeccompConnectorReasonV1::UnsupportedKernelPolicy
        } else {
            WorkloadSeccompConnectorReasonV1::UnexpectedObservation
        };
        return Err(WorkloadSeccompConnectorFailureV1::new(
            stage_for_operation_v1(operation),
            reason,
        ));
    }
    Ok(())
}

fn drive_stopped_child_v1(
    _permit: StoppedChildPermitV1,
    operations: &mut impl StoppedChildOperationsV1,
) -> Result<InstalledWorkloadSeccompWitnessV1, WorkloadSeccompConnectorFailureV1> {
    let result = (|| {
        observe_exact_v1(operations, ConnectorOperationV1::SignalBlock, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::SpawnChild, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::WaitInitialStop, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::VerifySingleTask, 1)?;
        observe_exact_v1(operations, ConnectorOperationV1::PtracePrepare, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::ReadNoNewPrivileges, 1)?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::ReadInitialSeccompMode,
            i64::from(SECCOMP_MODE_DISABLED_V1),
        )?;
        observe_exact_v1(operations, ConnectorOperationV1::ResumeForInstall, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::WaitInstalledStop, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::InstallTsyncFilter, 0)?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::ReadInstalledSeccompMode,
            i64::from(SECCOMP_MODE_FILTER_V1),
        )?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::PtraceReadbackCount,
            WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 as i64,
        )?;

        let mut readback = [ZERO_FILTER_V1; WORKLOAD_FILTER_INSTRUCTION_COUNT_V1];
        let read = operations
            .perform(
                ConnectorOperationV1::PtraceReadbackInstructions,
                Some(&mut readback),
            )
            .map_err(|error| {
                operation_failure_v1(ConnectorOperationV1::PtraceReadbackInstructions, error)
            })?;
        if read != WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 as i64 {
            return Err(WorkloadSeccompConnectorFailureV1::new(
                WorkloadSeccompConnectorStageV1::PtraceReadbackInstructions,
                WorkloadSeccompConnectorReasonV1::UnexpectedObservation,
            ));
        }
        verify_filter_v1(&readback).map_err(|_| {
            WorkloadSeccompConnectorFailureV1::new(
                WorkloadSeccompConnectorStageV1::VerifyReadback,
                WorkloadSeccompConnectorReasonV1::FilterMismatch,
            )
        })?;
        if workload_policy_digest_for_bytes_v1(&canonical_filter_bytes_v1(&readback))
            != workload_policy_digest_blake3_v1()
            || !trace_cookies_are_nonzero_and_unique_v1(&RESERVED_SECCOMP_TRACE_COOKIES_V1)
        {
            return Err(WorkloadSeccompConnectorFailureV1::new(
                WorkloadSeccompConnectorStageV1::VerifyReadback,
                WorkloadSeccompConnectorReasonV1::FilterMismatch,
            ));
        }

        observe_exact_v1(operations, ConnectorOperationV1::ResumeWithKill, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::ReapChild, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::ProveFinalEchild, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::SignalRestore, 0)?;

        let evidence = InstalledFilterEvidenceV1 {
            completed_operations: &WORKLOAD_SECCOMP_OPERATIONS_V1,
            task_count: 1,
            no_new_privileges: 1,
            initial_seccomp_mode: SECCOMP_MODE_DISABLED_V1,
            install_result: 0,
            installed_seccomp_mode: SECCOMP_MODE_FILTER_V1,
            readback_count: readback.len(),
            claimed_policy_digest: workload_policy_digest_blake3_v1(),
            readback: &readback,
        };
        verify_installed_transcript_v1(evidence).map_err(|_| {
            WorkloadSeccompConnectorFailureV1::new(
                WorkloadSeccompConnectorStageV1::VerifyReadback,
                WorkloadSeccompConnectorReasonV1::FilterMismatch,
            )
        })?;
        Ok(InstalledWorkloadSeccompWitnessV1 {
            _seal: InstalledWitnessSealV1,
            policy_digest: workload_policy_digest_blake3_v1(),
        })
    })();

    match result {
        Ok(witness) => Ok(witness),
        Err(first) => {
            let cleanup_complete = cleanup_after_failure_v1(operations);
            Err(first.with_cleanup(cleanup_complete))
        }
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
)))]
pub(in crate::linux_pytest) fn qualify_stopped_workload_filter_live_v1()
-> Result<InstalledWorkloadSeccompWitnessV1, WorkloadSeccompConnectorFailureV1> {
    Err(WorkloadSeccompConnectorFailureV1::new(
        WorkloadSeccompConnectorStageV1::SpawnChild,
        WorkloadSeccompConnectorReasonV1::UnsupportedTarget,
    ))
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
mod platform {
    use core::sync::atomic::{AtomicI32, Ordering};
    use std::fs;
    use std::io;
    use std::mem::MaybeUninit;
    use std::ptr;
    use std::time::{Duration, Instant};

    use super::*;

    const WAIT_BOUND_V1: Duration = Duration::from_secs(2);
    const WAIT_BACKOFF_V1: Duration = Duration::from_millis(1);
    const PTRACE_TRACEME_V1: libc::c_uint = 0;
    const PTRACE_CONT_V1: libc::c_uint = 7;
    const PTRACE_SETOPTIONS_V1: libc::c_uint = 0x4200;
    const PTRACE_O_EXITKILL_V1: usize = 0x0010_0000;

    #[repr(C)]
    struct SharedTranscriptV1 {
        no_new_privileges: AtomicI32,
        initial_seccomp_mode: AtomicI32,
        install_result: AtomicI32,
        installed_seccomp_mode: AtomicI32,
    }

    impl SharedTranscriptV1 {
        fn initialize(pointer: *mut Self) {
            unsafe {
                pointer.write(Self {
                    no_new_privileges: AtomicI32::new(-1),
                    initial_seccomp_mode: AtomicI32::new(-1),
                    install_result: AtomicI32::new(i32::MIN),
                    installed_seccomp_mode: AtomicI32::new(-1),
                });
            }
        }
    }

    #[repr(C)]
    struct LinuxSockFprogV1 {
        len: libc::c_ushort,
        filter: *const WorkloadSockFilterV1,
    }

    struct LiveStoppedChildOperationsV1 {
        child: Option<libc::pid_t>,
        shared: *mut SharedTranscriptV1,
        old_mask: MaybeUninit<libc::sigset_t>,
        signal_blocked: bool,
        reaped: bool,
    }

    impl LiveStoppedChildOperationsV1 {
        fn new() -> Self {
            Self {
                child: None,
                shared: ptr::null_mut(),
                old_mask: MaybeUninit::uninit(),
                signal_blocked: false,
                reaped: false,
            }
        }

        fn child(&self) -> Result<libc::pid_t, OperationErrorV1> {
            self.child.ok_or(OperationErrorV1::Failed)
        }

        fn shared(&self) -> Result<&SharedTranscriptV1, OperationErrorV1> {
            unsafe { self.shared.as_ref() }.ok_or(OperationErrorV1::Failed)
        }

        fn block_signal(&mut self) -> Result<i64, OperationErrorV1> {
            let mut set = MaybeUninit::<libc::sigset_t>::uninit();
            if unsafe { libc::sigemptyset(set.as_mut_ptr()) } != 0
                || unsafe { libc::sigaddset(set.as_mut_ptr(), libc::SIGCHLD) } != 0
            {
                return Err(OperationErrorV1::Failed);
            }
            let result = unsafe {
                libc::pthread_sigmask(libc::SIG_BLOCK, set.as_ptr(), self.old_mask.as_mut_ptr())
            };
            if result != 0 {
                return Err(OperationErrorV1::Failed);
            }
            self.signal_blocked = true;
            Ok(0)
        }

        fn spawn(&mut self) -> Result<i64, OperationErrorV1> {
            let mapping = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    core::mem::size_of::<SharedTranscriptV1>(),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if mapping == libc::MAP_FAILED {
                return Err(OperationErrorV1::Unsupported);
            }
            self.shared = mapping.cast();
            SharedTranscriptV1::initialize(self.shared);
            let child = unsafe { libc::fork() };
            if child < 0 {
                return Err(OperationErrorV1::Unsupported);
            }
            if child == 0 {
                unsafe { child_entry_v1(self.shared) };
            }
            self.child = Some(child);
            Ok(0)
        }

        fn wait_for_stop(&self, expected_signal: i32) -> Result<i64, OperationErrorV1> {
            let child = self.child()?;
            let deadline = Instant::now() + WAIT_BOUND_V1;
            loop {
                let mut status = 0;
                let waited =
                    unsafe { libc::waitpid(child, &mut status, libc::WNOHANG | libc::WUNTRACED) };
                if waited == child {
                    if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == expected_signal {
                        return Ok(0);
                    }
                    return Err(OperationErrorV1::Failed);
                }
                if waited < 0 {
                    return Err(classify_errno_v1(last_errno_v1()));
                }
                if Instant::now() >= deadline {
                    return Err(OperationErrorV1::Failed);
                }
                std::thread::sleep(WAIT_BACKOFF_V1);
            }
        }

        fn ptrace(
            &self,
            request: libc::c_uint,
            address: usize,
            data: usize,
        ) -> Result<i64, OperationErrorV1> {
            let result = unsafe {
                libc::ptrace(
                    request,
                    self.child()?,
                    address as *mut libc::c_void,
                    data as *mut libc::c_void,
                )
            };
            if result < 0 {
                Err(classify_errno_v1(last_errno_v1()))
            } else {
                Ok(result)
            }
        }

        fn verify_single_task(&self) -> Result<i64, OperationErrorV1> {
            let path = format!("/proc/{}/task", self.child()?);
            let mut entries = fs::read_dir(path).map_err(classify_io_v1)?;
            let first = entries.next().transpose().map_err(classify_io_v1)?;
            let second = entries.next().transpose().map_err(classify_io_v1)?;
            if first.is_some() && second.is_none() {
                Ok(1)
            } else {
                Err(OperationErrorV1::Failed)
            }
        }

        fn reap(&mut self) -> Result<i64, OperationErrorV1> {
            if self.reaped || self.child.is_none() {
                return Ok(0);
            }
            let child = self.child()?;
            let deadline = Instant::now() + WAIT_BOUND_V1;
            loop {
                let mut status = 0;
                let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
                if waited == child {
                    self.reaped = true;
                    return if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL {
                        Ok(0)
                    } else {
                        Err(OperationErrorV1::Failed)
                    };
                }
                if waited < 0 {
                    let error = last_errno_v1();
                    if error == libc::ECHILD {
                        self.reaped = true;
                        return Ok(0);
                    }
                    return Err(classify_errno_v1(error));
                }
                if Instant::now() >= deadline {
                    return Err(OperationErrorV1::Failed);
                }
                std::thread::sleep(WAIT_BACKOFF_V1);
            }
        }

        fn prove_echild(&self) -> Result<i64, OperationErrorV1> {
            let Some(child) = self.child else {
                return Ok(0);
            };
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if waited < 0 && last_errno_v1() == libc::ECHILD {
                Ok(0)
            } else {
                Err(OperationErrorV1::Failed)
            }
        }

        fn kill(&self) -> Result<i64, OperationErrorV1> {
            if self.reaped || self.child.is_none() {
                return Ok(0);
            }
            let result = unsafe { libc::kill(self.child()?, libc::SIGKILL) };
            if result == 0 || (result < 0 && last_errno_v1() == libc::ESRCH) {
                Ok(0)
            } else {
                Err(OperationErrorV1::Failed)
            }
        }

        fn restore_signal(&mut self) -> Result<i64, OperationErrorV1> {
            if !self.signal_blocked {
                return Ok(0);
            }
            let result = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, self.old_mask.as_ptr(), ptr::null_mut())
            };
            if result != 0 {
                return Err(OperationErrorV1::Failed);
            }
            self.signal_blocked = false;
            Ok(0)
        }
    }

    impl StoppedChildOperationsV1 for LiveStoppedChildOperationsV1 {
        fn perform(
            &mut self,
            operation: ConnectorOperationV1,
            readback: Option<&mut [WorkloadSockFilterV1]>,
        ) -> Result<i64, OperationErrorV1> {
            match operation {
                ConnectorOperationV1::SignalBlock => self.block_signal(),
                ConnectorOperationV1::SpawnChild => self.spawn(),
                ConnectorOperationV1::WaitInitialStop => self.wait_for_stop(libc::SIGSTOP),
                ConnectorOperationV1::VerifySingleTask => self.verify_single_task(),
                ConnectorOperationV1::PtracePrepare => {
                    self.ptrace(PTRACE_SETOPTIONS_V1, 0, PTRACE_O_EXITKILL_V1)
                }
                ConnectorOperationV1::ReadNoNewPrivileges => Ok(i64::from(
                    self.shared()?.no_new_privileges.load(Ordering::Acquire),
                )),
                ConnectorOperationV1::ReadInitialSeccompMode => Ok(i64::from(
                    self.shared()?.initial_seccomp_mode.load(Ordering::Acquire),
                )),
                ConnectorOperationV1::ResumeForInstall => self.ptrace(PTRACE_CONT_V1, 0, 0),
                ConnectorOperationV1::WaitInstalledStop => self.wait_for_stop(libc::SIGTRAP),
                ConnectorOperationV1::InstallTsyncFilter => {
                    let result = self.shared()?.install_result.load(Ordering::Acquire);
                    if result == 0 {
                        Ok(0)
                    } else if result < 0 {
                        Err(classify_errno_v1(result.saturating_neg()))
                    } else {
                        Err(OperationErrorV1::Failed)
                    }
                }
                ConnectorOperationV1::ReadInstalledSeccompMode => Ok(i64::from(
                    self.shared()?
                        .installed_seccomp_mode
                        .load(Ordering::Acquire),
                )),
                ConnectorOperationV1::PtraceReadbackCount => {
                    self.ptrace(PTRACE_SECCOMP_GET_FILTER_V1, 0, 0)
                }
                ConnectorOperationV1::PtraceReadbackInstructions => {
                    let output = readback.ok_or(OperationErrorV1::Failed)?;
                    self.ptrace(
                        PTRACE_SECCOMP_GET_FILTER_V1,
                        0,
                        output.as_mut_ptr() as usize,
                    )
                }
                ConnectorOperationV1::ResumeWithKill => {
                    self.ptrace(PTRACE_CONT_V1, 0, libc::SIGKILL as usize)
                }
                ConnectorOperationV1::ReapChild | ConnectorOperationV1::CleanupReap => self.reap(),
                ConnectorOperationV1::ProveFinalEchild
                | ConnectorOperationV1::CleanupFinalEchild => self.prove_echild(),
                ConnectorOperationV1::SignalRestore
                | ConnectorOperationV1::CleanupSignalRestore => self.restore_signal(),
                ConnectorOperationV1::CleanupKill => self.kill(),
            }
        }
    }

    impl Drop for LiveStoppedChildOperationsV1 {
        fn drop(&mut self) {
            let _ = self.kill();
            let _ = self.reap();
            let _ = self.restore_signal();
            if !self.shared.is_null() {
                unsafe {
                    libc::munmap(
                        self.shared.cast(),
                        core::mem::size_of::<SharedTranscriptV1>(),
                    );
                }
                self.shared = ptr::null_mut();
            }
        }
    }

    fn classify_io_v1(error: io::Error) -> OperationErrorV1 {
        error
            .raw_os_error()
            .map_or(OperationErrorV1::Failed, classify_errno_v1)
    }

    fn classify_errno_v1(error: i32) -> OperationErrorV1 {
        if matches!(
            error,
            libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM | libc::EACCES | libc::EINVAL
        ) {
            OperationErrorV1::Unsupported
        } else {
            OperationErrorV1::Failed
        }
    }

    fn last_errno_v1() -> i32 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }

    unsafe fn child_entry_v1(shared: *mut SharedTranscriptV1) -> ! {
        let ptrace_result = unsafe {
            libc::ptrace(
                PTRACE_TRACEME_V1,
                0,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            )
        };
        if ptrace_result != 0 {
            unsafe { libc::_exit(125) };
        }
        let initial_mode = unsafe { libc::prctl(PR_GET_SECCOMP_V1 as i32) };
        unsafe {
            (*shared)
                .initial_seccomp_mode
                .store(initial_mode, Ordering::Release);
        }
        let set_nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        let nnp = if set_nnp == 0 {
            unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS_V1 as i32) }
        } else {
            -1
        };
        unsafe {
            (*shared).no_new_privileges.store(nnp, Ordering::Release);
        }
        let pid = unsafe { libc::syscall(libc::SYS_getpid) };
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        if unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGSTOP) } != 0 {
            unsafe { libc::_exit(125) };
        }

        let program = LinuxSockFprogV1 {
            len: WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 as libc::c_ushort,
            filter: WORKLOAD_FILTER_V1.as_ptr(),
        };
        let install = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER_V1,
                SECCOMP_FILTER_FLAG_TSYNC_V1,
                &program,
            )
        };
        let install_result = if install == 0 {
            0
        } else {
            -unsafe { *libc::__errno_location() }
        };
        unsafe {
            (*shared)
                .install_result
                .store(install_result, Ordering::Release);
            (*shared).installed_seccomp_mode.store(
                if install == 0 {
                    i32::from(SECCOMP_MODE_FILTER_V1)
                } else {
                    -1
                },
                Ordering::Release,
            );
        }
        unsafe { core::arch::asm!("int3", options(noreturn)) };
    }

    pub(in crate::linux_pytest) fn qualify_stopped_workload_filter_live_v1()
    -> Result<InstalledWorkloadSeccompWitnessV1, WorkloadSeccompConnectorFailureV1> {
        let mut operations = LiveStoppedChildOperationsV1::new();
        drive_stopped_child_v1(
            StoppedChildPermitV1 {
                _seal: StoppedChildPermitSealV1,
            },
            &mut operations,
        )
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(in crate::linux_pytest) use platform::qualify_stopped_workload_filter_live_v1;

#[cfg(test)]
mod tests {
    use super::*;

    struct InjectedOperationsV1 {
        forward_failure: Option<ConnectorOperationV1>,
        cleanup_failure: Option<ConnectorOperationV1>,
        operations: Vec<ConnectorOperationV1>,
        mutate_readback: bool,
        unsupported_failure: bool,
    }

    impl InjectedOperationsV1 {
        fn clean() -> Self {
            Self {
                forward_failure: None,
                cleanup_failure: None,
                operations: Vec::new(),
                mutate_readback: false,
                unsupported_failure: false,
            }
        }

        fn expected_value(operation: ConnectorOperationV1) -> i64 {
            match operation {
                ConnectorOperationV1::VerifySingleTask
                | ConnectorOperationV1::ReadNoNewPrivileges => 1,
                ConnectorOperationV1::ReadInstalledSeccompMode => i64::from(SECCOMP_MODE_FILTER_V1),
                ConnectorOperationV1::PtraceReadbackCount
                | ConnectorOperationV1::PtraceReadbackInstructions => {
                    WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 as i64
                }
                _ => 0,
            }
        }
    }

    impl StoppedChildOperationsV1 for InjectedOperationsV1 {
        fn perform(
            &mut self,
            operation: ConnectorOperationV1,
            readback: Option<&mut [WorkloadSockFilterV1]>,
        ) -> Result<i64, OperationErrorV1> {
            self.operations.push(operation);
            if self.forward_failure == Some(operation) || self.cleanup_failure == Some(operation) {
                return Err(if self.unsupported_failure {
                    OperationErrorV1::Unsupported
                } else {
                    OperationErrorV1::Failed
                });
            }
            if operation == ConnectorOperationV1::PtraceReadbackInstructions {
                let output = readback.ok_or(OperationErrorV1::Failed)?;
                output.copy_from_slice(&WORKLOAD_FILTER_V1);
                if self.mutate_readback {
                    output[0].operand ^= 1;
                }
            }
            Ok(Self::expected_value(operation))
        }
    }

    fn permit_v1() -> StoppedChildPermitV1 {
        StoppedChildPermitV1 {
            _seal: StoppedChildPermitSealV1,
        }
    }

    #[test]
    fn injected_success_issues_only_a_redacted_non_authoritative_witness() {
        let mut operations = InjectedOperationsV1::clean();
        let witness = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap();
        assert_eq!(
            witness.policy_digest_blake3(),
            &workload_policy_digest_blake3_v1()
        );
        assert!(!witness.execution_authority());
        assert!(format!("{witness:?}").contains("<redacted-kernel-readback>"));
        assert!(
            !operations
                .operations
                .iter()
                .any(|operation| CLEANUP_OPERATIONS_V1.contains(operation))
        );
    }

    #[test]
    fn every_forward_operation_failure_preserves_first_stage_and_runs_full_cleanup() {
        for operation in FORWARD_OPERATIONS_V1
            .into_iter()
            .filter(|operation| !CLEANUP_OPERATIONS_V1.contains(operation))
        {
            let mut operations = InjectedOperationsV1 {
                forward_failure: Some(operation),
                ..InjectedOperationsV1::clean()
            };
            let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
            assert_eq!(failure.stage(), stage_for_operation_v1(operation));
            assert_eq!(
                failure.reason(),
                WorkloadSeccompConnectorReasonV1::KernelOperation
            );
            assert!(failure.cleanup_complete());
            assert_eq!(
                &operations.operations[operations.operations.len() - CLEANUP_OPERATIONS_V1.len()..],
                &CLEANUP_OPERATIONS_V1
            );
        }
    }

    #[test]
    fn every_cleanup_failure_keeps_the_first_operational_error_and_marks_uncertainty() {
        for cleanup_operation in CLEANUP_OPERATIONS_V1 {
            let mut operations = InjectedOperationsV1 {
                forward_failure: Some(ConnectorOperationV1::WaitInitialStop),
                cleanup_failure: Some(cleanup_operation),
                ..InjectedOperationsV1::clean()
            };
            let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
            assert_eq!(
                failure.stage(),
                WorkloadSeccompConnectorStageV1::WaitInitialStop
            );
            assert_eq!(
                failure.reason(),
                WorkloadSeccompConnectorReasonV1::KernelOperation
            );
            assert!(!failure.cleanup_complete());
            assert_eq!(
                &operations.operations[operations.operations.len() - CLEANUP_OPERATIONS_V1.len()..],
                &CLEANUP_OPERATIONS_V1
            );
        }
    }

    #[test]
    fn injected_kernel_policy_refusal_is_typed_and_still_cleans() {
        let mut operations = InjectedOperationsV1 {
            forward_failure: Some(ConnectorOperationV1::InstallTsyncFilter),
            unsupported_failure: true,
            ..InjectedOperationsV1::clean()
        };
        let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
        assert_eq!(
            failure.stage(),
            WorkloadSeccompConnectorStageV1::InstallTsyncFilter
        );
        assert_eq!(
            failure.reason(),
            WorkloadSeccompConnectorReasonV1::UnsupportedKernelPolicy
        );
        assert!(failure.cleanup_complete());
        assert!(!failure.execution_authority());
    }

    #[test]
    fn readback_mutation_refuses_and_cleans_without_issuing_a_witness() {
        let mut operations = InjectedOperationsV1 {
            mutate_readback: true,
            ..InjectedOperationsV1::clean()
        };
        let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
        assert_eq!(
            failure.stage(),
            WorkloadSeccompConnectorStageV1::VerifyReadback
        );
        assert_eq!(
            failure.reason(),
            WorkloadSeccompConnectorReasonV1::FilterMismatch
        );
        assert!(failure.cleanup_complete());
    }

    #[test]
    fn unsupported_target_or_live_policy_is_a_typed_non_pass() {
        match qualify_stopped_workload_filter_live_v1() {
            Ok(witness) => {
                assert!(!witness.execution_authority());
            }
            Err(failure) => {
                assert!(matches!(
                    failure.reason(),
                    WorkloadSeccompConnectorReasonV1::UnsupportedTarget
                        | WorkloadSeccompConnectorReasonV1::UnsupportedKernelPolicy
                        | WorkloadSeccompConnectorReasonV1::KernelOperation
                ));
                assert!(failure.cleanup_complete(), "{failure:?}");
                assert!(!failure.execution_authority());
            }
        }
    }

    #[test]
    fn connector_permit_and_witness_are_linear_and_non_clone() {
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

        <StoppedChildPermitV1 as AmbiguousIfClone<_>>::probe();
        <StoppedChildPermitV1 as AmbiguousIfCopy<_>>::probe();
        <InstalledWorkloadSeccompWitnessV1 as AmbiguousIfClone<_>>::probe();
        <InstalledWorkloadSeccompWitnessV1 as AmbiguousIfCopy<_>>::probe();
    }
}
