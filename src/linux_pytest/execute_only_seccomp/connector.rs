//! Stopped-child installer/readback checkpoint for the frozen workload filter.
//!
//! The live entry point creates only a disposable diagnostic child. The child
//! never accepts or executes a command. A completed, non-authoritative probe is
//! returned only after exact kernel readback, this process's terminal reap,
//! final `ECHILD`, and signal-mask restoration. It is not a live-child witness.
//!
//! The connector admits only an exactly single-task host. It checks that fact
//! before blocking every blockable signal, then rechecks exact `SIGCHLD` default
//! disposition after the block and immediately before any mapping or fork. With
//! no second task and no runnable signal handler, no in-process actor can race
//! the diagnostic child's reaping policy. Hosts that need to run this from a
//! multithreaded process must delegate to an owned single-threaded helper.
//! On refusal, the old signal mask is restored only after the saved PID is no
//! longer signalable and terminal ownership is proved or explicitly lost; a
//! pending-signal drift leaves the conservative blocked mask in place. This
//! protects the child identity, but does not claim to suppress safe ambient
//! handlers after a fully authenticated restoration.

use core::fmt;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux_pytest) enum WorkloadSeccompConnectorStageV1 {
    VerifyHostSingleTask,
    VerifySignalDisposition,
    ReadPendingSignals,
    SignalBlock,
    VerifySignalMask,
    AllocateSharedMapping,
    SpawnChild,
    WaitInitialStop,
    VerifyInitialSingleTask,
    PtracePrepare,
    ReadNoNewPrivileges,
    ReadInitialSeccompMode,
    ResumeForInstall,
    WaitInstalledStop,
    VerifyInstalledSingleTask,
    InstallTsyncFilter,
    PtraceReadbackCount,
    PtraceReadbackInstructions,
    VerifyReadback,
    ResumeWithKill,
    ReapChild,
    ProveFinalEchild,
    VerifyPendingSignals,
    SignalRestore,
    VerifyRestoredSignalMask,
    VerifyFinalSignalDisposition,
    ReleaseSharedMapping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux_pytest) enum WorkloadSeccompConnectorReasonV1 {
    UnsupportedTarget,
    UnsupportedKernelPolicy,
    KernelOperation,
    UnexpectedObservation,
    FilterMismatch,
    ReapingOwnershipLost,
    SignalStateChanged,
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

/// Opaque result of a fully closed disposable-child diagnostic.
///
/// The child and cleanup owner no longer exist when this value is returned, so
/// it cannot satisfy any API that requires a live installed-filter witness.
#[must_use = "a completed disposable workload-filter probe is diagnostic evidence only"]
pub(in crate::linux_pytest) struct CompletedDisposableWorkloadFilterProbeV1 {
    policy_digest: [u8; 32],
    instruction_count: u16,
}

impl CompletedDisposableWorkloadFilterProbeV1 {
    pub(in crate::linux_pytest) const fn policy_digest_blake3(&self) -> &[u8; 32] {
        &self.policy_digest
    }

    pub(in crate::linux_pytest) const fn instruction_count(&self) -> u16 {
        self.instruction_count
    }

    pub(in crate::linux_pytest) const fn live_child_authority(&self) -> bool {
        false
    }

    pub(in crate::linux_pytest) const fn execution_authority(&self) -> bool {
        false
    }

    pub(in crate::linux_pytest) const fn candidate_or_reuse_authority(&self) -> bool {
        false
    }
}

impl fmt::Debug for CompletedDisposableWorkloadFilterProbeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedDisposableWorkloadFilterProbeV1")
            .field("evidence", &"<redacted-completed-kernel-readback>")
            .field("instruction_count", &self.instruction_count)
            .field("live_child_authority", &false)
            .field("execution_authority", &false)
            .field("candidate_or_reuse_authority", &false)
            .finish()
    }
}

impl Drop for CompletedDisposableWorkloadFilterProbeV1 {
    fn drop(&mut self) {
        self.policy_digest.fill(0);
        self.instruction_count = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectorOperationV1 {
    VerifyHostSingleTask,
    VerifyInitialSignalDisposition,
    ReadInitialPendingSignals,
    SignalBlock,
    VerifyBlockedSignalMask,
    VerifyBlockedPendingSignals,
    VerifyPreForkHostSingleTask,
    VerifyPreForkSignalDisposition,
    AllocateSharedMapping,
    SpawnChild,
    WaitInitialStop,
    VerifyInitialSingleTask,
    PtracePrepare,
    ReadNoNewPrivileges,
    ReadInitialSeccompMode,
    ResumeForInstall,
    WaitInstalledStop,
    VerifyInstalledSingleTask,
    InstallTsyncFilter,
    PtraceReadbackCount,
    PtraceReadbackInstructions,
    ResumeWithKill,
    ReapChild,
    ProveFinalEchild,
    VerifyPendingSignals,
    SignalRestore,
    VerifyRestoredSignalMask,
    VerifyFinalSignalDisposition,
    ReleaseSharedMapping,
    CleanupKill,
    CleanupReap,
    CleanupFinalEchild,
    CleanupVerifyPendingSignals,
    CleanupSignalRestore,
    CleanupVerifyRestoredSignalMask,
    CleanupVerifyFinalSignalDisposition,
    CleanupSharedMapping,
}

const FORWARD_OPERATIONS_V1: [ConnectorOperationV1; 29] = [
    ConnectorOperationV1::VerifyInitialSignalDisposition,
    ConnectorOperationV1::VerifyHostSingleTask,
    ConnectorOperationV1::ReadInitialPendingSignals,
    ConnectorOperationV1::SignalBlock,
    ConnectorOperationV1::VerifyBlockedSignalMask,
    ConnectorOperationV1::VerifyBlockedPendingSignals,
    ConnectorOperationV1::VerifyPreForkHostSingleTask,
    ConnectorOperationV1::VerifyPreForkSignalDisposition,
    ConnectorOperationV1::AllocateSharedMapping,
    ConnectorOperationV1::SpawnChild,
    ConnectorOperationV1::WaitInitialStop,
    ConnectorOperationV1::VerifyInitialSingleTask,
    ConnectorOperationV1::PtracePrepare,
    ConnectorOperationV1::ReadNoNewPrivileges,
    ConnectorOperationV1::ReadInitialSeccompMode,
    ConnectorOperationV1::ResumeForInstall,
    ConnectorOperationV1::WaitInstalledStop,
    ConnectorOperationV1::VerifyInstalledSingleTask,
    ConnectorOperationV1::InstallTsyncFilter,
    ConnectorOperationV1::PtraceReadbackCount,
    ConnectorOperationV1::PtraceReadbackInstructions,
    ConnectorOperationV1::ResumeWithKill,
    ConnectorOperationV1::ReapChild,
    ConnectorOperationV1::ProveFinalEchild,
    ConnectorOperationV1::VerifyPendingSignals,
    ConnectorOperationV1::SignalRestore,
    ConnectorOperationV1::VerifyRestoredSignalMask,
    ConnectorOperationV1::VerifyFinalSignalDisposition,
    ConnectorOperationV1::ReleaseSharedMapping,
];

const CLEANUP_OPERATIONS_V1: [ConnectorOperationV1; 8] = [
    ConnectorOperationV1::CleanupKill,
    ConnectorOperationV1::CleanupReap,
    ConnectorOperationV1::CleanupFinalEchild,
    ConnectorOperationV1::CleanupVerifyPendingSignals,
    ConnectorOperationV1::CleanupSignalRestore,
    ConnectorOperationV1::CleanupVerifyRestoredSignalMask,
    ConnectorOperationV1::CleanupVerifyFinalSignalDisposition,
    ConnectorOperationV1::CleanupSharedMapping,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationErrorV1 {
    Unsupported,
    Failed,
    ReapingOwnershipLost,
    SignalStateChanged,
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
        ConnectorOperationV1::VerifyHostSingleTask
        | ConnectorOperationV1::VerifyPreForkHostSingleTask => {
            WorkloadSeccompConnectorStageV1::VerifyHostSingleTask
        }
        ConnectorOperationV1::VerifyInitialSignalDisposition
        | ConnectorOperationV1::VerifyPreForkSignalDisposition
        | ConnectorOperationV1::VerifyFinalSignalDisposition
        | ConnectorOperationV1::CleanupVerifyFinalSignalDisposition => {
            WorkloadSeccompConnectorStageV1::VerifySignalDisposition
        }
        ConnectorOperationV1::ReadInitialPendingSignals
        | ConnectorOperationV1::VerifyBlockedPendingSignals => {
            WorkloadSeccompConnectorStageV1::ReadPendingSignals
        }
        ConnectorOperationV1::SignalBlock => WorkloadSeccompConnectorStageV1::SignalBlock,
        ConnectorOperationV1::VerifyBlockedSignalMask => {
            WorkloadSeccompConnectorStageV1::VerifySignalMask
        }
        ConnectorOperationV1::AllocateSharedMapping => {
            WorkloadSeccompConnectorStageV1::AllocateSharedMapping
        }
        ConnectorOperationV1::SpawnChild => WorkloadSeccompConnectorStageV1::SpawnChild,
        ConnectorOperationV1::WaitInitialStop => WorkloadSeccompConnectorStageV1::WaitInitialStop,
        ConnectorOperationV1::VerifyInitialSingleTask => {
            WorkloadSeccompConnectorStageV1::VerifyInitialSingleTask
        }
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
        ConnectorOperationV1::VerifyInstalledSingleTask => {
            WorkloadSeccompConnectorStageV1::VerifyInstalledSingleTask
        }
        ConnectorOperationV1::InstallTsyncFilter => {
            WorkloadSeccompConnectorStageV1::InstallTsyncFilter
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
        ConnectorOperationV1::VerifyPendingSignals
        | ConnectorOperationV1::CleanupVerifyPendingSignals => {
            WorkloadSeccompConnectorStageV1::VerifyPendingSignals
        }
        ConnectorOperationV1::SignalRestore | ConnectorOperationV1::CleanupSignalRestore => {
            WorkloadSeccompConnectorStageV1::SignalRestore
        }
        ConnectorOperationV1::VerifyRestoredSignalMask
        | ConnectorOperationV1::CleanupVerifyRestoredSignalMask => {
            WorkloadSeccompConnectorStageV1::VerifyRestoredSignalMask
        }
        ConnectorOperationV1::ReleaseSharedMapping | ConnectorOperationV1::CleanupSharedMapping => {
            WorkloadSeccompConnectorStageV1::ReleaseSharedMapping
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
            OperationErrorV1::Unsupported
                if matches!(
                    operation,
                    ConnectorOperationV1::InstallTsyncFilter
                        | ConnectorOperationV1::PtraceReadbackCount
                        | ConnectorOperationV1::PtraceReadbackInstructions
                ) =>
            {
                WorkloadSeccompConnectorReasonV1::UnsupportedKernelPolicy
            }
            OperationErrorV1::Unsupported | OperationErrorV1::Failed => {
                WorkloadSeccompConnectorReasonV1::KernelOperation
            }
            OperationErrorV1::ReapingOwnershipLost => {
                WorkloadSeccompConnectorReasonV1::ReapingOwnershipLost
            }
            OperationErrorV1::SignalStateChanged => {
                WorkloadSeccompConnectorReasonV1::SignalStateChanged
            }
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
) -> Result<CompletedDisposableWorkloadFilterProbeV1, WorkloadSeccompConnectorFailureV1> {
    let result = (|| {
        observe_exact_v1(
            operations,
            ConnectorOperationV1::VerifyInitialSignalDisposition,
            0,
        )?;
        observe_exact_v1(operations, ConnectorOperationV1::VerifyHostSingleTask, 1)?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::ReadInitialPendingSignals,
            0,
        )?;
        observe_exact_v1(operations, ConnectorOperationV1::SignalBlock, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::VerifyBlockedSignalMask, 0)?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::VerifyBlockedPendingSignals,
            0,
        )?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::VerifyPreForkHostSingleTask,
            1,
        )?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::VerifyPreForkSignalDisposition,
            0,
        )?;
        observe_exact_v1(operations, ConnectorOperationV1::AllocateSharedMapping, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::SpawnChild, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::WaitInitialStop, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::VerifyInitialSingleTask, 1)?;
        observe_exact_v1(operations, ConnectorOperationV1::PtracePrepare, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::ReadNoNewPrivileges, 1)?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::ReadInitialSeccompMode,
            i64::from(SECCOMP_MODE_DISABLED_V1),
        )?;
        observe_exact_v1(operations, ConnectorOperationV1::ResumeForInstall, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::WaitInstalledStop, 0)?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::VerifyInstalledSingleTask,
            1,
        )?;
        observe_exact_v1(operations, ConnectorOperationV1::InstallTsyncFilter, 0)?;
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
        observe_exact_v1(operations, ConnectorOperationV1::VerifyPendingSignals, 0)?;
        observe_exact_v1(operations, ConnectorOperationV1::SignalRestore, 0)?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::VerifyRestoredSignalMask,
            0,
        )?;
        observe_exact_v1(
            operations,
            ConnectorOperationV1::VerifyFinalSignalDisposition,
            0,
        )?;
        observe_exact_v1(operations, ConnectorOperationV1::ReleaseSharedMapping, 0)?;

        let evidence = InstalledFilterEvidenceV1 {
            completed_operations: &WORKLOAD_SECCOMP_OPERATIONS_V1,
            task_count: 1,
            no_new_privileges: 1,
            initial_seccomp_mode: SECCOMP_MODE_DISABLED_V1,
            install_result: 0,
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
        Ok(CompletedDisposableWorkloadFilterProbeV1 {
            policy_digest: workload_policy_digest_blake3_v1(),
            instruction_count: WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 as u16,
        })
    })();

    match result {
        Ok(witness) => Ok(witness),
        Err(first) => {
            let cleanup_complete = cleanup_after_failure_v1(operations)
                && !matches!(
                    first.reason,
                    WorkloadSeccompConnectorReasonV1::SignalStateChanged
                        | WorkloadSeccompConnectorReasonV1::ReapingOwnershipLost
                );
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
-> Result<CompletedDisposableWorkloadFilterProbeV1, WorkloadSeccompConnectorFailureV1> {
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
    use std::ptr;
    use std::time::{Duration, Instant};

    use super::*;

    const WAIT_BOUND_V1: Duration = Duration::from_secs(2);
    const WAIT_BACKOFF_V1: Duration = Duration::from_millis(1);
    const PTRACE_TRACEME_V1: libc::c_uint = 0;
    const PTRACE_CONT_V1: libc::c_uint = 7;
    const PTRACE_SETOPTIONS_V1: libc::c_uint = 0x4200;
    const PTRACE_O_EXITKILL_V1: usize = 0x0010_0000;
    const KERNEL_SIGNAL_SET_BYTES_V1: usize = core::mem::size_of::<u64>();
    const SA_RESTORER_V1: libc::c_int = 0x0400_0000;
    const ALL_BLOCKABLE_SIGNALS_V1: u64 =
        !(signal_bit_v1(libc::SIGKILL) | signal_bit_v1(libc::SIGSTOP));

    const fn signal_bit_v1(signal: i32) -> u64 {
        1_u64 << (signal - 1)
    }

    #[repr(C)]
    struct SharedTranscriptV1 {
        no_new_privileges: AtomicI32,
        initial_seccomp_mode: AtomicI32,
        install_result: AtomicI32,
    }

    impl SharedTranscriptV1 {
        fn initialize(pointer: *mut Self) {
            unsafe {
                pointer.write(Self {
                    no_new_privileges: AtomicI32::new(-1),
                    initial_seccomp_mode: AtomicI32::new(-1),
                    install_result: AtomicI32::new(i32::MIN),
                });
            }
        }
    }

    #[repr(C)]
    struct LinuxSockFprogV1 {
        len: libc::c_ushort,
        filter: *const WorkloadSockFilterV1,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct SigchldDispositionV1 {
        flags: libc::c_int,
        restorer: usize,
    }

    struct LiveStoppedChildOperationsV1 {
        child: Option<libc::pid_t>,
        shared: *mut SharedTranscriptV1,
        old_mask: u64,
        initial_pending: u64,
        initial_sigchld: Option<SigchldDispositionV1>,
        pending_safe_for_restore: bool,
        signal_blocked: bool,
        reaped: bool,
        reaping_ownership_lost: bool,
        pid_signaling_suppressed: bool,
        final_echild_proven: bool,
        #[cfg(test)]
        fault_once: Option<(ConnectorOperationV1, OperationErrorV1)>,
        #[cfg(test)]
        kill_syscall_attempts: usize,
    }

    impl LiveStoppedChildOperationsV1 {
        fn new() -> Self {
            Self {
                child: None,
                shared: ptr::null_mut(),
                old_mask: 0,
                initial_pending: 0,
                initial_sigchld: None,
                pending_safe_for_restore: false,
                signal_blocked: false,
                reaped: false,
                reaping_ownership_lost: false,
                pid_signaling_suppressed: false,
                final_echild_proven: false,
                #[cfg(test)]
                fault_once: None,
                #[cfg(test)]
                kill_syscall_attempts: 0,
            }
        }

        fn child(&self) -> Result<libc::pid_t, OperationErrorV1> {
            self.child.ok_or(OperationErrorV1::Failed)
        }

        fn shared(&self) -> Result<&SharedTranscriptV1, OperationErrorV1> {
            unsafe { self.shared.as_ref() }.ok_or(OperationErrorV1::Failed)
        }

        fn observe_default_sigchld(&self) -> Result<SigchldDispositionV1, OperationErrorV1> {
            let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
            if unsafe { libc::sigaction(libc::SIGCHLD, ptr::null(), &mut action) } != 0 {
                return Err(OperationErrorV1::Failed);
            }
            let mut mask_empty = true;
            for signal in 1..=64 {
                let member = unsafe { libc::sigismember(&action.sa_mask, signal) };
                if member < 0 {
                    return Err(OperationErrorV1::Failed);
                }
                mask_empty &= member == 0;
            }
            if action.sa_sigaction != libc::SIG_DFL
                || action.sa_flags & !SA_RESTORER_V1 != 0
                || !mask_empty
            {
                return Err(OperationErrorV1::SignalStateChanged);
            }
            Ok(SigchldDispositionV1 {
                flags: action.sa_flags,
                restorer: action.sa_restorer.map_or(0, |restorer| restorer as usize),
            })
        }

        fn record_initial_sigchld(&mut self) -> Result<i64, OperationErrorV1> {
            self.initial_sigchld = Some(self.observe_default_sigchld()?);
            Ok(0)
        }

        fn verify_initial_sigchld_unchanged(&self) -> Result<i64, OperationErrorV1> {
            let observed = self.observe_default_sigchld()?;
            match self.initial_sigchld {
                Some(expected) if observed == expected => Ok(0),
                Some(_) => Err(OperationErrorV1::SignalStateChanged),
                None => Ok(0),
            }
        }

        fn read_initial_pending(&mut self) -> Result<i64, OperationErrorV1> {
            let mut pending_before = 0_u64;
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigpending,
                    &mut pending_before,
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } != 0
            {
                return Err(OperationErrorV1::Failed);
            }
            self.initial_pending = pending_before;
            Ok(0)
        }

        fn block_signal(&mut self) -> Result<i64, OperationErrorV1> {
            let desired = ALL_BLOCKABLE_SIGNALS_V1;
            let mut old_mask = 0_u64;
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_BLOCK,
                    &desired,
                    &mut old_mask,
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } != 0
            {
                return Err(OperationErrorV1::Failed);
            }
            self.old_mask = old_mask;
            self.signal_blocked = true;
            Ok(0)
        }

        fn verify_blocked_mask(&self) -> Result<i64, OperationErrorV1> {
            let mut observed_mask = 0_u64;
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    ptr::null::<u64>(),
                    &mut observed_mask,
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } != 0
                || observed_mask != (self.old_mask | ALL_BLOCKABLE_SIGNALS_V1)
            {
                return Err(OperationErrorV1::SignalStateChanged);
            }
            Ok(0)
        }

        fn verify_blocked_pending(&mut self) -> Result<i64, OperationErrorV1> {
            self.pending_safe_for_restore = false;
            let mut pending_after = 0_u64;
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigpending,
                    &mut pending_after,
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } != 0
                || pending_after != self.initial_pending
                || self.initial_pending & !self.old_mask != 0
            {
                return Err(OperationErrorV1::SignalStateChanged);
            }
            self.pending_safe_for_restore = true;
            Ok(0)
        }

        fn verify_pending_signals(&mut self) -> Result<i64, OperationErrorV1> {
            self.pending_safe_for_restore = false;
            let mut observed = 0_u64;
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigpending,
                    &mut observed,
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } != 0
            {
                return Err(OperationErrorV1::Failed);
            }
            if observed != self.initial_pending || self.initial_pending & !self.old_mask != 0 {
                return Err(OperationErrorV1::SignalStateChanged);
            }
            self.pending_safe_for_restore = true;
            Ok(0)
        }

        fn allocate_shared_mapping(&mut self) -> Result<i64, OperationErrorV1> {
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
                return Err(OperationErrorV1::Failed);
            }
            self.shared = mapping.cast();
            SharedTranscriptV1::initialize(self.shared);
            Ok(0)
        }

        fn spawn(&mut self) -> Result<i64, OperationErrorV1> {
            if self.shared.is_null() {
                return Err(OperationErrorV1::Failed);
            }
            let child = unsafe { libc::fork() };
            if child < 0 {
                return Err(OperationErrorV1::Failed);
            }
            if child == 0 {
                unsafe { child_entry_v1(self.shared) };
            }
            self.child = Some(child);
            Ok(0)
        }

        fn wait_for_stop(&mut self, expected_signal: i32) -> Result<i64, OperationErrorV1> {
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
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        self.reaped = true;
                        self.pid_signaling_suppressed = true;
                    }
                    return Err(OperationErrorV1::Failed);
                }
                if waited < 0 {
                    if last_errno_v1() == libc::ECHILD {
                        self.reaping_ownership_lost = true;
                        self.pid_signaling_suppressed = true;
                        return Err(OperationErrorV1::ReapingOwnershipLost);
                    }
                    return Err(OperationErrorV1::Failed);
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
            policy_operation: bool,
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
                let error = last_errno_v1();
                if policy_operation {
                    Err(classify_policy_errno_v1(error))
                } else {
                    Err(OperationErrorV1::Failed)
                }
            } else {
                Ok(result)
            }
        }

        fn verify_single_task(&self) -> Result<i64, OperationErrorV1> {
            let path = format!("/proc/{}/task", self.child()?);
            count_exactly_one_task_v1(path)
        }

        fn verify_host_single_task(&self) -> Result<i64, OperationErrorV1> {
            count_exactly_one_task_v1("/proc/self/task")
        }

        fn verify_restored_signal_mask(&mut self) -> Result<i64, OperationErrorV1> {
            if !self.signal_blocked {
                return Ok(0);
            }
            let mut observed = 0_u64;
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    ptr::null::<u64>(),
                    &mut observed,
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } != 0
                || observed != self.old_mask
            {
                return Err(OperationErrorV1::SignalStateChanged);
            }
            self.signal_blocked = false;
            Ok(0)
        }

        fn release_shared_mapping(&mut self) -> Result<i64, OperationErrorV1> {
            if self.shared.is_null() {
                return Ok(0);
            }
            if unsafe {
                libc::munmap(
                    self.shared.cast(),
                    core::mem::size_of::<SharedTranscriptV1>(),
                )
            } != 0
            {
                return Err(OperationErrorV1::Failed);
            }
            self.shared = ptr::null_mut();
            Ok(0)
        }
    }

    fn count_exactly_one_task_v1(
        path: impl AsRef<std::path::Path>,
    ) -> Result<i64, OperationErrorV1> {
        let mut entries = fs::read_dir(path).map_err(|_| OperationErrorV1::Failed)?;
        let first = entries
            .next()
            .transpose()
            .map_err(|_| OperationErrorV1::Failed)?;
        let second = entries
            .next()
            .transpose()
            .map_err(|_| OperationErrorV1::Failed)?;
        if first.is_some() && second.is_none() {
            Ok(1)
        } else {
            Err(OperationErrorV1::Failed)
        }
    }

    impl LiveStoppedChildOperationsV1 {
        fn reap(&mut self, cleanup: bool) -> Result<i64, OperationErrorV1> {
            if self.reaped || self.child.is_none() {
                return Ok(0);
            }
            if self.reaping_ownership_lost {
                return Err(OperationErrorV1::ReapingOwnershipLost);
            }
            let child = self.child()?;
            let deadline = Instant::now() + WAIT_BOUND_V1;
            loop {
                let mut status = 0;
                let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
                if waited == child {
                    if libc::WIFSIGNALED(status) || libc::WIFEXITED(status) {
                        self.reaped = true;
                        self.pid_signaling_suppressed = true;
                    }
                    return if (cleanup && self.reaped)
                        || (self.reaped
                            && libc::WIFSIGNALED(status)
                            && libc::WTERMSIG(status) == libc::SIGKILL)
                    {
                        Ok(0)
                    } else {
                        Err(OperationErrorV1::Failed)
                    };
                }
                if waited < 0 {
                    let error = last_errno_v1();
                    if error == libc::ECHILD {
                        self.reaping_ownership_lost = true;
                        self.pid_signaling_suppressed = true;
                        return Err(OperationErrorV1::ReapingOwnershipLost);
                    }
                    return Err(OperationErrorV1::Failed);
                }
                if Instant::now() >= deadline {
                    return Err(OperationErrorV1::Failed);
                }
                std::thread::sleep(WAIT_BACKOFF_V1);
            }
        }

        fn prove_echild(&mut self) -> Result<i64, OperationErrorV1> {
            let Some(child) = self.child else {
                self.final_echild_proven = true;
                return Ok(0);
            };
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if waited < 0 && last_errno_v1() == libc::ECHILD {
                if self.reaped {
                    self.final_echild_proven = true;
                    Ok(0)
                } else {
                    self.reaping_ownership_lost = true;
                    self.pid_signaling_suppressed = true;
                    Err(OperationErrorV1::ReapingOwnershipLost)
                }
            } else if waited == child && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                // Even though this operation expected ECHILD, it consumed the
                // terminal status. Retire the saved PID before returning the
                // typed mismatch so cleanup can never signal a recycled PID.
                self.reaped = true;
                self.pid_signaling_suppressed = true;
                Err(OperationErrorV1::Failed)
            } else {
                Err(OperationErrorV1::Failed)
            }
        }

        fn kill(&mut self) -> Result<i64, OperationErrorV1> {
            if self.pid_signaling_suppressed
                || self.reaped
                || self.reaping_ownership_lost
                || self.child.is_none()
            {
                return Ok(0);
            }
            #[cfg(test)]
            {
                self.kill_syscall_attempts = self.kill_syscall_attempts.saturating_add(1);
            }
            let result = unsafe { libc::kill(self.child()?, libc::SIGKILL) };
            if result == 0 || (result < 0 && last_errno_v1() == libc::ESRCH) {
                self.pid_signaling_suppressed = true;
                Ok(0)
            } else {
                Err(OperationErrorV1::Failed)
            }
        }

        fn restore_signal(&mut self) -> Result<i64, OperationErrorV1> {
            if !self.signal_blocked {
                return Ok(0);
            }
            let child_is_not_signalable = self.child.is_none()
                || (self.reaped && self.final_echild_proven)
                || self.reaping_ownership_lost;
            if !child_is_not_signalable || !self.pending_safe_for_restore {
                return Err(OperationErrorV1::SignalStateChanged);
            }
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &self.old_mask,
                    ptr::null_mut::<u64>(),
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } != 0
            {
                return Err(OperationErrorV1::Failed);
            }
            Ok(0)
        }
    }

    impl StoppedChildOperationsV1 for LiveStoppedChildOperationsV1 {
        fn perform(
            &mut self,
            operation: ConnectorOperationV1,
            readback: Option<&mut [WorkloadSockFilterV1]>,
        ) -> Result<i64, OperationErrorV1> {
            #[cfg(test)]
            if self
                .fault_once
                .is_some_and(|(candidate, _)| candidate == operation)
            {
                return Err(self
                    .fault_once
                    .take()
                    .expect("matched one-shot live fault")
                    .1);
            }
            match operation {
                ConnectorOperationV1::VerifyHostSingleTask
                | ConnectorOperationV1::VerifyPreForkHostSingleTask => {
                    self.verify_host_single_task()
                }
                ConnectorOperationV1::VerifyInitialSignalDisposition => {
                    self.record_initial_sigchld()
                }
                ConnectorOperationV1::VerifyPreForkSignalDisposition
                | ConnectorOperationV1::VerifyFinalSignalDisposition
                | ConnectorOperationV1::CleanupVerifyFinalSignalDisposition => {
                    self.verify_initial_sigchld_unchanged()
                }
                ConnectorOperationV1::ReadInitialPendingSignals => self.read_initial_pending(),
                ConnectorOperationV1::SignalBlock => self.block_signal(),
                ConnectorOperationV1::VerifyBlockedSignalMask => self.verify_blocked_mask(),
                ConnectorOperationV1::VerifyBlockedPendingSignals => self.verify_blocked_pending(),
                ConnectorOperationV1::AllocateSharedMapping => self.allocate_shared_mapping(),
                ConnectorOperationV1::SpawnChild => self.spawn(),
                ConnectorOperationV1::WaitInitialStop => self.wait_for_stop(libc::SIGSTOP),
                ConnectorOperationV1::VerifyInitialSingleTask
                | ConnectorOperationV1::VerifyInstalledSingleTask => self.verify_single_task(),
                ConnectorOperationV1::PtracePrepare => {
                    self.ptrace(PTRACE_SETOPTIONS_V1, 0, PTRACE_O_EXITKILL_V1, false)
                }
                ConnectorOperationV1::ReadNoNewPrivileges => Ok(i64::from(
                    self.shared()?.no_new_privileges.load(Ordering::Acquire),
                )),
                ConnectorOperationV1::ReadInitialSeccompMode => Ok(i64::from(
                    self.shared()?.initial_seccomp_mode.load(Ordering::Acquire),
                )),
                ConnectorOperationV1::ResumeForInstall => self.ptrace(PTRACE_CONT_V1, 0, 0, false),
                ConnectorOperationV1::WaitInstalledStop => self.wait_for_stop(libc::SIGTRAP),
                ConnectorOperationV1::InstallTsyncFilter => {
                    let result = self.shared()?.install_result.load(Ordering::Acquire);
                    if result == 0 {
                        Ok(0)
                    } else if result < 0 {
                        Err(classify_policy_errno_v1(result.saturating_neg()))
                    } else {
                        Err(OperationErrorV1::Failed)
                    }
                }
                ConnectorOperationV1::PtraceReadbackCount => {
                    self.ptrace(PTRACE_SECCOMP_GET_FILTER_V1, 0, 0, true)
                }
                ConnectorOperationV1::PtraceReadbackInstructions => {
                    let output = readback.ok_or(OperationErrorV1::Failed)?;
                    self.ptrace(
                        PTRACE_SECCOMP_GET_FILTER_V1,
                        0,
                        output.as_mut_ptr() as usize,
                        true,
                    )
                }
                ConnectorOperationV1::ResumeWithKill => {
                    self.ptrace(PTRACE_CONT_V1, 0, libc::SIGKILL as usize, false)
                }
                ConnectorOperationV1::ReapChild => self.reap(false),
                ConnectorOperationV1::CleanupReap => self.reap(true),
                ConnectorOperationV1::ProveFinalEchild
                | ConnectorOperationV1::CleanupFinalEchild => self.prove_echild(),
                ConnectorOperationV1::SignalRestore
                | ConnectorOperationV1::CleanupSignalRestore => self.restore_signal(),
                ConnectorOperationV1::VerifyRestoredSignalMask
                | ConnectorOperationV1::CleanupVerifyRestoredSignalMask => {
                    self.verify_restored_signal_mask()
                }
                ConnectorOperationV1::VerifyPendingSignals
                | ConnectorOperationV1::CleanupVerifyPendingSignals => {
                    self.verify_pending_signals()
                }
                ConnectorOperationV1::ReleaseSharedMapping
                | ConnectorOperationV1::CleanupSharedMapping => self.release_shared_mapping(),
                ConnectorOperationV1::CleanupKill => self.kill(),
            }
        }
    }

    impl Drop for LiveStoppedChildOperationsV1 {
        fn drop(&mut self) {
            // These are bounded last-resort retries only. Their results are
            // deliberately unobservable and can never upgrade a refusal's
            // independently recorded cleanup uncertainty to success.
            let _ = self.kill();
            let _ = self.reap(true);
            let _ = self.prove_echild();
            let _ = self.verify_pending_signals();
            let _ = self.restore_signal();
            let _ = self.verify_restored_signal_mask();
            let _ = self.verify_initial_sigchld_unchanged();
            let _ = self.release_shared_mapping();
        }
    }

    fn classify_policy_errno_v1(error: i32) -> OperationErrorV1 {
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
        }
        unsafe { core::arch::asm!("int3", options(noreturn)) };
    }

    #[cfg(test)]
    pub(super) fn test_reaping_policy_refusal_v1(no_cldwait: bool) -> bool {
        let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = if no_cldwait {
            libc::SIG_DFL
        } else {
            libc::SIG_IGN
        };
        action.sa_flags = if no_cldwait { libc::SA_NOCLDWAIT } else { 0 };
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGCHLD, &action, ptr::null_mut()) } != 0
        {
            return false;
        }
        let operations = LiveStoppedChildOperationsV1::new();
        operations.observe_default_sigchld() == Err(OperationErrorV1::SignalStateChanged)
    }

    #[cfg(test)]
    pub(super) fn test_competing_reaper_refusal_v1() -> bool {
        let child = unsafe { libc::fork() };
        if child < 0 {
            return false;
        }
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        if unsafe { libc::waitpid(child, &mut status, 0) } != child {
            return false;
        }
        let mut operations = LiveStoppedChildOperationsV1::new();
        operations.child = Some(child);
        operations.reap(false) == Err(OperationErrorV1::ReapingOwnershipLost)
    }

    #[cfg(test)]
    pub(super) fn test_competing_reaper_cleanup_uncertainty_v1() -> bool {
        let child = unsafe { libc::fork() };
        if child < 0 {
            return false;
        }
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        if unsafe { libc::waitpid(child, &mut status, 0) } != child {
            return false;
        }
        let mut operations = LiveStoppedChildOperationsV1::new();
        operations.child = Some(child);
        operations.kill().is_ok()
            && operations.reap(true) == Err(OperationErrorV1::ReapingOwnershipLost)
            && operations.kill().is_ok()
            && operations.kill_syscall_attempts == 1
            && operations.prove_echild() == Err(OperationErrorV1::ReapingOwnershipLost)
    }

    #[cfg(test)]
    static AMBIENT_HANDLER_CALLS_V1: AtomicI32 = AtomicI32::new(0);

    #[cfg(test)]
    extern "C" fn ambient_handler_v1(_: libc::c_int) {
        AMBIENT_HANDLER_CALLS_V1.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(super) fn test_child_retains_all_signal_mask_v1() -> bool {
        AMBIENT_HANDLER_CALLS_V1.store(0, Ordering::Relaxed);
        let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = ambient_handler_v1 as usize;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGUSR1, &action, ptr::null_mut()) } != 0
        {
            return false;
        }
        let mut operations = LiveStoppedChildOperationsV1::new();
        if operations.read_initial_pending().is_err()
            || operations.block_signal().is_err()
            || operations.verify_blocked_pending().is_err()
        {
            return false;
        }
        let child = unsafe { libc::fork() };
        if child < 0 {
            return false;
        }
        if child == 0 {
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            let sent = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1) };
            let mut pending = 0_u64;
            let pending_result = unsafe {
                libc::syscall(
                    libc::SYS_rt_sigpending,
                    &mut pending,
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            };
            let valid = sent == 0
                && pending_result == 0
                && pending & signal_bit_v1(libc::SIGUSR1) != 0
                && AMBIENT_HANDLER_CALLS_V1.load(Ordering::Relaxed) == 0;
            unsafe { libc::_exit(i32::from(!valid)) };
        }
        let mut status = 0;
        (unsafe { libc::waitpid(child, &mut status, 0) }) == child
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0
            && operations.restore_signal().is_ok()
            && operations.verify_restored_signal_mask().is_ok()
    }

    #[cfg(test)]
    pub(super) fn test_mapping_is_released_after_injected_spawn_failure_v1() -> bool {
        let mut operations = LiveStoppedChildOperationsV1::new();
        operations.fault_once = Some((ConnectorOperationV1::SpawnChild, OperationErrorV1::Failed));
        let failure = drive_stopped_child_v1(
            StoppedChildPermitV1 {
                _seal: StoppedChildPermitSealV1,
            },
            &mut operations,
        )
        .expect_err("the injected fork boundary must refuse");
        failure.stage() == WorkloadSeccompConnectorStageV1::SpawnChild
            && failure.cleanup_complete()
            && operations.shared.is_null()
            && operations.child.is_none()
            && !operations.signal_blocked
    }

    #[cfg(test)]
    pub(super) fn test_restore_readback_fault_has_bounded_fallback_v1() -> bool {
        let mut operations = LiveStoppedChildOperationsV1::new();
        if operations.read_initial_pending().is_err()
            || operations.block_signal().is_err()
            || operations.verify_blocked_pending().is_err()
            || operations.restore_signal().is_err()
        {
            return false;
        }
        operations.fault_once = Some((
            ConnectorOperationV1::VerifyRestoredSignalMask,
            OperationErrorV1::SignalStateChanged,
        ));
        if operations.perform(ConnectorOperationV1::VerifyRestoredSignalMask, None)
            != Err(OperationErrorV1::SignalStateChanged)
        {
            return false;
        }
        let first = operation_failure_v1(
            ConnectorOperationV1::VerifyRestoredSignalMask,
            OperationErrorV1::SignalStateChanged,
        );
        let cleanup_complete = cleanup_after_failure_v1(&mut operations)
            && first.reason != WorkloadSeccompConnectorReasonV1::SignalStateChanged;
        let failure = first.with_cleanup(cleanup_complete);
        !failure.cleanup_complete() && !operations.signal_blocked
    }

    #[cfg(test)]
    pub(super) fn test_drop_retry_cannot_upgrade_recorded_uncertainty_v1() -> bool {
        let mut original_mask = 0_u64;
        if unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                ptr::null::<u64>(),
                &mut original_mask,
                KERNEL_SIGNAL_SET_BYTES_V1,
            )
        } != 0
        {
            return false;
        }
        let refusal = WorkloadSeccompConnectorFailureV1::new(
            WorkloadSeccompConnectorStageV1::SpawnChild,
            WorkloadSeccompConnectorReasonV1::KernelOperation,
        )
        .with_cleanup(false);
        {
            let mut operations = LiveStoppedChildOperationsV1::new();
            if operations.read_initial_pending().is_err()
                || operations.block_signal().is_err()
                || operations.allocate_shared_mapping().is_err()
            {
                return false;
            }
            // Drop performs the bounded cleanup retry while `refusal` already
            // owns its independent, immutable cleanup-uncertainty result.
        }
        let mut restored_mask = 0_u64;
        let readback_ok = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                ptr::null::<u64>(),
                &mut restored_mask,
                KERNEL_SIGNAL_SET_BYTES_V1,
            )
        } == 0;
        readback_ok && restored_mask == original_mask && !refusal.cleanup_complete()
    }

    #[cfg(test)]
    pub(super) fn test_early_terminal_wait_retires_saved_pid_v1() -> bool {
        let child = unsafe { libc::fork() };
        if child < 0 {
            return false;
        }
        if child == 0 {
            unsafe { libc::_exit(125) };
        }
        let mut operations = LiveStoppedChildOperationsV1::new();
        operations.child = Some(child);
        operations.wait_for_stop(libc::SIGSTOP) == Err(OperationErrorV1::Failed)
            && operations.reaped
            && operations.kill().is_ok()
            && operations.kill_syscall_attempts == 0
            && operations.prove_echild().is_ok()
            && operations.final_echild_proven
    }

    #[cfg(test)]
    pub(super) fn test_wait_for_stop_echild_suppresses_saved_pid_v1() -> bool {
        let child = unsafe { libc::fork() };
        if child < 0 {
            return false;
        }
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        if unsafe { libc::waitpid(child, &mut status, 0) } != child {
            return false;
        }
        let mut operations = LiveStoppedChildOperationsV1::new();
        operations.child = Some(child);
        operations.wait_for_stop(libc::SIGSTOP) == Err(OperationErrorV1::ReapingOwnershipLost)
            && operations.reaping_ownership_lost
            && operations.kill().is_ok()
            && operations.kill_syscall_attempts == 0
            && operations.prove_echild() == Err(OperationErrorV1::ReapingOwnershipLost)
    }

    #[cfg(test)]
    pub(super) fn test_pending_handler_stays_blocked_across_cleanup_reap_failure_v1() -> bool {
        AMBIENT_HANDLER_CALLS_V1.store(0, Ordering::Relaxed);
        let signal_mask = signal_bit_v1(libc::SIGUSR1);
        let mut original_mask = 0_u64;
        if unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                &signal_mask,
                &mut original_mask,
                KERNEL_SIGNAL_SET_BYTES_V1,
            )
        } != 0
        {
            return false;
        }
        let mut original_action = unsafe { core::mem::zeroed::<libc::sigaction>() };
        let mut custom = unsafe { core::mem::zeroed::<libc::sigaction>() };
        custom.sa_sigaction = ambient_handler_v1 as usize;
        if unsafe { libc::sigemptyset(&mut custom.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGUSR1, ptr::null(), &mut original_action) } != 0
            || unsafe { libc::sigaction(libc::SIGUSR1, &custom, ptr::null_mut()) } != 0
            || unsafe { libc::raise(libc::SIGUSR1) } != 0
        {
            return false;
        }

        let mut operations = LiveStoppedChildOperationsV1::new();
        if operations.record_initial_sigchld().is_err()
            || operations.read_initial_pending().is_err()
            || operations.block_signal().is_err()
            || operations.verify_blocked_pending().is_err()
        {
            return false;
        }
        let child = unsafe { libc::fork() };
        if child < 0 {
            return false;
        }
        if child == 0 {
            loop {
                unsafe { libc::pause() };
            }
        }
        operations.child = Some(child);
        operations.fault_once = Some((ConnectorOperationV1::CleanupReap, OperationErrorV1::Failed));
        let cleanup_complete = cleanup_after_failure_v1(&mut operations);
        let stayed_blocked =
            operations.signal_blocked && AMBIENT_HANDLER_CALLS_V1.load(Ordering::Relaxed) == 0;
        drop(operations);

        let mut ignore = unsafe { core::mem::zeroed::<libc::sigaction>() };
        ignore.sa_sigaction = libc::SIG_IGN;
        let restored = unsafe { libc::sigemptyset(&mut ignore.sa_mask) } == 0
            && unsafe { libc::sigaction(libc::SIGUSR1, &ignore, ptr::null_mut()) } == 0
            && unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_SETMASK,
                    &original_mask,
                    ptr::null_mut::<u64>(),
                    KERNEL_SIGNAL_SET_BYTES_V1,
                )
            } == 0
            && unsafe { libc::sigaction(libc::SIGUSR1, &original_action, ptr::null_mut()) } == 0;
        !cleanup_complete
            && stayed_blocked
            && restored
            && AMBIENT_HANDLER_CALLS_V1.load(Ordering::Relaxed) == 0
    }

    #[cfg(test)]
    pub(super) fn test_multithreaded_custom_sigchld_refuses_before_child_v1() -> bool {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        AMBIENT_HANDLER_CALLS_V1.store(0, Ordering::Relaxed);
        let mut old = unsafe { core::mem::zeroed::<libc::sigaction>() };
        let mut custom = unsafe { core::mem::zeroed::<libc::sigaction>() };
        custom.sa_sigaction = ambient_handler_v1 as usize;
        if unsafe { libc::sigemptyset(&mut custom.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGCHLD, ptr::null(), &mut old) } != 0
            || unsafe { libc::sigaction(libc::SIGCHLD, &custom, ptr::null_mut()) } != 0
        {
            return false;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        });
        let result = qualify_stopped_workload_filter_live_v1();
        stop.store(true, Ordering::Release);
        let joined = thread.join().is_ok();
        let restored = unsafe { libc::sigaction(libc::SIGCHLD, &old, ptr::null_mut()) } == 0;
        matches!(
            result,
            Err(failure)
                if failure.stage() == WorkloadSeccompConnectorStageV1::VerifySignalDisposition
                    && failure.reason() == WorkloadSeccompConnectorReasonV1::SignalStateChanged
                    && !failure.cleanup_complete()
        ) && AMBIENT_HANDLER_CALLS_V1.load(Ordering::Relaxed) == 0
            && joined
            && restored
    }

    pub(in crate::linux_pytest) fn qualify_stopped_workload_filter_live_v1()
    -> Result<CompletedDisposableWorkloadFilterProbeV1, WorkloadSeccompConnectorFailureV1> {
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
        forward_error: OperationErrorV1,
        cleanup_error: OperationErrorV1,
        observed_override: Option<(ConnectorOperationV1, i64)>,
    }

    impl InjectedOperationsV1 {
        fn clean() -> Self {
            Self {
                forward_failure: None,
                cleanup_failure: None,
                operations: Vec::new(),
                mutate_readback: false,
                forward_error: OperationErrorV1::Failed,
                cleanup_error: OperationErrorV1::Failed,
                observed_override: None,
            }
        }

        fn expected_value(operation: ConnectorOperationV1) -> i64 {
            match operation {
                ConnectorOperationV1::VerifyHostSingleTask
                | ConnectorOperationV1::VerifyPreForkHostSingleTask
                | ConnectorOperationV1::VerifyInitialSingleTask
                | ConnectorOperationV1::VerifyInstalledSingleTask
                | ConnectorOperationV1::ReadNoNewPrivileges => 1,
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
            if self.forward_failure == Some(operation) {
                return Err(self.forward_error);
            }
            if self.cleanup_failure == Some(operation) {
                return Err(self.cleanup_error);
            }
            if operation == ConnectorOperationV1::PtraceReadbackInstructions {
                let output = readback.ok_or(OperationErrorV1::Failed)?;
                output.copy_from_slice(&WORKLOAD_FILTER_V1);
                if self.mutate_readback {
                    output[0].operand ^= 1;
                }
            }
            Ok(self
                .observed_override
                .filter(|(candidate, _)| *candidate == operation)
                .map_or_else(|| Self::expected_value(operation), |(_, value)| value))
        }
    }

    #[derive(Clone, Copy)]
    enum AbstractWaitEffectV1 {
        TerminalStatusConsumed,
        ReapingOwnershipLost,
    }

    struct AbstractWaitStateOperationsV1 {
        effect: AbstractWaitEffectV1,
        child_signalable: bool,
        terminal_observed: bool,
        ownership_lost: bool,
        kill_attempts: usize,
        operations: Vec<ConnectorOperationV1>,
    }

    impl AbstractWaitStateOperationsV1 {
        fn new(effect: AbstractWaitEffectV1) -> Self {
            Self {
                effect,
                child_signalable: false,
                terminal_observed: false,
                ownership_lost: false,
                kill_attempts: 0,
                operations: Vec::new(),
            }
        }
    }

    impl StoppedChildOperationsV1 for AbstractWaitStateOperationsV1 {
        fn perform(
            &mut self,
            operation: ConnectorOperationV1,
            _readback: Option<&mut [WorkloadSockFilterV1]>,
        ) -> Result<i64, OperationErrorV1> {
            self.operations.push(operation);
            match operation {
                ConnectorOperationV1::SpawnChild => {
                    self.child_signalable = true;
                    Ok(0)
                }
                ConnectorOperationV1::WaitInitialStop => {
                    self.child_signalable = false;
                    match self.effect {
                        AbstractWaitEffectV1::TerminalStatusConsumed => {
                            self.terminal_observed = true;
                            Err(OperationErrorV1::Failed)
                        }
                        AbstractWaitEffectV1::ReapingOwnershipLost => {
                            self.ownership_lost = true;
                            Err(OperationErrorV1::ReapingOwnershipLost)
                        }
                    }
                }
                ConnectorOperationV1::CleanupKill => {
                    if self.child_signalable {
                        self.kill_attempts = self.kill_attempts.saturating_add(1);
                    }
                    Ok(0)
                }
                ConnectorOperationV1::CleanupReap | ConnectorOperationV1::CleanupFinalEchild
                    if self.ownership_lost =>
                {
                    Err(OperationErrorV1::ReapingOwnershipLost)
                }
                _ => Ok(InjectedOperationsV1::expected_value(operation)),
            }
        }
    }

    fn permit_v1() -> StoppedChildPermitV1 {
        StoppedChildPermitV1 {
            _seal: StoppedChildPermitSealV1,
        }
    }

    #[test]
    fn injected_success_returns_only_a_redacted_completed_disposable_probe() {
        let mut operations = InjectedOperationsV1::clean();
        let probe = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap();
        assert_eq!(
            probe.policy_digest_blake3(),
            &workload_policy_digest_blake3_v1()
        );
        assert_eq!(
            usize::from(probe.instruction_count()),
            WORKLOAD_FILTER_INSTRUCTION_COUNT_V1
        );
        assert!(!probe.live_child_authority());
        assert!(!probe.execution_authority());
        assert!(!probe.candidate_or_reuse_authority());
        assert!(format!("{probe:?}").contains("<redacted-completed-kernel-readback>"));
        assert!(
            !operations
                .operations
                .iter()
                .any(|operation| CLEANUP_OPERATIONS_V1.contains(operation))
        );
        assert_eq!(operations.operations, FORWARD_OPERATIONS_V1);
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
    fn cleanup_echild_never_proves_cleanup_and_preserves_the_first_forward_failure() {
        let mut operations = InjectedOperationsV1 {
            forward_failure: Some(ConnectorOperationV1::WaitInitialStop),
            cleanup_failure: Some(ConnectorOperationV1::CleanupReap),
            cleanup_error: OperationErrorV1::ReapingOwnershipLost,
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

    #[test]
    fn abstract_terminal_wait_effect_retires_signaling_before_cleanup() {
        let mut operations =
            AbstractWaitStateOperationsV1::new(AbstractWaitEffectV1::TerminalStatusConsumed);
        let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
        assert_eq!(
            failure.stage(),
            WorkloadSeccompConnectorStageV1::WaitInitialStop
        );
        assert!(failure.cleanup_complete());
        assert!(operations.terminal_observed);
        assert_eq!(operations.kill_attempts, 0);
    }

    #[test]
    fn abstract_echild_effect_suppresses_signaling_but_never_proves_cleanup() {
        let mut operations =
            AbstractWaitStateOperationsV1::new(AbstractWaitEffectV1::ReapingOwnershipLost);
        let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
        assert_eq!(
            failure.reason(),
            WorkloadSeccompConnectorReasonV1::ReapingOwnershipLost
        );
        assert!(!failure.cleanup_complete());
        assert!(operations.ownership_lost);
        assert_eq!(operations.kill_attempts, 0);
        assert!(
            operations
                .operations
                .contains(&ConnectorOperationV1::CleanupFinalEchild)
        );
    }

    #[test]
    fn injected_kernel_policy_refusal_is_typed_and_still_cleans() {
        let mut operations = InjectedOperationsV1 {
            forward_failure: Some(ConnectorOperationV1::InstallTsyncFilter),
            forward_error: OperationErrorV1::Unsupported,
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
    fn unsupported_errno_shape_on_lifecycle_operations_is_not_policy_unsupported() {
        for operation in [
            ConnectorOperationV1::WaitInitialStop,
            ConnectorOperationV1::ResumeForInstall,
            ConnectorOperationV1::ReapChild,
        ] {
            let mut operations = InjectedOperationsV1 {
                forward_failure: Some(operation),
                forward_error: OperationErrorV1::Unsupported,
                ..InjectedOperationsV1::clean()
            };
            let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
            assert_eq!(failure.stage(), stage_for_operation_v1(operation));
            assert_eq!(
                failure.reason(),
                WorkloadSeccompConnectorReasonV1::KernelOperation
            );
        }
    }

    #[test]
    fn forward_echild_is_reaping_ownership_loss_and_never_returns_a_probe() {
        let mut operations = InjectedOperationsV1 {
            forward_failure: Some(ConnectorOperationV1::ReapChild),
            forward_error: OperationErrorV1::ReapingOwnershipLost,
            ..InjectedOperationsV1::clean()
        };
        let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
        assert_eq!(failure.stage(), WorkloadSeccompConnectorStageV1::ReapChild);
        assert_eq!(
            failure.reason(),
            WorkloadSeccompConnectorReasonV1::ReapingOwnershipLost
        );
        assert!(!failure.cleanup_complete());
    }

    #[test]
    fn changed_pending_signal_state_is_a_typed_fail_closed_result() {
        let mut operations = InjectedOperationsV1 {
            forward_failure: Some(ConnectorOperationV1::VerifyPendingSignals),
            forward_error: OperationErrorV1::SignalStateChanged,
            ..InjectedOperationsV1::clean()
        };
        let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
        assert_eq!(
            failure.stage(),
            WorkloadSeccompConnectorStageV1::VerifyPendingSignals
        );
        assert_eq!(
            failure.reason(),
            WorkloadSeccompConnectorReasonV1::SignalStateChanged
        );
        assert!(!failure.cleanup_complete());
    }

    #[test]
    fn post_install_task_growth_refuses_before_filter_readback() {
        let mut operations = InjectedOperationsV1 {
            observed_override: Some((ConnectorOperationV1::VerifyInstalledSingleTask, 2)),
            ..InjectedOperationsV1::clean()
        };
        let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
        assert_eq!(
            failure.stage(),
            WorkloadSeccompConnectorStageV1::VerifyInstalledSingleTask
        );
        assert_eq!(
            failure.reason(),
            WorkloadSeccompConnectorReasonV1::UnexpectedObservation
        );
        assert!(
            !operations
                .operations
                .contains(&ConnectorOperationV1::PtraceReadbackCount)
        );
    }

    #[test]
    fn every_wrong_forward_observation_refuses() {
        for operation in FORWARD_OPERATIONS_V1 {
            let wrong = InjectedOperationsV1::expected_value(operation).saturating_add(7);
            let mut operations = InjectedOperationsV1 {
                observed_override: Some((operation, wrong)),
                ..InjectedOperationsV1::clean()
            };
            let failure = drive_stopped_child_v1(permit_v1(), &mut operations).unwrap_err();
            assert_eq!(failure.stage(), stage_for_operation_v1(operation));
            assert!(failure.cleanup_complete());
        }
    }

    #[test]
    fn readback_mutation_refuses_and_cleans_without_returning_a_probe() {
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
            Ok(probe) => {
                assert!(!probe.live_child_authority());
                assert!(!probe.execution_authority());
                assert!(!probe.candidate_or_reuse_authority());
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
    fn connector_permit_and_completed_probe_are_linear_and_non_clone() {
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
        <CompletedDisposableWorkloadFilterProbeV1 as AmbiguousIfClone<_>>::probe();
        <CompletedDisposableWorkloadFilterProbeV1 as AmbiguousIfCopy<_>>::probe();
        assert_ne!(
            core::any::TypeId::of::<CompletedDisposableWorkloadFilterProbeV1>(),
            core::any::TypeId::of::<InstalledWorkloadSeccompWitnessV1>()
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    fn assert_isolated_linux_case_v1(case: fn() -> bool) {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::_exit(i32::from(!case())) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "status={status}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_sig_ign_and_no_cldwait_are_typed_signal_state_refusals() {
        assert_isolated_linux_case_v1(|| platform::test_reaping_policy_refusal_v1(false));
        assert_isolated_linux_case_v1(|| platform::test_reaping_policy_refusal_v1(true));
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn multithreaded_custom_sigchld_refuses_before_spawning_and_never_calls_handler() {
        assert_isolated_linux_case_v1(
            platform::test_multithreaded_custom_sigchld_refuses_before_child_v1,
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_mmap_success_then_injected_fork_failure_unmaps_exact_mapping() {
        assert_isolated_linux_case_v1(
            platform::test_mapping_is_released_after_injected_spawn_failure_v1,
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_restore_success_then_readback_failure_uses_bounded_fallback() {
        assert_isolated_linux_case_v1(
            platform::test_restore_readback_fault_has_bounded_fallback_v1,
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_drop_cleanup_retry_cannot_upgrade_recorded_uncertainty() {
        assert_isolated_linux_case_v1(
            platform::test_drop_retry_cannot_upgrade_recorded_uncertainty_v1,
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_early_terminal_wait_retires_saved_pid_before_cleanup_kill() {
        assert_isolated_linux_case_v1(platform::test_early_terminal_wait_retires_saved_pid_v1);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_wait_echild_suppresses_saved_pid_before_cleanup_kill() {
        assert_isolated_linux_case_v1(platform::test_wait_for_stop_echild_suppresses_saved_pid_v1);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_pending_handler_stays_blocked_when_cleanup_reap_is_uncertain() {
        assert_isolated_linux_case_v1(
            platform::test_pending_handler_stays_blocked_across_cleanup_reap_failure_v1,
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_competing_reaper_is_not_accepted_as_forward_reap_evidence() {
        assert_isolated_linux_case_v1(platform::test_competing_reaper_refusal_v1);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_esrch_then_echild_is_cleanup_uncertainty_not_cleanup_proof() {
        assert_isolated_linux_case_v1(platform::test_competing_reaper_cleanup_uncertainty_v1);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn live_child_mask_prevents_an_ambient_handler_from_running() {
        assert_isolated_linux_case_v1(platform::test_child_retains_all_signal_mask_v1);
    }
}
