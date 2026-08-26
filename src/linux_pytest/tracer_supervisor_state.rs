//! Pure stop/response correlation planner for the future Linux x86_64 tracer.
//!
//! This module composes the existing wait-status, event-message, syscall-info,
//! fork-family, and logical-task contracts. It performs no syscall and accepts
//! no command. A caller must retain each linear token while the corresponding
//! tracee is stopped, perform exactly the requested kernel operation, and feed
//! the response back with the same TID and stop class. Any disagreement or
//! unsupported stop permanently poisons the planner.
//!
//! The stopped-seccomp permit is deliberately short lived. It owns the
//! non-`Copy` decoded frame only while the same correlated stop is held and
//! must be consumed before a resume intent exists. Its sole production
//! constructor is gated by the fixed no-command kernel connector, which proves
//! the exact ptrace options and installed filter before issuance. That
//! diagnostic boundary is not tracing-completeness or isolation authority. No
//! type here grants observation completeness, EffectIR, execution, or reuse
//! authority.

use super::tracer_event_message::{
    DecodedLinuxPtraceEventMessageV1, LinuxPtraceEventMessageDecodeErrorV1,
    decode_linux_ptrace_event_message_x86_64_v1,
};
use super::tracer_fork_decode::{
    CLONE3_ARGS_BUFFER_BYTES_V1, Clone3ArgsCaptureV1, ForkFamilyBirthObservationV1,
    ForkFamilyDecodeErrorV1, decode_fork_family_entry_x86_64_v1, plan_clone3_args_read_x86_64_v1,
};
use super::tracer_seccomp::{
    TracerSupervisorCleanupCompletionPermitV1, TracerSupervisorIssuerPermitV1,
};
use super::tracer_syscall_info::{
    DecodedPtraceSyscallInfoX8664V1, DecodedSeccompSyscallInfoX8664V1,
    PtraceSyscallInfoDecodeErrorV1, decode_ptrace_syscall_info_x86_64_v1,
};
use super::tracer_task_state::{
    NormalizedTracerTaskEventSinkV1, TRACER_TASK_CLONE_NR_X86_64_V1,
    TRACER_TASK_CLONE3_NR_X86_64_V1, TRACER_TASK_EXECVE_NR_X86_64_V1,
    TRACER_TASK_EXECVEAT_NR_X86_64_V1, TRACER_TASK_FORK_NR_X86_64_V1, TRACER_TASK_MAX_TASKS_V1,
    TRACER_TASK_VFORK_NR_X86_64_V1, TracerTaskExecuteOnlyReasonV1, TracerTaskObservationV1,
    TracerTaskStateRecorderV1,
};
use super::tracer_wait_status::{
    LinuxPtraceEventStopSignalShapeV1, LinuxPtraceEventV1, LinuxWaitStatusClassV1,
    LinuxWaitStatusDecodeErrorV1, decode_linux_wait_status_x86_64_v1,
};
use core::sync::atomic::{AtomicU64, Ordering};

const EVENT_MESSAGE_BYTES_X86_64_V1: usize = 8;
const SYSCALL_INFO_BYTES_X86_64_V1: usize = 84;
const MAX_PENDING_CHILD_STOPS_V1: usize = TRACER_TASK_MAX_TASKS_V1 - 1;
static NEXT_SUPERVISOR_SESSION_BRAND_V1: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TracerSupervisorSyscallInfoKindV1 {
    SeccompEntry,
    SyscallExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TracerSupervisorResumeRequestV1 {
    Continue,
    Syscall,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PendingResumeStepV1 {
    session_brand: u64,
    raw_tid: i32,
    stop_generation: u64,
    request: TracerSupervisorResumeRequestV1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResumeStepPositionV1 {
    OnlyOrChild,
    Parent,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingResumeCursorV1 {
    One(PendingResumeStepV1),
    ChildThenParent {
        child: PendingResumeStepV1,
        parent: PendingResumeStepV1,
    },
    Parent(PendingResumeStepV1),
}

impl PendingResumeCursorV1 {
    const fn current(self) -> (PendingResumeStepV1, ResumeStepPositionV1) {
        match self {
            Self::One(step) => (step, ResumeStepPositionV1::OnlyOrChild),
            Self::ChildThenParent { child, .. } => (child, ResumeStepPositionV1::OnlyOrChild),
            Self::Parent(step) => (step, ResumeStepPositionV1::Parent),
        }
    }

    const fn advanced(self) -> Option<Self> {
        match self {
            Self::One(_) | Self::Parent(_) => None,
            Self::ChildThenParent { parent, .. } => Some(Self::Parent(parent)),
        }
    }
}

/// Linear instruction to read one event message from one still-held stop.
/// Fields are private so sibling modules cannot forge a different correlation.
pub(super) struct TracerSupervisorEventMessageReadV1 {
    session_brand: u64,
    raw_tid: i32,
    stop_generation: u64,
    event: LinuxPtraceEventV1,
}

impl TracerSupervisorEventMessageReadV1 {
    pub(super) const fn raw_tid(&self) -> i32 {
        self.raw_tid
    }

    pub(super) const fn event(&self) -> LinuxPtraceEventV1 {
        self.event
    }
}

/// Linear instruction to read one syscall-info frame from one held stop.
pub(super) struct TracerSupervisorSyscallInfoReadV1 {
    session_brand: u64,
    raw_tid: i32,
    stop_generation: u64,
    kind: TracerSupervisorSyscallInfoKindV1,
}

impl TracerSupervisorSyscallInfoReadV1 {
    pub(super) const fn raw_tid(&self) -> i32 {
        self.raw_tid
    }
}

/// A linear, locally correlated seccomp-stop capability.
///
/// The private constructor is reachable only after exact planner correlation
/// and the single-live-task prerequisite. Because this pure planner cannot
/// prove that bytes came from the kernel or that a seccomp filter was installed,
/// no production issuer exists yet. The frame, including its instruction
/// pointer and raw arguments, is no longer retained after the permit is
/// consumed; dropping it does not zero its former storage.
pub(super) struct StoppedSeccompTaskPermitV1 {
    session_brand: u64,
    raw_tid: i32,
    stop_generation: u64,
    frame: DecodedSeccompSyscallInfoX8664V1,
}

/// Linear instruction to copy one exact native `clone_args` prefix while the
/// correlated seccomp stop remains held.
///
/// The raw address and syscall frame exist only in this transport token. The
/// token is neither `Clone` nor `Copy`, and its private fields prevent a
/// sibling from changing its task, stop, address, or declared length. It is
/// still only a pure-planner instruction: no process-memory read is proven.
pub(super) struct TracerSupervisorClone3ArgsReadV1 {
    session_brand: u64,
    raw_tid: i32,
    stop_generation: u64,
    address: u64,
    byte_count: usize,
    frame: DecodedSeccompSyscallInfoX8664V1,
}

impl TracerSupervisorClone3ArgsReadV1 {
    pub(super) const fn raw_tid(&self) -> i32 {
        self.raw_tid
    }

    pub(super) const fn address(&self) -> u64 {
        self.address
    }

    pub(super) const fn byte_count(&self) -> usize {
        self.byte_count
    }
}

/// One linear resume instruction. Its private correlation fields bind it to
/// one supervisor, one held stop, and one cursor position.
pub(super) struct TracerSupervisorResumeIntentV1 {
    session_brand: u64,
    position: ResumeStepPositionV1,
    raw_tid: i32,
    stop_generation: u64,
    request: TracerSupervisorResumeRequestV1,
}

impl TracerSupervisorResumeIntentV1 {
    pub(super) const fn raw_tid(&self) -> i32 {
        self.raw_tid
    }

    pub(super) const fn request(&self) -> TracerSupervisorResumeRequestV1 {
        self.request
    }
}

/// The only actions this pure planner can request.
///
/// None is evidence that a kernel operation actually occurred.
pub(super) enum TracerSupervisorIntentV1 {
    ReadEventMessage(TracerSupervisorEventMessageReadV1),
    ReadSyscallInfo(TracerSupervisorSyscallInfoReadV1),
    HoldStoppedSeccompTask(StoppedSeccompTaskPermitV1),
    ReadClone3Args(TracerSupervisorClone3ArgsReadV1),
    Resume(TracerSupervisorResumeIntentV1),
    WaitForNextStop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TracerSupervisorExecuteOnlyReasonV1 {
    InvalidRawTid,
    SessionBrandExhausted,
    UnknownRawTid,
    StopGenerationOverflow,
    TransportSequenceOverflow,
    StopWhileExchangePending,
    WaitStatusDecode(LinuxWaitStatusDecodeErrorV1),
    ContinuedStatusUnsupported,
    EventZeroStopUnsupported,
    EventStopContextAmbiguous,
    ChildInitialStopCorrelationMissing,
    UnexpectedSyscallStop,
    UnexpectedPtraceEvent,
    EventMessageResponseOutOfOrder,
    EventMessageCorrelationMismatch,
    EventMessageDecode(LinuxPtraceEventMessageDecodeErrorV1),
    EventMessageShapeMismatch,
    SyscallInfoResponseOutOfOrder,
    SyscallInfoCorrelationMismatch,
    SyscallInfoDecode(PtraceSyscallInfoDecodeErrorV1),
    SyscallInfoShapeMismatch,
    SeccompPermitResponseOutOfOrder,
    SeccompPermitCorrelationMismatch,
    Clone3ArgsReadResponseOutOfOrder,
    Clone3ArgsReadCorrelationMismatch,
    Clone3ArgsReadUnavailable,
    ForkFamilyDecode(ForkFamilyDecodeErrorV1),
    PendingForkCapacityExceeded,
    DuplicatePendingFork,
    ForkEventMismatch,
    DuplicatePendingChildStop,
    PendingChildStopCapacityExceeded,
    ChildInitialStopCorrelationAmbiguous,
    ResumeConfirmationOutOfOrder,
    ResumeCorrelationMismatch,
    IncompleteShutdown,
    TaskState(TracerTaskExecuteOnlyReasonV1),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingExchangeV1 {
    None,
    EventMessage {
        session_brand: u64,
        raw_tid: i32,
        stop_generation: u64,
        event: LinuxPtraceEventV1,
    },
    SyscallInfo {
        session_brand: u64,
        raw_tid: i32,
        stop_generation: u64,
        kind: TracerSupervisorSyscallInfoKindV1,
    },
    SeccompPermit {
        session_brand: u64,
        raw_tid: i32,
        stop_generation: u64,
    },
    Clone3ArgsRead {
        session_brand: u64,
        raw_tid: i32,
        stop_generation: u64,
        address: u64,
        byte_count: usize,
    },
    Resume {
        session_brand: u64,
        cursor: PendingResumeCursorV1,
    },
}

#[derive(Clone, Copy)]
struct PendingForkV1 {
    raw_tid: i32,
    event: LinuxPtraceEventV1,
    observation: Option<ForkFamilyBirthObservationV1>,
    held_child_raw_tid: i32,
    held_parent_stop_generation: u64,
}

impl PendingForkV1 {
    const EMPTY: Self = Self {
        raw_tid: 0,
        event: LinuxPtraceEventV1::Fork,
        observation: None,
        held_child_raw_tid: 0,
        held_parent_stop_generation: 0,
    };
}

#[derive(Clone, Copy)]
struct PendingChildStopV1 {
    raw_tid: i32,
    stop_generation: u64,
}

impl PendingChildStopV1 {
    const EMPTY: Self = Self {
        raw_tid: 0,
        stop_generation: 0,
    };
}

/// Fixed-capacity transport planner. The first rejection is permanent.
pub(super) struct TracerSupervisorStateV1 {
    session_brand: u64,
    task_state: TracerTaskStateRecorderV1,
    pending_forks: [PendingForkV1; TRACER_TASK_MAX_TASKS_V1],
    pending_child_stops: [PendingChildStopV1; MAX_PENDING_CHILD_STOPS_V1],
    next_stop_generation: u64,
    next_transport_sequence: u64,
    exchange: PendingExchangeV1,
    poisoned: Option<TracerSupervisorExecuteOnlyReasonV1>,
}

impl TracerSupervisorStateV1 {
    /// Start from one already-established, running traced task.
    ///
    /// This records logical initial birth only. It does not prove seize,
    /// options, filter installation, isolation, or the caller's prior resume.
    pub(super) fn begin<S: NormalizedTracerTaskEventSinkV1>(
        _issuer: TracerSupervisorIssuerPermitV1,
        initial_raw_tid: i32,
        sink: &mut S,
    ) -> Result<Self, TracerSupervisorExecuteOnlyReasonV1> {
        if initial_raw_tid <= 0 {
            return Err(TracerSupervisorExecuteOnlyReasonV1::InvalidRawTid);
        }
        let session_brand = NEXT_SUPERVISOR_SESSION_BRAND_V1
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |brand| {
                brand.checked_add(1)
            })
            .map_err(|_| TracerSupervisorExecuteOnlyReasonV1::SessionBrandExhausted)?;
        let mut task_state = TracerTaskStateRecorderV1::new();
        task_state
            .observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: 1,
                    raw_tid: initial_raw_tid,
                },
                sink,
            )
            .map_err(TracerSupervisorExecuteOnlyReasonV1::TaskState)?;
        Ok(Self {
            session_brand,
            task_state,
            pending_forks: [PendingForkV1::EMPTY; TRACER_TASK_MAX_TASKS_V1],
            pending_child_stops: [PendingChildStopV1::EMPTY; MAX_PENDING_CHILD_STOPS_V1],
            next_stop_generation: 1,
            next_transport_sequence: 2,
            exchange: PendingExchangeV1::None,
            poisoned: None,
        })
    }

    pub(super) fn observe_wait<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        raw_tid: i32,
        raw_status: i32,
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        self.require_healthy()?;
        if self.exchange != PendingExchangeV1::None {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::StopWhileExchangePending);
        }
        if raw_tid <= 0 {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::InvalidRawTid);
        }
        let class = match decode_linux_wait_status_x86_64_v1(raw_status) {
            Ok(class) => class,
            Err(error) => {
                return self.poison(TracerSupervisorExecuteOnlyReasonV1::WaitStatusDecode(error));
            }
        };
        let live_task = self.task_state.contains_live_raw_tid(raw_tid);
        let announced_child = self.task_state.is_announced_child_awaiting_ready(raw_tid);
        let known_task = live_task || announced_child;
        if !known_task {
            return match &class {
                LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(candidate)
                    if candidate.signal_shape
                        == LinuxPtraceEventStopSignalShapeV1::TrapInitialChildOrInterrupt =>
                {
                    let stop_generation = self.allocate_stop_generation()?;
                    self.accept_unannounced_child_initial_stop(raw_tid, stop_generation, sink)
                }
                LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(_) => {
                    self.poison(TracerSupervisorExecuteOnlyReasonV1::EventStopContextAmbiguous)
                }
                _ => self.poison(TracerSupervisorExecuteOnlyReasonV1::UnknownRawTid),
            };
        }
        if announced_child
            && !live_task
            && !matches!(
                &class,
                LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(candidate)
                    if candidate.signal_shape
                        == LinuxPtraceEventStopSignalShapeV1::TrapInitialChildOrInterrupt
            )
        {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::EventStopContextAmbiguous);
        }
        let stop_generation = self.allocate_stop_generation()?;

        match class {
            LinuxWaitStatusClassV1::Final(termination) => {
                let sequence = self.allocate_transport_sequence()?;
                self.emit_task(
                    TracerTaskObservationV1::TerminalReap {
                        sequence,
                        raw_tid,
                        termination,
                    },
                    sink,
                )?;
                self.remove_pending_fork(raw_tid)?;
                Ok(TracerSupervisorIntentV1::WaitForNextStop)
            }
            LinuxWaitStatusClassV1::SyscallEntryOrExitStop => {
                if self.task_state.pending_syscall_number(raw_tid).is_none() {
                    return self.poison(TracerSupervisorExecuteOnlyReasonV1::UnexpectedSyscallStop);
                }
                Ok(self.issue_syscall_info_read(
                    raw_tid,
                    stop_generation,
                    TracerSupervisorSyscallInfoKindV1::SyscallExit,
                ))
            }
            LinuxWaitStatusClassV1::PtraceEvent(event) => {
                self.validate_ptrace_event_for_task(raw_tid, event)?;
                Ok(self.issue_event_message_read(raw_tid, stop_generation, event))
            }
            LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(candidate) => {
                if candidate.signal_shape
                    != LinuxPtraceEventStopSignalShapeV1::TrapInitialChildOrInterrupt
                {
                    return self
                        .poison(TracerSupervisorExecuteOnlyReasonV1::EventStopContextAmbiguous);
                }
                self.accept_exact_child_initial_stop(raw_tid, stop_generation, sink)
            }
            LinuxWaitStatusClassV1::EventZeroStopRequiringSiginfo(_) => {
                self.poison(TracerSupervisorExecuteOnlyReasonV1::EventZeroStopUnsupported)
            }
            LinuxWaitStatusClassV1::Continued => {
                self.poison(TracerSupervisorExecuteOnlyReasonV1::ContinuedStatusUnsupported)
            }
        }
    }

    pub(super) fn accept_event_message<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        token: TracerSupervisorEventMessageReadV1,
        bytes: &[u8; EVENT_MESSAGE_BYTES_X86_64_V1],
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        self.require_healthy()?;
        let PendingExchangeV1::EventMessage {
            session_brand,
            raw_tid,
            stop_generation,
            event,
        } = self.exchange
        else {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::EventMessageResponseOutOfOrder);
        };
        if session_brand != self.session_brand
            || token.session_brand != session_brand
            || token.raw_tid != raw_tid
            || token.stop_generation != stop_generation
            || token.event != event
        {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::EventMessageCorrelationMismatch);
        }
        let decoded = match decode_linux_ptrace_event_message_x86_64_v1(event, bytes) {
            Ok(decoded) => decoded,
            Err(error) => {
                return self.poison(TracerSupervisorExecuteOnlyReasonV1::EventMessageDecode(
                    error,
                ));
            }
        };

        match (event, decoded) {
            (
                LinuxPtraceEventV1::Seccomp,
                DecodedLinuxPtraceEventMessageV1::SeccompTraceCookieSchemaMatched,
            ) => Ok(self.issue_syscall_info_read(
                raw_tid,
                stop_generation,
                TracerSupervisorSyscallInfoKindV1::SeccompEntry,
            )),
            (
                LinuxPtraceEventV1::Fork | LinuxPtraceEventV1::Vfork | LinuxPtraceEventV1::Clone,
                DecodedLinuxPtraceEventMessageV1::ChildTid(child_tid),
            ) => self.accept_fork_event_message(
                raw_tid,
                stop_generation,
                event,
                child_tid.raw_tid(),
                sink,
            ),
            (LinuxPtraceEventV1::Exec, DecodedLinuxPtraceEventMessageV1::FormerTid(former_tid)) => {
                let sequence = self.allocate_transport_sequence()?;
                self.emit_task(
                    TracerTaskObservationV1::Exec {
                        sequence,
                        raw_tid,
                        former_raw_tid: former_tid.raw_tid(),
                    },
                    sink,
                )?;
                let step = self.resume_step(
                    raw_tid,
                    stop_generation,
                    TracerSupervisorResumeRequestV1::Syscall,
                );
                Ok(self.issue_one_resume(step))
            }
            (
                LinuxPtraceEventV1::Exit,
                DecodedLinuxPtraceEventMessageV1::ExitTermination(termination),
            ) => {
                let sequence = self.allocate_transport_sequence()?;
                self.emit_task(
                    TracerTaskObservationV1::PtraceExitEvent {
                        sequence,
                        raw_tid,
                        termination,
                    },
                    sink,
                )?;
                self.remove_pending_fork(raw_tid)?;
                let step = self.resume_step(
                    raw_tid,
                    stop_generation,
                    TracerSupervisorResumeRequestV1::Continue,
                );
                Ok(self.issue_one_resume(step))
            }
            _ => self.poison(TracerSupervisorExecuteOnlyReasonV1::EventMessageShapeMismatch),
        }
    }

    pub(super) fn accept_syscall_info<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        token: TracerSupervisorSyscallInfoReadV1,
        returned_byte_count: usize,
        buffer: &[u8; SYSCALL_INFO_BYTES_X86_64_V1],
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        self.require_healthy()?;
        let PendingExchangeV1::SyscallInfo {
            session_brand,
            raw_tid,
            stop_generation,
            kind,
        } = self.exchange
        else {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::SyscallInfoResponseOutOfOrder);
        };
        if session_brand != self.session_brand
            || token.session_brand != session_brand
            || token.raw_tid != raw_tid
            || token.stop_generation != stop_generation
            || token.kind != kind
        {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::SyscallInfoCorrelationMismatch);
        }
        let decoded = match decode_ptrace_syscall_info_x86_64_v1(returned_byte_count, buffer) {
            Ok(decoded) => decoded,
            Err(error) => {
                return self.poison(TracerSupervisorExecuteOnlyReasonV1::SyscallInfoDecode(
                    error,
                ));
            }
        };

        match (kind, decoded) {
            (
                TracerSupervisorSyscallInfoKindV1::SeccompEntry,
                DecodedPtraceSyscallInfoX8664V1::Seccomp(frame),
            ) => {
                self.exchange = PendingExchangeV1::SeccompPermit {
                    session_brand: self.session_brand,
                    raw_tid,
                    stop_generation,
                };
                Ok(TracerSupervisorIntentV1::HoldStoppedSeccompTask(
                    StoppedSeccompTaskPermitV1 {
                        session_brand: self.session_brand,
                        raw_tid,
                        stop_generation,
                        frame,
                    },
                ))
            }
            (
                TracerSupervisorSyscallInfoKindV1::SyscallExit,
                DecodedPtraceSyscallInfoX8664V1::Exit(frame),
            ) => {
                let sequence = self.allocate_transport_sequence()?;
                self.emit_task(
                    TracerTaskObservationV1::SyscallExit {
                        sequence,
                        raw_tid,
                        result: frame.return_value(),
                    },
                    sink,
                )?;
                self.remove_pending_fork(raw_tid)?;
                let step = self.resume_step(
                    raw_tid,
                    stop_generation,
                    TracerSupervisorResumeRequestV1::Continue,
                );
                Ok(self.issue_one_resume(step))
            }
            _ => self.poison(TracerSupervisorExecuteOnlyReasonV1::SyscallInfoShapeMismatch),
        }
    }

    pub(super) fn consume_stopped_seccomp_permit<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        permit: StoppedSeccompTaskPermitV1,
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        self.require_healthy()?;
        let PendingExchangeV1::SeccompPermit {
            session_brand,
            raw_tid,
            stop_generation,
        } = self.exchange
        else {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::SeccompPermitResponseOutOfOrder);
        };
        if session_brand != self.session_brand
            || permit.session_brand != session_brand
            || permit.raw_tid != raw_tid
            || permit.stop_generation != stop_generation
        {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::SeccompPermitCorrelationMismatch);
        }
        let syscall_number = permit.frame.syscall_number();
        if syscall_number == TRACER_TASK_CLONE3_NR_X86_64_V1 {
            let read_spec = match plan_clone3_args_read_x86_64_v1(permit.frame.arguments()) {
                Ok(spec) => spec,
                Err(error) => {
                    return self
                        .poison(TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(error));
                }
            };
            let address = read_spec.address();
            let byte_count = read_spec.byte_count();
            self.exchange = PendingExchangeV1::Clone3ArgsRead {
                session_brand: self.session_brand,
                raw_tid,
                stop_generation,
                address,
                byte_count,
            };
            return Ok(TracerSupervisorIntentV1::ReadClone3Args(
                TracerSupervisorClone3ArgsReadV1 {
                    session_brand: self.session_brand,
                    raw_tid,
                    stop_generation,
                    address,
                    byte_count,
                    frame: permit.frame,
                },
            ));
        }
        self.finish_stopped_seccomp_frame(raw_tid, stop_generation, permit.frame, None, sink)
    }

    /// Consume the exact result of the requested bounded `clone_args` copy.
    ///
    /// The response remains correlated to the same held seccomp stop. No
    /// resume can be issued before this token is consumed successfully.
    pub(super) fn accept_clone3_args_read<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        token: TracerSupervisorClone3ArgsReadV1,
        capture: Clone3ArgsCaptureV1<'_>,
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        self.require_healthy()?;
        let PendingExchangeV1::Clone3ArgsRead {
            session_brand,
            raw_tid,
            stop_generation,
            address,
            byte_count,
        } = self.exchange
        else {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::Clone3ArgsReadResponseOutOfOrder);
        };
        if session_brand != self.session_brand
            || token.session_brand != session_brand
            || token.raw_tid != raw_tid
            || token.stop_generation != stop_generation
            || token.address != address
            || token.byte_count != byte_count
            || token.frame.syscall_number() != TRACER_TASK_CLONE3_NR_X86_64_V1
            || token.frame.arguments()[0] != address
            || token.frame.arguments()[1] != byte_count as u64
        {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::Clone3ArgsReadCorrelationMismatch);
        }
        let exact = match capture {
            Clone3ArgsCaptureV1::Exact {
                copied_byte_count,
                buffer,
            } => (copied_byte_count, buffer),
            Clone3ArgsCaptureV1::Unavailable => {
                return self.poison(TracerSupervisorExecuteOnlyReasonV1::Clone3ArgsReadUnavailable);
            }
            Clone3ArgsCaptureV1::NotApplicable => {
                return self.poison(TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(
                    ForkFamilyDecodeErrorV1::UnexpectedClone3Capture,
                ));
            }
        };
        self.finish_stopped_seccomp_frame(raw_tid, stop_generation, token.frame, Some(exact), sink)
    }

    fn finish_stopped_seccomp_frame<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        raw_tid: i32,
        stop_generation: u64,
        frame: DecodedSeccompSyscallInfoX8664V1,
        clone3_capture: Option<(usize, &[u8; CLONE3_ARGS_BUFFER_BYTES_V1])>,
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        let syscall_number = frame.syscall_number();
        let fork = self.decode_pending_fork(syscall_number, frame.arguments(), clone3_capture)?;
        let pending_index = if fork.is_some() {
            if self.pending_fork_index(raw_tid).is_some() {
                return self.poison(TracerSupervisorExecuteOnlyReasonV1::DuplicatePendingFork);
            }
            match self.empty_pending_fork_index() {
                Some(index) => Some(index),
                None => {
                    return self
                        .poison(TracerSupervisorExecuteOnlyReasonV1::PendingForkCapacityExceeded);
                }
            }
        } else {
            None
        };
        let sequence = self.allocate_transport_sequence()?;
        self.emit_task(
            TracerTaskObservationV1::SeccompEntry {
                sequence,
                raw_tid,
                syscall_number,
            },
            sink,
        )?;
        if let (Some(index), Some((event, observation))) = (pending_index, fork) {
            self.pending_forks[index] = PendingForkV1 {
                raw_tid,
                event,
                observation: Some(observation),
                held_child_raw_tid: 0,
                held_parent_stop_generation: 0,
            };
        }
        let step = self.resume_step(
            raw_tid,
            stop_generation,
            TracerSupervisorResumeRequestV1::Syscall,
        );
        Ok(self.issue_one_resume(step))
    }

    pub(super) fn confirm_resume_succeeded(
        &mut self,
        intent: TracerSupervisorResumeIntentV1,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        self.require_healthy()?;
        let PendingExchangeV1::Resume {
            session_brand,
            cursor,
        } = self.exchange
        else {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::ResumeConfirmationOutOfOrder);
        };
        let (expected, position) = cursor.current();
        if session_brand != self.session_brand
            || expected.session_brand != session_brand
            || intent.session_brand != session_brand
            || intent.position != position
            || intent.raw_tid != expected.raw_tid
            || intent.stop_generation != expected.stop_generation
            || intent.request != expected.request
        {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::ResumeCorrelationMismatch);
        }
        if let Some(next_cursor) = cursor.advanced() {
            self.exchange = PendingExchangeV1::Resume {
                session_brand,
                cursor: next_cursor,
            };
            Ok(TracerSupervisorIntentV1::Resume(Self::resume_intent(
                next_cursor,
            )))
        } else {
            self.exchange = PendingExchangeV1::None;
            Ok(TracerSupervisorIntentV1::WaitForNextStop)
        }
    }

    fn validate_ptrace_event_for_task(
        &mut self,
        raw_tid: i32,
        event: LinuxPtraceEventV1,
    ) -> Result<(), TracerSupervisorExecuteOnlyReasonV1> {
        match event {
            LinuxPtraceEventV1::Seccomp => {
                if self.task_state.pending_syscall_number(raw_tid).is_some() {
                    return self.poison(TracerSupervisorExecuteOnlyReasonV1::UnexpectedPtraceEvent);
                }
            }
            LinuxPtraceEventV1::Fork | LinuxPtraceEventV1::Vfork | LinuxPtraceEventV1::Clone => {
                let Some(index) = self.pending_fork_index(raw_tid) else {
                    return self.poison(TracerSupervisorExecuteOnlyReasonV1::UnexpectedPtraceEvent);
                };
                let pending = self.pending_forks[index];
                if pending.held_child_raw_tid != 0 || pending.event != event {
                    return self.poison(TracerSupervisorExecuteOnlyReasonV1::ForkEventMismatch);
                }
            }
            LinuxPtraceEventV1::Exec => {
                if !matches!(
                    self.task_state.pending_syscall_number(raw_tid),
                    Some(TRACER_TASK_EXECVE_NR_X86_64_V1 | TRACER_TASK_EXECVEAT_NR_X86_64_V1)
                ) {
                    return self.poison(TracerSupervisorExecuteOnlyReasonV1::UnexpectedPtraceEvent);
                }
            }
            LinuxPtraceEventV1::Exit => {}
        }
        Ok(())
    }

    fn accept_fork_event_message<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        parent_raw_tid: i32,
        stop_generation: u64,
        event: LinuxPtraceEventV1,
        child_raw_tid: i32,
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        let Some(parent_index) = self.pending_fork_index(parent_raw_tid) else {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::UnexpectedPtraceEvent);
        };
        let pending = self.pending_forks[parent_index];
        let Some(observation) = pending.observation else {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::ForkEventMismatch);
        };
        if pending.event != event || pending.held_child_raw_tid != 0 {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::ForkEventMismatch);
        }
        if self
            .pending_forks
            .iter()
            .enumerate()
            .any(|(index, fork)| index != parent_index && fork.held_child_raw_tid == child_raw_tid)
        {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::ChildInitialStopCorrelationAmbiguous);
        }
        let pending_child_index = self.pending_child_stop_index(child_raw_tid);
        if pending_child_index.is_none()
            && self.pending_child_stop_count() >= self.awaiting_fork_event_count()
        {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::ChildInitialStopCorrelationAmbiguous);
        }
        let sequence = self.allocate_transport_sequence()?;
        self.emit_task(
            TracerTaskObservationV1::ChildAnnouncement {
                sequence,
                parent_raw_tid,
                child_raw_tid,
                kind: observation.kind,
                group_relation: observation.relation,
            },
            sink,
        )?;
        if let Some(child_index) = pending_child_index {
            let child_stop_generation = self.pending_child_stops[child_index].stop_generation;
            self.pending_child_stops[child_index] = PendingChildStopV1::EMPTY;
            self.pending_forks[parent_index] = PendingForkV1::EMPTY;
            let child_step = self.resume_step(
                child_raw_tid,
                child_stop_generation,
                TracerSupervisorResumeRequestV1::Continue,
            );
            let parent_step = self.resume_step(
                parent_raw_tid,
                stop_generation,
                TracerSupervisorResumeRequestV1::Syscall,
            );
            Ok(self.issue_child_then_parent_resume(child_step, parent_step))
        } else {
            self.pending_forks[parent_index].held_child_raw_tid = child_raw_tid;
            self.pending_forks[parent_index].held_parent_stop_generation = stop_generation;
            self.exchange = PendingExchangeV1::None;
            Ok(TracerSupervisorIntentV1::WaitForNextStop)
        }
    }

    fn accept_unannounced_child_initial_stop<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        child_raw_tid: i32,
        stop_generation: u64,
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        if self.pending_child_stop_index(child_raw_tid).is_some() {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::DuplicatePendingChildStop);
        }
        let pending_child_count = self.pending_child_stop_count();
        let awaiting_fork_count = self.awaiting_fork_event_count();
        if awaiting_fork_count == 0 {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::EventStopContextAmbiguous);
        }
        if pending_child_count >= awaiting_fork_count {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::ChildInitialStopCorrelationAmbiguous);
        }
        let Some(index) = self.empty_pending_child_stop_index() else {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::PendingChildStopCapacityExceeded);
        };
        let sequence = self.allocate_transport_sequence()?;
        self.emit_task(
            TracerTaskObservationV1::ChildReady {
                sequence,
                child_raw_tid,
            },
            sink,
        )?;
        self.pending_child_stops[index] = PendingChildStopV1 {
            raw_tid: child_raw_tid,
            stop_generation,
        };
        Ok(TracerSupervisorIntentV1::WaitForNextStop)
    }

    fn accept_exact_child_initial_stop<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        child_raw_tid: i32,
        stop_generation: u64,
        sink: &mut S,
    ) -> Result<TracerSupervisorIntentV1, TracerSupervisorExecuteOnlyReasonV1> {
        if !self
            .task_state
            .is_announced_child_awaiting_ready(child_raw_tid)
        {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::EventStopContextAmbiguous);
        }
        let Some(parent_index) = self
            .pending_forks
            .iter()
            .position(|pending| pending.held_child_raw_tid == child_raw_tid)
        else {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::ChildInitialStopCorrelationMissing);
        };
        if self.pending_forks[parent_index + 1..]
            .iter()
            .any(|pending| pending.held_child_raw_tid == child_raw_tid)
        {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::ChildInitialStopCorrelationAmbiguous);
        }
        let parent_raw_tid = self.pending_forks[parent_index].raw_tid;
        let parent_stop_generation = self.pending_forks[parent_index].held_parent_stop_generation;
        let sequence = self.allocate_transport_sequence()?;
        self.emit_task(
            TracerTaskObservationV1::ChildReady {
                sequence,
                child_raw_tid,
            },
            sink,
        )?;
        self.pending_forks[parent_index] = PendingForkV1::EMPTY;
        let child_step = self.resume_step(
            child_raw_tid,
            stop_generation,
            TracerSupervisorResumeRequestV1::Continue,
        );
        let parent_step = self.resume_step(
            parent_raw_tid,
            parent_stop_generation,
            TracerSupervisorResumeRequestV1::Syscall,
        );
        Ok(self.issue_child_then_parent_resume(child_step, parent_step))
    }

    fn decode_pending_fork(
        &mut self,
        syscall_number: u32,
        arguments: &[u64; 6],
        clone3_capture: Option<(usize, &[u8; CLONE3_ARGS_BUFFER_BYTES_V1])>,
    ) -> Result<
        Option<(LinuxPtraceEventV1, ForkFamilyBirthObservationV1)>,
        TracerSupervisorExecuteOnlyReasonV1,
    > {
        if !matches!(
            syscall_number,
            TRACER_TASK_CLONE_NR_X86_64_V1
                | TRACER_TASK_CLONE3_NR_X86_64_V1
                | TRACER_TASK_FORK_NR_X86_64_V1
                | TRACER_TASK_VFORK_NR_X86_64_V1
        ) {
            return Ok(None);
        }

        for event in [
            LinuxPtraceEventV1::Fork,
            LinuxPtraceEventV1::Vfork,
            LinuxPtraceEventV1::Clone,
        ] {
            let capture = match clone3_capture {
                Some((copied_byte_count, buffer)) => Clone3ArgsCaptureV1::Exact {
                    copied_byte_count,
                    buffer,
                },
                None => Clone3ArgsCaptureV1::NotApplicable,
            };
            match decode_fork_family_entry_x86_64_v1(syscall_number, arguments, capture, event) {
                Ok(observation) => return Ok(Some((event, observation))),
                Err(ForkFamilyDecodeErrorV1::PtraceEventMismatch) => {}
                Err(error) => {
                    return self
                        .poison(TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(error));
                }
            }
        }
        self.poison(TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(
            ForkFamilyDecodeErrorV1::PtraceEventMismatch,
        ))
    }

    fn issue_event_message_read(
        &mut self,
        raw_tid: i32,
        stop_generation: u64,
        event: LinuxPtraceEventV1,
    ) -> TracerSupervisorIntentV1 {
        self.exchange = PendingExchangeV1::EventMessage {
            session_brand: self.session_brand,
            raw_tid,
            stop_generation,
            event,
        };
        TracerSupervisorIntentV1::ReadEventMessage(TracerSupervisorEventMessageReadV1 {
            session_brand: self.session_brand,
            raw_tid,
            stop_generation,
            event,
        })
    }

    fn issue_syscall_info_read(
        &mut self,
        raw_tid: i32,
        stop_generation: u64,
        kind: TracerSupervisorSyscallInfoKindV1,
    ) -> TracerSupervisorIntentV1 {
        self.exchange = PendingExchangeV1::SyscallInfo {
            session_brand: self.session_brand,
            raw_tid,
            stop_generation,
            kind,
        };
        TracerSupervisorIntentV1::ReadSyscallInfo(TracerSupervisorSyscallInfoReadV1 {
            session_brand: self.session_brand,
            raw_tid,
            stop_generation,
            kind,
        })
    }

    fn resume_step(
        &self,
        raw_tid: i32,
        stop_generation: u64,
        request: TracerSupervisorResumeRequestV1,
    ) -> PendingResumeStepV1 {
        PendingResumeStepV1 {
            session_brand: self.session_brand,
            raw_tid,
            stop_generation,
            request,
        }
    }

    fn issue_one_resume(&mut self, step: PendingResumeStepV1) -> TracerSupervisorIntentV1 {
        self.issue_resume_cursor(PendingResumeCursorV1::One(step))
    }

    fn issue_child_then_parent_resume(
        &mut self,
        child: PendingResumeStepV1,
        parent: PendingResumeStepV1,
    ) -> TracerSupervisorIntentV1 {
        self.issue_resume_cursor(PendingResumeCursorV1::ChildThenParent { child, parent })
    }

    fn issue_resume_cursor(&mut self, cursor: PendingResumeCursorV1) -> TracerSupervisorIntentV1 {
        self.exchange = PendingExchangeV1::Resume {
            session_brand: self.session_brand,
            cursor,
        };
        TracerSupervisorIntentV1::Resume(Self::resume_intent(cursor))
    }

    fn resume_intent(cursor: PendingResumeCursorV1) -> TracerSupervisorResumeIntentV1 {
        let (step, position) = cursor.current();
        TracerSupervisorResumeIntentV1 {
            session_brand: step.session_brand,
            position,
            raw_tid: step.raw_tid,
            stop_generation: step.stop_generation,
            request: step.request,
        }
    }

    fn emit_task<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        observation: TracerTaskObservationV1,
        sink: &mut S,
    ) -> Result<(), TracerSupervisorExecuteOnlyReasonV1> {
        match self.task_state.observe(observation, sink) {
            Ok(()) => Ok(()),
            Err(error) => self.poison(TracerSupervisorExecuteOnlyReasonV1::TaskState(error)),
        }
    }

    fn pending_fork_index(&self, raw_tid: i32) -> Option<usize> {
        self.pending_forks
            .iter()
            .position(|pending| pending.raw_tid == raw_tid)
    }

    fn empty_pending_fork_index(&self) -> Option<usize> {
        self.pending_forks
            .iter()
            .position(|pending| pending.raw_tid == 0)
    }

    fn awaiting_fork_event_count(&self) -> usize {
        self.pending_forks
            .iter()
            .filter(|pending| pending.raw_tid != 0 && pending.held_child_raw_tid == 0)
            .count()
    }

    fn pending_child_stop_count(&self) -> usize {
        self.pending_child_stops
            .iter()
            .filter(|pending| pending.raw_tid != 0)
            .count()
    }

    fn pending_child_stop_index(&self, raw_tid: i32) -> Option<usize> {
        self.pending_child_stops
            .iter()
            .position(|pending| pending.raw_tid == raw_tid)
    }

    fn empty_pending_child_stop_index(&self) -> Option<usize> {
        self.pending_child_stop_index(0)
    }

    fn remove_pending_fork(
        &mut self,
        raw_tid: i32,
    ) -> Result<(), TracerSupervisorExecuteOnlyReasonV1> {
        if let Some(index) = self.pending_fork_index(raw_tid) {
            self.pending_forks[index] = PendingForkV1::EMPTY;
        }
        if self.pending_child_stop_count() > self.awaiting_fork_event_count() {
            return self
                .poison(TracerSupervisorExecuteOnlyReasonV1::ChildInitialStopCorrelationAmbiguous);
        }
        Ok(())
    }

    fn allocate_stop_generation(&mut self) -> Result<u64, TracerSupervisorExecuteOnlyReasonV1> {
        let generation = self.next_stop_generation;
        let Some(next) = generation.checked_add(1) else {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::StopGenerationOverflow);
        };
        self.next_stop_generation = next;
        Ok(generation)
    }

    fn allocate_transport_sequence(&mut self) -> Result<u64, TracerSupervisorExecuteOnlyReasonV1> {
        let sequence = self.next_transport_sequence;
        let Some(next) = sequence.checked_add(1) else {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::TransportSequenceOverflow);
        };
        self.next_transport_sequence = next;
        Ok(sequence)
    }

    fn require_healthy(&self) -> Result<(), TracerSupervisorExecuteOnlyReasonV1> {
        match self.poisoned {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    /// Consume a fully drained planner after the connector has independently
    /// proven final `ECHILD` and completed signal/descriptor cleanup.
    pub(super) fn complete(
        mut self,
        _cleanup: TracerSupervisorCleanupCompletionPermitV1,
    ) -> Result<CompletedTracerSupervisorStateV1, TracerSupervisorExecuteOnlyReasonV1> {
        self.require_healthy()?;
        if self.exchange != PendingExchangeV1::None
            || self
                .pending_forks
                .iter()
                .any(|pending| pending.raw_tid != 0)
            || self
                .pending_child_stops
                .iter()
                .any(|pending| pending.raw_tid != 0)
        {
            return self.poison(TracerSupervisorExecuteOnlyReasonV1::IncompleteShutdown);
        }
        let completed = self
            .task_state
            .complete()
            .map_err(TracerSupervisorExecuteOnlyReasonV1::TaskState)?;
        Ok(CompletedTracerSupervisorStateV1 {
            summary: completed.summary(),
        })
    }

    fn poison<T>(
        &mut self,
        reason: TracerSupervisorExecuteOnlyReasonV1,
    ) -> Result<T, TracerSupervisorExecuteOnlyReasonV1> {
        let first = *self.poisoned.get_or_insert(reason);
        Err(first)
    }
}

/// Redacted completion of the pure planner and task lifecycle recorder.
///
/// This carries no raw TID, descriptor, stopped frame, EffectIR object,
/// execution authority, or reuse authority.
pub(super) struct CompletedTracerSupervisorStateV1 {
    summary: super::tracer_task_state::TracerTaskCompletionSummaryV1,
}

impl CompletedTracerSupervisorStateV1 {
    pub(super) const fn summary(&self) -> super::tracer_task_state::TracerTaskCompletionSummaryV1 {
        self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::super::tracer_task_state::NormalizedTracerTaskEventV1;
    use super::*;

    const ROOT_TID: i32 = 41_001;
    const CHILD_TID: i32 = 42_001;
    const GRANDCHILD_A_TID: i32 = 43_001;
    const GRANDCHILD_B_TID: i32 = 44_001;
    const SIGCHLD: u64 = 17;
    const SIGTRAP: u8 = 5;
    const SIGSTOP: u8 = 19;
    const PTRACE_EVENT_STOP: u16 = 128;

    struct FixedSinkV1<const N: usize> {
        events: [Option<NormalizedTracerTaskEventV1>; N],
        length: usize,
    }

    impl<const N: usize> FixedSinkV1<N> {
        const fn new() -> Self {
            Self {
                events: [None; N],
                length: 0,
            }
        }
    }

    impl<const N: usize> NormalizedTracerTaskEventSinkV1 for FixedSinkV1<N> {
        fn emit(&mut self, event: NormalizedTracerTaskEventV1) -> Result<(), ()> {
            if self.length == N {
                return Err(());
            }
            self.events[self.length] = Some(event);
            self.length += 1;
            Ok(())
        }
    }

    fn ptrace_event_status(event: LinuxPtraceEventV1) -> i32 {
        (i32::from(event as u16) << 16) | (i32::from(SIGTRAP) << 8) | 0x7f
    }

    fn event_stop_status(signal: u8) -> i32 {
        (i32::from(PTRACE_EVENT_STOP) << 16) | (i32::from(signal) << 8) | 0x7f
    }

    fn syscall_stop_status() -> i32 {
        (i32::from(SIGTRAP | 0x80) << 8) | 0x7f
    }

    fn event_message(value: u64) -> [u8; EVENT_MESSAGE_BYTES_X86_64_V1] {
        value.to_le_bytes()
    }

    fn write_u32(buffer: &mut [u8; SYSCALL_INFO_BYTES_X86_64_V1], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buffer: &mut [u8; SYSCALL_INFO_BYTES_X86_64_V1], offset: usize, value: u64) {
        buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn seccomp_info(
        syscall_number: u32,
        arguments: [u64; 6],
    ) -> [u8; SYSCALL_INFO_BYTES_X86_64_V1] {
        let mut buffer = [0_u8; SYSCALL_INFO_BYTES_X86_64_V1];
        buffer[0] = 3;
        write_u32(&mut buffer, 4, 0xc000_003e);
        write_u64(&mut buffer, 8, 0x0000_7fff_1234_5678);
        write_u64(&mut buffer, 24, u64::from(syscall_number));
        for (index, argument) in arguments.into_iter().enumerate() {
            write_u64(&mut buffer, 32 + index * 8, argument);
        }
        write_u32(
            &mut buffer,
            80,
            u32::from(super::super::tracer_seccomp::trace_all_native_seccomp_cookie_spec_v1()),
        );
        buffer
    }

    fn exit_info(return_value: i64) -> [u8; SYSCALL_INFO_BYTES_X86_64_V1] {
        let mut buffer = [0_u8; SYSCALL_INFO_BYTES_X86_64_V1];
        buffer[0] = 2;
        write_u32(&mut buffer, 4, 0xc000_003e);
        write_u64(&mut buffer, 8, 0x0000_7fff_1234_5678);
        write_u64(&mut buffer, 24, return_value as u64);
        buffer[32] = u8::from((-4095..=-1).contains(&return_value));
        buffer
    }

    fn take_event_read(intent: TracerSupervisorIntentV1) -> TracerSupervisorEventMessageReadV1 {
        match intent {
            TracerSupervisorIntentV1::ReadEventMessage(token) => token,
            _ => panic!("expected event-message read"),
        }
    }

    fn take_syscall_read(intent: TracerSupervisorIntentV1) -> TracerSupervisorSyscallInfoReadV1 {
        match intent {
            TracerSupervisorIntentV1::ReadSyscallInfo(token) => token,
            _ => panic!("expected syscall-info read"),
        }
    }

    fn take_seccomp_permit(intent: TracerSupervisorIntentV1) -> StoppedSeccompTaskPermitV1 {
        match intent {
            TracerSupervisorIntentV1::HoldStoppedSeccompTask(permit) => permit,
            _ => panic!("expected stopped-seccomp permit"),
        }
    }

    fn take_clone3_read(intent: TracerSupervisorIntentV1) -> TracerSupervisorClone3ArgsReadV1 {
        match intent {
            TracerSupervisorIntentV1::ReadClone3Args(token) => token,
            _ => panic!("expected clone3 args read"),
        }
    }

    fn take_resume(intent: TracerSupervisorIntentV1) -> TracerSupervisorResumeIntentV1 {
        match intent {
            TracerSupervisorIntentV1::Resume(intent) => intent,
            _ => panic!("expected resume intent"),
        }
    }

    fn begin<const N: usize>(sink: &mut FixedSinkV1<N>) -> TracerSupervisorStateV1 {
        TracerSupervisorStateV1::begin(
            TracerSupervisorIssuerPermitV1::issue_for_test(),
            ROOT_TID,
            sink,
        )
        .expect("initial birth")
    }

    fn reach_seccomp_syscall_read<const N: usize>(
        supervisor: &mut TracerSupervisorStateV1,
        raw_tid: i32,
        sink: &mut FixedSinkV1<N>,
    ) -> TracerSupervisorSyscallInfoReadV1 {
        let event_read = take_event_read(
            supervisor
                .observe_wait(
                    raw_tid,
                    ptrace_event_status(LinuxPtraceEventV1::Seccomp),
                    sink,
                )
                .expect("seccomp wait"),
        );
        assert_eq!(event_read.raw_tid(), raw_tid);
        let cookie =
            u64::from(super::super::tracer_seccomp::trace_all_native_seccomp_cookie_spec_v1());
        let syscall_read = take_syscall_read(
            supervisor
                .accept_event_message(event_read, &event_message(cookie), sink)
                .expect("seccomp event message"),
        );
        assert_eq!(syscall_read.raw_tid(), raw_tid);
        syscall_read
    }

    fn reach_seccomp_permit<const N: usize>(
        supervisor: &mut TracerSupervisorStateV1,
        raw_tid: i32,
        syscall_number: u32,
        arguments: [u64; 6],
        sink: &mut FixedSinkV1<N>,
    ) -> StoppedSeccompTaskPermitV1 {
        let syscall_read = reach_seccomp_syscall_read(supervisor, raw_tid, sink);
        take_seccomp_permit(
            supervisor
                .accept_syscall_info(
                    syscall_read,
                    84,
                    &seccomp_info(syscall_number, arguments),
                    sink,
                )
                .expect("seccomp syscall info"),
        )
    }

    fn enter_syscall<const N: usize>(
        supervisor: &mut TracerSupervisorStateV1,
        raw_tid: i32,
        syscall_number: u32,
        arguments: [u64; 6],
        sink: &mut FixedSinkV1<N>,
    ) {
        let permit = reach_seccomp_permit(supervisor, raw_tid, syscall_number, arguments, sink);
        assert_eq!(permit.raw_tid, raw_tid);
        assert_eq!(permit.frame.syscall_number(), syscall_number);
        assert_eq!(permit.frame.arguments(), &arguments);
        let resume = take_resume(
            supervisor
                .consume_stopped_seccomp_permit(permit, sink)
                .expect("consume seccomp permit"),
        );
        assert_eq!(resume.raw_tid(), raw_tid);
        assert_eq!(resume.request(), TracerSupervisorResumeRequestV1::Syscall);
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(resume)
                .expect("confirm seccomp resume"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
    }

    fn clone3_buffer(flags: u64, exit_signal: u64) -> [u8; CLONE3_ARGS_BUFFER_BYTES_V1] {
        let mut buffer = [0_u8; CLONE3_ARGS_BUFFER_BYTES_V1];
        buffer[0..8].copy_from_slice(&flags.to_le_bytes());
        buffer[32..40].copy_from_slice(&exit_signal.to_le_bytes());
        buffer
    }

    fn reach_clone3_read<const N: usize>(
        supervisor: &mut TracerSupervisorStateV1,
        raw_tid: i32,
        address: u64,
        declared_size: usize,
        sink: &mut FixedSinkV1<N>,
    ) -> TracerSupervisorClone3ArgsReadV1 {
        let permit = reach_seccomp_permit(
            supervisor,
            raw_tid,
            TRACER_TASK_CLONE3_NR_X86_64_V1,
            [address, declared_size as u64, 0, 0, 0, 0],
            sink,
        );
        take_clone3_read(
            supervisor
                .consume_stopped_seccomp_permit(permit, sink)
                .expect("plan clone3 args read"),
        )
    }

    fn enter_clone3<const N: usize>(
        supervisor: &mut TracerSupervisorStateV1,
        raw_tid: i32,
        address: u64,
        declared_size: usize,
        sink: &mut FixedSinkV1<N>,
    ) {
        let read = reach_clone3_read(supervisor, raw_tid, address, declared_size, sink);
        assert_eq!(read.raw_tid(), raw_tid);
        assert_eq!(read.address(), address);
        assert_eq!(read.byte_count(), declared_size);
        let buffer = clone3_buffer(0, SIGCHLD);
        let resume = take_resume(
            supervisor
                .accept_clone3_args_read(
                    read,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: declared_size,
                        buffer: &buffer,
                    },
                    sink,
                )
                .expect("accept clone3 args read"),
        );
        assert_eq!(resume.raw_tid(), raw_tid);
        assert_eq!(resume.request(), TracerSupervisorResumeRequestV1::Syscall);
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(resume)
                .expect("confirm clone3 seccomp resume"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
    }

    fn finish_syscall<const N: usize>(
        supervisor: &mut TracerSupervisorStateV1,
        raw_tid: i32,
        result: i64,
        sink: &mut FixedSinkV1<N>,
    ) {
        let read = take_syscall_read(
            supervisor
                .observe_wait(raw_tid, syscall_stop_status(), sink)
                .expect("syscall-exit stop"),
        );
        let resume = take_resume(
            supervisor
                .accept_syscall_info(read, 33, &exit_info(result), sink)
                .expect("syscall-exit info"),
        );
        assert_eq!(resume.raw_tid(), raw_tid);
        assert_eq!(resume.request(), TracerSupervisorResumeRequestV1::Continue);
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(resume)
                .expect("confirm syscall-exit resume"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
    }

    fn finish_zero_exit<const N: usize>(
        supervisor: &mut TracerSupervisorStateV1,
        raw_tid: i32,
        sink: &mut FixedSinkV1<N>,
    ) {
        enter_syscall(
            supervisor,
            raw_tid,
            super::super::tracer_task_state::TRACER_TASK_EXIT_NR_X86_64_V1,
            [0; 6],
            sink,
        );
        let exit_read = take_event_read(
            supervisor
                .observe_wait(raw_tid, ptrace_event_status(LinuxPtraceEventV1::Exit), sink)
                .expect("ptrace exit event"),
        );
        let resume = take_resume(
            supervisor
                .accept_event_message(exit_read, &event_message(0), sink)
                .expect("zero exit message"),
        );
        assert_eq!(resume.request(), TracerSupervisorResumeRequestV1::Continue);
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(resume)
                .expect("confirm exit resume"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        assert!(matches!(
            supervisor
                .observe_wait(raw_tid, 0, sink)
                .expect("terminal zero reap"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
    }

    fn confirm_child_then_parent(
        supervisor: &mut TracerSupervisorStateV1,
        intent: TracerSupervisorIntentV1,
        child_raw_tid: i32,
        parent_raw_tid: i32,
    ) {
        let child = take_resume(intent);
        assert!(child.position == ResumeStepPositionV1::OnlyOrChild);
        assert_eq!(child.raw_tid(), child_raw_tid);
        assert_eq!(child.request(), TracerSupervisorResumeRequestV1::Continue);
        let parent = take_resume(supervisor.confirm_resume_succeeded(child).unwrap());
        assert!(parent.position == ResumeStepPositionV1::Parent);
        assert_eq!(parent.raw_tid(), parent_raw_tid);
        assert_eq!(parent.request(), TracerSupervisorResumeRequestV1::Syscall);
        assert!(matches!(
            supervisor.confirm_resume_succeeded(parent).unwrap(),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
    }

    #[test]
    fn exact_seccomp_syscall_exit_and_signal_exit_path() {
        let mut sink = FixedSinkV1::<16>::new();
        let mut supervisor = begin(&mut sink);
        enter_syscall(&mut supervisor, ROOT_TID, 39, [0; 6], &mut sink);
        finish_syscall(&mut supervisor, ROOT_TID, ROOT_TID.into(), &mut sink);

        let exit_read = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Exit),
                    &mut sink,
                )
                .expect("exit event"),
        );
        let resume = take_resume(
            supervisor
                .accept_event_message(exit_read, &event_message(9), &mut sink)
                .expect("exit message"),
        );
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(resume)
                .expect("confirm terminal resume"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        assert!(matches!(
            supervisor
                .observe_wait(ROOT_TID, 9, &mut sink)
                .expect("terminal reap"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        assert_eq!(sink.length, 5);
    }

    #[test]
    fn exact_fork_event_holds_parent_until_distinct_child_initial_stop() {
        let mut sink = FixedSinkV1::<16>::new();
        let mut supervisor = begin(&mut sink);
        enter_syscall(
            &mut supervisor,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );

        let fork_read = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .expect("fork event"),
        );
        assert!(matches!(
            supervisor
                .accept_event_message(fork_read, &event_message(CHILD_TID as u64), &mut sink,)
                .expect("child TID"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));

        let child_resume = take_resume(
            supervisor
                .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                .expect("distinct child initial stop"),
        );
        assert!(child_resume.position == ResumeStepPositionV1::OnlyOrChild);
        assert_eq!(child_resume.raw_tid(), CHILD_TID);
        assert_eq!(child_resume.stop_generation, 3);
        assert_eq!(
            child_resume.request(),
            TracerSupervisorResumeRequestV1::Continue
        );
        let parent_resume = take_resume(
            supervisor
                .confirm_resume_succeeded(child_resume)
                .expect("resume child"),
        );
        assert!(parent_resume.position == ResumeStepPositionV1::Parent);
        assert_eq!(parent_resume.raw_tid(), ROOT_TID);
        assert_eq!(parent_resume.stop_generation, 2);
        assert_eq!(
            parent_resume.request(),
            TracerSupervisorResumeRequestV1::Syscall
        );
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(parent_resume)
                .expect("resume parent"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        finish_syscall(&mut supervisor, ROOT_TID, CHILD_TID.into(), &mut sink);
        assert_eq!(sink.length, 4);
    }

    #[test]
    fn child_initial_stop_before_parent_event_correlates_by_exact_tid() {
        let mut sink = FixedSinkV1::<16>::new();
        let mut supervisor = begin(&mut sink);
        enter_syscall(
            &mut supervisor,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );

        assert!(matches!(
            supervisor
                .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                .expect("unannounced child initial stop"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        let fork_read = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .expect("parent fork event"),
        );
        let child_resume = take_resume(
            supervisor
                .accept_event_message(fork_read, &event_message(CHILD_TID as u64), &mut sink)
                .expect("exact retained child"),
        );
        assert_eq!(child_resume.raw_tid(), CHILD_TID);
        assert_eq!(child_resume.stop_generation, 2);
        let parent_resume = take_resume(
            supervisor
                .confirm_resume_succeeded(child_resume)
                .expect("resume retained child"),
        );
        assert_eq!(parent_resume.raw_tid(), ROOT_TID);
        assert_eq!(parent_resume.stop_generation, 3);
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(parent_resume)
                .expect("resume exact parent"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        finish_syscall(&mut supervisor, ROOT_TID, CHILD_TID.into(), &mut sink);
        assert_eq!(sink.length, 4);
    }

    #[test]
    fn wait_between_child_and_parent_resume_confirmations_is_terminal() {
        let mut sink = FixedSinkV1::<16>::new();
        let mut supervisor = begin(&mut sink);
        enter_syscall(
            &mut supervisor,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );
        let fork_read = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .unwrap(),
        );
        supervisor
            .accept_event_message(fork_read, &event_message(CHILD_TID as u64), &mut sink)
            .unwrap();
        let child_resume = take_resume(
            supervisor
                .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                .unwrap(),
        );
        let _parent_resume =
            take_resume(supervisor.confirm_resume_succeeded(child_resume).unwrap());
        assert_eq!(
            supervisor
                .observe_wait(ROOT_TID, syscall_stop_status(), &mut sink)
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::StopWhileExchangePending)
        );
    }

    #[test]
    fn two_child_first_stops_correlate_by_event_tid_not_arrival_order() {
        let mut sink = FixedSinkV1::<64>::new();
        let mut supervisor = begin(&mut sink);

        enter_syscall(
            &mut supervisor,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );
        let first_fork = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .unwrap(),
        );
        supervisor
            .accept_event_message(first_fork, &event_message(CHILD_TID as u64), &mut sink)
            .unwrap();
        let first_child = supervisor
            .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
            .unwrap();
        confirm_child_then_parent(&mut supervisor, first_child, CHILD_TID, ROOT_TID);
        finish_syscall(&mut supervisor, ROOT_TID, CHILD_TID.into(), &mut sink);

        enter_syscall(
            &mut supervisor,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );
        enter_syscall(
            &mut supervisor,
            CHILD_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );
        for child_raw_tid in [GRANDCHILD_A_TID, GRANDCHILD_B_TID] {
            assert!(matches!(
                supervisor
                    .observe_wait(child_raw_tid, event_stop_status(SIGTRAP), &mut sink)
                    .unwrap(),
                TracerSupervisorIntentV1::WaitForNextStop
            ));
        }

        let root_fork = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .unwrap(),
        );
        let root_pair = supervisor
            .accept_event_message(
                root_fork,
                &event_message(GRANDCHILD_B_TID as u64),
                &mut sink,
            )
            .unwrap();
        confirm_child_then_parent(&mut supervisor, root_pair, GRANDCHILD_B_TID, ROOT_TID);

        let child_fork = take_event_read(
            supervisor
                .observe_wait(
                    CHILD_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .unwrap(),
        );
        let child_pair = supervisor
            .accept_event_message(
                child_fork,
                &event_message(GRANDCHILD_A_TID as u64),
                &mut sink,
            )
            .unwrap();
        confirm_child_then_parent(&mut supervisor, child_pair, GRANDCHILD_A_TID, CHILD_TID);
        finish_syscall(
            &mut supervisor,
            ROOT_TID,
            GRANDCHILD_B_TID.into(),
            &mut sink,
        );
        finish_syscall(
            &mut supervisor,
            CHILD_TID,
            GRANDCHILD_A_TID.into(),
            &mut sink,
        );
    }

    #[test]
    fn exact_exec_event_is_correlated_before_syscall_exit() {
        let mut sink = FixedSinkV1::<16>::new();
        let mut supervisor = begin(&mut sink);
        enter_syscall(&mut supervisor, ROOT_TID, 59, [0; 6], &mut sink);
        let exec_read = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Exec),
                    &mut sink,
                )
                .expect("exec event"),
        );
        let resume = take_resume(
            supervisor
                .accept_event_message(exec_read, &event_message(ROOT_TID as u64), &mut sink)
                .expect("exec former TID"),
        );
        assert_eq!(resume.raw_tid(), ROOT_TID);
        assert_eq!(resume.request(), TracerSupervisorResumeRequestV1::Syscall);
        assert!(matches!(
            supervisor
                .confirm_resume_succeeded(resume)
                .expect("resume to exec exit"),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        finish_syscall(&mut supervisor, ROOT_TID, 0, &mut sink);
        assert_eq!(sink.length, 4);
    }

    #[test]
    fn wrong_tid_and_wrong_event_are_exact_permanent_correlation_failures() {
        for wrong_tid in [true, false] {
            let mut sink = FixedSinkV1::<8>::new();
            let mut supervisor = begin(&mut sink);
            let mut token = take_event_read(
                supervisor
                    .observe_wait(
                        ROOT_TID,
                        ptrace_event_status(LinuxPtraceEventV1::Seccomp),
                        &mut sink,
                    )
                    .unwrap(),
            );
            if wrong_tid {
                token.raw_tid += 1;
            } else {
                token.event = LinuxPtraceEventV1::Fork;
            }
            let error = supervisor
                .accept_event_message(token, &event_message(0), &mut sink)
                .err();
            assert_eq!(
                error,
                Some(TracerSupervisorExecuteOnlyReasonV1::EventMessageCorrelationMismatch)
            );
            assert_eq!(supervisor.observe_wait(ROOT_TID, 9, &mut sink).err(), error);
        }
    }

    #[test]
    fn duplicate_response_and_out_of_order_syscall_exit_poison_once() {
        let mut sink = FixedSinkV1::<8>::new();
        let mut supervisor = begin(&mut sink);
        let token = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Seccomp),
                    &mut sink,
                )
                .unwrap(),
        );
        let generation = token.stop_generation;
        let session_brand = token.session_brand;
        let cookie =
            u64::from(super::super::tracer_seccomp::trace_all_native_seccomp_cookie_spec_v1());
        let _next = supervisor
            .accept_event_message(token, &event_message(cookie), &mut sink)
            .unwrap();
        let duplicate = TracerSupervisorEventMessageReadV1 {
            session_brand,
            raw_tid: ROOT_TID,
            stop_generation: generation,
            event: LinuxPtraceEventV1::Seccomp,
        };
        assert_eq!(
            supervisor
                .accept_event_message(duplicate, &event_message(cookie), &mut sink)
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::EventMessageResponseOutOfOrder)
        );

        let mut sink = FixedSinkV1::<8>::new();
        let mut supervisor = begin(&mut sink);
        assert_eq!(
            supervisor
                .observe_wait(ROOT_TID, syscall_stop_status(), &mut sink)
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::UnexpectedSyscallStop)
        );
    }

    #[test]
    fn ambiguous_child_or_interrupt_and_continued_stops_fail_closed() {
        for raw_status in [
            event_stop_status(SIGTRAP),
            event_stop_status(SIGSTOP),
            0xffff,
        ] {
            let mut sink = FixedSinkV1::<8>::new();
            let mut supervisor = begin(&mut sink);
            let expected = if raw_status == 0xffff {
                TracerSupervisorExecuteOnlyReasonV1::ContinuedStatusUnsupported
            } else {
                TracerSupervisorExecuteOnlyReasonV1::EventStopContextAmbiguous
            };
            assert_eq!(
                supervisor
                    .observe_wait(ROOT_TID, raw_status, &mut sink)
                    .err(),
                Some(expected)
            );
        }
    }

    #[test]
    fn unannounced_child_stop_duplicates_and_overcommit_fail_closed() {
        for (second_tid, expected) in [
            (
                CHILD_TID,
                TracerSupervisorExecuteOnlyReasonV1::DuplicatePendingChildStop,
            ),
            (
                GRANDCHILD_A_TID,
                TracerSupervisorExecuteOnlyReasonV1::ChildInitialStopCorrelationAmbiguous,
            ),
        ] {
            let mut sink = FixedSinkV1::<16>::new();
            let mut supervisor = begin(&mut sink);
            enter_syscall(
                &mut supervisor,
                ROOT_TID,
                TRACER_TASK_FORK_NR_X86_64_V1,
                [0; 6],
                &mut sink,
            );
            assert!(matches!(
                supervisor
                    .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                    .unwrap(),
                TracerSupervisorIntentV1::WaitForNextStop
            ));
            assert_eq!(
                supervisor
                    .observe_wait(second_tid, event_stop_status(SIGTRAP), &mut sink)
                    .err(),
                Some(expected)
            );
        }
    }

    #[test]
    fn announced_child_accepts_only_its_exact_initial_stop() {
        let mut sink = FixedSinkV1::<16>::new();
        let mut supervisor = begin(&mut sink);
        enter_syscall(
            &mut supervisor,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );
        let fork_read = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .unwrap(),
        );
        supervisor
            .accept_event_message(fork_read, &event_message(CHILD_TID as u64), &mut sink)
            .unwrap();
        assert_eq!(
            supervisor.observe_wait(CHILD_TID, 9, &mut sink).err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::EventStopContextAmbiguous)
        );
    }

    #[test]
    fn stop_generation_overflow_is_typed_and_sticky() {
        let mut sink = FixedSinkV1::<8>::new();
        let mut supervisor = begin(&mut sink);
        supervisor.next_stop_generation = u64::MAX;
        let error = supervisor
            .observe_wait(
                ROOT_TID,
                ptrace_event_status(LinuxPtraceEventV1::Exit),
                &mut sink,
            )
            .err();
        assert_eq!(
            error,
            Some(TracerSupervisorExecuteOnlyReasonV1::StopGenerationOverflow)
        );
        assert_eq!(supervisor.observe_wait(ROOT_TID, 9, &mut sink).err(), error);
    }

    #[test]
    fn decoder_mismatch_and_unknown_tid_are_permanent() {
        let mut sink = FixedSinkV1::<8>::new();
        let mut supervisor = begin(&mut sink);
        assert_eq!(
            supervisor.observe_wait(ROOT_TID + 1, 9, &mut sink).err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::UnknownRawTid)
        );
        assert_eq!(
            supervisor.observe_wait(ROOT_TID, 9, &mut sink).err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::UnknownRawTid)
        );

        let mut sink = FixedSinkV1::<8>::new();
        let mut supervisor = begin(&mut sink);
        let token = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Seccomp),
                    &mut sink,
                )
                .unwrap(),
        );
        assert!(matches!(
            supervisor
                .accept_event_message(token, &event_message(0), &mut sink)
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::EventMessageDecode(
                LinuxPtraceEventMessageDecodeErrorV1::SeccompTraceCookieSchemaMismatch
            ))
        ));
    }

    #[test]
    fn multiple_live_tasks_allow_normal_syscalls_and_bounded_clone3_capture() {
        let mut sink = FixedSinkV1::<16>::new();
        let mut supervisor = begin(&mut sink);
        enter_syscall(
            &mut supervisor,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            [0; 6],
            &mut sink,
        );
        let fork_read = take_event_read(
            supervisor
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Fork),
                    &mut sink,
                )
                .unwrap(),
        );
        assert!(matches!(
            supervisor
                .accept_event_message(fork_read, &event_message(CHILD_TID as u64), &mut sink,)
                .unwrap(),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        let resume = take_resume(
            supervisor
                .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                .unwrap(),
        );
        let parent_resume = take_resume(supervisor.confirm_resume_succeeded(resume).unwrap());
        assert!(matches!(
            supervisor.confirm_resume_succeeded(parent_resume).unwrap(),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        finish_syscall(&mut supervisor, ROOT_TID, CHILD_TID.into(), &mut sink);

        let permit = reach_seccomp_permit(&mut supervisor, ROOT_TID, 39, [0; 6], &mut sink);
        let resume = take_resume(
            supervisor
                .consume_stopped_seccomp_permit(permit, &mut sink)
                .expect("ordinary syscall needs no process-memory read"),
        );
        assert!(matches!(
            supervisor.confirm_resume_succeeded(resume).unwrap(),
            TracerSupervisorIntentV1::WaitForNextStop
        ));
        finish_syscall(&mut supervisor, ROOT_TID, ROOT_TID.into(), &mut sink);

        enter_clone3(&mut supervisor, ROOT_TID, 0x1000, 88, &mut sink);
    }

    #[test]
    fn clone3_published_versions_request_exact_bounded_copy_before_resume() {
        for declared_size in [64, 80, 88] {
            let mut sink = FixedSinkV1::<16>::new();
            let mut supervisor = begin(&mut sink);
            let address = 0x1000 + declared_size as u64;
            let read =
                reach_clone3_read(&mut supervisor, ROOT_TID, address, declared_size, &mut sink);
            assert_eq!(read.raw_tid(), ROOT_TID);
            assert_eq!(read.address(), address);
            assert_eq!(read.byte_count(), declared_size);
            assert_eq!(sink.length, 1);

            let buffer = clone3_buffer(0, SIGCHLD);
            let resume = take_resume(
                supervisor
                    .accept_clone3_args_read(
                        read,
                        Clone3ArgsCaptureV1::Exact {
                            copied_byte_count: declared_size,
                            buffer: &buffer,
                        },
                        &mut sink,
                    )
                    .expect("exact clone3 capture"),
            );
            assert_eq!(sink.length, 2);
            assert_eq!(resume.raw_tid(), ROOT_TID);
            assert_eq!(resume.request(), TracerSupervisorResumeRequestV1::Syscall);
            assert!(matches!(
                supervisor.confirm_resume_succeeded(resume).unwrap(),
                TracerSupervisorIntentV1::WaitForNextStop
            ));
            finish_syscall(&mut supervisor, ROOT_TID, -1, &mut sink);
        }
    }

    #[test]
    fn clone3_invalid_pointer_and_sizes_fail_before_copy_or_resume() {
        for (address, declared_size, expected) in [
            (0, 64, ForkFamilyDecodeErrorV1::Clone3NullArgsPointer),
            (
                0x1000,
                63,
                ForkFamilyDecodeErrorV1::Clone3DeclaredSizeTooSmall,
            ),
            (
                0x1000,
                65,
                ForkFamilyDecodeErrorV1::Clone3DeclaredSizeAmbiguous,
            ),
            (
                0x1000,
                89,
                ForkFamilyDecodeErrorV1::Clone3DeclaredSizeTooLarge,
            ),
        ] {
            let mut sink = FixedSinkV1::<8>::new();
            let mut supervisor = begin(&mut sink);
            let permit = reach_seccomp_permit(
                &mut supervisor,
                ROOT_TID,
                TRACER_TASK_CLONE3_NR_X86_64_V1,
                [address, declared_size, 0, 0, 0, 0],
                &mut sink,
            );
            let error = supervisor
                .consume_stopped_seccomp_permit(permit, &mut sink)
                .err();
            assert_eq!(
                error,
                Some(TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(
                    expected
                ))
            );
            assert_eq!(sink.length, 1);
            assert_eq!(supervisor.observe_wait(ROOT_TID, 9, &mut sink).err(), error);
        }
    }

    #[test]
    fn clone3_unavailable_short_long_and_dirty_tail_copies_fail_sticky() {
        for case in 0..5 {
            let mut sink = FixedSinkV1::<8>::new();
            let mut supervisor = begin(&mut sink);
            let read = reach_clone3_read(&mut supervisor, ROOT_TID, 0x1000, 64, &mut sink);
            let mut buffer = clone3_buffer(0, SIGCHLD);
            if case == 4 {
                buffer[64] = 1;
            }
            let result = match case {
                0 => supervisor.accept_clone3_args_read(
                    read,
                    Clone3ArgsCaptureV1::Unavailable,
                    &mut sink,
                ),
                1 => supervisor.accept_clone3_args_read(
                    read,
                    Clone3ArgsCaptureV1::NotApplicable,
                    &mut sink,
                ),
                2 => supervisor.accept_clone3_args_read(
                    read,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: 63,
                        buffer: &buffer,
                    },
                    &mut sink,
                ),
                3 => supervisor.accept_clone3_args_read(
                    read,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: 65,
                        buffer: &buffer,
                    },
                    &mut sink,
                ),
                _ => supervisor.accept_clone3_args_read(
                    read,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: 64,
                        buffer: &buffer,
                    },
                    &mut sink,
                ),
            };
            let expected = match case {
                0 => TracerSupervisorExecuteOnlyReasonV1::Clone3ArgsReadUnavailable,
                1 => TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(
                    ForkFamilyDecodeErrorV1::UnexpectedClone3Capture,
                ),
                2 | 3 => TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(
                    ForkFamilyDecodeErrorV1::Clone3CopiedByteCountMismatch,
                ),
                _ => TracerSupervisorExecuteOnlyReasonV1::ForkFamilyDecode(
                    ForkFamilyDecodeErrorV1::Clone3UncopiedTailNonzero,
                ),
            };
            assert_eq!(result.err(), Some(expected));
            assert_eq!(sink.length, 1);
            assert_eq!(
                supervisor.observe_wait(ROOT_TID, 9, &mut sink).err(),
                Some(expected)
            );
        }
    }

    #[test]
    fn clone3_read_tokens_are_session_tid_stop_address_and_length_bound() {
        for mutation in 0..5 {
            let mut sink = FixedSinkV1::<8>::new();
            let mut supervisor = begin(&mut sink);
            let mut read = reach_clone3_read(&mut supervisor, ROOT_TID, 0x1000, 64, &mut sink);
            match mutation {
                0 => read.session_brand = read.session_brand.wrapping_add(1),
                1 => read.raw_tid += 1,
                2 => read.stop_generation = read.stop_generation.wrapping_add(1),
                3 => read.address += 8,
                _ => read.byte_count += 8,
            }
            let buffer = clone3_buffer(0, SIGCHLD);
            let error = supervisor
                .accept_clone3_args_read(
                    read,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: 64,
                        buffer: &buffer,
                    },
                    &mut sink,
                )
                .err();
            assert_eq!(
                error,
                Some(TracerSupervisorExecuteOnlyReasonV1::Clone3ArgsReadCorrelationMismatch)
            );
            assert_eq!(supervisor.observe_wait(ROOT_TID, 9, &mut sink).err(), error);
        }

        let mut sink_a = FixedSinkV1::<8>::new();
        let mut sink_b = FixedSinkV1::<8>::new();
        let mut supervisor_a = begin(&mut sink_a);
        let mut supervisor_b = begin(&mut sink_b);
        let read_a = reach_clone3_read(&mut supervisor_a, ROOT_TID, 0x1000, 64, &mut sink_a);
        let _read_b = reach_clone3_read(&mut supervisor_b, ROOT_TID, 0x1000, 64, &mut sink_b);
        let buffer = clone3_buffer(0, SIGCHLD);
        assert_eq!(
            supervisor_b
                .accept_clone3_args_read(
                    read_a,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: 64,
                        buffer: &buffer,
                    },
                    &mut sink_b,
                )
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::Clone3ArgsReadCorrelationMismatch)
        );
    }

    #[test]
    fn duplicate_clone3_response_after_resume_intent_fails_out_of_order() {
        let mut sink_a = FixedSinkV1::<8>::new();
        let mut sink_b = FixedSinkV1::<8>::new();
        let mut supervisor_a = begin(&mut sink_a);
        let mut supervisor_b = begin(&mut sink_b);
        let read_a = reach_clone3_read(&mut supervisor_a, ROOT_TID, 0x1000, 64, &mut sink_a);
        let read_b = reach_clone3_read(&mut supervisor_b, ROOT_TID, 0x1000, 64, &mut sink_b);
        let buffer = clone3_buffer(0, SIGCHLD);
        assert!(matches!(
            supervisor_a
                .accept_clone3_args_read(
                    read_a,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: 64,
                        buffer: &buffer,
                    },
                    &mut sink_a,
                )
                .unwrap(),
            TracerSupervisorIntentV1::Resume(_)
        ));
        assert_eq!(
            supervisor_a
                .accept_clone3_args_read(
                    read_b,
                    Clone3ArgsCaptureV1::Exact {
                        copied_byte_count: 64,
                        buffer: &buffer,
                    },
                    &mut sink_a,
                )
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::Clone3ArgsReadResponseOutOfOrder)
        );
    }

    #[test]
    fn clone3_fork_correlates_parent_first_and_child_first_delivery() {
        for child_first in [false, true] {
            let mut sink = FixedSinkV1::<16>::new();
            let mut supervisor = begin(&mut sink);
            enter_clone3(&mut supervisor, ROOT_TID, 0x1000, 88, &mut sink);

            if child_first {
                assert!(matches!(
                    supervisor
                        .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                        .unwrap(),
                    TracerSupervisorIntentV1::WaitForNextStop
                ));
            }
            let event_read = take_event_read(
                supervisor
                    .observe_wait(
                        ROOT_TID,
                        ptrace_event_status(LinuxPtraceEventV1::Fork),
                        &mut sink,
                    )
                    .unwrap(),
            );
            let after_event = supervisor
                .accept_event_message(event_read, &event_message(CHILD_TID as u64), &mut sink)
                .unwrap();
            if child_first {
                confirm_child_then_parent(&mut supervisor, after_event, CHILD_TID, ROOT_TID);
            } else {
                assert!(matches!(
                    after_event,
                    TracerSupervisorIntentV1::WaitForNextStop
                ));
                let pair = supervisor
                    .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                    .unwrap();
                confirm_child_then_parent(&mut supervisor, pair, CHILD_TID, ROOT_TID);
            }
            finish_syscall(&mut supervisor, ROOT_TID, CHILD_TID.into(), &mut sink);
        }
    }

    #[test]
    fn exact_two_task_transcripts_complete_with_the_same_redacted_summary() {
        for child_first in [false, true] {
            let mut sink = FixedSinkV1::<16>::new();
            let mut supervisor = begin(&mut sink);
            enter_clone3(&mut supervisor, ROOT_TID, 0x1000, 88, &mut sink);

            if child_first {
                assert!(matches!(
                    supervisor
                        .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                        .unwrap(),
                    TracerSupervisorIntentV1::WaitForNextStop
                ));
            }
            let event_read = take_event_read(
                supervisor
                    .observe_wait(
                        ROOT_TID,
                        ptrace_event_status(LinuxPtraceEventV1::Fork),
                        &mut sink,
                    )
                    .unwrap(),
            );
            let after_event = supervisor
                .accept_event_message(event_read, &event_message(CHILD_TID as u64), &mut sink)
                .unwrap();
            if child_first {
                confirm_child_then_parent(&mut supervisor, after_event, CHILD_TID, ROOT_TID);
            } else {
                assert!(matches!(
                    after_event,
                    TracerSupervisorIntentV1::WaitForNextStop
                ));
                let pair = supervisor
                    .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                    .unwrap();
                confirm_child_then_parent(&mut supervisor, pair, CHILD_TID, ROOT_TID);
            }
            finish_syscall(&mut supervisor, ROOT_TID, CHILD_TID.into(), &mut sink);
            finish_zero_exit(&mut supervisor, CHILD_TID, &mut sink);
            finish_zero_exit(&mut supervisor, ROOT_TID, &mut sink);

            let completed = supervisor
                .complete(TracerSupervisorCleanupCompletionPermitV1::issue_for_test())
                .expect("complete fixed transcript");
            let summary = completed.summary();
            assert_eq!(summary.task_count, 2);
            assert_eq!(summary.accepted_transition_count, 11);
            assert_eq!(summary.fork_birth_count, 1);
            assert_eq!(summary.vfork_birth_count, 0);
            assert_eq!(summary.clone_birth_count, 0);
            assert_eq!(summary.seccomp_entry_count, 3);
            assert_eq!(summary.syscall_exit_count, 1);
            assert_eq!(summary.no_return_resolution_count, 2);
            assert_eq!(summary.ptrace_exit_event_count, 2);
            assert_eq!(summary.terminal_reap_count, 2);
        }
    }

    #[test]
    fn supervisor_completion_rejects_live_or_pending_state() {
        let mut live_sink = FixedSinkV1::<4>::new();
        let live = begin(&mut live_sink);
        assert_eq!(
            live.complete(TracerSupervisorCleanupCompletionPermitV1::issue_for_test())
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::TaskState(
                TracerTaskExecuteOnlyReasonV1::IncompleteShutdown,
            ))
        );

        let mut pending_sink = FixedSinkV1::<4>::new();
        let mut pending = begin(&mut pending_sink);
        let _exchange = pending
            .observe_wait(
                ROOT_TID,
                ptrace_event_status(LinuxPtraceEventV1::Seccomp),
                &mut pending_sink,
            )
            .unwrap();
        assert_eq!(
            pending
                .complete(TracerSupervisorCleanupCompletionPermitV1::issue_for_test())
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::IncompleteShutdown)
        );
    }

    #[test]
    fn clone3_capture_selects_exact_fork_vfork_and_clone_events() {
        for (flags, exit_signal, expected_event) in [
            (0, SIGCHLD, LinuxPtraceEventV1::Fork),
            (0x4100, 0, LinuxPtraceEventV1::Vfork),
            (0, 0, LinuxPtraceEventV1::Clone),
        ] {
            let mut sink = FixedSinkV1::<16>::new();
            let mut supervisor = begin(&mut sink);
            let read = reach_clone3_read(&mut supervisor, ROOT_TID, 0x1000, 88, &mut sink);
            let buffer = clone3_buffer(flags, exit_signal);
            let resume = take_resume(
                supervisor
                    .accept_clone3_args_read(
                        read,
                        Clone3ArgsCaptureV1::Exact {
                            copied_byte_count: 88,
                            buffer: &buffer,
                        },
                        &mut sink,
                    )
                    .unwrap(),
            );
            assert!(matches!(
                supervisor.confirm_resume_succeeded(resume).unwrap(),
                TracerSupervisorIntentV1::WaitForNextStop
            ));
            assert!(matches!(
                supervisor
                    .observe_wait(CHILD_TID, event_stop_status(SIGTRAP), &mut sink)
                    .unwrap(),
                TracerSupervisorIntentV1::WaitForNextStop
            ));
            let event_read = take_event_read(
                supervisor
                    .observe_wait(ROOT_TID, ptrace_event_status(expected_event), &mut sink)
                    .unwrap(),
            );
            let pair = supervisor
                .accept_event_message(event_read, &event_message(CHILD_TID as u64), &mut sink)
                .unwrap();
            confirm_child_then_parent(&mut supervisor, pair, CHILD_TID, ROOT_TID);
            finish_syscall(&mut supervisor, ROOT_TID, CHILD_TID.into(), &mut sink);
        }
    }

    #[test]
    fn event_message_tokens_cannot_cross_supervisor_sessions() {
        let mut sink_a = FixedSinkV1::<8>::new();
        let mut sink_b = FixedSinkV1::<8>::new();
        let mut supervisor_a = begin(&mut sink_a);
        let mut supervisor_b = begin(&mut sink_b);
        let token_a = take_event_read(
            supervisor_a
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Exit),
                    &mut sink_a,
                )
                .unwrap(),
        );
        let token_b = take_event_read(
            supervisor_b
                .observe_wait(
                    ROOT_TID,
                    ptrace_event_status(LinuxPtraceEventV1::Exit),
                    &mut sink_b,
                )
                .unwrap(),
        );
        assert_eq!(token_a.raw_tid, token_b.raw_tid);
        assert_eq!(token_a.stop_generation, token_b.stop_generation);
        assert_eq!(token_a.event, token_b.event);
        assert_ne!(token_a.session_brand, token_b.session_brand);
        assert_eq!(
            supervisor_b
                .accept_event_message(token_a, &event_message(15), &mut sink_b)
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::EventMessageCorrelationMismatch)
        );
    }

    #[test]
    fn syscall_info_tokens_cannot_cross_supervisor_sessions() {
        let mut sink_a = FixedSinkV1::<8>::new();
        let mut sink_b = FixedSinkV1::<8>::new();
        let mut supervisor_a = begin(&mut sink_a);
        let mut supervisor_b = begin(&mut sink_b);
        let token_a = reach_seccomp_syscall_read(&mut supervisor_a, ROOT_TID, &mut sink_a);
        let token_b = reach_seccomp_syscall_read(&mut supervisor_b, ROOT_TID, &mut sink_b);
        assert_eq!(token_a.raw_tid, token_b.raw_tid);
        assert_eq!(token_a.stop_generation, token_b.stop_generation);
        assert_eq!(token_a.kind, token_b.kind);
        assert_ne!(token_a.session_brand, token_b.session_brand);
        assert_eq!(
            supervisor_b
                .accept_syscall_info(token_a, 84, &seccomp_info(102, [0; 6]), &mut sink_b,)
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::SyscallInfoCorrelationMismatch)
        );
    }

    #[test]
    fn stopped_seccomp_permits_cannot_cross_supervisor_sessions() {
        let mut sink_a = FixedSinkV1::<8>::new();
        let mut sink_b = FixedSinkV1::<8>::new();
        let mut supervisor_a = begin(&mut sink_a);
        let mut supervisor_b = begin(&mut sink_b);
        let permit_a = reach_seccomp_permit(&mut supervisor_a, ROOT_TID, 39, [0; 6], &mut sink_a);
        let permit_b = reach_seccomp_permit(&mut supervisor_b, ROOT_TID, 102, [0; 6], &mut sink_b);
        assert_eq!(permit_a.raw_tid, permit_b.raw_tid);
        assert_eq!(permit_a.stop_generation, permit_b.stop_generation);
        assert_ne!(
            permit_a.frame.syscall_number(),
            permit_b.frame.syscall_number()
        );
        assert_ne!(permit_a.session_brand, permit_b.session_brand);
        assert_eq!(
            supervisor_b
                .consume_stopped_seccomp_permit(permit_a, &mut sink_b)
                .err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::SeccompPermitCorrelationMismatch)
        );
    }

    #[test]
    fn resume_tokens_cannot_cross_supervisor_sessions() {
        let mut sink_a = FixedSinkV1::<8>::new();
        let mut sink_b = FixedSinkV1::<8>::new();
        let mut supervisor_a = begin(&mut sink_a);
        let mut supervisor_b = begin(&mut sink_b);
        let permit_a = reach_seccomp_permit(&mut supervisor_a, ROOT_TID, 39, [0; 6], &mut sink_a);
        let permit_b = reach_seccomp_permit(&mut supervisor_b, ROOT_TID, 102, [0; 6], &mut sink_b);
        let resume_a = take_resume(
            supervisor_a
                .consume_stopped_seccomp_permit(permit_a, &mut sink_a)
                .unwrap(),
        );
        let resume_b = take_resume(
            supervisor_b
                .consume_stopped_seccomp_permit(permit_b, &mut sink_b)
                .unwrap(),
        );
        assert_eq!(resume_a.raw_tid, resume_b.raw_tid);
        assert_eq!(resume_a.stop_generation, resume_b.stop_generation);
        assert_eq!(resume_a.request, resume_b.request);
        assert_ne!(resume_a.session_brand, resume_b.session_brand);
        assert_eq!(
            supervisor_b.confirm_resume_succeeded(resume_a).err(),
            Some(TracerSupervisorExecuteOnlyReasonV1::ResumeCorrelationMismatch)
        );
    }
}
