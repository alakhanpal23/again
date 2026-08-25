//! Fixed-capacity logical task lifecycle for the future Linux ptrace supervisor.
//!
//! Raw Linux TIDs are accepted only as live correlation inputs and are erased
//! on terminal reap. Normalized events and completion summaries contain only
//! logical task IDs. This module records no `EffectIR`, creates no execution or
//! reuse authority, and owns no descriptors.

use super::{LinuxWaitTerminationV1, LogicalTaskId};

pub(super) const TRACER_TASK_MAX_TASKS_V1: usize = 256;
pub(super) const TRACER_TASK_CLONE_NR_X86_64_V1: u32 = 56;
pub(super) const TRACER_TASK_FORK_NR_X86_64_V1: u32 = 57;
pub(super) const TRACER_TASK_VFORK_NR_X86_64_V1: u32 = 58;
pub(super) const TRACER_TASK_EXECVE_NR_X86_64_V1: u32 = 59;
pub(super) const TRACER_TASK_EXIT_NR_X86_64_V1: u32 = 60;
pub(super) const TRACER_TASK_EXIT_GROUP_NR_X86_64_V1: u32 = 231;
pub(super) const TRACER_TASK_EXECVEAT_NR_X86_64_V1: u32 = 322;
pub(super) const TRACER_TASK_CLONE3_NR_X86_64_V1: u32 = 435;

const _: () = assert!(TRACER_TASK_MAX_TASKS_V1 == 256);
const _: () = assert!(TRACER_TASK_MAX_TASKS_V1 as u64 == super::LINUX_PYTEST_V1_MAX_TASK_LIFETIMES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TracerTaskBirthKindV1 {
    Initial,
    Fork,
    Vfork,
    Clone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TracerTaskChildBirthKindV1 {
    Fork,
    Vfork,
    Clone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TracerTaskGroupRelationV1 {
    NewThreadGroup,
    SharesParentThreadGroup,
}

impl TracerTaskChildBirthKindV1 {
    const fn normalized(self) -> TracerTaskBirthKindV1 {
        match self {
            Self::Fork => TracerTaskBirthKindV1::Fork,
            Self::Vfork => TracerTaskBirthKindV1::Vfork,
            Self::Clone => TracerTaskBirthKindV1::Clone,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TracerTaskNoReturnKindV1 {
    Exit,
    ExitGroup,
}

/// One control or kernel-derived transition. The type intentionally has no
/// `Debug`, `Clone`, or `Copy` implementation so raw TIDs are not casually
/// retained or logged by callers. Every `sequence` field is local transport
/// ordering and must never be copied into durable semantic trace counters.
pub(super) enum TracerTaskObservationV1 {
    InitialBirth {
        sequence: u64,
        raw_tid: i32,
    },
    /// A parent ptrace fork-family event plus exact GETEVENTMSG child TID.
    /// `group_relation` is decoder evidence; it is never inferred from `kind`.
    ChildAnnouncement {
        sequence: u64,
        parent_raw_tid: i32,
        child_raw_tid: i32,
        kind: TracerTaskChildBirthKindV1,
        group_relation: TracerTaskGroupRelationV1,
    },
    /// The auto-attached child reached its distinct initial `PTRACE_EVENT_STOP`.
    /// The outer supervisor must first resume that stop with `PTRACE_CONT`, never
    /// `PTRACE_SYSCALL`, so no child-side creation-syscall exit can appear alone.
    ChildReady {
        sequence: u64,
        child_raw_tid: i32,
    },
    Exec {
        sequence: u64,
        raw_tid: i32,
        former_raw_tid: i32,
    },
    SeccompEntry {
        sequence: u64,
        raw_tid: i32,
        syscall_number: u32,
    },
    SyscallExit {
        sequence: u64,
        raw_tid: i32,
        result: i64,
    },
    PtraceExitEvent {
        sequence: u64,
        raw_tid: i32,
        termination: LinuxWaitTerminationV1,
    },
    TerminalReap {
        sequence: u64,
        raw_tid: i32,
        termination: LinuxWaitTerminationV1,
    },
}

impl TracerTaskObservationV1 {
    const fn sequence(&self) -> u64 {
        match self {
            Self::InitialBirth { sequence, .. }
            | Self::ChildAnnouncement { sequence, .. }
            | Self::ChildReady { sequence, .. }
            | Self::Exec { sequence, .. }
            | Self::SeccompEntry { sequence, .. }
            | Self::SyscallExit { sequence, .. }
            | Self::PtraceExitEvent { sequence, .. }
            | Self::TerminalReap { sequence, .. } => *sequence,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NormalizedTracerTaskEventV1 {
    Birth {
        transport_sequence: u64,
        logical_task_id: LogicalTaskId,
        parent_logical_task_id: Option<LogicalTaskId>,
        thread_group_logical_task_id: LogicalTaskId,
        kind: TracerTaskBirthKindV1,
    },
    Exec {
        transport_sequence: u64,
        logical_task_id: LogicalTaskId,
        syscall_number: u32,
    },
    SeccompEntry {
        transport_sequence: u64,
        logical_task_id: LogicalTaskId,
        syscall_number: u32,
    },
    SyscallExit {
        transport_sequence: u64,
        logical_task_id: LogicalTaskId,
        syscall_number: u32,
    },
    PtraceExitEvent {
        transport_sequence: u64,
        logical_task_id: LogicalTaskId,
        termination: LinuxWaitTerminationV1,
        resolved_no_return: Option<TracerTaskNoReturnKindV1>,
    },
    TerminalReap {
        transport_sequence: u64,
        logical_task_id: LogicalTaskId,
        termination: LinuxWaitTerminationV1,
    },
}

/// A bounded caller-owned sink. Rejection permanently poisons the recorder.
pub(super) trait NormalizedTracerTaskEventSinkV1 {
    fn emit(&mut self, event: NormalizedTracerTaskEventV1) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TracerTaskExecuteOnlyReasonV1 {
    SequenceMismatch,
    CounterOverflow,
    InvalidRawTid,
    UnknownRawTid,
    DuplicateRawTid,
    InitialBirthRequired,
    DuplicateInitialBirth,
    TaskCapacityExceeded,
    ParentNotRunning,
    SelfParentTid,
    ChildAnnouncementWithoutEntry,
    ChildAnnouncementSyscallMismatch,
    DuplicateChildAnnouncement,
    DuplicateChildReady,
    ChildNotReady,
    MissingChildAnnouncement,
    ChildResultMismatch,
    BirthGroupRelationMismatch,
    DuplicateExec,
    ExecWithoutEntry,
    ExecSyscallMismatch,
    ExecTidReplacementUnsupported,
    ExecThreadTeardownUnsupported,
    DuplicateSeccompEntry,
    SyscallExitWithoutEntry,
    SyscallRestartUnsupported,
    NoReturnResolutionRequired,
    MissingExecEvent,
    ExecResultMismatch,
    OutstandingSyscall,
    DuplicatePtraceExit,
    LateLifecycleEvent,
    ReapBeforePtraceExit,
    InvalidTermination,
    TerminationMismatch,
    SinkRejected,
    IncompleteShutdown,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TaskPhaseV1 {
    Unused,
    Running,
    ExitObserved,
    Reaped,
}

#[derive(Clone, Copy)]
struct TaskSlotV1 {
    logical_task_id: LogicalTaskId,
    thread_group_logical_task_id: LogicalTaskId,
    raw_tid: i32,
    phase: TaskPhaseV1,
    pending_syscall: Option<u32>,
    child_ready_seen_for_pending: bool,
    pending_child_raw_tid: i32,
    exec_event_seen_for_pending: bool,
    exec_seen_ever: bool,
    termination: Option<LinuxWaitTerminationV1>,
}

impl TaskSlotV1 {
    const EMPTY: Self = Self {
        logical_task_id: LogicalTaskId(0),
        thread_group_logical_task_id: LogicalTaskId(0),
        raw_tid: 0,
        phase: TaskPhaseV1::Unused,
        pending_syscall: None,
        child_ready_seen_for_pending: false,
        pending_child_raw_tid: 0,
        exec_event_seen_for_pending: false,
        exec_seen_ever: false,
        termination: None,
    };
}

#[derive(Clone, Copy)]
struct PendingChildAnnouncementV1 {
    parent_index: usize,
    kind: TracerTaskChildBirthKindV1,
    group_relation: TracerTaskGroupRelationV1,
}

#[derive(Clone, Copy)]
struct PendingChildCorrelationV1 {
    raw_tid: i32,
    announcement: Option<PendingChildAnnouncementV1>,
    ready_seen: bool,
}

impl PendingChildCorrelationV1 {
    const EMPTY: Self = Self {
        raw_tid: 0,
        announcement: None,
        ready_seen: false,
    };
}

#[derive(Clone, Copy, Default)]
struct TracerTaskCountersV1 {
    accepted_transition_count: u64,
    initial_birth_count: u64,
    child_announcement_count: u64,
    child_ready_count: u64,
    fork_birth_count: u64,
    vfork_birth_count: u64,
    clone_birth_count: u64,
    exec_count: u64,
    seccomp_entry_count: u64,
    syscall_exit_count: u64,
    no_return_resolution_count: u64,
    ptrace_exit_event_count: u64,
    terminal_reap_count: u64,
}

#[derive(Clone, Copy)]
enum CounterKindV1 {
    InitialBirth,
    ChildAnnouncement,
    ChildReady,
    Exec,
    SeccompEntry,
    SyscallExit,
    PtraceExitEvent,
    TerminalReap,
}

impl TracerTaskCountersV1 {
    fn incremented(mut self, kind: CounterKindV1) -> Result<Self, TracerTaskExecuteOnlyReasonV1> {
        self.accepted_transition_count = self
            .accepted_transition_count
            .checked_add(1)
            .ok_or(TracerTaskExecuteOnlyReasonV1::CounterOverflow)?;
        let counter = match kind {
            CounterKindV1::InitialBirth => &mut self.initial_birth_count,
            CounterKindV1::ChildAnnouncement => &mut self.child_announcement_count,
            CounterKindV1::ChildReady => &mut self.child_ready_count,
            CounterKindV1::Exec => &mut self.exec_count,
            CounterKindV1::SeccompEntry => &mut self.seccomp_entry_count,
            CounterKindV1::SyscallExit => &mut self.syscall_exit_count,
            CounterKindV1::PtraceExitEvent => &mut self.ptrace_exit_event_count,
            CounterKindV1::TerminalReap => &mut self.terminal_reap_count,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(TracerTaskExecuteOnlyReasonV1::CounterOverflow)?;
        Ok(self)
    }

    fn with_correlated_birth(
        mut self,
        kind: TracerTaskChildBirthKindV1,
    ) -> Result<Self, TracerTaskExecuteOnlyReasonV1> {
        let counter = match kind {
            TracerTaskChildBirthKindV1::Fork => &mut self.fork_birth_count,
            TracerTaskChildBirthKindV1::Vfork => &mut self.vfork_birth_count,
            TracerTaskChildBirthKindV1::Clone => &mut self.clone_birth_count,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(TracerTaskExecuteOnlyReasonV1::CounterOverflow)?;
        Ok(self)
    }

    fn with_no_return_resolution(mut self) -> Result<Self, TracerTaskExecuteOnlyReasonV1> {
        self.no_return_resolution_count = self
            .no_return_resolution_count
            .checked_add(1)
            .ok_or(TracerTaskExecuteOnlyReasonV1::CounterOverflow)?;
        Ok(self)
    }
}

/// Fixed-capacity live correlation state. The first rejection is permanent and
/// is returned by every later call.
pub(super) struct TracerTaskStateRecorderV1 {
    tasks: [TaskSlotV1; TRACER_TASK_MAX_TASKS_V1],
    pending_children: [PendingChildCorrelationV1; TRACER_TASK_MAX_TASKS_V1],
    slots_used: usize,
    next_logical_task_id: u32,
    next_transport_sequence: u64,
    counters: TracerTaskCountersV1,
    poisoned: Option<TracerTaskExecuteOnlyReasonV1>,
}

impl TracerTaskStateRecorderV1 {
    pub(super) const fn new() -> Self {
        Self {
            tasks: [TaskSlotV1::EMPTY; TRACER_TASK_MAX_TASKS_V1],
            pending_children: [PendingChildCorrelationV1::EMPTY; TRACER_TASK_MAX_TASKS_V1],
            slots_used: 0,
            next_logical_task_id: 1,
            next_transport_sequence: 1,
            counters: TracerTaskCountersV1 {
                accepted_transition_count: 0,
                initial_birth_count: 0,
                child_announcement_count: 0,
                child_ready_count: 0,
                fork_birth_count: 0,
                vfork_birth_count: 0,
                clone_birth_count: 0,
                exec_count: 0,
                seccomp_entry_count: 0,
                syscall_exit_count: 0,
                no_return_resolution_count: 0,
                ptrace_exit_event_count: 0,
                terminal_reap_count: 0,
            },
            poisoned: None,
        }
    }

    /// Whether `raw_tid` currently names one non-reaped task lifetime.
    ///
    /// This is a correlation predicate only. It does not prove that the task
    /// is ptrace-stopped, that its address space is quiescent, or that any
    /// kernel response belongs to the current stop.
    pub(super) fn contains_live_raw_tid(&self, raw_tid: i32) -> bool {
        self.find_live_task(raw_tid).is_some()
    }

    /// Whether a child announcement is waiting for that child's distinct
    /// initial `PTRACE_EVENT_STOP` observation.
    ///
    /// The result exposes no parent identity or lifecycle data and grants no
    /// authority to classify or resume a stop.
    pub(super) fn is_announced_child_awaiting_ready(&self, raw_tid: i32) -> bool {
        self.pending_children.iter().any(|pending| {
            pending.raw_tid == raw_tid && pending.announcement.is_some() && !pending.ready_seen
        })
    }

    /// Return the syscall currently awaiting resolution for one live task.
    ///
    /// The value is transient correlation state already owned by this
    /// recorder. It proves neither a current ptrace stop nor syscall-frame
    /// provenance.
    pub(super) fn pending_syscall_number(&self, raw_tid: i32) -> Option<u32> {
        self.find_live_task(raw_tid)
            .and_then(|index| self.tasks[index].pending_syscall)
    }

    pub(super) fn observe<S: NormalizedTracerTaskEventSinkV1>(
        &mut self,
        observation: TracerTaskObservationV1,
        sink: &mut S,
    ) -> Result<(), TracerTaskExecuteOnlyReasonV1> {
        if let Some(reason) = self.poisoned {
            return Err(reason);
        }
        let sequence = observation.sequence();
        if sequence != self.next_transport_sequence {
            return self.poison(TracerTaskExecuteOnlyReasonV1::SequenceMismatch);
        }
        if self.slots_used == 0
            && !matches!(&observation, TracerTaskObservationV1::InitialBirth { .. })
        {
            return self.poison(TracerTaskExecuteOnlyReasonV1::InitialBirthRequired);
        }
        let Some(next_transport_sequence) = self.next_transport_sequence.checked_add(1) else {
            return self.poison(TracerTaskExecuteOnlyReasonV1::CounterOverflow);
        };

        let accepted = match observation {
            TracerTaskObservationV1::InitialBirth { raw_tid, .. } => {
                self.observe_initial_birth(sequence, raw_tid)
            }
            TracerTaskObservationV1::ChildAnnouncement {
                parent_raw_tid,
                child_raw_tid,
                kind,
                group_relation,
                ..
            } => self.observe_child_announcement(
                sequence,
                parent_raw_tid,
                child_raw_tid,
                kind,
                group_relation,
            ),
            TracerTaskObservationV1::ChildReady { child_raw_tid, .. } => {
                self.observe_child_ready(sequence, child_raw_tid)
            }
            TracerTaskObservationV1::Exec {
                raw_tid,
                former_raw_tid,
                ..
            } => self.observe_exec(sequence, raw_tid, former_raw_tid),
            TracerTaskObservationV1::SeccompEntry {
                raw_tid,
                syscall_number,
                ..
            } => self.observe_seccomp_entry(sequence, raw_tid, syscall_number),
            TracerTaskObservationV1::SyscallExit {
                raw_tid, result, ..
            } => self.observe_syscall_exit(sequence, raw_tid, result),
            TracerTaskObservationV1::PtraceExitEvent {
                raw_tid,
                termination,
                ..
            } => self.observe_ptrace_exit(sequence, raw_tid, termination),
            TracerTaskObservationV1::TerminalReap {
                raw_tid,
                termination,
                ..
            } => self.observe_terminal_reap(sequence, raw_tid, termination),
        };
        let (event, next_counters) = match accepted {
            Ok(value) => value,
            Err(reason) => return self.poison(reason),
        };
        if let Some(event) = event
            && sink.emit(event).is_err()
        {
            return self.poison(TracerTaskExecuteOnlyReasonV1::SinkRejected);
        }
        self.counters = next_counters;
        self.next_transport_sequence = next_transport_sequence;
        Ok(())
    }

    pub(super) fn complete(
        mut self,
    ) -> Result<CompletedTracerTaskStateV1, TracerTaskExecuteOnlyReasonV1> {
        if let Some(reason) = self.poisoned {
            return Err(reason);
        }
        let Some(resolved_syscall_count) = self
            .counters
            .syscall_exit_count
            .checked_add(self.counters.no_return_resolution_count)
        else {
            return self.poison(TracerTaskExecuteOnlyReasonV1::CounterOverflow);
        };
        let Some(expected_transition_count) = self
            .counters
            .initial_birth_count
            .checked_add(self.counters.child_announcement_count)
            .and_then(|count| count.checked_add(self.counters.child_ready_count))
            .and_then(|count| count.checked_add(self.counters.exec_count))
            .and_then(|count| count.checked_add(self.counters.seccomp_entry_count))
            .and_then(|count| count.checked_add(self.counters.syscall_exit_count))
            .and_then(|count| count.checked_add(self.counters.ptrace_exit_event_count))
            .and_then(|count| count.checked_add(self.counters.terminal_reap_count))
        else {
            return self.poison(TracerTaskExecuteOnlyReasonV1::CounterOverflow);
        };
        if self.slots_used == 0
            || self.tasks[..self.slots_used]
                .iter()
                .any(|task| task.phase != TaskPhaseV1::Reaped || task.raw_tid != 0)
            || self
                .pending_children
                .iter()
                .any(|pending| pending.raw_tid != 0)
            || self.counters.initial_birth_count != 1
            || self.counters.accepted_transition_count != expected_transition_count
            || self.counters.child_announcement_count != self.counters.child_ready_count
            || self.counters.child_ready_count != self.slots_used.saturating_sub(1) as u64
            || self
                .counters
                .fork_birth_count
                .checked_add(self.counters.vfork_birth_count)
                .and_then(|count| count.checked_add(self.counters.clone_birth_count))
                != Some(self.slots_used.saturating_sub(1) as u64)
            || self.counters.ptrace_exit_event_count != self.slots_used as u64
            || self.counters.terminal_reap_count != self.slots_used as u64
            || self.counters.exec_count > self.slots_used as u64
            || self.counters.no_return_resolution_count > self.counters.ptrace_exit_event_count
            || self.counters.seccomp_entry_count != resolved_syscall_count
        {
            return self.poison(TracerTaskExecuteOnlyReasonV1::IncompleteShutdown);
        }
        let task_count = match u16::try_from(self.slots_used) {
            Ok(task_count) => task_count,
            Err(_) => return self.poison(TracerTaskExecuteOnlyReasonV1::CounterOverflow),
        };
        Ok(CompletedTracerTaskStateV1 {
            summary: TracerTaskCompletionSummaryV1 {
                task_count,
                accepted_transition_count: self.counters.accepted_transition_count,
                initial_birth_count: self.counters.initial_birth_count,
                child_announcement_count: self.counters.child_announcement_count,
                child_ready_count: self.counters.child_ready_count,
                fork_birth_count: self.counters.fork_birth_count,
                vfork_birth_count: self.counters.vfork_birth_count,
                clone_birth_count: self.counters.clone_birth_count,
                exec_count: self.counters.exec_count,
                seccomp_entry_count: self.counters.seccomp_entry_count,
                syscall_exit_count: self.counters.syscall_exit_count,
                no_return_resolution_count: self.counters.no_return_resolution_count,
                ptrace_exit_event_count: self.counters.ptrace_exit_event_count,
                terminal_reap_count: self.counters.terminal_reap_count,
            },
        })
    }

    fn observe_initial_birth(
        &mut self,
        sequence: u64,
        raw_tid: i32,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        if self.slots_used != 0 {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateInitialBirth);
        }
        let logical_task_id = self.insert_task(raw_tid, None)?;
        Ok((
            Some(NormalizedTracerTaskEventV1::Birth {
                transport_sequence: sequence,
                logical_task_id,
                parent_logical_task_id: None,
                thread_group_logical_task_id: logical_task_id,
                kind: TracerTaskBirthKindV1::Initial,
            }),
            self.counters.incremented(CounterKindV1::InitialBirth)?,
        ))
    }

    fn observe_child_announcement(
        &mut self,
        sequence: u64,
        parent_raw_tid: i32,
        child_raw_tid: i32,
        kind: TracerTaskChildBirthKindV1,
        group_relation: TracerTaskGroupRelationV1,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        Self::require_positive_tid(parent_raw_tid)?;
        Self::require_positive_tid(child_raw_tid)?;
        if parent_raw_tid == child_raw_tid {
            return Err(TracerTaskExecuteOnlyReasonV1::SelfParentTid);
        }
        let parent_index = self
            .find_live_task(parent_raw_tid)
            .ok_or(TracerTaskExecuteOnlyReasonV1::UnknownRawTid)?;
        if self.tasks[parent_index].phase != TaskPhaseV1::Running {
            return Err(TracerTaskExecuteOnlyReasonV1::ParentNotRunning);
        }
        let creation_syscall = self.tasks[parent_index]
            .pending_syscall
            .ok_or(TracerTaskExecuteOnlyReasonV1::ChildAnnouncementWithoutEntry)?;
        if !Self::creation_syscall_permits(Some(creation_syscall), kind) {
            return Err(TracerTaskExecuteOnlyReasonV1::ChildAnnouncementSyscallMismatch);
        }
        if self.tasks[parent_index].pending_child_raw_tid != 0 {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateChildAnnouncement);
        }
        if !matches!(kind, TracerTaskChildBirthKindV1::Clone)
            && group_relation != TracerTaskGroupRelationV1::NewThreadGroup
        {
            return Err(TracerTaskExecuteOnlyReasonV1::BirthGroupRelationMismatch);
        }
        if self.find_live_task(child_raw_tid).is_some() {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateRawTid);
        }
        let pending_index = self.pending_child_index_or_insert(child_raw_tid)?;
        if self.pending_children[pending_index].announcement.is_some() {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateChildAnnouncement);
        }
        self.pending_children[pending_index].announcement = Some(PendingChildAnnouncementV1 {
            parent_index,
            kind,
            group_relation,
        });
        self.tasks[parent_index].pending_child_raw_tid = child_raw_tid;
        let next_counters = self
            .counters
            .incremented(CounterKindV1::ChildAnnouncement)?;
        self.finish_child_correlation(sequence, pending_index, next_counters)
    }

    fn observe_child_ready(
        &mut self,
        sequence: u64,
        child_raw_tid: i32,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        Self::require_positive_tid(child_raw_tid)?;
        if self.find_live_task(child_raw_tid).is_some() {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateChildReady);
        }
        let pending_index = self.pending_child_index_or_insert(child_raw_tid)?;
        if self.pending_children[pending_index].ready_seen {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateChildReady);
        }
        self.pending_children[pending_index].ready_seen = true;
        let next_counters = self.counters.incremented(CounterKindV1::ChildReady)?;
        self.finish_child_correlation(sequence, pending_index, next_counters)
    }

    fn finish_child_correlation(
        &mut self,
        sequence: u64,
        pending_index: usize,
        next_counters: TracerTaskCountersV1,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        let pending = self.pending_children[pending_index];
        let Some(announcement) = pending.announcement else {
            return Ok((None, next_counters));
        };
        if !pending.ready_seen {
            return Ok((None, next_counters));
        }
        let parent = self.tasks[announcement.parent_index];
        if parent.phase != TaskPhaseV1::Running {
            return Err(TracerTaskExecuteOnlyReasonV1::ParentNotRunning);
        }
        if parent.pending_child_raw_tid != pending.raw_tid
            || !Self::creation_syscall_permits(parent.pending_syscall, announcement.kind)
        {
            return Err(TracerTaskExecuteOnlyReasonV1::ChildAnnouncementSyscallMismatch);
        }
        let inherited_thread_group = match announcement.group_relation {
            TracerTaskGroupRelationV1::NewThreadGroup => None,
            TracerTaskGroupRelationV1::SharesParentThreadGroup => {
                Some(parent.thread_group_logical_task_id)
            }
        };
        let logical_task_id = self.insert_task(pending.raw_tid, inherited_thread_group)?;
        self.tasks[announcement.parent_index].child_ready_seen_for_pending = true;
        self.pending_children[pending_index] = PendingChildCorrelationV1::EMPTY;
        Ok((
            Some(NormalizedTracerTaskEventV1::Birth {
                transport_sequence: sequence,
                logical_task_id,
                parent_logical_task_id: Some(parent.logical_task_id),
                thread_group_logical_task_id: inherited_thread_group.unwrap_or(logical_task_id),
                kind: announcement.kind.normalized(),
            }),
            next_counters.with_correlated_birth(announcement.kind)?,
        ))
    }

    const fn creation_syscall_permits(
        syscall_number: Option<u32>,
        kind: TracerTaskChildBirthKindV1,
    ) -> bool {
        match syscall_number {
            Some(TRACER_TASK_FORK_NR_X86_64_V1) => {
                matches!(kind, TracerTaskChildBirthKindV1::Fork)
            }
            Some(TRACER_TASK_VFORK_NR_X86_64_V1) => {
                matches!(kind, TracerTaskChildBirthKindV1::Vfork)
            }
            Some(TRACER_TASK_CLONE_NR_X86_64_V1 | TRACER_TASK_CLONE3_NR_X86_64_V1) => true,
            _ => false,
        }
    }

    fn observe_exec(
        &mut self,
        sequence: u64,
        raw_tid: i32,
        former_raw_tid: i32,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        Self::require_positive_tid(former_raw_tid)?;
        if raw_tid != former_raw_tid {
            return Err(TracerTaskExecuteOnlyReasonV1::ExecTidReplacementUnsupported);
        }
        let index = self.running_task_index(raw_tid)?;
        let syscall_number = self.tasks[index]
            .pending_syscall
            .ok_or(TracerTaskExecuteOnlyReasonV1::ExecWithoutEntry)?;
        if !matches!(
            syscall_number,
            TRACER_TASK_EXECVE_NR_X86_64_V1 | TRACER_TASK_EXECVEAT_NR_X86_64_V1
        ) {
            return Err(TracerTaskExecuteOnlyReasonV1::ExecSyscallMismatch);
        }
        if self.tasks[index].exec_event_seen_for_pending || self.tasks[index].exec_seen_ever {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateExec);
        }
        let thread_group = self.tasks[index].thread_group_logical_task_id;
        if self.tasks[..self.slots_used]
            .iter()
            .filter(|task| {
                task.raw_tid > 0
                    && task.phase != TaskPhaseV1::Reaped
                    && task.thread_group_logical_task_id == thread_group
            })
            .count()
            != 1
        {
            return Err(TracerTaskExecuteOnlyReasonV1::ExecThreadTeardownUnsupported);
        }
        self.tasks[index].exec_event_seen_for_pending = true;
        self.tasks[index].exec_seen_ever = true;
        Ok((
            Some(NormalizedTracerTaskEventV1::Exec {
                transport_sequence: sequence,
                logical_task_id: self.tasks[index].logical_task_id,
                syscall_number,
            }),
            self.counters.incremented(CounterKindV1::Exec)?,
        ))
    }

    fn observe_seccomp_entry(
        &mut self,
        sequence: u64,
        raw_tid: i32,
        syscall_number: u32,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        let index = self.running_task_index(raw_tid)?;
        if self.tasks[index].pending_syscall.is_some() {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateSeccompEntry);
        }
        self.tasks[index].pending_syscall = Some(syscall_number);
        self.tasks[index].child_ready_seen_for_pending = false;
        self.tasks[index].pending_child_raw_tid = 0;
        self.tasks[index].exec_event_seen_for_pending = false;
        Ok((
            Some(NormalizedTracerTaskEventV1::SeccompEntry {
                transport_sequence: sequence,
                logical_task_id: self.tasks[index].logical_task_id,
                syscall_number,
            }),
            self.counters.incremented(CounterKindV1::SeccompEntry)?,
        ))
    }

    fn observe_syscall_exit(
        &mut self,
        sequence: u64,
        raw_tid: i32,
        result: i64,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        let index = self.running_task_index(raw_tid)?;
        let syscall_number = self.tasks[index]
            .pending_syscall
            .ok_or(TracerTaskExecuteOnlyReasonV1::SyscallExitWithoutEntry)?;
        if Self::is_restart_result(result) {
            return Err(TracerTaskExecuteOnlyReasonV1::SyscallRestartUnsupported);
        }
        if matches!(
            syscall_number,
            TRACER_TASK_EXIT_NR_X86_64_V1 | TRACER_TASK_EXIT_GROUP_NR_X86_64_V1
        ) {
            return Err(TracerTaskExecuteOnlyReasonV1::NoReturnResolutionRequired);
        }
        if matches!(
            syscall_number,
            TRACER_TASK_EXECVE_NR_X86_64_V1 | TRACER_TASK_EXECVEAT_NR_X86_64_V1
        ) {
            match (self.tasks[index].exec_event_seen_for_pending, result) {
                (true, 0) | (false, -4095..=-1) => {}
                (false, 0) => return Err(TracerTaskExecuteOnlyReasonV1::MissingExecEvent),
                _ => return Err(TracerTaskExecuteOnlyReasonV1::ExecResultMismatch),
            }
        }
        if Self::is_creation_syscall(syscall_number) {
            let announced = self.tasks[index].pending_child_raw_tid != 0;
            let ready = self.tasks[index].child_ready_seen_for_pending;
            match result {
                -4095..=-1 if !announced => {}
                1..=i64::MAX if !announced => {
                    return Err(TracerTaskExecuteOnlyReasonV1::MissingChildAnnouncement);
                }
                1..=i64::MAX if !ready => {
                    return Err(TracerTaskExecuteOnlyReasonV1::ChildNotReady);
                }
                1..=i64::MAX if result == i64::from(self.tasks[index].pending_child_raw_tid) => {}
                _ => return Err(TracerTaskExecuteOnlyReasonV1::ChildResultMismatch),
            }
        }
        self.tasks[index].pending_syscall = None;
        self.tasks[index].child_ready_seen_for_pending = false;
        self.tasks[index].pending_child_raw_tid = 0;
        self.tasks[index].exec_event_seen_for_pending = false;
        Ok((
            Some(NormalizedTracerTaskEventV1::SyscallExit {
                transport_sequence: sequence,
                logical_task_id: self.tasks[index].logical_task_id,
                syscall_number,
            }),
            self.counters.incremented(CounterKindV1::SyscallExit)?,
        ))
    }

    fn observe_ptrace_exit(
        &mut self,
        sequence: u64,
        raw_tid: i32,
        termination: LinuxWaitTerminationV1,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        if !termination.valid() {
            return Err(TracerTaskExecuteOnlyReasonV1::InvalidTermination);
        }
        let index = self.live_task_index(raw_tid)?;
        match self.tasks[index].phase {
            TaskPhaseV1::Running => {}
            TaskPhaseV1::ExitObserved => {
                return Err(TracerTaskExecuteOnlyReasonV1::DuplicatePtraceExit);
            }
            TaskPhaseV1::Unused | TaskPhaseV1::Reaped => {
                return Err(TracerTaskExecuteOnlyReasonV1::UnknownRawTid);
            }
        }
        let resolved_no_return = match termination {
            LinuxWaitTerminationV1::Exited { .. } => match self.tasks[index].pending_syscall {
                Some(TRACER_TASK_EXIT_NR_X86_64_V1) => Some(TracerTaskNoReturnKindV1::Exit),
                Some(TRACER_TASK_EXIT_GROUP_NR_X86_64_V1) => {
                    Some(TracerTaskNoReturnKindV1::ExitGroup)
                }
                None => return Err(TracerTaskExecuteOnlyReasonV1::NoReturnResolutionRequired),
                Some(_) => return Err(TracerTaskExecuteOnlyReasonV1::OutstandingSyscall),
            },
            LinuxWaitTerminationV1::Signaled { .. } => {
                if self.tasks[index].pending_syscall.is_some() {
                    return Err(TracerTaskExecuteOnlyReasonV1::OutstandingSyscall);
                }
                None
            }
        };
        self.tasks[index].pending_syscall = None;
        self.tasks[index].child_ready_seen_for_pending = false;
        self.tasks[index].pending_child_raw_tid = 0;
        self.tasks[index].exec_event_seen_for_pending = false;
        self.tasks[index].phase = TaskPhaseV1::ExitObserved;
        self.tasks[index].termination = Some(termination);
        let mut next_counters = self.counters.incremented(CounterKindV1::PtraceExitEvent)?;
        if resolved_no_return.is_some() {
            next_counters = next_counters.with_no_return_resolution()?;
        }
        Ok((
            Some(NormalizedTracerTaskEventV1::PtraceExitEvent {
                transport_sequence: sequence,
                logical_task_id: self.tasks[index].logical_task_id,
                termination,
                resolved_no_return,
            }),
            next_counters,
        ))
    }

    fn observe_terminal_reap(
        &mut self,
        sequence: u64,
        raw_tid: i32,
        termination: LinuxWaitTerminationV1,
    ) -> Result<
        (Option<NormalizedTracerTaskEventV1>, TracerTaskCountersV1),
        TracerTaskExecuteOnlyReasonV1,
    > {
        if !termination.valid() {
            return Err(TracerTaskExecuteOnlyReasonV1::InvalidTermination);
        }
        let index = self.live_task_index(raw_tid)?;
        match self.tasks[index].phase {
            TaskPhaseV1::Running => {
                return Err(TracerTaskExecuteOnlyReasonV1::ReapBeforePtraceExit);
            }
            TaskPhaseV1::ExitObserved => {}
            TaskPhaseV1::Unused | TaskPhaseV1::Reaped => {
                return Err(TracerTaskExecuteOnlyReasonV1::UnknownRawTid);
            }
        }
        if self.tasks[index].termination != Some(termination) {
            return Err(TracerTaskExecuteOnlyReasonV1::TerminationMismatch);
        }
        let logical_task_id = self.tasks[index].logical_task_id;
        self.tasks[index].phase = TaskPhaseV1::Reaped;
        self.tasks[index].raw_tid = 0;
        self.tasks[index].pending_syscall = None;
        self.tasks[index].child_ready_seen_for_pending = false;
        self.tasks[index].pending_child_raw_tid = 0;
        self.tasks[index].exec_event_seen_for_pending = false;
        Ok((
            Some(NormalizedTracerTaskEventV1::TerminalReap {
                transport_sequence: sequence,
                logical_task_id,
                termination,
            }),
            self.counters.incremented(CounterKindV1::TerminalReap)?,
        ))
    }

    fn insert_task(
        &mut self,
        raw_tid: i32,
        inherited_thread_group: Option<LogicalTaskId>,
    ) -> Result<LogicalTaskId, TracerTaskExecuteOnlyReasonV1> {
        Self::require_positive_tid(raw_tid)?;
        if self.find_live_task(raw_tid).is_some() {
            return Err(TracerTaskExecuteOnlyReasonV1::DuplicateRawTid);
        }
        if self.slots_used >= TRACER_TASK_MAX_TASKS_V1 {
            return Err(TracerTaskExecuteOnlyReasonV1::TaskCapacityExceeded);
        }
        let logical_task_id = self.next_logical_task_id;
        if logical_task_id == 0 {
            return Err(TracerTaskExecuteOnlyReasonV1::CounterOverflow);
        }
        let next_logical_task_id = logical_task_id
            .checked_add(1)
            .ok_or(TracerTaskExecuteOnlyReasonV1::CounterOverflow)?;
        self.tasks[self.slots_used] = TaskSlotV1 {
            logical_task_id: LogicalTaskId(logical_task_id),
            thread_group_logical_task_id: inherited_thread_group
                .unwrap_or(LogicalTaskId(logical_task_id)),
            raw_tid,
            phase: TaskPhaseV1::Running,
            pending_syscall: None,
            child_ready_seen_for_pending: false,
            pending_child_raw_tid: 0,
            exec_event_seen_for_pending: false,
            exec_seen_ever: false,
            termination: None,
        };
        self.slots_used += 1;
        self.next_logical_task_id = next_logical_task_id;
        Ok(LogicalTaskId(logical_task_id))
    }

    fn pending_child_index_or_insert(
        &mut self,
        raw_tid: i32,
    ) -> Result<usize, TracerTaskExecuteOnlyReasonV1> {
        if let Some(index) = self
            .pending_children
            .iter()
            .position(|pending| pending.raw_tid == raw_tid)
        {
            return Ok(index);
        }
        let pending_count = self
            .pending_children
            .iter()
            .filter(|pending| pending.raw_tid != 0)
            .count();
        if self
            .slots_used
            .checked_add(pending_count)
            .is_none_or(|count| count >= TRACER_TASK_MAX_TASKS_V1)
        {
            return Err(TracerTaskExecuteOnlyReasonV1::TaskCapacityExceeded);
        }
        let index = self
            .pending_children
            .iter()
            .position(|pending| pending.raw_tid == 0)
            .ok_or(TracerTaskExecuteOnlyReasonV1::TaskCapacityExceeded)?;
        self.pending_children[index] = PendingChildCorrelationV1 {
            raw_tid,
            announcement: None,
            ready_seen: false,
        };
        Ok(index)
    }

    const fn is_creation_syscall(syscall_number: u32) -> bool {
        matches!(
            syscall_number,
            TRACER_TASK_CLONE_NR_X86_64_V1
                | TRACER_TASK_FORK_NR_X86_64_V1
                | TRACER_TASK_VFORK_NR_X86_64_V1
                | TRACER_TASK_CLONE3_NR_X86_64_V1
        )
    }

    const fn is_restart_result(result: i64) -> bool {
        matches!(result, -512 | -513 | -514 | -516)
    }

    fn live_task_index(&self, raw_tid: i32) -> Result<usize, TracerTaskExecuteOnlyReasonV1> {
        Self::require_positive_tid(raw_tid)?;
        self.find_live_task(raw_tid)
            .ok_or(TracerTaskExecuteOnlyReasonV1::UnknownRawTid)
    }

    fn running_task_index(&self, raw_tid: i32) -> Result<usize, TracerTaskExecuteOnlyReasonV1> {
        let index = self.live_task_index(raw_tid)?;
        match self.tasks[index].phase {
            TaskPhaseV1::Running => Ok(index),
            TaskPhaseV1::ExitObserved => Err(TracerTaskExecuteOnlyReasonV1::LateLifecycleEvent),
            TaskPhaseV1::Unused | TaskPhaseV1::Reaped => {
                Err(TracerTaskExecuteOnlyReasonV1::UnknownRawTid)
            }
        }
    }

    fn find_live_task(&self, raw_tid: i32) -> Option<usize> {
        self.tasks[..self.slots_used]
            .iter()
            .position(|task| task.raw_tid == raw_tid && task.phase != TaskPhaseV1::Reaped)
    }

    const fn require_positive_tid(raw_tid: i32) -> Result<(), TracerTaskExecuteOnlyReasonV1> {
        if raw_tid > 0 {
            Ok(())
        } else {
            Err(TracerTaskExecuteOnlyReasonV1::InvalidRawTid)
        }
    }

    fn poison<T>(
        &mut self,
        reason: TracerTaskExecuteOnlyReasonV1,
    ) -> Result<T, TracerTaskExecuteOnlyReasonV1> {
        let first = *self.poisoned.get_or_insert(reason);
        Err(first)
    }
}

#[derive(Debug)]
pub(super) struct CompletedTracerTaskStateV1 {
    summary: TracerTaskCompletionSummaryV1,
}

impl CompletedTracerTaskStateV1 {
    pub(super) const fn summary(&self) -> TracerTaskCompletionSummaryV1 {
        self.summary
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TracerTaskCompletionSummaryV1 {
    pub(super) task_count: u16,
    /// All accepted control/transport state transitions. This is deliberately not
    /// `TraceCountersV2::event_count` or its semantic final sequence.
    pub(super) accepted_transition_count: u64,
    pub(super) initial_birth_count: u64,
    pub(super) child_announcement_count: u64,
    pub(super) child_ready_count: u64,
    pub(super) fork_birth_count: u64,
    pub(super) vfork_birth_count: u64,
    pub(super) clone_birth_count: u64,
    pub(super) exec_count: u64,
    pub(super) seccomp_entry_count: u64,
    pub(super) syscall_exit_count: u64,
    pub(super) no_return_resolution_count: u64,
    pub(super) ptrace_exit_event_count: u64,
    pub(super) terminal_reap_count: u64,
}

// A future durable adapter must count only completed semantic syscall
// transactions as `event_count`. Its ptrace-event count includes the synthetic
// initial birth plus correlated child births, exec events, and ptrace exit
// events; terminal reaps are excluded. This summary alone grants no adapter or
// durable completeness authority.

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_TID: i32 = 41_001;
    const CHILD_TID: i32 = 42_001;

    struct FixedSinkV1<const N: usize> {
        events: [Option<NormalizedTracerTaskEventV1>; N],
        length: usize,
        reject: bool,
    }

    impl<const N: usize> FixedSinkV1<N> {
        const fn new() -> Self {
            Self {
                events: [None; N],
                length: 0,
                reject: false,
            }
        }

        fn event(&self, index: usize) -> NormalizedTracerTaskEventV1 {
            self.events[index].expect("test event exists")
        }
    }

    impl<const N: usize> NormalizedTracerTaskEventSinkV1 for FixedSinkV1<N> {
        fn emit(&mut self, event: NormalizedTracerTaskEventV1) -> Result<(), ()> {
            if self.reject || self.length == N {
                return Err(());
            }
            self.events[self.length] = Some(event);
            self.length += 1;
            Ok(())
        }
    }

    fn observe<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        observation: TracerTaskObservationV1,
    ) {
        recorder.observe(observation, sink).unwrap();
    }

    fn initial<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
    ) {
        observe(
            recorder,
            sink,
            TracerTaskObservationV1::InitialBirth {
                sequence: recorder.next_transport_sequence,
                raw_tid: ROOT_TID,
            },
        );
    }

    fn entry<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        raw_tid: i32,
        syscall_number: u32,
    ) {
        observe(
            recorder,
            sink,
            TracerTaskObservationV1::SeccompEntry {
                sequence: recorder.next_transport_sequence,
                raw_tid,
                syscall_number,
            },
        );
    }

    fn syscall_exit<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        raw_tid: i32,
        result: i64,
    ) {
        observe(
            recorder,
            sink,
            TracerTaskObservationV1::SyscallExit {
                sequence: recorder.next_transport_sequence,
                raw_tid,
                result,
            },
        );
    }

    fn announce<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        parent_raw_tid: i32,
        child_raw_tid: i32,
        kind: TracerTaskChildBirthKindV1,
        group_relation: TracerTaskGroupRelationV1,
    ) {
        observe(
            recorder,
            sink,
            TracerTaskObservationV1::ChildAnnouncement {
                sequence: recorder.next_transport_sequence,
                parent_raw_tid,
                child_raw_tid,
                kind,
                group_relation,
            },
        );
    }

    fn ready<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        child_raw_tid: i32,
    ) {
        observe(
            recorder,
            sink,
            TracerTaskObservationV1::ChildReady {
                sequence: recorder.next_transport_sequence,
                child_raw_tid,
            },
        );
    }

    fn create_child<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        child_raw_tid: i32,
        syscall_number: u32,
        kind: TracerTaskChildBirthKindV1,
        group_relation: TracerTaskGroupRelationV1,
        ready_first: bool,
    ) -> NormalizedTracerTaskEventV1 {
        entry(recorder, sink, ROOT_TID, syscall_number);
        let birth_event_index = sink.length;
        if ready_first {
            ready(recorder, sink, child_raw_tid);
            assert_eq!(sink.length, birth_event_index);
            announce(
                recorder,
                sink,
                ROOT_TID,
                child_raw_tid,
                kind,
                group_relation,
            );
        } else {
            announce(
                recorder,
                sink,
                ROOT_TID,
                child_raw_tid,
                kind,
                group_relation,
            );
            assert_eq!(sink.length, birth_event_index);
            ready(recorder, sink, child_raw_tid);
        }
        assert_eq!(sink.length, birth_event_index + 1);
        let birth = sink.event(birth_event_index);
        syscall_exit(recorder, sink, ROOT_TID, i64::from(child_raw_tid));
        birth
    }

    fn ptrace_exit<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        raw_tid: i32,
        termination: LinuxWaitTerminationV1,
    ) -> NormalizedTracerTaskEventV1 {
        let index = sink.length;
        observe(
            recorder,
            sink,
            TracerTaskObservationV1::PtraceExitEvent {
                sequence: recorder.next_transport_sequence,
                raw_tid,
                termination,
            },
        );
        sink.event(index)
    }

    fn reap<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        raw_tid: i32,
        termination: LinuxWaitTerminationV1,
    ) {
        observe(
            recorder,
            sink,
            TracerTaskObservationV1::TerminalReap {
                sequence: recorder.next_transport_sequence,
                raw_tid,
                termination,
            },
        );
    }

    fn normal_exit<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        raw_tid: i32,
        code: u8,
        group: bool,
    ) -> NormalizedTracerTaskEventV1 {
        let syscall_number = if group {
            TRACER_TASK_EXIT_GROUP_NR_X86_64_V1
        } else {
            TRACER_TASK_EXIT_NR_X86_64_V1
        };
        entry(recorder, sink, raw_tid, syscall_number);
        let termination = LinuxWaitTerminationV1::Exited { code };
        let event = ptrace_exit(recorder, sink, raw_tid, termination);
        reap(recorder, sink, raw_tid, termination);
        event
    }

    fn assert_poison_is_sticky<const N: usize>(
        recorder: &mut TracerTaskStateRecorderV1,
        sink: &mut FixedSinkV1<N>,
        reason: TracerTaskExecuteOnlyReasonV1,
    ) {
        assert_eq!(recorder.poisoned, Some(reason));
        assert_eq!(
            recorder.observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: recorder.next_transport_sequence,
                    raw_tid: ROOT_TID,
                },
                sink,
            ),
            Err(reason)
        );
    }

    #[test]
    fn supervisor_correlation_queries_expose_only_lifecycle_shape() {
        let mut recorder = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();

        assert!(!recorder.contains_live_raw_tid(ROOT_TID));
        assert!(!recorder.is_announced_child_awaiting_ready(CHILD_TID));
        assert_eq!(recorder.pending_syscall_number(ROOT_TID), None);

        initial(&mut recorder, &mut sink);
        assert!(recorder.contains_live_raw_tid(ROOT_TID));

        entry(
            &mut recorder,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_CLONE_NR_X86_64_V1,
        );
        assert_eq!(
            recorder.pending_syscall_number(ROOT_TID),
            Some(TRACER_TASK_CLONE_NR_X86_64_V1)
        );
        announce(
            &mut recorder,
            &mut sink,
            ROOT_TID,
            CHILD_TID,
            TracerTaskChildBirthKindV1::Clone,
            TracerTaskGroupRelationV1::NewThreadGroup,
        );
        assert!(!recorder.contains_live_raw_tid(CHILD_TID));
        assert!(recorder.is_announced_child_awaiting_ready(CHILD_TID));

        ready(&mut recorder, &mut sink, CHILD_TID);
        assert!(recorder.contains_live_raw_tid(CHILD_TID));
        assert!(!recorder.is_announced_child_awaiting_ready(CHILD_TID));

        syscall_exit(&mut recorder, &mut sink, ROOT_TID, i64::from(CHILD_TID));
        assert_eq!(recorder.pending_syscall_number(ROOT_TID), None);
        normal_exit(&mut recorder, &mut sink, CHILD_TID, 0, false);
        assert!(!recorder.contains_live_raw_tid(CHILD_TID));
    }

    #[test]
    fn single_task_lifecycle_is_exact_redacted_and_complete_without_exec() {
        let mut recorder = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();
        initial(&mut recorder, &mut sink);
        entry(&mut recorder, &mut sink, ROOT_TID, 39);
        syscall_exit(&mut recorder, &mut sink, ROOT_TID, i64::from(ROOT_TID));
        assert_eq!(
            sink.event(2),
            NormalizedTracerTaskEventV1::SyscallExit {
                transport_sequence: 3,
                logical_task_id: LogicalTaskId(1),
                syscall_number: 39,
            }
        );
        let exit_event = normal_exit(&mut recorder, &mut sink, ROOT_TID, 0, true);
        assert_eq!(
            exit_event,
            NormalizedTracerTaskEventV1::PtraceExitEvent {
                transport_sequence: 5,
                logical_task_id: LogicalTaskId(1),
                termination: LinuxWaitTerminationV1::Exited { code: 0 },
                resolved_no_return: Some(TracerTaskNoReturnKindV1::ExitGroup),
            }
        );

        for index in 0..sink.length {
            let debug = format!("{:?}", sink.event(index));
            assert!(!debug.contains(&ROOT_TID.to_string()));
            assert!(!debug.contains("raw_tid"));
            assert!(!debug.contains("result"));
        }
        let completed = recorder.complete().unwrap();
        let summary = completed.summary();
        assert_eq!(summary.task_count, 1);
        assert_eq!(summary.accepted_transition_count, 6);
        assert_eq!(summary.initial_birth_count, 1);
        assert_eq!(summary.child_announcement_count, 0);
        assert_eq!(summary.child_ready_count, 0);
        assert_eq!(summary.exec_count, 0);
        assert_eq!(summary.seccomp_entry_count, 2);
        assert_eq!(summary.syscall_exit_count, 1);
        assert_eq!(summary.no_return_resolution_count, 1);
        assert_eq!(summary.ptrace_exit_event_count, 1);
        assert_eq!(summary.terminal_reap_count, 1);
        let debug = format!("{completed:?}");
        assert!(!debug.contains(&ROOT_TID.to_string()));
        assert!(!debug.contains("raw_tid"));
    }

    #[test]
    fn child_correlation_accepts_both_wait_orders_and_assigns_logical_groups() {
        let mut recorder = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<64>::new();
        initial(&mut recorder, &mut sink);
        let fork = create_child(
            &mut recorder,
            &mut sink,
            CHILD_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Fork,
            TracerTaskGroupRelationV1::NewThreadGroup,
            false,
        );
        assert_eq!(
            fork,
            NormalizedTracerTaskEventV1::Birth {
                transport_sequence: 4,
                logical_task_id: LogicalTaskId(2),
                parent_logical_task_id: Some(LogicalTaskId(1)),
                thread_group_logical_task_id: LogicalTaskId(2),
                kind: TracerTaskBirthKindV1::Fork,
            }
        );
        let vfork = create_child(
            &mut recorder,
            &mut sink,
            CHILD_TID + 1,
            TRACER_TASK_VFORK_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Vfork,
            TracerTaskGroupRelationV1::NewThreadGroup,
            true,
        );
        assert_eq!(
            vfork,
            NormalizedTracerTaskEventV1::Birth {
                transport_sequence: 8,
                logical_task_id: LogicalTaskId(3),
                parent_logical_task_id: Some(LogicalTaskId(1)),
                thread_group_logical_task_id: LogicalTaskId(3),
                kind: TracerTaskBirthKindV1::Vfork,
            }
        );
        let clone_new = create_child(
            &mut recorder,
            &mut sink,
            CHILD_TID + 2,
            TRACER_TASK_CLONE3_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Clone,
            TracerTaskGroupRelationV1::NewThreadGroup,
            false,
        );
        assert_eq!(
            clone_new,
            NormalizedTracerTaskEventV1::Birth {
                transport_sequence: 12,
                logical_task_id: LogicalTaskId(4),
                parent_logical_task_id: Some(LogicalTaskId(1)),
                thread_group_logical_task_id: LogicalTaskId(4),
                kind: TracerTaskBirthKindV1::Clone,
            }
        );
        let clone_thread = create_child(
            &mut recorder,
            &mut sink,
            CHILD_TID + 3,
            TRACER_TASK_CLONE_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Clone,
            TracerTaskGroupRelationV1::SharesParentThreadGroup,
            true,
        );
        assert_eq!(
            clone_thread,
            NormalizedTracerTaskEventV1::Birth {
                transport_sequence: 16,
                logical_task_id: LogicalTaskId(5),
                parent_logical_task_id: Some(LogicalTaskId(1)),
                thread_group_logical_task_id: LogicalTaskId(1),
                kind: TracerTaskBirthKindV1::Clone,
            }
        );

        entry(&mut recorder, &mut sink, CHILD_TID, 39);
        syscall_exit(&mut recorder, &mut sink, CHILD_TID, 7);
        for tid in [CHILD_TID, CHILD_TID + 1, CHILD_TID + 2, CHILD_TID + 3] {
            normal_exit(&mut recorder, &mut sink, tid, 0, false);
        }
        normal_exit(&mut recorder, &mut sink, ROOT_TID, 0, true);
        let summary = recorder.complete().unwrap().summary();
        assert_eq!(summary.task_count, 5);
        assert_eq!(summary.child_announcement_count, 4);
        assert_eq!(summary.child_ready_count, 4);
        assert_eq!(summary.fork_birth_count, 1);
        assert_eq!(summary.vfork_birth_count, 1);
        assert_eq!(summary.clone_birth_count, 2);
        assert_eq!(summary.exec_count, 0);
    }

    #[test]
    fn creation_syscall_to_ptrace_event_matrix_is_complete() {
        use TracerTaskChildBirthKindV1::{Clone, Fork, Vfork};

        let allowed = [
            (TRACER_TASK_FORK_NR_X86_64_V1, Fork),
            (TRACER_TASK_VFORK_NR_X86_64_V1, Vfork),
            (TRACER_TASK_CLONE_NR_X86_64_V1, Fork),
            (TRACER_TASK_CLONE_NR_X86_64_V1, Vfork),
            (TRACER_TASK_CLONE_NR_X86_64_V1, Clone),
            (TRACER_TASK_CLONE3_NR_X86_64_V1, Fork),
            (TRACER_TASK_CLONE3_NR_X86_64_V1, Vfork),
            (TRACER_TASK_CLONE3_NR_X86_64_V1, Clone),
        ];
        for (syscall_number, kind) in allowed {
            let mut recorder = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<16>::new();
            initial(&mut recorder, &mut sink);
            create_child(
                &mut recorder,
                &mut sink,
                CHILD_TID,
                syscall_number,
                kind,
                TracerTaskGroupRelationV1::NewThreadGroup,
                false,
            );
            normal_exit(&mut recorder, &mut sink, CHILD_TID, 0, false);
            normal_exit(&mut recorder, &mut sink, ROOT_TID, 0, true);
            assert_eq!(recorder.complete().unwrap().summary().task_count, 2);
        }

        let forbidden = [
            (TRACER_TASK_FORK_NR_X86_64_V1, Vfork),
            (TRACER_TASK_FORK_NR_X86_64_V1, Clone),
            (TRACER_TASK_VFORK_NR_X86_64_V1, Fork),
            (TRACER_TASK_VFORK_NR_X86_64_V1, Clone),
            (39, Fork),
            (39, Vfork),
            (39, Clone),
        ];
        for (syscall_number, kind) in forbidden {
            let mut recorder = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<8>::new();
            initial(&mut recorder, &mut sink);
            entry(&mut recorder, &mut sink, ROOT_TID, syscall_number);
            let sequence = recorder.next_transport_sequence;
            assert_eq!(
                recorder.observe(
                    TracerTaskObservationV1::ChildAnnouncement {
                        sequence,
                        parent_raw_tid: ROOT_TID,
                        child_raw_tid: CHILD_TID,
                        kind,
                        group_relation: TracerTaskGroupRelationV1::NewThreadGroup,
                    },
                    &mut sink,
                ),
                Err(TracerTaskExecuteOnlyReasonV1::ChildAnnouncementSyscallMismatch)
            );
        }
    }

    #[test]
    fn group_relation_is_explicit_and_never_inferred_from_clone_event_alone() {
        use TracerTaskChildBirthKindV1::{Fork, Vfork};

        for relation in [
            TracerTaskGroupRelationV1::NewThreadGroup,
            TracerTaskGroupRelationV1::SharesParentThreadGroup,
        ] {
            let mut recorder = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<16>::new();
            initial(&mut recorder, &mut sink);
            let event = create_child(
                &mut recorder,
                &mut sink,
                CHILD_TID,
                TRACER_TASK_CLONE_NR_X86_64_V1,
                TracerTaskChildBirthKindV1::Clone,
                relation,
                false,
            );
            let expected_group = if relation == TracerTaskGroupRelationV1::NewThreadGroup {
                LogicalTaskId(2)
            } else {
                LogicalTaskId(1)
            };
            assert!(matches!(
                event,
                NormalizedTracerTaskEventV1::Birth {
                    thread_group_logical_task_id,
                    ..
                } if thread_group_logical_task_id == expected_group
            ));
        }

        for (syscall_number, kind) in [
            (TRACER_TASK_FORK_NR_X86_64_V1, Fork),
            (TRACER_TASK_VFORK_NR_X86_64_V1, Vfork),
            (TRACER_TASK_CLONE_NR_X86_64_V1, Fork),
        ] {
            let mut recorder = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<8>::new();
            initial(&mut recorder, &mut sink);
            entry(&mut recorder, &mut sink, ROOT_TID, syscall_number);
            let sequence = recorder.next_transport_sequence;
            assert_eq!(
                recorder.observe(
                    TracerTaskObservationV1::ChildAnnouncement {
                        sequence,
                        parent_raw_tid: ROOT_TID,
                        child_raw_tid: CHILD_TID,
                        kind,
                        group_relation: TracerTaskGroupRelationV1::SharesParentThreadGroup,
                    },
                    &mut sink,
                ),
                Err(TracerTaskExecuteOnlyReasonV1::BirthGroupRelationMismatch)
            );
        }
    }

    #[test]
    fn child_announcement_and_readiness_are_exactly_once_and_must_correlate() {
        let mut duplicate_ready = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut duplicate_ready, &mut sink);
        ready(&mut duplicate_ready, &mut sink, CHILD_TID);
        assert_eq!(
            duplicate_ready.observe(
                TracerTaskObservationV1::ChildReady {
                    sequence: duplicate_ready.next_transport_sequence,
                    child_raw_tid: CHILD_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::DuplicateChildReady)
        );

        let mut duplicate_announcement = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut duplicate_announcement, &mut sink);
        entry(
            &mut duplicate_announcement,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
        );
        announce(
            &mut duplicate_announcement,
            &mut sink,
            ROOT_TID,
            CHILD_TID,
            TracerTaskChildBirthKindV1::Fork,
            TracerTaskGroupRelationV1::NewThreadGroup,
        );
        assert_eq!(
            duplicate_announcement.observe(
                TracerTaskObservationV1::ChildAnnouncement {
                    sequence: duplicate_announcement.next_transport_sequence,
                    parent_raw_tid: ROOT_TID,
                    child_raw_tid: CHILD_TID + 1,
                    kind: TracerTaskChildBirthKindV1::Fork,
                    group_relation: TracerTaskGroupRelationV1::NewThreadGroup,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::DuplicateChildAnnouncement)
        );

        let mut child_before_ready = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut child_before_ready, &mut sink);
        entry(
            &mut child_before_ready,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
        );
        announce(
            &mut child_before_ready,
            &mut sink,
            ROOT_TID,
            CHILD_TID,
            TracerTaskChildBirthKindV1::Fork,
            TracerTaskGroupRelationV1::NewThreadGroup,
        );
        assert_eq!(
            child_before_ready.observe(
                TracerTaskObservationV1::SeccompEntry {
                    sequence: child_before_ready.next_transport_sequence,
                    raw_tid: CHILD_TID,
                    syscall_number: 39,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::UnknownRawTid)
        );

        let mut wrong_ready = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut wrong_ready, &mut sink);
        entry(
            &mut wrong_ready,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
        );
        announce(
            &mut wrong_ready,
            &mut sink,
            ROOT_TID,
            CHILD_TID,
            TracerTaskChildBirthKindV1::Fork,
            TracerTaskGroupRelationV1::NewThreadGroup,
        );
        ready(&mut wrong_ready, &mut sink, CHILD_TID + 1);
        assert_eq!(
            wrong_ready.observe(
                TracerTaskObservationV1::SyscallExit {
                    sequence: wrong_ready.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    result: i64::from(CHILD_TID),
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ChildNotReady)
        );

        let mut orphan_ready = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut orphan_ready, &mut sink);
        ready(&mut orphan_ready, &mut sink, CHILD_TID);
        assert!(matches!(
            orphan_ready.complete(),
            Err(TracerTaskExecuteOnlyReasonV1::IncompleteShutdown)
        ));
    }

    #[test]
    fn parent_creation_result_must_match_the_correlated_ready_child() {
        let mut missing = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut missing, &mut sink);
        entry(
            &mut missing,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
        );
        assert_eq!(
            missing.observe(
                TracerTaskObservationV1::SyscallExit {
                    sequence: missing.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    result: i64::from(CHILD_TID),
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::MissingChildAnnouncement)
        );

        for result in [0, -4096, i64::from(CHILD_TID + 1), -1] {
            let mut mismatch = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<8>::new();
            initial(&mut mismatch, &mut sink);
            entry(
                &mut mismatch,
                &mut sink,
                ROOT_TID,
                TRACER_TASK_FORK_NR_X86_64_V1,
            );
            announce(
                &mut mismatch,
                &mut sink,
                ROOT_TID,
                CHILD_TID,
                TracerTaskChildBirthKindV1::Fork,
                TracerTaskGroupRelationV1::NewThreadGroup,
            );
            ready(&mut mismatch, &mut sink, CHILD_TID);
            assert_eq!(
                mismatch.observe(
                    TracerTaskObservationV1::SyscallExit {
                        sequence: mismatch.next_transport_sequence,
                        raw_tid: ROOT_TID,
                        result,
                    },
                    &mut sink,
                ),
                Err(TracerTaskExecuteOnlyReasonV1::ChildResultMismatch)
            );
        }

        let mut failed = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();
        initial(&mut failed, &mut sink);
        for result in [-1, -4095] {
            entry(
                &mut failed,
                &mut sink,
                ROOT_TID,
                TRACER_TASK_CLONE3_NR_X86_64_V1,
            );
            syscall_exit(&mut failed, &mut sink, ROOT_TID, result);
        }
        normal_exit(&mut failed, &mut sink, ROOT_TID, 0, true);
        assert_eq!(failed.complete().unwrap().summary().task_count, 1);
    }

    #[test]
    fn exec_is_an_inflight_single_use_transition_and_failed_exec_is_allowed() {
        let mut successful = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();
        initial(&mut successful, &mut sink);
        entry(
            &mut successful,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVE_NR_X86_64_V1,
        );
        let sequence = successful.next_transport_sequence;
        observe(
            &mut successful,
            &mut sink,
            TracerTaskObservationV1::Exec {
                sequence,
                raw_tid: ROOT_TID,
                former_raw_tid: ROOT_TID,
            },
        );
        assert_eq!(
            successful.tasks[0].pending_syscall,
            Some(TRACER_TASK_EXECVE_NR_X86_64_V1)
        );
        syscall_exit(&mut successful, &mut sink, ROOT_TID, 0);
        normal_exit(&mut successful, &mut sink, ROOT_TID, 0, true);
        assert_eq!(successful.complete().unwrap().summary().exec_count, 1);

        let mut failed = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();
        initial(&mut failed, &mut sink);
        entry(
            &mut failed,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVEAT_NR_X86_64_V1,
        );
        syscall_exit(&mut failed, &mut sink, ROOT_TID, -2);
        normal_exit(&mut failed, &mut sink, ROOT_TID, 0, true);
        assert_eq!(failed.complete().unwrap().summary().exec_count, 0);
    }

    #[test]
    fn every_exec_order_result_identity_and_repeat_violation_poisons() {
        let mut without_entry = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut without_entry, &mut sink);
        assert_eq!(
            without_entry.observe(
                TracerTaskObservationV1::Exec {
                    sequence: without_entry.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    former_raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ExecWithoutEntry)
        );

        let mut wrong_syscall = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut wrong_syscall, &mut sink);
        entry(&mut wrong_syscall, &mut sink, ROOT_TID, 39);
        assert_eq!(
            wrong_syscall.observe(
                TracerTaskObservationV1::Exec {
                    sequence: wrong_syscall.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    former_raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ExecSyscallMismatch)
        );

        let mut replacement = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut replacement, &mut sink);
        entry(
            &mut replacement,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVE_NR_X86_64_V1,
        );
        assert_eq!(
            replacement.observe(
                TracerTaskObservationV1::Exec {
                    sequence: replacement.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    former_raw_tid: ROOT_TID + 1,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ExecTidReplacementUnsupported)
        );

        let mut missing = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut missing, &mut sink);
        entry(
            &mut missing,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVE_NR_X86_64_V1,
        );
        assert_eq!(
            missing.observe(
                TracerTaskObservationV1::SyscallExit {
                    sequence: missing.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    result: 0,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::MissingExecEvent)
        );

        for result in [-1, -4096, 1] {
            let mut bad_result = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<8>::new();
            initial(&mut bad_result, &mut sink);
            entry(
                &mut bad_result,
                &mut sink,
                ROOT_TID,
                TRACER_TASK_EXECVE_NR_X86_64_V1,
            );
            let sequence = bad_result.next_transport_sequence;
            observe(
                &mut bad_result,
                &mut sink,
                TracerTaskObservationV1::Exec {
                    sequence,
                    raw_tid: ROOT_TID,
                    former_raw_tid: ROOT_TID,
                },
            );
            assert_eq!(
                bad_result.observe(
                    TracerTaskObservationV1::SyscallExit {
                        sequence: bad_result.next_transport_sequence,
                        raw_tid: ROOT_TID,
                        result,
                    },
                    &mut sink,
                ),
                Err(TracerTaskExecuteOnlyReasonV1::ExecResultMismatch)
            );
        }

        let mut duplicate = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();
        initial(&mut duplicate, &mut sink);
        entry(
            &mut duplicate,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVE_NR_X86_64_V1,
        );
        let sequence = duplicate.next_transport_sequence;
        observe(
            &mut duplicate,
            &mut sink,
            TracerTaskObservationV1::Exec {
                sequence,
                raw_tid: ROOT_TID,
                former_raw_tid: ROOT_TID,
            },
        );
        assert_eq!(
            duplicate.observe(
                TracerTaskObservationV1::Exec {
                    sequence: duplicate.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    former_raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::DuplicateExec)
        );

        let mut repeated = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();
        initial(&mut repeated, &mut sink);
        entry(
            &mut repeated,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVE_NR_X86_64_V1,
        );
        let sequence = repeated.next_transport_sequence;
        observe(
            &mut repeated,
            &mut sink,
            TracerTaskObservationV1::Exec {
                sequence,
                raw_tid: ROOT_TID,
                former_raw_tid: ROOT_TID,
            },
        );
        syscall_exit(&mut repeated, &mut sink, ROOT_TID, 0);
        entry(
            &mut repeated,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVEAT_NR_X86_64_V1,
        );
        assert_eq!(
            repeated.observe(
                TracerTaskObservationV1::Exec {
                    sequence: repeated.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    former_raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::DuplicateExec)
        );
    }

    #[test]
    fn exec_rejects_live_shared_threads_but_not_distinct_thread_groups() {
        let mut shared = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<16>::new();
        initial(&mut shared, &mut sink);
        create_child(
            &mut shared,
            &mut sink,
            CHILD_TID,
            TRACER_TASK_CLONE_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Clone,
            TracerTaskGroupRelationV1::SharesParentThreadGroup,
            false,
        );
        entry(
            &mut shared,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVE_NR_X86_64_V1,
        );
        assert_eq!(
            shared.observe(
                TracerTaskObservationV1::Exec {
                    sequence: shared.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    former_raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ExecThreadTeardownUnsupported)
        );

        let mut distinct = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<32>::new();
        initial(&mut distinct, &mut sink);
        create_child(
            &mut distinct,
            &mut sink,
            CHILD_TID,
            TRACER_TASK_CLONE3_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Clone,
            TracerTaskGroupRelationV1::NewThreadGroup,
            false,
        );
        entry(
            &mut distinct,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXECVE_NR_X86_64_V1,
        );
        let sequence = distinct.next_transport_sequence;
        observe(
            &mut distinct,
            &mut sink,
            TracerTaskObservationV1::Exec {
                sequence,
                raw_tid: ROOT_TID,
                former_raw_tid: ROOT_TID,
            },
        );
        syscall_exit(&mut distinct, &mut sink, ROOT_TID, 0);
        normal_exit(&mut distinct, &mut sink, CHILD_TID, 0, false);
        normal_exit(&mut distinct, &mut sink, ROOT_TID, 0, true);
        assert_eq!(distinct.complete().unwrap().summary().exec_count, 1);
    }

    #[test]
    fn no_return_resolution_is_atomic_with_ptrace_exit() {
        for (syscall_number, expected) in [
            (
                TRACER_TASK_EXIT_NR_X86_64_V1,
                TracerTaskNoReturnKindV1::Exit,
            ),
            (
                TRACER_TASK_EXIT_GROUP_NR_X86_64_V1,
                TracerTaskNoReturnKindV1::ExitGroup,
            ),
        ] {
            let mut recorder = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<8>::new();
            initial(&mut recorder, &mut sink);
            entry(&mut recorder, &mut sink, ROOT_TID, syscall_number);
            let event = ptrace_exit(
                &mut recorder,
                &mut sink,
                ROOT_TID,
                LinuxWaitTerminationV1::Exited { code: 0 },
            );
            assert!(matches!(
                event,
                NormalizedTracerTaskEventV1::PtraceExitEvent {
                    resolved_no_return: Some(actual),
                    ..
                } if actual == expected
            ));
            reap(
                &mut recorder,
                &mut sink,
                ROOT_TID,
                LinuxWaitTerminationV1::Exited { code: 0 },
            );
            let summary = recorder.complete().unwrap().summary();
            assert_eq!(summary.no_return_resolution_count, 1);
            assert_eq!(summary.accepted_transition_count, 4);
        }

        let mut ordinary_exit = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut ordinary_exit, &mut sink);
        entry(
            &mut ordinary_exit,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXIT_NR_X86_64_V1,
        );
        assert_eq!(
            ordinary_exit.observe(
                TracerTaskObservationV1::SyscallExit {
                    sequence: ordinary_exit.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    result: 0,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::NoReturnResolutionRequired)
        );

        let mut missing = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut missing, &mut sink);
        assert_eq!(
            missing.observe(
                TracerTaskObservationV1::PtraceExitEvent {
                    sequence: missing.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    termination: LinuxWaitTerminationV1::Exited { code: 0 },
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::NoReturnResolutionRequired)
        );

        let mut wrong_pending = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut wrong_pending, &mut sink);
        entry(&mut wrong_pending, &mut sink, ROOT_TID, 39);
        assert_eq!(
            wrong_pending.observe(
                TracerTaskObservationV1::PtraceExitEvent {
                    sequence: wrong_pending.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    termination: LinuxWaitTerminationV1::Exited { code: 0 },
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::OutstandingSyscall)
        );
    }

    #[test]
    fn signaled_and_normal_termination_paths_are_strict() {
        let mut signaled = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut signaled, &mut sink);
        let termination = LinuxWaitTerminationV1::Signaled {
            signal: 11,
            core_dumped: true,
        };
        ptrace_exit(&mut signaled, &mut sink, ROOT_TID, termination);
        reap(&mut signaled, &mut sink, ROOT_TID, termination);
        assert_eq!(signaled.complete().unwrap().summary().task_count, 1);

        for signal in [0, 65] {
            let mut invalid = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<8>::new();
            initial(&mut invalid, &mut sink);
            assert_eq!(
                invalid.observe(
                    TracerTaskObservationV1::PtraceExitEvent {
                        sequence: invalid.next_transport_sequence,
                        raw_tid: ROOT_TID,
                        termination: LinuxWaitTerminationV1::Signaled {
                            signal,
                            core_dumped: false,
                        },
                    },
                    &mut sink,
                ),
                Err(TracerTaskExecuteOnlyReasonV1::InvalidTermination)
            );
        }

        let mut pending_signal = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut pending_signal, &mut sink);
        entry(&mut pending_signal, &mut sink, ROOT_TID, 39);
        assert_eq!(
            pending_signal.observe(
                TracerTaskObservationV1::PtraceExitEvent {
                    sequence: pending_signal.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    termination: LinuxWaitTerminationV1::Signaled {
                        signal: 9,
                        core_dumped: false,
                    },
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::OutstandingSyscall)
        );

        let mut mismatch = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut mismatch, &mut sink);
        let expected = LinuxWaitTerminationV1::Signaled {
            signal: 15,
            core_dumped: false,
        };
        ptrace_exit(&mut mismatch, &mut sink, ROOT_TID, expected);
        assert_eq!(
            mismatch.observe(
                TracerTaskObservationV1::TerminalReap {
                    sequence: mismatch.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    termination: LinuxWaitTerminationV1::Signaled {
                        signal: 11,
                        core_dumped: true,
                    },
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::TerminationMismatch)
        );
    }

    #[test]
    fn duplicate_reordered_unknown_and_late_transitions_poison_first() {
        let mut sequence = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        assert_eq!(
            sequence.observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: 2,
                    raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::SequenceMismatch)
        );
        assert_poison_is_sticky(
            &mut sequence,
            &mut sink,
            TracerTaskExecuteOnlyReasonV1::SequenceMismatch,
        );

        let mut duplicate_initial = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut duplicate_initial, &mut sink);
        assert_eq!(
            duplicate_initial.observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: duplicate_initial.next_transport_sequence,
                    raw_tid: ROOT_TID + 1,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::DuplicateInitialBirth)
        );

        for raw_tid in [0, -1] {
            let mut invalid = TracerTaskStateRecorderV1::new();
            let mut sink = FixedSinkV1::<8>::new();
            assert_eq!(
                invalid.observe(
                    TracerTaskObservationV1::InitialBirth {
                        sequence: 1,
                        raw_tid,
                    },
                    &mut sink,
                ),
                Err(TracerTaskExecuteOnlyReasonV1::InvalidRawTid)
            );
        }

        let mut syscall = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut syscall, &mut sink);
        assert_eq!(
            syscall.observe(
                TracerTaskObservationV1::SyscallExit {
                    sequence: syscall.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    result: 0,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::SyscallExitWithoutEntry)
        );

        let mut duplicate_entry = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut duplicate_entry, &mut sink);
        entry(&mut duplicate_entry, &mut sink, ROOT_TID, 39);
        assert_eq!(
            duplicate_entry.observe(
                TracerTaskObservationV1::SeccompEntry {
                    sequence: duplicate_entry.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    syscall_number: 39,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::DuplicateSeccompEntry)
        );

        let mut restart = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut restart, &mut sink);
        entry(&mut restart, &mut sink, ROOT_TID, 39);
        assert_eq!(
            restart.observe(
                TracerTaskObservationV1::SyscallExit {
                    sequence: restart.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    result: -512,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::SyscallRestartUnsupported)
        );

        let mut reap_first = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut reap_first, &mut sink);
        assert_eq!(
            reap_first.observe(
                TracerTaskObservationV1::TerminalReap {
                    sequence: reap_first.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    termination: LinuxWaitTerminationV1::Exited { code: 0 },
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ReapBeforePtraceExit)
        );

        let mut duplicate_exit = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut duplicate_exit, &mut sink);
        entry(
            &mut duplicate_exit,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXIT_NR_X86_64_V1,
        );
        ptrace_exit(
            &mut duplicate_exit,
            &mut sink,
            ROOT_TID,
            LinuxWaitTerminationV1::Exited { code: 0 },
        );
        assert_eq!(
            duplicate_exit.observe(
                TracerTaskObservationV1::PtraceExitEvent {
                    sequence: duplicate_exit.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    termination: LinuxWaitTerminationV1::Exited { code: 0 },
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::DuplicatePtraceExit)
        );

        let mut late = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut late, &mut sink);
        entry(
            &mut late,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXIT_NR_X86_64_V1,
        );
        ptrace_exit(
            &mut late,
            &mut sink,
            ROOT_TID,
            LinuxWaitTerminationV1::Exited { code: 0 },
        );
        assert_eq!(
            late.observe(
                TracerTaskObservationV1::SeccompEntry {
                    sequence: late.next_transport_sequence,
                    raw_tid: ROOT_TID,
                    syscall_number: 39,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::LateLifecycleEvent)
        );
    }

    #[test]
    fn parent_and_child_identity_violations_are_typed() {
        let mut no_initial = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        assert_eq!(
            no_initial.observe(
                TracerTaskObservationV1::ChildReady {
                    sequence: 1,
                    child_raw_tid: CHILD_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::InitialBirthRequired)
        );

        let mut no_entry = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut no_entry, &mut sink);
        assert_eq!(
            no_entry.observe(
                TracerTaskObservationV1::ChildAnnouncement {
                    sequence: no_entry.next_transport_sequence,
                    parent_raw_tid: ROOT_TID,
                    child_raw_tid: CHILD_TID,
                    kind: TracerTaskChildBirthKindV1::Fork,
                    group_relation: TracerTaskGroupRelationV1::NewThreadGroup,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ChildAnnouncementWithoutEntry)
        );

        let mut self_parent = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut self_parent, &mut sink);
        entry(
            &mut self_parent,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
        );
        assert_eq!(
            self_parent.observe(
                TracerTaskObservationV1::ChildAnnouncement {
                    sequence: self_parent.next_transport_sequence,
                    parent_raw_tid: ROOT_TID,
                    child_raw_tid: ROOT_TID,
                    kind: TracerTaskChildBirthKindV1::Fork,
                    group_relation: TracerTaskGroupRelationV1::NewThreadGroup,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::SelfParentTid)
        );

        let mut unknown = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut unknown, &mut sink);
        assert_eq!(
            unknown.observe(
                TracerTaskObservationV1::SeccompEntry {
                    sequence: unknown.next_transport_sequence,
                    raw_tid: CHILD_TID,
                    syscall_number: 39,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::UnknownRawTid)
        );

        let mut parent_not_running = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut parent_not_running, &mut sink);
        entry(
            &mut parent_not_running,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_EXIT_NR_X86_64_V1,
        );
        ptrace_exit(
            &mut parent_not_running,
            &mut sink,
            ROOT_TID,
            LinuxWaitTerminationV1::Exited { code: 0 },
        );
        assert_eq!(
            parent_not_running.observe(
                TracerTaskObservationV1::ChildAnnouncement {
                    sequence: parent_not_running.next_transport_sequence,
                    parent_raw_tid: ROOT_TID,
                    child_raw_tid: CHILD_TID,
                    kind: TracerTaskChildBirthKindV1::Fork,
                    group_relation: TracerTaskGroupRelationV1::NewThreadGroup,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::ParentNotRunning)
        );
    }

    #[test]
    fn exact_256_task_boundary_completes_and_257th_task_poisons() {
        let mut exact = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<1600>::new();
        initial(&mut exact, &mut sink);
        for index in 1..TRACER_TASK_MAX_TASKS_V1 {
            create_child(
                &mut exact,
                &mut sink,
                ROOT_TID + index as i32,
                TRACER_TASK_CLONE3_NR_X86_64_V1,
                TracerTaskChildBirthKindV1::Clone,
                TracerTaskGroupRelationV1::NewThreadGroup,
                index % 2 == 0,
            );
        }
        assert_eq!(exact.slots_used, TRACER_TASK_MAX_TASKS_V1);
        assert_eq!(
            exact.tasks[TRACER_TASK_MAX_TASKS_V1 - 1].logical_task_id,
            LogicalTaskId(TRACER_TASK_MAX_TASKS_V1 as u32)
        );
        for index in 1..TRACER_TASK_MAX_TASKS_V1 {
            normal_exit(&mut exact, &mut sink, ROOT_TID + index as i32, 0, false);
        }
        normal_exit(&mut exact, &mut sink, ROOT_TID, 0, true);
        let summary = exact.complete().unwrap().summary();
        assert_eq!(summary.task_count, 256);
        assert_eq!(summary.child_announcement_count, 255);
        assert_eq!(summary.child_ready_count, 255);
        assert_eq!(summary.clone_birth_count, 255);

        let mut overflow = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<1024>::new();
        initial(&mut overflow, &mut sink);
        for index in 1..TRACER_TASK_MAX_TASKS_V1 {
            create_child(
                &mut overflow,
                &mut sink,
                ROOT_TID + index as i32,
                TRACER_TASK_CLONE_NR_X86_64_V1,
                TracerTaskChildBirthKindV1::Clone,
                TracerTaskGroupRelationV1::NewThreadGroup,
                false,
            );
        }
        entry(
            &mut overflow,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_CLONE_NR_X86_64_V1,
        );
        assert_eq!(
            overflow.observe(
                TracerTaskObservationV1::ChildAnnouncement {
                    sequence: overflow.next_transport_sequence,
                    parent_raw_tid: ROOT_TID,
                    child_raw_tid: ROOT_TID + 256,
                    kind: TracerTaskChildBirthKindV1::Clone,
                    group_relation: TracerTaskGroupRelationV1::NewThreadGroup,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::TaskCapacityExceeded)
        );
    }

    #[test]
    fn counter_sequence_logical_id_and_completion_overflows_fail_closed() {
        let mut sequence = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        sequence.next_transport_sequence = u64::MAX;
        assert_eq!(
            sequence.observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: u64::MAX,
                    raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::CounterOverflow)
        );

        let mut transition = TracerTaskStateRecorderV1::new();
        transition.counters.accepted_transition_count = u64::MAX;
        assert_eq!(
            transition.observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: 1,
                    raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::CounterOverflow)
        );

        let mut logical = TracerTaskStateRecorderV1::new();
        logical.next_logical_task_id = u32::MAX;
        assert_eq!(
            logical.observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: 1,
                    raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::CounterOverflow)
        );

        let mut resolution_sum = TracerTaskStateRecorderV1::new();
        resolution_sum.counters.syscall_exit_count = u64::MAX;
        resolution_sum.counters.no_return_resolution_count = 1;
        assert!(matches!(
            resolution_sum.complete(),
            Err(TracerTaskExecuteOnlyReasonV1::CounterOverflow)
        ));

        let mut birth_counter = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut birth_counter, &mut sink);
        entry(
            &mut birth_counter,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
        );
        announce(
            &mut birth_counter,
            &mut sink,
            ROOT_TID,
            CHILD_TID,
            TracerTaskChildBirthKindV1::Fork,
            TracerTaskGroupRelationV1::NewThreadGroup,
        );
        birth_counter.counters.fork_birth_count = u64::MAX;
        assert_eq!(
            birth_counter.observe(
                TracerTaskObservationV1::ChildReady {
                    sequence: birth_counter.next_transport_sequence,
                    child_raw_tid: CHILD_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::CounterOverflow)
        );
    }

    #[test]
    fn incomplete_shutdown_and_sink_rejection_are_terminal() {
        assert!(matches!(
            TracerTaskStateRecorderV1::new().complete(),
            Err(TracerTaskExecuteOnlyReasonV1::IncompleteShutdown)
        ));

        let mut incomplete = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut incomplete, &mut sink);
        assert!(matches!(
            incomplete.complete(),
            Err(TracerTaskExecuteOnlyReasonV1::IncompleteShutdown)
        ));

        let mut rejected = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        sink.reject = true;
        assert_eq!(
            rejected.observe(
                TracerTaskObservationV1::InitialBirth {
                    sequence: 1,
                    raw_tid: ROOT_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::SinkRejected)
        );
        assert_poison_is_sticky(
            &mut rejected,
            &mut sink,
            TracerTaskExecuteOnlyReasonV1::SinkRejected,
        );

        let mut deferred_rejection = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<8>::new();
        initial(&mut deferred_rejection, &mut sink);
        entry(
            &mut deferred_rejection,
            &mut sink,
            ROOT_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
        );
        sink.reject = true;
        announce(
            &mut deferred_rejection,
            &mut sink,
            ROOT_TID,
            CHILD_TID,
            TracerTaskChildBirthKindV1::Fork,
            TracerTaskGroupRelationV1::NewThreadGroup,
        );
        assert_eq!(
            deferred_rejection.observe(
                TracerTaskObservationV1::ChildReady {
                    sequence: deferred_rejection.next_transport_sequence,
                    child_raw_tid: CHILD_TID,
                },
                &mut sink,
            ),
            Err(TracerTaskExecuteOnlyReasonV1::SinkRejected)
        );
    }

    #[test]
    fn raw_tid_is_erased_on_reap_and_can_be_reused_with_a_new_logical_id() {
        let mut recorder = TracerTaskStateRecorderV1::new();
        let mut sink = FixedSinkV1::<48>::new();
        initial(&mut recorder, &mut sink);
        create_child(
            &mut recorder,
            &mut sink,
            CHILD_TID,
            TRACER_TASK_FORK_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Fork,
            TracerTaskGroupRelationV1::NewThreadGroup,
            false,
        );
        normal_exit(&mut recorder, &mut sink, CHILD_TID, 0, false);
        assert_eq!(recorder.tasks[1].raw_tid, 0);
        assert!(recorder.tasks[1].phase == TaskPhaseV1::Reaped);
        let second = create_child(
            &mut recorder,
            &mut sink,
            CHILD_TID,
            TRACER_TASK_CLONE3_NR_X86_64_V1,
            TracerTaskChildBirthKindV1::Clone,
            TracerTaskGroupRelationV1::NewThreadGroup,
            true,
        );
        assert!(matches!(
            second,
            NormalizedTracerTaskEventV1::Birth {
                logical_task_id: LogicalTaskId(3),
                ..
            }
        ));
        normal_exit(&mut recorder, &mut sink, CHILD_TID, 0, false);
        normal_exit(&mut recorder, &mut sink, ROOT_TID, 0, true);
        assert_eq!(recorder.complete().unwrap().summary().task_count, 3);
    }
}
