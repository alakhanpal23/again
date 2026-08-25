//! Pure protocol checker for the fixed ptrace transport diagnostic.
//!
//! This module deliberately models one closed, no-command proof. It does not
//! record effects, describe trace completeness, or grant execution/reuse
//! authority. The Linux transport feeds observations one at a time; only tests
//! may use the slice adapter below.

use super::ptrace_transport_qualification::FixedPtraceTransportRecorderPermitV1;
use super::{LogicalTaskId, RawLinuxWaitStatusV1};

pub(super) const PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1: u32 = 0xc000_003e;
pub(super) const PTRACE_TRANSPORT_GETPID_NR_X86_64_V1: i64 = 39;
pub(super) const PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1: i64 = 110;
pub(super) const PTRACE_TRANSPORT_GETPID_COOKIE_V1: u16 = 0xa611;
pub(super) const PTRACE_TRANSPORT_GETPPID_COOKIE_V1: u16 = 0xa612;
pub(super) const PTRACE_TRANSPORT_EXACT_EVENT_COUNT_V1: u8 = 4;
pub(super) const PTRACE_TRANSPORT_LOGICAL_TASK_ID_V1: LogicalTaskId = LogicalTaskId(1);

const PTRACE_TRANSPORT_SECCOMP_STOP_COUNT_V1: u8 = 2;
const PTRACE_TRANSPORT_PTRACE_EXIT_EVENT_COUNT_V1: u8 = 1;
const PTRACE_TRANSPORT_TERMINAL_REAP_COUNT_V1: u8 = 1;
const PTRACE_TRANSPORT_PROTOCOL_DOMAIN_V1: &[u8] = b"again fixed ptrace transport diagnostic v1";
const FNV1A64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Exact, non-cryptographic checksum of the redacted protocol transcript.
///
/// It is a schema-drift tripwire, not identity, evidence, or reuse authority.
pub(super) const PTRACE_TRANSPORT_PROTOCOL_FINGERPRINT_V1: u64 = 0xf410_1836_ef74_bb4f;

#[derive(Clone, Copy)]
pub(super) enum FixedPtraceTransportEventV1 {
    SeccompStop {
        raw_tid: i32,
        architecture: u32,
        syscall_number: i64,
        arguments: [u64; 6],
        cookie: u16,
    },
    PtraceExitEvent {
        raw_tid: i32,
        status: u64,
    },
    TerminalReap {
        raw_tid: i32,
        wait_status: RawLinuxWaitStatusV1,
    },
}

impl FixedPtraceTransportEventV1 {
    fn raw_tid(self) -> i32 {
        match self {
            Self::SeccompStop { raw_tid, .. }
            | Self::PtraceExitEvent { raw_tid, .. }
            | Self::TerminalReap { raw_tid, .. } => raw_tid,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum FixedPtraceTransportProtocolErrorV1 {
    EventLimitExceeded,
    IncompleteSequence,
    NonPositiveRawTid,
    RawTidChanged,
    UnexpectedEventKind,
    WrongArchitecture,
    WrongSyscallNumber,
    NonzeroSyscallArgument,
    WrongSeccompCookie,
    WrongPtraceExitStatus,
    NonterminalReap,
    WrongTerminalReapStatus,
    ProtocolFingerprintMismatch,
}

/// Fixed-size incremental checker. A rejected observation consumes the state,
/// so callers cannot accidentally continue from a poisoned prefix.
pub(super) struct FixedPtraceTransportProbeRecorderV1 {
    raw_tid: Option<i32>,
    accepted_event_count: u8,
    protocol_fingerprint: u64,
}

impl FixedPtraceTransportProbeRecorderV1 {
    pub(super) fn new(_permit: FixedPtraceTransportRecorderPermitV1) -> Self {
        Self::initialize()
    }

    fn initialize() -> Self {
        let mut protocol_fingerprint = FNV1A64_OFFSET_BASIS;
        protocol_fingerprint =
            fingerprint_bytes_v1(protocol_fingerprint, PTRACE_TRANSPORT_PROTOCOL_DOMAIN_V1);
        protocol_fingerprint =
            fingerprint_u32_v1(protocol_fingerprint, PTRACE_TRANSPORT_LOGICAL_TASK_ID_V1.0);
        Self {
            raw_tid: None,
            accepted_event_count: 0,
            protocol_fingerprint,
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        Self::initialize()
    }

    pub(super) fn observe(
        mut self,
        event: FixedPtraceTransportEventV1,
    ) -> Result<Self, FixedPtraceTransportProtocolErrorV1> {
        if self.accepted_event_count >= PTRACE_TRANSPORT_EXACT_EVENT_COUNT_V1 {
            return Err(FixedPtraceTransportProtocolErrorV1::EventLimitExceeded);
        }

        let raw_tid = event.raw_tid();
        if raw_tid <= 0 {
            return Err(FixedPtraceTransportProtocolErrorV1::NonPositiveRawTid);
        }
        match self.raw_tid {
            None => self.raw_tid = Some(raw_tid),
            Some(expected) if expected != raw_tid => {
                return Err(FixedPtraceTransportProtocolErrorV1::RawTidChanged);
            }
            Some(_) => {}
        }

        match self.accepted_event_count {
            0 => self.observe_seccomp_stop_v1(
                event,
                PTRACE_TRANSPORT_GETPID_NR_X86_64_V1,
                PTRACE_TRANSPORT_GETPID_COOKIE_V1,
            )?,
            1 => self.observe_seccomp_stop_v1(
                event,
                PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1,
                PTRACE_TRANSPORT_GETPPID_COOKIE_V1,
            )?,
            2 => self.observe_ptrace_exit_event_v1(event)?,
            3 => self.observe_terminal_reap_v1(event)?,
            _ => return Err(FixedPtraceTransportProtocolErrorV1::EventLimitExceeded),
        }
        self.accepted_event_count += 1;
        Ok(self)
    }

    pub(super) fn complete(
        self,
    ) -> Result<CompletedFixedPtraceTransportProbeV1, FixedPtraceTransportProtocolErrorV1> {
        if self.accepted_event_count != PTRACE_TRANSPORT_EXACT_EVENT_COUNT_V1 {
            return Err(FixedPtraceTransportProtocolErrorV1::IncompleteSequence);
        }
        if self.protocol_fingerprint != PTRACE_TRANSPORT_PROTOCOL_FINGERPRINT_V1 {
            return Err(FixedPtraceTransportProtocolErrorV1::ProtocolFingerprintMismatch);
        }
        Ok(CompletedFixedPtraceTransportProbeV1 {
            summary: FixedPtraceTransportProbeSummaryV1 {
                logical_task_id: PTRACE_TRANSPORT_LOGICAL_TASK_ID_V1,
                event_count: PTRACE_TRANSPORT_EXACT_EVENT_COUNT_V1,
                seccomp_stop_count: PTRACE_TRANSPORT_SECCOMP_STOP_COUNT_V1,
                ptrace_exit_event_count: PTRACE_TRANSPORT_PTRACE_EXIT_EVENT_COUNT_V1,
                terminal_reap_count: PTRACE_TRANSPORT_TERMINAL_REAP_COUNT_V1,
                protocol_fingerprint: self.protocol_fingerprint,
            },
        })
    }

    fn observe_seccomp_stop_v1(
        &mut self,
        event: FixedPtraceTransportEventV1,
        expected_syscall_number: i64,
        expected_cookie: u16,
    ) -> Result<(), FixedPtraceTransportProtocolErrorV1> {
        let FixedPtraceTransportEventV1::SeccompStop {
            architecture,
            syscall_number,
            arguments,
            cookie,
            ..
        } = event
        else {
            return Err(FixedPtraceTransportProtocolErrorV1::UnexpectedEventKind);
        };
        if architecture != PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1 {
            return Err(FixedPtraceTransportProtocolErrorV1::WrongArchitecture);
        }
        if syscall_number != expected_syscall_number {
            return Err(FixedPtraceTransportProtocolErrorV1::WrongSyscallNumber);
        }
        if arguments != [0; 6] {
            return Err(FixedPtraceTransportProtocolErrorV1::NonzeroSyscallArgument);
        }
        if cookie != expected_cookie {
            return Err(FixedPtraceTransportProtocolErrorV1::WrongSeccompCookie);
        }

        self.protocol_fingerprint = fingerprint_u8_v1(self.protocol_fingerprint, 1);
        self.protocol_fingerprint = fingerprint_u32_v1(self.protocol_fingerprint, architecture);
        self.protocol_fingerprint = fingerprint_i64_v1(self.protocol_fingerprint, syscall_number);
        for argument in arguments {
            self.protocol_fingerprint = fingerprint_u64_v1(self.protocol_fingerprint, argument);
        }
        self.protocol_fingerprint = fingerprint_u16_v1(self.protocol_fingerprint, cookie);
        Ok(())
    }

    fn observe_ptrace_exit_event_v1(
        &mut self,
        event: FixedPtraceTransportEventV1,
    ) -> Result<(), FixedPtraceTransportProtocolErrorV1> {
        let FixedPtraceTransportEventV1::PtraceExitEvent { status, .. } = event else {
            return Err(FixedPtraceTransportProtocolErrorV1::UnexpectedEventKind);
        };
        if status != 0 {
            return Err(FixedPtraceTransportProtocolErrorV1::WrongPtraceExitStatus);
        }
        self.protocol_fingerprint = fingerprint_u8_v1(self.protocol_fingerprint, 2);
        self.protocol_fingerprint = fingerprint_u64_v1(self.protocol_fingerprint, status);
        Ok(())
    }

    fn observe_terminal_reap_v1(
        &mut self,
        event: FixedPtraceTransportEventV1,
    ) -> Result<(), FixedPtraceTransportProtocolErrorV1> {
        let FixedPtraceTransportEventV1::TerminalReap { wait_status, .. } = event else {
            return Err(FixedPtraceTransportProtocolErrorV1::UnexpectedEventKind);
        };
        if !wait_status.is_final() {
            return Err(FixedPtraceTransportProtocolErrorV1::NonterminalReap);
        }
        if wait_status != RawLinuxWaitStatusV1::exited(0) {
            return Err(FixedPtraceTransportProtocolErrorV1::WrongTerminalReapStatus);
        }
        self.protocol_fingerprint = fingerprint_u8_v1(self.protocol_fingerprint, 3);
        self.protocol_fingerprint = fingerprint_u32_v1(self.protocol_fingerprint, wait_status.0);
        Ok(())
    }
}

/// Successful evidence is deliberately reduced to this non-authoritative,
/// redacted projection before leaving the protocol checker.
pub(super) struct CompletedFixedPtraceTransportProbeV1 {
    summary: FixedPtraceTransportProbeSummaryV1,
}

impl CompletedFixedPtraceTransportProbeV1 {
    pub(super) fn redacted_summary(&self) -> FixedPtraceTransportProbeSummaryV1 {
        self.summary
    }
}

#[derive(Clone, Copy)]
pub(super) struct FixedPtraceTransportProbeSummaryV1 {
    logical_task_id: LogicalTaskId,
    event_count: u8,
    seccomp_stop_count: u8,
    ptrace_exit_event_count: u8,
    terminal_reap_count: u8,
    protocol_fingerprint: u64,
}

impl FixedPtraceTransportProbeSummaryV1 {
    pub(super) fn logical_task_id(self) -> LogicalTaskId {
        self.logical_task_id
    }

    pub(super) fn event_count(self) -> u8 {
        self.event_count
    }

    pub(super) fn seccomp_stop_count(self) -> u8 {
        self.seccomp_stop_count
    }

    pub(super) fn ptrace_exit_event_count(self) -> u8 {
        self.ptrace_exit_event_count
    }

    pub(super) fn terminal_reap_count(self) -> u8 {
        self.terminal_reap_count
    }

    pub(super) fn protocol_fingerprint(self) -> u64 {
        self.protocol_fingerprint
    }
}

fn fingerprint_bytes_v1(mut fingerprint: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        fingerprint ^= u64::from(*byte);
        fingerprint = fingerprint.wrapping_mul(FNV1A64_PRIME);
    }
    fingerprint
}

fn fingerprint_u8_v1(fingerprint: u64, value: u8) -> u64 {
    fingerprint_bytes_v1(fingerprint, &[value])
}

fn fingerprint_u16_v1(fingerprint: u64, value: u16) -> u64 {
    fingerprint_bytes_v1(fingerprint, &value.to_be_bytes())
}

fn fingerprint_u32_v1(fingerprint: u64, value: u32) -> u64 {
    fingerprint_bytes_v1(fingerprint, &value.to_be_bytes())
}

fn fingerprint_u64_v1(fingerprint: u64, value: u64) -> u64 {
    fingerprint_bytes_v1(fingerprint, &value.to_be_bytes())
}

fn fingerprint_i64_v1(fingerprint: u64, value: i64) -> u64 {
    fingerprint_bytes_v1(fingerprint, &value.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_TID: i32 = 41_003;

    fn seccomp_event(
        raw_tid: i32,
        architecture: u32,
        syscall_number: i64,
        arguments: [u64; 6],
        cookie: u16,
    ) -> FixedPtraceTransportEventV1 {
        FixedPtraceTransportEventV1::SeccompStop {
            raw_tid,
            architecture,
            syscall_number,
            arguments,
            cookie,
        }
    }

    fn getpid_event(raw_tid: i32) -> FixedPtraceTransportEventV1 {
        seccomp_event(
            raw_tid,
            PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
            PTRACE_TRANSPORT_GETPID_NR_X86_64_V1,
            [0; 6],
            PTRACE_TRANSPORT_GETPID_COOKIE_V1,
        )
    }

    fn getppid_event(raw_tid: i32) -> FixedPtraceTransportEventV1 {
        seccomp_event(
            raw_tid,
            PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
            PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1,
            [0; 6],
            PTRACE_TRANSPORT_GETPPID_COOKIE_V1,
        )
    }

    fn exit_event(raw_tid: i32) -> FixedPtraceTransportEventV1 {
        FixedPtraceTransportEventV1::PtraceExitEvent { raw_tid, status: 0 }
    }

    fn reap_event(raw_tid: i32) -> FixedPtraceTransportEventV1 {
        FixedPtraceTransportEventV1::TerminalReap {
            raw_tid,
            wait_status: RawLinuxWaitStatusV1::exited(0),
        }
    }

    fn exact_events(raw_tid: i32) -> [FixedPtraceTransportEventV1; 4] {
        [
            getpid_event(raw_tid),
            getppid_event(raw_tid),
            exit_event(raw_tid),
            reap_event(raw_tid),
        ]
    }

    fn accept_events_for_test(
        events: &[FixedPtraceTransportEventV1],
    ) -> Result<CompletedFixedPtraceTransportProbeV1, FixedPtraceTransportProtocolErrorV1> {
        let mut recorder = FixedPtraceTransportProbeRecorderV1::new_for_test();
        for event in events {
            recorder = recorder.observe(*event)?;
        }
        recorder.complete()
    }

    fn error_for(events: &[FixedPtraceTransportEventV1]) -> FixedPtraceTransportProtocolErrorV1 {
        match accept_events_for_test(events) {
            Ok(_) => panic!("mutated transcript unexpectedly completed"),
            Err(error) => error,
        }
    }

    #[test]
    fn exact_transcript_returns_only_redacted_non_authoritative_summary() {
        let completed = accept_events_for_test(&exact_events(RAW_TID)).unwrap();
        let summary = completed.redacted_summary();
        assert_eq!(summary.logical_task_id(), LogicalTaskId(1));
        assert_eq!(summary.event_count(), 4);
        assert_eq!(summary.seccomp_stop_count(), 2);
        assert_eq!(summary.ptrace_exit_event_count(), 1);
        assert_eq!(summary.terminal_reap_count(), 1);
        assert_eq!(
            summary.protocol_fingerprint(),
            PTRACE_TRANSPORT_PROTOCOL_FINGERPRINT_V1
        );

        // The completed value contains only the same redacted summary; no raw
        // TID or descriptor survives completion.
        assert_eq!(
            std::mem::size_of::<CompletedFixedPtraceTransportProbeV1>(),
            std::mem::size_of::<FixedPtraceTransportProbeSummaryV1>()
        );
    }

    #[test]
    fn missing_duplicate_reordered_and_extra_events_fail_closed() {
        let exact = exact_events(RAW_TID);
        assert_eq!(
            error_for(&exact[..3]),
            FixedPtraceTransportProtocolErrorV1::IncompleteSequence
        );

        let duplicate = [exact[0], exact[0], exact[2], exact[3]];
        assert_eq!(
            error_for(&duplicate),
            FixedPtraceTransportProtocolErrorV1::WrongSyscallNumber
        );

        let reordered = [exact[1], exact[0], exact[2], exact[3]];
        assert_eq!(
            error_for(&reordered),
            FixedPtraceTransportProtocolErrorV1::WrongSyscallNumber
        );

        let recorder = exact
            .iter()
            .copied()
            .try_fold(
                FixedPtraceTransportProbeRecorderV1::new_for_test(),
                |recorder, event| recorder.observe(event),
            )
            .unwrap();
        assert_eq!(
            recorder.observe(exact[3]).err().unwrap(),
            FixedPtraceTransportProtocolErrorV1::EventLimitExceeded
        );
    }

    #[test]
    fn event_kind_and_raw_tid_are_exact() {
        let exact = exact_events(RAW_TID);
        let wrong_kind = [exact[2], exact[1], exact[2], exact[3]];
        assert_eq!(
            error_for(&wrong_kind),
            FixedPtraceTransportProtocolErrorV1::UnexpectedEventKind
        );

        let changed_tid = [exact[0], getppid_event(RAW_TID + 1), exact[2], exact[3]];
        assert_eq!(
            error_for(&changed_tid),
            FixedPtraceTransportProtocolErrorV1::RawTidChanged
        );

        for raw_tid in [i32::MIN, -1, 0] {
            let invalid = exact_events(raw_tid);
            assert_eq!(
                error_for(&invalid),
                FixedPtraceTransportProtocolErrorV1::NonPositiveRawTid
            );
        }
    }

    #[test]
    fn seccomp_architecture_syscall_arguments_and_cookies_are_exact() {
        let exact = exact_events(RAW_TID);
        let mutations = [
            (
                seccomp_event(
                    RAW_TID,
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1 ^ 1,
                    PTRACE_TRANSPORT_GETPID_NR_X86_64_V1,
                    [0; 6],
                    PTRACE_TRANSPORT_GETPID_COOKIE_V1,
                ),
                FixedPtraceTransportProtocolErrorV1::WrongArchitecture,
            ),
            (
                seccomp_event(
                    RAW_TID,
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                    PTRACE_TRANSPORT_GETPID_NR_X86_64_V1 + 1,
                    [0; 6],
                    PTRACE_TRANSPORT_GETPID_COOKIE_V1,
                ),
                FixedPtraceTransportProtocolErrorV1::WrongSyscallNumber,
            ),
            (
                seccomp_event(
                    RAW_TID,
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                    PTRACE_TRANSPORT_GETPID_NR_X86_64_V1,
                    [0, 0, 0, 1, 0, 0],
                    PTRACE_TRANSPORT_GETPID_COOKIE_V1,
                ),
                FixedPtraceTransportProtocolErrorV1::NonzeroSyscallArgument,
            ),
            (
                seccomp_event(
                    RAW_TID,
                    PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                    PTRACE_TRANSPORT_GETPID_NR_X86_64_V1,
                    [0; 6],
                    PTRACE_TRANSPORT_GETPID_COOKIE_V1 ^ 1,
                ),
                FixedPtraceTransportProtocolErrorV1::WrongSeccompCookie,
            ),
        ];
        for (mutated_first, expected_error) in mutations {
            let mutated = [mutated_first, exact[1], exact[2], exact[3]];
            assert_eq!(error_for(&mutated), expected_error);
        }

        for argument_index in 0..6 {
            let mut arguments = [0; 6];
            arguments[argument_index] = 1_u64 << (argument_index * 7);
            let mutated_second = seccomp_event(
                RAW_TID,
                PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
                PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1,
                arguments,
                PTRACE_TRANSPORT_GETPPID_COOKIE_V1,
            );
            let mutated = [exact[0], mutated_second, exact[2], exact[3]];
            assert_eq!(
                error_for(&mutated),
                FixedPtraceTransportProtocolErrorV1::NonzeroSyscallArgument
            );
        }

        let wrong_second_cookie = seccomp_event(
            RAW_TID,
            PTRACE_TRANSPORT_AUDIT_ARCH_X86_64_V1,
            PTRACE_TRANSPORT_GETPPID_NR_X86_64_V1,
            [0; 6],
            PTRACE_TRANSPORT_GETPPID_COOKIE_V1 ^ 1,
        );
        let mutated = [exact[0], wrong_second_cookie, exact[2], exact[3]];
        assert_eq!(
            error_for(&mutated),
            FixedPtraceTransportProtocolErrorV1::WrongSeccompCookie
        );
    }

    #[test]
    fn exit_and_terminal_reap_are_exact() {
        let exact = exact_events(RAW_TID);
        let wrong_exit = FixedPtraceTransportEventV1::PtraceExitEvent {
            raw_tid: RAW_TID,
            status: 1,
        };
        assert_eq!(
            error_for(&[exact[0], exact[1], wrong_exit, exact[3]]),
            FixedPtraceTransportProtocolErrorV1::WrongPtraceExitStatus
        );

        for nonterminal in [RawLinuxWaitStatusV1(0x007f), RawLinuxWaitStatusV1(0xffff)] {
            let reap = FixedPtraceTransportEventV1::TerminalReap {
                raw_tid: RAW_TID,
                wait_status: nonterminal,
            };
            assert_eq!(
                error_for(&[exact[0], exact[1], exact[2], reap]),
                FixedPtraceTransportProtocolErrorV1::NonterminalReap
            );
        }

        for terminal_failure in [RawLinuxWaitStatusV1::exited(1), RawLinuxWaitStatusV1(9)] {
            let reap = FixedPtraceTransportEventV1::TerminalReap {
                raw_tid: RAW_TID,
                wait_status: terminal_failure,
            };
            assert_eq!(
                error_for(&[exact[0], exact[1], exact[2], reap]),
                FixedPtraceTransportProtocolErrorV1::WrongTerminalReapStatus
            );
        }
    }
}
