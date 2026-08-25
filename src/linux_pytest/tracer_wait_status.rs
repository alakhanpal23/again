//! Allocation-free classification of Linux x86_64 `waitpid(__WALL)` status.
//!
//! This module admits only status words the production ptrace protocol expects
//! Linux to emit. It deliberately rejects merely macro-decodable bit patterns
//! that the kernel cannot produce, such as an exit payload on a signaled reap,
//! a core flag for a non-core-dumping x86_64 signal, or ptrace event bits on a
//! non-stop result.
//!
//! A syscall stop still needs `PTRACE_GET_SYSCALL_INFO` to distinguish entry
//! from exit. An event-zero stop still needs `PTRACE_GETSIGINFO` to distinguish
//! signal-delivery and group-stop cases. `PTRACE_EVENT_STOP` still needs exact
//! task context to distinguish an automatically attached child's initial stop,
//! an interrupt stop, and a seized group-stop. This decoder stores no task ID,
//! event message, command, path, or pointer and grants no authority.

const LINUX_WAIT_LOW_BYTE_MASK_V1: u32 = 0x0000_00ff;
const LINUX_WAIT_SIGNAL_MASK_V1: u8 = 0x7f;
const LINUX_WAIT_CORE_FLAG_V1: u8 = 0x80;
const LINUX_WAIT_STOP_LOW_BYTE_V1: u8 = 0x7f;
const LINUX_WAIT_CONTINUED_V1: u32 = 0x0000_ffff;
const LINUX_WAIT_EVENT_MASK_V1: u32 = 0xffff_0000;

const LINUX_X86_64_MAX_SIGNAL_V1: u8 = 64;
const LINUX_SIGQUIT_V1: u8 = 3;
const LINUX_SIGILL_V1: u8 = 4;
const LINUX_SIGTRAP_V1: u8 = 5;
const LINUX_SIGABRT_V1: u8 = 6;
const LINUX_SIGBUS_V1: u8 = 7;
const LINUX_SIGFPE_V1: u8 = 8;
const LINUX_SIGSEGV_V1: u8 = 11;
const LINUX_SIGSTOP_V1: u8 = 19;
const LINUX_SIGTSTP_V1: u8 = 20;
const LINUX_SIGTTIN_V1: u8 = 21;
const LINUX_SIGTTOU_V1: u8 = 22;
const LINUX_SIGXCPU_V1: u8 = 24;
const LINUX_SIGXFSZ_V1: u8 = 25;
const LINUX_SIGSYS_V1: u8 = 31;
const LINUX_TRACESYSGOOD_STOP_SIGNAL_V1: u8 = LINUX_SIGTRAP_V1 | 0x80;

const LINUX_PTRACE_EVENT_FORK_V1: u16 = 1;
const LINUX_PTRACE_EVENT_VFORK_V1: u16 = 2;
const LINUX_PTRACE_EVENT_CLONE_V1: u16 = 3;
const LINUX_PTRACE_EVENT_EXEC_V1: u16 = 4;
const LINUX_PTRACE_EVENT_VFORK_DONE_V1: u16 = 5;
const LINUX_PTRACE_EVENT_EXIT_V1: u16 = 6;
const LINUX_PTRACE_EVENT_SECCOMP_V1: u16 = 7;
const LINUX_PTRACE_EVENT_STOP_V1: u16 = 128;

const _: () = assert!(LINUX_WAIT_STOP_LOW_BYTE_V1 == 0x7f);
const _: () = assert!(LINUX_WAIT_CONTINUED_V1 == 0xffff);
const _: () = assert!(LINUX_TRACESYSGOOD_STOP_SIGNAL_V1 == 0x85);
const _: () = assert!(LINUX_PTRACE_EVENT_STOP_V1 == 128);

/// A final wait result with all status-only ambiguity removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxWaitTerminationV1 {
    Exited { code: u8 },
    Signaled { signal: u8, core_dumped: bool },
}

/// Ptrace events admitted by the first production tracer contract.
///
/// `PTRACE_EVENT_VFORK_DONE` is intentionally absent because the tracer does
/// not enable that option. Receiving it therefore fails closed as a known but
/// unsupported event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(super) enum LinuxPtraceEventV1 {
    Fork = LINUX_PTRACE_EVENT_FORK_V1,
    Vfork = LINUX_PTRACE_EVENT_VFORK_V1,
    Clone = LINUX_PTRACE_EVENT_CLONE_V1,
    Exec = LINUX_PTRACE_EVENT_EXEC_V1,
    Exit = LINUX_PTRACE_EVENT_EXIT_V1,
    Seccomp = LINUX_PTRACE_EVENT_SECCOMP_V1,
}

/// Signal-shape information available in a `PTRACE_EVENT_STOP` status alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxPtraceEventStopSignalShapeV1 {
    /// `SIGTRAP`: either a seized auto-attached child's initial stop or a
    /// `PTRACE_INTERRUPT` stop. Task context is mandatory to distinguish them.
    TrapInitialChildOrInterrupt,
    /// One of SIGSTOP, SIGTSTP, SIGTTIN, or SIGTTOU. The status is a seized
    /// group-stop shape, but task context is still mandatory before resuming.
    JobControlGroupStop,
}

/// A valid `PTRACE_EVENT_STOP` status that remains non-actionable by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinuxPtraceEventStopCandidateV1 {
    pub(super) stop_signal: u8,
    pub(super) signal_shape: LinuxPtraceEventStopSignalShapeV1,
}

/// An event-zero ptrace stop requiring a later exact `PTRACE_GETSIGINFO` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinuxEventZeroStopCandidateV1 {
    pub(super) stop_signal: u8,
}

/// Data-minimized classification of one exact raw Linux wait status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxWaitStatusClassV1 {
    Final(LinuxWaitTerminationV1),
    /// `SIGTRAP | 0x80` with event zero. Entry versus exit remains unresolved.
    SyscallEntryOrExitStop,
    PtraceEvent(LinuxPtraceEventV1),
    PtraceEventStopRequiringContext(LinuxPtraceEventStopCandidateV1),
    EventZeroStopRequiringSiginfo(LinuxEventZeroStopCandidateV1),
    /// Exact `0xffff`. A connector that did not request `WCONTINUED` must
    /// treat this classified shape as protocol-unexpected and fail closed.
    Continued,
}

/// Exact fail-closed rejection classes, in decoder precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxWaitStatusDecodeErrorV1 {
    /// Bits 16..31 are ptrace-event space and are legal only on a stop status.
    PtraceEventBitsOnNonStop,
    CoreFlagWithoutSignal,
    ReservedContinuationEncoding,
    InvalidTerminationSignal {
        signal: u8,
    },
    SignaledTerminationHasExitPayload,
    CoreFlagForNonCoreDumpSignal {
        signal: u8,
    },
    InvalidEventZeroStopSignal {
        stop_signal: u8,
    },
    PtraceEventSignalMismatch {
        event_code: u16,
        stop_signal: u8,
    },
    UnsupportedPtraceEventVforkDone,
    PtraceEventStopSignalMismatch {
        stop_signal: u8,
    },
    UnknownPtraceEvent {
        event_code: u16,
    },
}

/// Static classifier facts. This zero-sized diagnostic value is not authority.
pub(super) struct LinuxWaitStatusClassifierSummaryV1 {
    _private: (),
}

#[allow(dead_code)] // Kept as a reviewable connector contract.
impl LinuxWaitStatusClassifierSummaryV1 {
    pub(super) const fn classifier_id(&self) -> &'static str {
        "linux-x86_64-waitpid-wall-status-v1"
    }

    pub(super) const fn max_signal(&self) -> u8 {
        LINUX_X86_64_MAX_SIGNAL_V1
    }

    pub(super) const fn allocation_free(&self) -> bool {
        true
    }

    pub(super) const fn stores_task_identity(&self) -> bool {
        false
    }

    pub(super) const fn stores_event_message(&self) -> bool {
        false
    }

    pub(super) const fn observation_completeness_authority(&self) -> bool {
        false
    }

    pub(super) const fn effect_ir_authority(&self) -> bool {
        false
    }

    pub(super) const fn execution_authority(&self) -> bool {
        false
    }

    pub(super) const fn reuse_authority(&self) -> bool {
        false
    }
}

#[allow(dead_code)] // Read by the future ptrace connector and tests.
pub(super) static LINUX_WAIT_STATUS_CLASSIFIER_SUMMARY_V1: LinuxWaitStatusClassifierSummaryV1 =
    LinuxWaitStatusClassifierSummaryV1 { _private: () };

/// Classify one raw status returned by a successful positive `waitpid(__WALL)`.
///
/// The caller must not invoke this for `waitpid` return zero or failure. This
/// function is pure and allocation-free. The output is not sufficient to
/// authorize a resume action, declare trace completeness, or build EffectIR.
#[allow(dead_code)] // Called by the future ptrace connector after integration.
pub(super) const fn decode_linux_wait_status_x86_64_v1(
    raw_status: i32,
) -> Result<LinuxWaitStatusClassV1, LinuxWaitStatusDecodeErrorV1> {
    let status = raw_status as u32;
    let low_byte = (status & LINUX_WAIT_LOW_BYTE_MASK_V1) as u8;

    // Ptrace events occupy bits 16..31 only on a stopped status. Reject this
    // structural conflict before interpreting any terminal subfields.
    if status & LINUX_WAIT_EVENT_MASK_V1 != 0 && low_byte != LINUX_WAIT_STOP_LOW_BYTE_V1 {
        return Err(LinuxWaitStatusDecodeErrorV1::PtraceEventBitsOnNonStop);
    }

    if status == LINUX_WAIT_CONTINUED_V1 {
        return Ok(LinuxWaitStatusClassV1::Continued);
    }

    if low_byte == 0 {
        return Ok(LinuxWaitStatusClassV1::Final(
            LinuxWaitTerminationV1::Exited {
                code: ((status >> 8) & 0xff) as u8,
            },
        ));
    }

    if low_byte == LINUX_WAIT_CORE_FLAG_V1 {
        return Err(LinuxWaitStatusDecodeErrorV1::CoreFlagWithoutSignal);
    }

    if low_byte == LINUX_WAIT_STOP_LOW_BYTE_V1 {
        return decode_linux_ptrace_stop_v1(status);
    }

    if low_byte == u8::MAX {
        return Err(LinuxWaitStatusDecodeErrorV1::ReservedContinuationEncoding);
    }

    decode_linux_terminal_signal_v1(status, low_byte)
}

const fn decode_linux_terminal_signal_v1(
    status: u32,
    low_byte: u8,
) -> Result<LinuxWaitStatusClassV1, LinuxWaitStatusDecodeErrorV1> {
    let signal = low_byte & LINUX_WAIT_SIGNAL_MASK_V1;
    if signal == 0 || signal > LINUX_X86_64_MAX_SIGNAL_V1 {
        return Err(LinuxWaitStatusDecodeErrorV1::InvalidTerminationSignal { signal });
    }
    if status & 0x0000_ff00 != 0 {
        return Err(LinuxWaitStatusDecodeErrorV1::SignaledTerminationHasExitPayload);
    }

    let core_dumped = low_byte & LINUX_WAIT_CORE_FLAG_V1 != 0;
    if core_dumped && !is_x86_64_core_dump_signal_v1(signal) {
        return Err(LinuxWaitStatusDecodeErrorV1::CoreFlagForNonCoreDumpSignal { signal });
    }

    Ok(LinuxWaitStatusClassV1::Final(
        LinuxWaitTerminationV1::Signaled {
            signal,
            core_dumped,
        },
    ))
}

const fn decode_linux_ptrace_stop_v1(
    status: u32,
) -> Result<LinuxWaitStatusClassV1, LinuxWaitStatusDecodeErrorV1> {
    let stop_signal = ((status >> 8) & 0xff) as u8;
    let event_code = (status >> 16) as u16;

    let event = match event_code {
        0 => {
            if stop_signal == LINUX_TRACESYSGOOD_STOP_SIGNAL_V1 {
                return Ok(LinuxWaitStatusClassV1::SyscallEntryOrExitStop);
            }
            if stop_signal == 0 || stop_signal > LINUX_X86_64_MAX_SIGNAL_V1 {
                return Err(LinuxWaitStatusDecodeErrorV1::InvalidEventZeroStopSignal {
                    stop_signal,
                });
            }
            return Ok(LinuxWaitStatusClassV1::EventZeroStopRequiringSiginfo(
                LinuxEventZeroStopCandidateV1 { stop_signal },
            ));
        }
        LINUX_PTRACE_EVENT_FORK_V1 => LinuxPtraceEventV1::Fork,
        LINUX_PTRACE_EVENT_VFORK_V1 => LinuxPtraceEventV1::Vfork,
        LINUX_PTRACE_EVENT_CLONE_V1 => LinuxPtraceEventV1::Clone,
        LINUX_PTRACE_EVENT_EXEC_V1 => LinuxPtraceEventV1::Exec,
        LINUX_PTRACE_EVENT_VFORK_DONE_V1 => {
            if stop_signal != LINUX_SIGTRAP_V1 {
                return Err(LinuxWaitStatusDecodeErrorV1::PtraceEventSignalMismatch {
                    event_code,
                    stop_signal,
                });
            }
            return Err(LinuxWaitStatusDecodeErrorV1::UnsupportedPtraceEventVforkDone);
        }
        LINUX_PTRACE_EVENT_EXIT_V1 => LinuxPtraceEventV1::Exit,
        LINUX_PTRACE_EVENT_SECCOMP_V1 => LinuxPtraceEventV1::Seccomp,
        LINUX_PTRACE_EVENT_STOP_V1 => return decode_ptrace_event_stop_v1(stop_signal),
        _ => {
            return Err(LinuxWaitStatusDecodeErrorV1::UnknownPtraceEvent { event_code });
        }
    };
    if stop_signal != LINUX_SIGTRAP_V1 {
        return Err(LinuxWaitStatusDecodeErrorV1::PtraceEventSignalMismatch {
            event_code: event as u16,
            stop_signal,
        });
    }
    Ok(LinuxWaitStatusClassV1::PtraceEvent(event))
}

const fn decode_ptrace_event_stop_v1(
    stop_signal: u8,
) -> Result<LinuxWaitStatusClassV1, LinuxWaitStatusDecodeErrorV1> {
    let signal_shape = if stop_signal == LINUX_SIGTRAP_V1 {
        LinuxPtraceEventStopSignalShapeV1::TrapInitialChildOrInterrupt
    } else if is_job_control_stop_signal_v1(stop_signal) {
        LinuxPtraceEventStopSignalShapeV1::JobControlGroupStop
    } else {
        return Err(LinuxWaitStatusDecodeErrorV1::PtraceEventStopSignalMismatch { stop_signal });
    };

    Ok(LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(
        LinuxPtraceEventStopCandidateV1 {
            stop_signal,
            signal_shape,
        },
    ))
}

const fn is_job_control_stop_signal_v1(signal: u8) -> bool {
    matches!(
        signal,
        LINUX_SIGSTOP_V1 | LINUX_SIGTSTP_V1 | LINUX_SIGTTIN_V1 | LINUX_SIGTTOU_V1
    )
}

const fn is_x86_64_core_dump_signal_v1(signal: u8) -> bool {
    matches!(
        signal,
        LINUX_SIGQUIT_V1
            | LINUX_SIGILL_V1
            | LINUX_SIGTRAP_V1
            | LINUX_SIGABRT_V1
            | LINUX_SIGBUS_V1
            | LINUX_SIGFPE_V1
            | LINUX_SIGSEGV_V1
            | LINUX_SIGXCPU_V1
            | LINUX_SIGXFSZ_V1
            | LINUX_SIGSYS_V1
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit_status_v1(code: u8) -> i32 {
        i32::from(code) << 8
    }

    fn signal_status_v1(signal: u8, core_dumped: bool) -> i32 {
        i32::from(signal) | if core_dumped { 0x80 } else { 0 }
    }

    fn stop_status_v1(event_code: u16, stop_signal: u8) -> i32 {
        (i32::from(event_code) << 16) | (i32::from(stop_signal) << 8) | 0x7f
    }

    #[test]
    fn numeric_linux_encodings_are_frozen() {
        assert_eq!(LINUX_WAIT_STOP_LOW_BYTE_V1, 0x7f);
        assert_eq!(LINUX_WAIT_CONTINUED_V1, 0xffff);
        assert_eq!(LINUX_TRACESYSGOOD_STOP_SIGNAL_V1, 0x85);
        assert_eq!(LinuxPtraceEventV1::Fork as u16, 1);
        assert_eq!(LinuxPtraceEventV1::Vfork as u16, 2);
        assert_eq!(LinuxPtraceEventV1::Clone as u16, 3);
        assert_eq!(LinuxPtraceEventV1::Exec as u16, 4);
        assert_eq!(LinuxPtraceEventV1::Exit as u16, 6);
        assert_eq!(LinuxPtraceEventV1::Seccomp as u16, 7);
        assert_eq!(LINUX_PTRACE_EVENT_STOP_V1, 128);
    }

    #[test]
    fn final_exit_signal_and_core_boundaries_are_exact() {
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(exit_status_v1(0)),
            Ok(LinuxWaitStatusClassV1::Final(
                LinuxWaitTerminationV1::Exited { code: 0 }
            ))
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(exit_status_v1(u8::MAX)),
            Ok(LinuxWaitStatusClassV1::Final(
                LinuxWaitTerminationV1::Exited { code: u8::MAX }
            ))
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(signal_status_v1(1, false)),
            Ok(LinuxWaitStatusClassV1::Final(
                LinuxWaitTerminationV1::Signaled {
                    signal: 1,
                    core_dumped: false,
                }
            ))
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(signal_status_v1(64, false)),
            Ok(LinuxWaitStatusClassV1::Final(
                LinuxWaitTerminationV1::Signaled {
                    signal: 64,
                    core_dumped: false,
                }
            ))
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(signal_status_v1(LINUX_SIGSEGV_V1, true)),
            Ok(LinuxWaitStatusClassV1::Final(
                LinuxWaitTerminationV1::Signaled {
                    signal: LINUX_SIGSEGV_V1,
                    core_dumped: true,
                }
            ))
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(signal_status_v1(65, false)),
            Err(LinuxWaitStatusDecodeErrorV1::InvalidTerminationSignal { signal: 65 })
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(signal_status_v1(9, true)),
            Err(LinuxWaitStatusDecodeErrorV1::CoreFlagForNonCoreDumpSignal { signal: 9 })
        );

        for signal in 1..=LINUX_X86_64_MAX_SIGNAL_V1 {
            assert!(matches!(
                decode_linux_wait_status_x86_64_v1(signal_status_v1(signal, false)),
                Ok(LinuxWaitStatusClassV1::Final(
                    LinuxWaitTerminationV1::Signaled {
                        signal: decoded,
                        core_dumped: false,
                    }
                )) if decoded == signal
            ));
            assert_eq!(
                decode_linux_wait_status_x86_64_v1(signal_status_v1(signal, true)).is_ok(),
                is_x86_64_core_dump_signal_v1(signal)
            );
        }
    }

    #[test]
    fn syscall_stop_preserves_entry_exit_obligation() {
        let decoded = decode_linux_wait_status_x86_64_v1(stop_status_v1(
            0,
            LINUX_TRACESYSGOOD_STOP_SIGNAL_V1,
        ));
        assert_eq!(decoded, Ok(LinuxWaitStatusClassV1::SyscallEntryOrExitStop));
    }

    #[test]
    fn admitted_ptrace_events_require_exact_sigtrap() {
        let cases = [
            (LINUX_PTRACE_EVENT_FORK_V1, LinuxPtraceEventV1::Fork),
            (LINUX_PTRACE_EVENT_VFORK_V1, LinuxPtraceEventV1::Vfork),
            (LINUX_PTRACE_EVENT_CLONE_V1, LinuxPtraceEventV1::Clone),
            (LINUX_PTRACE_EVENT_EXEC_V1, LinuxPtraceEventV1::Exec),
            (LINUX_PTRACE_EVENT_EXIT_V1, LinuxPtraceEventV1::Exit),
            (LINUX_PTRACE_EVENT_SECCOMP_V1, LinuxPtraceEventV1::Seccomp),
        ];
        for (event_code, expected) in cases {
            assert_eq!(
                decode_linux_wait_status_x86_64_v1(stop_status_v1(event_code, LINUX_SIGTRAP_V1,)),
                Ok(LinuxWaitStatusClassV1::PtraceEvent(expected))
            );
            for stop_signal in 0..=u8::MAX {
                if stop_signal == LINUX_SIGTRAP_V1 {
                    continue;
                }
                assert_eq!(
                    decode_linux_wait_status_x86_64_v1(stop_status_v1(event_code, stop_signal,)),
                    Err(LinuxWaitStatusDecodeErrorV1::PtraceEventSignalMismatch {
                        event_code,
                        stop_signal,
                    })
                );
            }
        }
    }

    #[test]
    fn event_stop_accepts_only_trap_or_job_control_shapes() {
        let trap = decode_linux_wait_status_x86_64_v1(stop_status_v1(
            LINUX_PTRACE_EVENT_STOP_V1,
            LINUX_SIGTRAP_V1,
        ))
        .expect("trap event stop");
        let LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(trap) = trap else {
            panic!("wrong event-stop class");
        };
        assert_eq!(trap.stop_signal, LINUX_SIGTRAP_V1);
        assert_eq!(
            trap.signal_shape,
            LinuxPtraceEventStopSignalShapeV1::TrapInitialChildOrInterrupt
        );

        for stop_signal in [
            LINUX_SIGSTOP_V1,
            LINUX_SIGTSTP_V1,
            LINUX_SIGTTIN_V1,
            LINUX_SIGTTOU_V1,
        ] {
            let decoded = decode_linux_wait_status_x86_64_v1(stop_status_v1(
                LINUX_PTRACE_EVENT_STOP_V1,
                stop_signal,
            ))
            .expect("job-control event stop");
            let LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(candidate) = decoded else {
                panic!("wrong job-control class");
            };
            assert_eq!(candidate.stop_signal, stop_signal);
            assert_eq!(
                candidate.signal_shape,
                LinuxPtraceEventStopSignalShapeV1::JobControlGroupStop
            );
        }

        for stop_signal in 0..=u8::MAX {
            if stop_signal == LINUX_SIGTRAP_V1 || is_job_control_stop_signal_v1(stop_signal) {
                continue;
            }
            assert_eq!(
                decode_linux_wait_status_x86_64_v1(stop_status_v1(
                    LINUX_PTRACE_EVENT_STOP_V1,
                    stop_signal,
                )),
                Err(LinuxWaitStatusDecodeErrorV1::PtraceEventStopSignalMismatch { stop_signal })
            );
        }
    }

    #[test]
    fn event_zero_stops_never_claim_signal_or_group_stop_classification() {
        for stop_signal in 1..=LINUX_X86_64_MAX_SIGNAL_V1 {
            let decoded = decode_linux_wait_status_x86_64_v1(stop_status_v1(0, stop_signal))
                .expect("valid event-zero stop");
            let LinuxWaitStatusClassV1::EventZeroStopRequiringSiginfo(candidate) = decoded else {
                panic!("wrong event-zero class");
            };
            assert_eq!(candidate.stop_signal, stop_signal);
        }
        for stop_signal in 0..=u8::MAX {
            if (1..=LINUX_X86_64_MAX_SIGNAL_V1).contains(&stop_signal)
                || stop_signal == LINUX_TRACESYSGOOD_STOP_SIGNAL_V1
            {
                continue;
            }
            assert_eq!(
                decode_linux_wait_status_x86_64_v1(stop_status_v1(0, stop_signal)),
                Err(LinuxWaitStatusDecodeErrorV1::InvalidEventZeroStopSignal { stop_signal })
            );
        }
    }

    #[test]
    fn all_ptrace_event_codes_have_one_frozen_outcome_at_sigtrap() {
        for event_code in 0..=u16::MAX {
            let decoded =
                decode_linux_wait_status_x86_64_v1(stop_status_v1(event_code, LINUX_SIGTRAP_V1));
            match event_code {
                0 => assert!(matches!(
                    decoded,
                    Ok(LinuxWaitStatusClassV1::EventZeroStopRequiringSiginfo(_))
                )),
                LINUX_PTRACE_EVENT_FORK_V1
                | LINUX_PTRACE_EVENT_VFORK_V1
                | LINUX_PTRACE_EVENT_CLONE_V1
                | LINUX_PTRACE_EVENT_EXEC_V1
                | LINUX_PTRACE_EVENT_EXIT_V1
                | LINUX_PTRACE_EVENT_SECCOMP_V1 => {
                    assert!(matches!(
                        decoded,
                        Ok(LinuxWaitStatusClassV1::PtraceEvent(_))
                    ));
                }
                LINUX_PTRACE_EVENT_VFORK_DONE_V1 => assert_eq!(
                    decoded,
                    Err(LinuxWaitStatusDecodeErrorV1::UnsupportedPtraceEventVforkDone)
                ),
                LINUX_PTRACE_EVENT_STOP_V1 => assert!(matches!(
                    decoded,
                    Ok(LinuxWaitStatusClassV1::PtraceEventStopRequiringContext(_))
                )),
                _ => assert_eq!(
                    decoded,
                    Err(LinuxWaitStatusDecodeErrorV1::UnknownPtraceEvent { event_code })
                ),
            }
        }
    }

    #[test]
    fn known_unsupported_vfork_done_checks_its_fixed_signal_first() {
        for stop_signal in 0..=u8::MAX {
            let decoded = decode_linux_wait_status_x86_64_v1(stop_status_v1(
                LINUX_PTRACE_EVENT_VFORK_DONE_V1,
                stop_signal,
            ));
            if stop_signal == LINUX_SIGTRAP_V1 {
                assert_eq!(
                    decoded,
                    Err(LinuxWaitStatusDecodeErrorV1::UnsupportedPtraceEventVforkDone)
                );
            } else {
                assert_eq!(
                    decoded,
                    Err(LinuxWaitStatusDecodeErrorV1::PtraceEventSignalMismatch {
                        event_code: LINUX_PTRACE_EVENT_VFORK_DONE_V1,
                        stop_signal,
                    })
                );
            }
        }
    }

    #[test]
    fn every_low_sixteen_bit_status_has_a_frozen_partition() {
        let mut exited = 0_u32;
        let mut signaled = 0_u32;
        let mut syscall = 0_u32;
        let mut event_zero = 0_u32;
        let mut continued = 0_u32;
        let mut core_without_signal = 0_u32;
        let mut reserved_continuation = 0_u32;
        let mut invalid_termination_signal = 0_u32;
        let mut termination_payload = 0_u32;
        let mut invalid_core_signal = 0_u32;
        let mut invalid_stop_signal = 0_u32;

        for raw_status in 0..=u16::MAX {
            match decode_linux_wait_status_x86_64_v1(i32::from(raw_status)) {
                Ok(LinuxWaitStatusClassV1::Final(LinuxWaitTerminationV1::Exited { code })) => {
                    assert_eq!(raw_status, u16::from(code) << 8);
                    exited += 1;
                }
                Ok(LinuxWaitStatusClassV1::Final(LinuxWaitTerminationV1::Signaled {
                    signal,
                    core_dumped,
                })) => {
                    assert_eq!(
                        raw_status,
                        u16::from(signal)
                            | if core_dumped {
                                u16::from(LINUX_WAIT_CORE_FLAG_V1)
                            } else {
                                0
                            }
                    );
                    signaled += 1;
                }
                Ok(LinuxWaitStatusClassV1::SyscallEntryOrExitStop) => {
                    assert_eq!(
                        raw_status,
                        (u16::from(LINUX_TRACESYSGOOD_STOP_SIGNAL_V1) << 8)
                            | u16::from(LINUX_WAIT_STOP_LOW_BYTE_V1)
                    );
                    syscall += 1;
                }
                Ok(LinuxWaitStatusClassV1::EventZeroStopRequiringSiginfo(candidate)) => {
                    assert_eq!(
                        raw_status,
                        (u16::from(candidate.stop_signal) << 8)
                            | u16::from(LINUX_WAIT_STOP_LOW_BYTE_V1)
                    );
                    event_zero += 1;
                }
                Ok(LinuxWaitStatusClassV1::Continued) => {
                    assert_eq!(u32::from(raw_status), LINUX_WAIT_CONTINUED_V1);
                    continued += 1;
                }
                Err(LinuxWaitStatusDecodeErrorV1::CoreFlagWithoutSignal) => {
                    core_without_signal += 1;
                }
                Err(LinuxWaitStatusDecodeErrorV1::ReservedContinuationEncoding) => {
                    reserved_continuation += 1;
                }
                Err(LinuxWaitStatusDecodeErrorV1::InvalidTerminationSignal { .. }) => {
                    invalid_termination_signal += 1;
                }
                Err(LinuxWaitStatusDecodeErrorV1::SignaledTerminationHasExitPayload) => {
                    termination_payload += 1;
                }
                Err(LinuxWaitStatusDecodeErrorV1::CoreFlagForNonCoreDumpSignal { .. }) => {
                    invalid_core_signal += 1;
                }
                Err(LinuxWaitStatusDecodeErrorV1::InvalidEventZeroStopSignal { .. }) => {
                    invalid_stop_signal += 1;
                }
                other => panic!("unexpected low-status partition {raw_status:#06x}: {other:?}"),
            }
        }

        assert_eq!(exited, 256);
        assert_eq!(signaled, 74);
        assert_eq!(syscall, 1);
        assert_eq!(event_zero, 64);
        assert_eq!(continued, 1);
        assert_eq!(core_without_signal, 256);
        assert_eq!(reserved_continuation, 255);
        assert_eq!(invalid_termination_signal, 31_744);
        assert_eq!(termination_payload, 32_640);
        assert_eq!(invalid_core_signal, 54);
        assert_eq!(invalid_stop_signal, 191);
    }

    #[test]
    fn high_event_bits_are_legal_only_for_stop_statuses() {
        for event_code in 1..=u16::MAX {
            for low_status in [
                exit_status_v1(0),
                exit_status_v1(u8::MAX),
                signal_status_v1(9, false),
                signal_status_v1(LINUX_SIGSEGV_V1, true),
                LINUX_WAIT_CONTINUED_V1 as i32,
            ] {
                let raw_status = low_status | ((i32::from(event_code)) << 16);
                assert_eq!(
                    decode_linux_wait_status_x86_64_v1(raw_status),
                    Err(LinuxWaitStatusDecodeErrorV1::PtraceEventBitsOnNonStop)
                );
            }
        }
    }

    #[test]
    fn rejection_precedence_is_exact() {
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(0x0001_0080),
            Err(LinuxWaitStatusDecodeErrorV1::PtraceEventBitsOnNonStop)
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(0x0000_0180),
            Err(LinuxWaitStatusDecodeErrorV1::CoreFlagWithoutSignal)
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(0x0000_01ff),
            Err(LinuxWaitStatusDecodeErrorV1::ReservedContinuationEncoding)
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(0x0000_0141),
            Err(LinuxWaitStatusDecodeErrorV1::InvalidTerminationSignal { signal: 65 })
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(0x0000_0109),
            Err(LinuxWaitStatusDecodeErrorV1::SignaledTerminationHasExitPayload)
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(stop_status_v1(5, 9)),
            Err(LinuxWaitStatusDecodeErrorV1::PtraceEventSignalMismatch {
                event_code: 5,
                stop_signal: 9,
            })
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(stop_status_v1(5, LINUX_SIGTRAP_V1)),
            Err(LinuxWaitStatusDecodeErrorV1::UnsupportedPtraceEventVforkDone)
        );
        assert_eq!(
            decode_linux_wait_status_x86_64_v1(stop_status_v1(0xffff, 0)),
            Err(LinuxWaitStatusDecodeErrorV1::UnknownPtraceEvent { event_code: 0xffff })
        );
    }

    #[test]
    fn static_summary_is_data_free_and_grants_no_authority() {
        let summary = &LINUX_WAIT_STATUS_CLASSIFIER_SUMMARY_V1;
        assert_eq!(
            summary.classifier_id(),
            "linux-x86_64-waitpid-wall-status-v1"
        );
        assert_eq!(summary.max_signal(), 64);
        assert!(summary.allocation_free());
        assert!(!summary.stores_task_identity());
        assert!(!summary.stores_event_message());
        assert!(!summary.observation_completeness_authority());
        assert!(!summary.effect_ir_authority());
        assert!(!summary.execution_authority());
        assert!(!summary.reuse_authority());
    }
}
