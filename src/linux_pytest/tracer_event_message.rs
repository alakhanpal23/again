//! Pure decoder for native Linux x86_64 `PTRACE_GETEVENTMSG` payloads.
//!
//! A successful native request writes one eight-byte `unsigned long`. Fork,
//! vfork, and clone events carry the new TID as seen in the tracer's PID
//! namespace; exec carries the former TID; exit carries the kernel's raw wait
//! status; and seccomp carries the low 16-bit `SECCOMP_RET_DATA` value.
//!
//! Linux documents a PID-namespace attachment race that can yield a bogus but
//! numerically valid event PID. Consequently, decoded TIDs remain correlation
//! inputs only: a future connector must match them to exact stopped-task state.
//! A child-TID message carries no thread-group relation; in particular, clone
//! must never be interpreted as thread sharing without separate syscall data.
//! Likewise, a decoded exit message must later equal the terminal reap. This
//! module performs no syscall, stores no command, path, or pointer, and grants
//! no observation-completeness, EffectIR, execution, or reuse authority.
//! Matching the static seccomp policy cookie proves schema compatibility only;
//! a future connector must separately retain sealed filter-install evidence.

use super::LinuxWaitTerminationV1;
use super::tracer_wait_status::{
    LinuxPtraceEventV1, LinuxWaitStatusClassV1, LinuxWaitStatusDecodeErrorV1,
    decode_linux_wait_status_x86_64_v1,
};

const PTRACE_EVENT_MESSAGE_BYTES_X86_64_V1: usize = 8;
const LINUX_X86_64_MAX_POSSIBLE_TID_V1: u32 = 4 * 1024 * 1024 - 1;

const _: () = assert!(PTRACE_EVENT_MESSAGE_BYTES_X86_64_V1 == size_of::<u64>());
const _: () = assert!(LINUX_X86_64_MAX_POSSIBLE_TID_V1 == 4_194_303);

/// A positive TID in the tracer's PID namespace.
///
/// This value intentionally has no `Debug`, `Clone`, or `Copy` implementation:
/// it is ephemeral correlation data, not durable identity or authority.
pub(super) struct LinuxPtraceEventTidV1 {
    raw_tid: i32,
}

#[allow(dead_code)] // Used by the future ptrace connector after integration.
impl LinuxPtraceEventTidV1 {
    pub(super) const fn raw_tid(&self) -> i32 {
        self.raw_tid
    }
}

/// The exact event-specific message shapes admitted by this decoder.
///
/// This enum intentionally has no `Debug`, `Clone`, or `Copy` implementation
/// because its TID variants hold ephemeral kernel correlation values.
#[allow(dead_code)] // Foundational output for the future ptrace connector.
pub(super) enum DecodedLinuxPtraceEventMessageV1 {
    ChildTid(LinuxPtraceEventTidV1),
    FormerTid(LinuxPtraceEventTidV1),
    ExitTermination(LinuxWaitTerminationV1),
    /// The event message matched the static trace-all filter specification.
    /// This does not prove that the filter was installed for the stopped task.
    SeccompTraceCookieSchemaMatched,
}

/// Exact fail-closed rejection classes, in decoder precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxPtraceEventMessageDecodeErrorV1 {
    /// Native x86_64 event values used here are all zero-extended from 32 bits.
    UpperWordNonzero,
    TidZero,
    TidExceedsLinuxX8664Limit,
    ExitMessageMalformed(LinuxWaitStatusDecodeErrorV1),
    ExitMessageIsNotFinal,
    SeccompReservedBitsNonzero,
    SeccompTraceCookieSchemaMismatch,
}

/// Static decoder facts. This zero-sized diagnostic value is not authority.
pub(super) struct LinuxPtraceEventMessageDecoderSummaryV1 {
    _private: (),
}

#[allow(dead_code)] // Kept as a reviewable connector contract.
impl LinuxPtraceEventMessageDecoderSummaryV1 {
    pub(super) const fn decoder_id(&self) -> &'static str {
        "linux-x86_64-ptrace-geteventmsg-v1"
    }

    pub(super) const fn event_message_byte_count(&self) -> u8 {
        PTRACE_EVENT_MESSAGE_BYTES_X86_64_V1 as u8
    }

    pub(super) const fn max_possible_tid(&self) -> u32 {
        LINUX_X86_64_MAX_POSSIBLE_TID_V1
    }

    pub(super) const fn allocation_free(&self) -> bool {
        true
    }

    pub(super) const fn performs_syscall(&self) -> bool {
        false
    }

    pub(super) const fn stores_command_path_or_pointer(&self) -> bool {
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
pub(super) static LINUX_PTRACE_EVENT_MESSAGE_DECODER_SUMMARY_V1:
    LinuxPtraceEventMessageDecoderSummaryV1 =
    LinuxPtraceEventMessageDecoderSummaryV1 { _private: () };

/// Decode bytes written by one successful native x86_64 `PTRACE_GETEVENTMSG`.
///
/// The event must be the already-classified wait event for the same stopped
/// task. The caller must invoke this only after ptrace returned exactly zero.
/// Success produces correlation data, never authority.
#[allow(dead_code)] // Called by the future ptrace connector after integration.
pub(super) fn decode_linux_ptrace_event_message_x86_64_v1(
    event: LinuxPtraceEventV1,
    bytes: &[u8; PTRACE_EVENT_MESSAGE_BYTES_X86_64_V1],
) -> Result<DecodedLinuxPtraceEventMessageV1, LinuxPtraceEventMessageDecodeErrorV1> {
    let raw_message = u64::from_le_bytes(*bytes);
    if raw_message > u64::from(u32::MAX) {
        return Err(LinuxPtraceEventMessageDecodeErrorV1::UpperWordNonzero);
    }

    match event {
        LinuxPtraceEventV1::Fork | LinuxPtraceEventV1::Vfork | LinuxPtraceEventV1::Clone => {
            decode_tid_v1(raw_message).map(DecodedLinuxPtraceEventMessageV1::ChildTid)
        }
        LinuxPtraceEventV1::Exec => {
            decode_tid_v1(raw_message).map(DecodedLinuxPtraceEventMessageV1::FormerTid)
        }
        LinuxPtraceEventV1::Exit => decode_exit_v1(raw_message),
        LinuxPtraceEventV1::Seccomp => decode_seccomp_cookie_v1(raw_message),
    }
}

fn decode_tid_v1(
    raw_message: u64,
) -> Result<LinuxPtraceEventTidV1, LinuxPtraceEventMessageDecodeErrorV1> {
    if raw_message == 0 {
        return Err(LinuxPtraceEventMessageDecodeErrorV1::TidZero);
    }
    if raw_message > u64::from(LINUX_X86_64_MAX_POSSIBLE_TID_V1) {
        return Err(LinuxPtraceEventMessageDecodeErrorV1::TidExceedsLinuxX8664Limit);
    }

    Ok(LinuxPtraceEventTidV1 {
        raw_tid: raw_message as i32,
    })
}

fn decode_exit_v1(
    raw_message: u64,
) -> Result<DecodedLinuxPtraceEventMessageV1, LinuxPtraceEventMessageDecodeErrorV1> {
    let raw_status = raw_message as u32 as i32;
    match decode_linux_wait_status_x86_64_v1(raw_status) {
        Ok(LinuxWaitStatusClassV1::Final(termination)) => Ok(
            DecodedLinuxPtraceEventMessageV1::ExitTermination(termination),
        ),
        Ok(_) => Err(LinuxPtraceEventMessageDecodeErrorV1::ExitMessageIsNotFinal),
        Err(error) => Err(LinuxPtraceEventMessageDecodeErrorV1::ExitMessageMalformed(
            error,
        )),
    }
}

fn decode_seccomp_cookie_v1(
    raw_message: u64,
) -> Result<DecodedLinuxPtraceEventMessageV1, LinuxPtraceEventMessageDecodeErrorV1> {
    if raw_message > u64::from(u16::MAX) {
        return Err(LinuxPtraceEventMessageDecodeErrorV1::SeccompReservedBitsNonzero);
    }
    let expected_cookie =
        u64::from(super::tracer_seccomp::trace_all_native_seccomp_cookie_spec_v1());
    if raw_message != expected_cookie {
        return Err(LinuxPtraceEventMessageDecodeErrorV1::SeccompTraceCookieSchemaMismatch);
    }
    Ok(DecodedLinuxPtraceEventMessageV1::SeccompTraceCookieSchemaMatched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_v1(value: u64) -> [u8; PTRACE_EVENT_MESSAGE_BYTES_X86_64_V1] {
        value.to_le_bytes()
    }

    fn decode_v1(
        event: LinuxPtraceEventV1,
        value: u64,
    ) -> Result<DecodedLinuxPtraceEventMessageV1, LinuxPtraceEventMessageDecodeErrorV1> {
        decode_linux_ptrace_event_message_x86_64_v1(event, &bytes_v1(value))
    }

    fn expect_tid_v1(decoded: DecodedLinuxPtraceEventMessageV1, child: bool) -> i32 {
        match (decoded, child) {
            (DecodedLinuxPtraceEventMessageV1::ChildTid(tid), true)
            | (DecodedLinuxPtraceEventMessageV1::FormerTid(tid), false) => tid.raw_tid(),
            _ => panic!("wrong TID message shape"),
        }
    }

    #[test]
    fn native_layout_and_frozen_limits_are_exact() {
        let summary = &LINUX_PTRACE_EVENT_MESSAGE_DECODER_SUMMARY_V1;
        assert_eq!(summary.event_message_byte_count(), 8);
        assert_eq!(summary.max_possible_tid(), 4_194_303);
        assert_eq!(bytes_v1(0x0102_0304_0506_0708), [8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn all_child_events_share_exact_positive_tid_boundaries() {
        for event in [
            LinuxPtraceEventV1::Fork,
            LinuxPtraceEventV1::Vfork,
            LinuxPtraceEventV1::Clone,
        ] {
            assert_eq!(
                decode_v1(event, 0).err(),
                Some(LinuxPtraceEventMessageDecodeErrorV1::TidZero)
            );
            assert_eq!(
                expect_tid_v1(decode_v1(event, 1).expect("minimum TID"), true),
                1
            );
            assert_eq!(
                expect_tid_v1(
                    decode_v1(event, u64::from(LINUX_X86_64_MAX_POSSIBLE_TID_V1))
                        .expect("maximum possible TID"),
                    true,
                ),
                LINUX_X86_64_MAX_POSSIBLE_TID_V1 as i32
            );
            assert_eq!(
                decode_v1(event, u64::from(LINUX_X86_64_MAX_POSSIBLE_TID_V1) + 1,).err(),
                Some(LinuxPtraceEventMessageDecodeErrorV1::TidExceedsLinuxX8664Limit)
            );
        }
    }

    #[test]
    fn exec_former_tid_uses_the_same_strict_range_but_distinct_shape() {
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Exec, 0).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::TidZero)
        );
        assert_eq!(
            expect_tid_v1(
                decode_v1(LinuxPtraceEventV1::Exec, 1).expect("minimum former TID"),
                false,
            ),
            1
        );
        assert_eq!(
            expect_tid_v1(
                decode_v1(
                    LinuxPtraceEventV1::Exec,
                    u64::from(LINUX_X86_64_MAX_POSSIBLE_TID_V1),
                )
                .expect("maximum former TID"),
                false,
            ),
            LINUX_X86_64_MAX_POSSIBLE_TID_V1 as i32
        );
        assert_eq!(
            decode_v1(
                LinuxPtraceEventV1::Exec,
                u64::from(LINUX_X86_64_MAX_POSSIBLE_TID_V1) + 1,
            )
            .err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::TidExceedsLinuxX8664Limit)
        );
    }

    #[test]
    fn exit_message_reuses_only_exact_final_wait_shapes() {
        for code in 0..=u8::MAX {
            let raw_status = u64::from(code) << 8;
            let decoded =
                decode_v1(LinuxPtraceEventV1::Exit, raw_status).expect("all exit codes are exact");
            let DecodedLinuxPtraceEventMessageV1::ExitTermination(LinuxWaitTerminationV1::Exited {
                code: decoded_code,
            }) = decoded
            else {
                panic!("wrong exit message shape");
            };
            assert_eq!(decoded_code, code);
        }

        for signal in 1..=64_u8 {
            let decoded = decode_v1(LinuxPtraceEventV1::Exit, u64::from(signal))
                .expect("all native signals are exact without core flag");
            let DecodedLinuxPtraceEventMessageV1::ExitTermination(
                LinuxWaitTerminationV1::Signaled {
                    signal: decoded_signal,
                    core_dumped: false,
                },
            ) = decoded
            else {
                panic!("wrong signaled message shape");
            };
            assert_eq!(decoded_signal, signal);
        }

        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Exit, 0xffff).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::ExitMessageIsNotFinal)
        );
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Exit, 0x0109).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::ExitMessageMalformed(
                LinuxWaitStatusDecodeErrorV1::SignaledTerminationHasExitPayload,
            ))
        );
    }

    #[test]
    fn every_low_exit_status_matches_the_strict_wait_classifier() {
        for raw_status in 0..=u16::MAX {
            let wait = decode_linux_wait_status_x86_64_v1(i32::from(raw_status));
            let event = decode_v1(LinuxPtraceEventV1::Exit, u64::from(raw_status));
            match wait {
                Ok(LinuxWaitStatusClassV1::Final(expected)) => {
                    let DecodedLinuxPtraceEventMessageV1::ExitTermination(actual) =
                        event.expect("final wait status must be accepted")
                    else {
                        panic!("wrong exit event shape");
                    };
                    assert_eq!(actual, expected);
                }
                Ok(_) => assert_eq!(
                    event.err(),
                    Some(LinuxPtraceEventMessageDecodeErrorV1::ExitMessageIsNotFinal)
                ),
                Err(error) => assert_eq!(
                    event.err(),
                    Some(LinuxPtraceEventMessageDecodeErrorV1::ExitMessageMalformed(
                        error
                    ))
                ),
            }
        }
    }

    #[test]
    fn seccomp_cookie_has_exact_sixteen_bit_shape_and_value() {
        let expected =
            u64::from(super::super::tracer_seccomp::trace_all_native_seccomp_cookie_spec_v1());
        assert!(matches!(
            decode_v1(LinuxPtraceEventV1::Seccomp, expected),
            Ok(DecodedLinuxPtraceEventMessageV1::SeccompTraceCookieSchemaMatched)
        ));

        for value in 0..=u16::MAX {
            let decoded = decode_v1(LinuxPtraceEventV1::Seccomp, u64::from(value));
            if u64::from(value) == expected {
                assert!(decoded.is_ok());
            } else {
                assert_eq!(
                    decoded.err(),
                    Some(LinuxPtraceEventMessageDecodeErrorV1::SeccompTraceCookieSchemaMismatch)
                );
            }
        }
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Seccomp, 1 << 16).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::SeccompReservedBitsNonzero)
        );
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Seccomp, u64::from(u32::MAX)).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::SeccompReservedBitsNonzero)
        );
    }

    #[test]
    fn upper_word_rejection_precedes_every_event_specific_error() {
        for event in [
            LinuxPtraceEventV1::Fork,
            LinuxPtraceEventV1::Vfork,
            LinuxPtraceEventV1::Clone,
            LinuxPtraceEventV1::Exec,
            LinuxPtraceEventV1::Exit,
            LinuxPtraceEventV1::Seccomp,
        ] {
            for low_word in [0_u64, u64::from(u32::MAX)] {
                assert_eq!(
                    decode_v1(event, (1_u64 << 32) | low_word).err(),
                    Some(LinuxPtraceEventMessageDecodeErrorV1::UpperWordNonzero)
                );
                assert_eq!(
                    decode_v1(event, (u64::from(u32::MAX) << 32) | low_word).err(),
                    Some(LinuxPtraceEventMessageDecodeErrorV1::UpperWordNonzero)
                );
            }
        }
    }

    #[test]
    fn exact_event_specific_rejection_precedence_is_frozen() {
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Fork, 0).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::TidZero)
        );
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Fork, u64::from(u32::MAX)).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::TidExceedsLinuxX8664Limit)
        );
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Exit, 0x0001_0000).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::ExitMessageMalformed(
                LinuxWaitStatusDecodeErrorV1::PtraceEventBitsOnNonStop,
            ))
        );
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Seccomp, 0x0001_0000).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::SeccompReservedBitsNonzero)
        );
        assert_eq!(
            decode_v1(LinuxPtraceEventV1::Seccomp, 0).err(),
            Some(LinuxPtraceEventMessageDecodeErrorV1::SeccompTraceCookieSchemaMismatch)
        );
    }

    #[test]
    fn static_summary_grants_no_authority() {
        let summary = &LINUX_PTRACE_EVENT_MESSAGE_DECODER_SUMMARY_V1;
        assert_eq!(summary.decoder_id(), "linux-x86_64-ptrace-geteventmsg-v1");
        assert!(summary.allocation_free());
        assert!(!summary.performs_syscall());
        assert!(!summary.stores_command_path_or_pointer());
        assert!(!summary.observation_completeness_authority());
        assert!(!summary.effect_ir_authority());
        assert!(!summary.execution_authority());
        assert!(!summary.reuse_authority());
    }
}
