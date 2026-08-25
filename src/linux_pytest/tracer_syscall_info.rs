//! Pure decoder for the two x86_64 `PTRACE_GET_SYSCALL_INFO` records needed by
//! the future Linux tracer.
//!
//! The caller supplies one zero-initialized 84-byte buffer and the exact
//! successful return value from `ptrace`. Only the current Linux seccomp
//! record (84 bytes) and exit record (33 bytes) are accepted. Parsing is
//! explicit little-endian byte parsing; it does not depend on the host C ABI
//! and performs no allocation.
//!
//! Decoded values contain instruction, argument, and result words that can be
//! process addresses. The frame types deliberately do not implement `Debug`,
//! `Clone`, or `Copy`. Stack pointers and already-validated header flags,
//! cookies, and exit-error flags are discarded. This decoder contains no task
//! identifier and grants no observation-completeness, EffectIR, execution, or
//! reuse authority.

const PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1: usize = 84;
const PTRACE_SYSCALL_INFO_EXIT_BYTES_V1: usize = 33;
const PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1: usize = 84;

const PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1: u8 = 2;
const PTRACE_SYSCALL_INFO_SECCOMP_OPERATION_V1: u8 = 3;

const OPERATION_OFFSET_V1: usize = 0;
const RESERVED_OFFSET_V1: usize = 1;
const FLAGS_OFFSET_V1: usize = 2;
const ARCHITECTURE_OFFSET_V1: usize = 4;
const INSTRUCTION_POINTER_OFFSET_V1: usize = 8;
#[cfg(test)]
const STACK_POINTER_OFFSET_V1: usize = 16;
const UNION_OFFSET_V1: usize = 24;

const SECCOMP_SYSCALL_NUMBER_OFFSET_V1: usize = UNION_OFFSET_V1;
const SECCOMP_ARGUMENTS_OFFSET_V1: usize = 32;
const SECCOMP_ARGUMENT_COUNT_V1: usize = 6;
const SECCOMP_RETURN_DATA_OFFSET_V1: usize = 80;

const EXIT_RETURN_VALUE_OFFSET_V1: usize = UNION_OFFSET_V1;
const EXIT_IS_ERROR_OFFSET_V1: usize = 32;
const EXIT_TAIL_OFFSET_V1: usize = PTRACE_SYSCALL_INFO_EXIT_BYTES_V1;

const AUDIT_ARCH_X86_64_V1: u32 = 0xc000_003e;
const X32_SYSCALL_BIT_V1: u32 = 0x4000_0000;
const MAX_X86_64_ERRNO_V1: i64 = 4_095;

const _: [(); PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1] =
    [(); SECCOMP_RETURN_DATA_OFFSET_V1 + size_of::<u32>()];
const _: [(); PTRACE_SYSCALL_INFO_EXIT_BYTES_V1] = [(); EXIT_IS_ERROR_OFFSET_V1 + 1];
const _: [(); SECCOMP_RETURN_DATA_OFFSET_V1] =
    [(); SECCOMP_ARGUMENTS_OFFSET_V1 + SECCOMP_ARGUMENT_COUNT_V1 * size_of::<u64>()];

/// Typed, data-free rejection reasons for a malformed or unsupported record.
///
/// No variant retains raw instruction pointers, stack pointers, arguments, or
/// results from the tracee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PtraceSyscallInfoDecodeErrorV1 {
    UnsupportedReturnedByteCount,
    UnsupportedOperation,
    ExitReturnedByteCountMismatch,
    SeccompReturnedByteCountMismatch,
    HeaderReservedByteNonzero,
    HeaderFlagsNonzero,
    ArchitectureMismatch,
    SeccompSyscallNumberDoesNotFitU32,
    SeccompSyscallNumberUsesX32Abi,
    SeccompSyscallNumberNotCanonicalNative,
    SeccompCookieMismatch,
    ExitTailNonzero,
    ExitIsErrorInvalid,
    ExitResultShapeMismatch,
}

/// A validated seccomp-stop frame.
///
/// This type intentionally has no `Debug`, `Clone`, or `Copy` implementation:
/// its words may contain tracee addresses. The instruction pointer exists only
/// for immediate sealed-executable mapping and must not be logged or persisted.
#[allow(dead_code)] // Foundational output for the future syscall decoder.
pub(super) struct DecodedSeccompSyscallInfoX8664V1 {
    instruction_pointer: u64,
    syscall_number: u32,
    arguments: [u64; SECCOMP_ARGUMENT_COUNT_V1],
}

#[allow(dead_code)] // Accessed by the future syscall decoder after integration.
impl DecodedSeccompSyscallInfoX8664V1 {
    pub(super) const fn instruction_pointer(&self) -> u64 {
        self.instruction_pointer
    }

    pub(super) const fn syscall_number(&self) -> u32 {
        self.syscall_number
    }

    pub(super) const fn arguments(&self) -> &[u64; SECCOMP_ARGUMENT_COUNT_V1] {
        &self.arguments
    }
}

/// A validated syscall-exit frame.
///
/// This type intentionally has no `Debug`, `Clone`, or `Copy` implementation:
/// its words may contain tracee addresses. The instruction pointer exists only
/// for immediate sealed-executable mapping and must not be logged or persisted.
#[allow(dead_code)] // Foundational output for the future syscall decoder.
pub(super) struct DecodedExitSyscallInfoX8664V1 {
    instruction_pointer: u64,
    return_value: i64,
}

#[allow(dead_code)] // Accessed by the future syscall decoder after integration.
impl DecodedExitSyscallInfoX8664V1 {
    pub(super) const fn instruction_pointer(&self) -> u64 {
        self.instruction_pointer
    }

    pub(super) const fn return_value(&self) -> i64 {
        self.return_value
    }
}

/// The only two syscall-info shapes admitted by this decoder.
///
/// This enum intentionally has no `Debug`, `Clone`, or `Copy` implementation
/// because both variants contain raw tracee words.
#[allow(dead_code)] // Foundational output for the future ptrace connector.
pub(super) enum DecodedPtraceSyscallInfoX8664V1 {
    Seccomp(DecodedSeccompSyscallInfoX8664V1),
    Exit(DecodedExitSyscallInfoX8664V1),
}

/// Static decoder facts. This zero-sized value is diagnostic, never authority.
pub(super) struct PtraceSyscallInfoDecoderSummaryV1 {
    _private: (),
}

#[allow(dead_code)] // Kept as a reviewable connector contract.
impl PtraceSyscallInfoDecoderSummaryV1 {
    pub(super) const fn decoder_id(&self) -> &'static str {
        "x86_64-ptrace-syscall-info-seccomp-exit-v1"
    }

    pub(super) const fn buffer_byte_count(&self) -> u8 {
        PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1 as u8
    }

    pub(super) const fn seccomp_returned_byte_count(&self) -> u8 {
        PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1 as u8
    }

    pub(super) const fn exit_returned_byte_count(&self) -> u8 {
        PTRACE_SYSCALL_INFO_EXIT_BYTES_V1 as u8
    }

    pub(super) const fn allocation_free(&self) -> bool {
        true
    }

    pub(super) const fn contains_task_identity(&self) -> bool {
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
pub(super) static PTRACE_SYSCALL_INFO_DECODER_SUMMARY_V1: PtraceSyscallInfoDecoderSummaryV1 =
    PtraceSyscallInfoDecoderSummaryV1 { _private: () };

/// Decode one caller-zeroed fixed buffer after a successful ptrace request.
///
/// `returned_byte_count` must be the unmodified positive value returned by
/// `PTRACE_GET_SYSCALL_INFO`. This function is pure and allocation-free. Its
/// output is an observation frame only; it cannot authorize any later stage.
#[allow(dead_code)] // Called by the future ptrace connector after integration.
pub(super) fn decode_ptrace_syscall_info_x86_64_v1(
    returned_byte_count: usize,
    buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
) -> Result<DecodedPtraceSyscallInfoX8664V1, PtraceSyscallInfoDecodeErrorV1> {
    if returned_byte_count != PTRACE_SYSCALL_INFO_EXIT_BYTES_V1
        && returned_byte_count != PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1
    {
        return Err(PtraceSyscallInfoDecodeErrorV1::UnsupportedReturnedByteCount);
    }

    match buffer[OPERATION_OFFSET_V1] {
        PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1 => {
            if returned_byte_count != PTRACE_SYSCALL_INFO_EXIT_BYTES_V1 {
                return Err(PtraceSyscallInfoDecodeErrorV1::ExitReturnedByteCountMismatch);
            }
            validate_common_header_v1(buffer)?;
            decode_exit_v1(buffer)
        }
        PTRACE_SYSCALL_INFO_SECCOMP_OPERATION_V1 => {
            if returned_byte_count != PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1 {
                return Err(PtraceSyscallInfoDecodeErrorV1::SeccompReturnedByteCountMismatch);
            }
            validate_common_header_v1(buffer)?;
            decode_seccomp_v1(buffer)
        }
        _ => Err(PtraceSyscallInfoDecodeErrorV1::UnsupportedOperation),
    }
}

fn validate_common_header_v1(
    buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
) -> Result<(), PtraceSyscallInfoDecodeErrorV1> {
    if buffer[RESERVED_OFFSET_V1] != 0 {
        return Err(PtraceSyscallInfoDecodeErrorV1::HeaderReservedByteNonzero);
    }
    if read_u16_le_v1(buffer, FLAGS_OFFSET_V1) != 0 {
        return Err(PtraceSyscallInfoDecodeErrorV1::HeaderFlagsNonzero);
    }
    if read_u32_le_v1(buffer, ARCHITECTURE_OFFSET_V1) != AUDIT_ARCH_X86_64_V1 {
        return Err(PtraceSyscallInfoDecodeErrorV1::ArchitectureMismatch);
    }
    Ok(())
}

fn decode_seccomp_v1(
    buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
) -> Result<DecodedPtraceSyscallInfoX8664V1, PtraceSyscallInfoDecodeErrorV1> {
    let raw_syscall_number = read_u64_le_v1(buffer, SECCOMP_SYSCALL_NUMBER_OFFSET_V1);
    let syscall_number = u32::try_from(raw_syscall_number)
        .map_err(|_| PtraceSyscallInfoDecodeErrorV1::SeccompSyscallNumberDoesNotFitU32)?;
    if syscall_number & X32_SYSCALL_BIT_V1 != 0 {
        return Err(PtraceSyscallInfoDecodeErrorV1::SeccompSyscallNumberUsesX32Abi);
    }
    // On x86, syscall_get_nr() returns an int. A bit-31-set value that did
    // come from the kernel would therefore be sign-extended in the u64 UAPI
    // field, not encoded as a zero-extended u32.
    if syscall_number > i32::MAX as u32 {
        return Err(PtraceSyscallInfoDecodeErrorV1::SeccompSyscallNumberNotCanonicalNative);
    }

    let expected_cookie =
        super::tracer_seccomp::TRACE_ALL_NATIVE_SECCOMP_POLICY_SUMMARY_V1.trace_cookie();
    if read_u32_le_v1(buffer, SECCOMP_RETURN_DATA_OFFSET_V1) != u32::from(expected_cookie) {
        return Err(PtraceSyscallInfoDecodeErrorV1::SeccompCookieMismatch);
    }

    let mut arguments = [0_u64; SECCOMP_ARGUMENT_COUNT_V1];
    let mut argument_index = 0;
    while argument_index < SECCOMP_ARGUMENT_COUNT_V1 {
        arguments[argument_index] = read_u64_le_v1(
            buffer,
            SECCOMP_ARGUMENTS_OFFSET_V1 + argument_index * size_of::<u64>(),
        );
        argument_index += 1;
    }

    Ok(DecodedPtraceSyscallInfoX8664V1::Seccomp(
        DecodedSeccompSyscallInfoX8664V1 {
            instruction_pointer: read_u64_le_v1(buffer, INSTRUCTION_POINTER_OFFSET_V1),
            syscall_number,
            arguments,
        },
    ))
}

fn decode_exit_v1(
    buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
) -> Result<DecodedPtraceSyscallInfoX8664V1, PtraceSyscallInfoDecodeErrorV1> {
    let mut tail_index = EXIT_TAIL_OFFSET_V1;
    while tail_index < buffer.len() {
        if buffer[tail_index] != 0 {
            return Err(PtraceSyscallInfoDecodeErrorV1::ExitTailNonzero);
        }
        tail_index += 1;
    }

    let is_error = match buffer[EXIT_IS_ERROR_OFFSET_V1] {
        0 => false,
        1 => true,
        _ => return Err(PtraceSyscallInfoDecodeErrorV1::ExitIsErrorInvalid),
    };
    let return_value = read_i64_le_v1(buffer, EXIT_RETURN_VALUE_OFFSET_V1);
    let has_x86_64_errno_shape = (-MAX_X86_64_ERRNO_V1..=-1).contains(&return_value);
    if is_error != has_x86_64_errno_shape {
        return Err(PtraceSyscallInfoDecodeErrorV1::ExitResultShapeMismatch);
    }

    Ok(DecodedPtraceSyscallInfoX8664V1::Exit(
        DecodedExitSyscallInfoX8664V1 {
            instruction_pointer: read_u64_le_v1(buffer, INSTRUCTION_POINTER_OFFSET_V1),
            return_value,
        },
    ))
}

fn read_u16_le_v1(buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1], offset: usize) -> u16 {
    u16::from_le_bytes([buffer[offset], buffer[offset + 1]])
}

fn read_u32_le_v1(buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

fn read_u64_le_v1(buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1], offset: usize) -> u64 {
    u64::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ])
}

fn read_i64_le_v1(buffer: &[u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1], offset: usize) -> i64 {
    read_u64_le_v1(buffer, offset) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[repr(C)]
    struct LinuxPtraceSyscallInfoHeaderTripwireV1 {
        operation: u8,
        reserved: u8,
        flags: u16,
        architecture: u32,
        instruction_pointer: u64,
        stack_pointer: u64,
    }

    #[repr(C)]
    struct LinuxPtraceSyscallInfoExitTripwireV1 {
        return_value: i64,
        is_error: u8,
    }

    #[repr(C)]
    struct LinuxPtraceSyscallInfoSeccompTripwireV1 {
        syscall_number: u64,
        arguments: [u64; 6],
        return_data: u32,
        reserved2: u32,
    }

    fn write_u16_le_v1(
        buffer: &mut [u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
        offset: usize,
        value: u16,
    ) {
        buffer[offset..offset + size_of::<u16>()].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32_le_v1(
        buffer: &mut [u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
        offset: usize,
        value: u32,
    ) {
        buffer[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64_le_v1(
        buffer: &mut [u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
        offset: usize,
        value: u64,
    ) {
        buffer[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i64_le_v1(
        buffer: &mut [u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1],
        offset: usize,
        value: i64,
    ) {
        buffer[offset..offset + size_of::<i64>()].copy_from_slice(&value.to_le_bytes());
    }

    fn common_buffer_v1(operation: u8) -> [u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1] {
        let mut buffer = [0_u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1];
        buffer[OPERATION_OFFSET_V1] = operation;
        write_u32_le_v1(&mut buffer, ARCHITECTURE_OFFSET_V1, AUDIT_ARCH_X86_64_V1);
        write_u64_le_v1(
            &mut buffer,
            INSTRUCTION_POINTER_OFFSET_V1,
            0x0123_4567_89ab_cdef,
        );
        write_u64_le_v1(&mut buffer, STACK_POINTER_OFFSET_V1, 0xfedc_ba98_7654_3210);
        buffer
    }

    fn seccomp_buffer_v1(
        syscall_number: u64,
        arguments: [u64; SECCOMP_ARGUMENT_COUNT_V1],
    ) -> [u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1] {
        let mut buffer = common_buffer_v1(PTRACE_SYSCALL_INFO_SECCOMP_OPERATION_V1);
        write_u64_le_v1(
            &mut buffer,
            SECCOMP_SYSCALL_NUMBER_OFFSET_V1,
            syscall_number,
        );
        let mut argument_index = 0;
        while argument_index < arguments.len() {
            write_u64_le_v1(
                &mut buffer,
                SECCOMP_ARGUMENTS_OFFSET_V1 + argument_index * size_of::<u64>(),
                arguments[argument_index],
            );
            argument_index += 1;
        }
        write_u32_le_v1(
            &mut buffer,
            SECCOMP_RETURN_DATA_OFFSET_V1,
            u32::from(
                super::super::tracer_seccomp::TRACE_ALL_NATIVE_SECCOMP_POLICY_SUMMARY_V1
                    .trace_cookie(),
            ),
        );
        buffer
    }

    fn exit_buffer_v1(
        return_value: i64,
        is_error: u8,
    ) -> [u8; PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1] {
        let mut buffer = common_buffer_v1(PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1);
        write_i64_le_v1(&mut buffer, EXIT_RETURN_VALUE_OFFSET_V1, return_value);
        buffer[EXIT_IS_ERROR_OFFSET_V1] = is_error;
        buffer
    }

    #[test]
    fn linux_uapi_layout_offsets_and_return_sizes_are_frozen() {
        assert_eq!(PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1, 84);
        assert_eq!(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, 33);
        assert_eq!(PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1, 84);
        assert_eq!(PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1, 2);
        assert_eq!(PTRACE_SYSCALL_INFO_SECCOMP_OPERATION_V1, 3);

        assert_eq!(size_of::<LinuxPtraceSyscallInfoHeaderTripwireV1>(), 24);
        assert_eq!(align_of::<LinuxPtraceSyscallInfoHeaderTripwireV1>(), 8);
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoHeaderTripwireV1, operation),
            0
        );
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoHeaderTripwireV1, reserved),
            1
        );
        assert_eq!(offset_of!(LinuxPtraceSyscallInfoHeaderTripwireV1, flags), 2);
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoHeaderTripwireV1, architecture),
            4
        );
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoHeaderTripwireV1, instruction_pointer),
            8
        );
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoHeaderTripwireV1, stack_pointer),
            16
        );

        assert_eq!(size_of::<LinuxPtraceSyscallInfoExitTripwireV1>(), 16);
        assert_eq!(align_of::<LinuxPtraceSyscallInfoExitTripwireV1>(), 8);
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoExitTripwireV1, return_value),
            0
        );
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoExitTripwireV1, is_error),
            8
        );
        assert_eq!(
            UNION_OFFSET_V1 + offset_of!(LinuxPtraceSyscallInfoExitTripwireV1, is_error) + 1,
            33
        );

        assert_eq!(size_of::<LinuxPtraceSyscallInfoSeccompTripwireV1>(), 64);
        assert_eq!(align_of::<LinuxPtraceSyscallInfoSeccompTripwireV1>(), 8);
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoSeccompTripwireV1, syscall_number),
            0
        );
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoSeccompTripwireV1, arguments),
            8
        );
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoSeccompTripwireV1, return_data),
            56
        );
        assert_eq!(
            offset_of!(LinuxPtraceSyscallInfoSeccompTripwireV1, reserved2),
            60
        );
        // The current UAPI's `reserved2` starts immediately after the exact
        // 84-byte seccomp payload; C layout then aligns the member to 64 bytes.
        assert_eq!(
            UNION_OFFSET_V1 + offset_of!(LinuxPtraceSyscallInfoSeccompTripwireV1, reserved2),
            PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1
        );
        assert_eq!(
            UNION_OFFSET_V1 + size_of::<LinuxPtraceSyscallInfoSeccompTripwireV1>(),
            88
        );
        assert_eq!(
            UNION_OFFSET_V1 + offset_of!(LinuxPtraceSyscallInfoSeccompTripwireV1, return_data) + 4,
            84
        );

        assert_eq!(AUDIT_ARCH_X86_64_V1, 0xc000_003e);
        assert_eq!(X32_SYSCALL_BIT_V1, 0x4000_0000);
        assert_eq!(MAX_X86_64_ERRNO_V1, 4_095);
    }

    #[test]
    fn canonical_seccomp_frame_decodes_exact_little_endian_words() {
        let arguments = [
            0,
            1,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            u64::from(u32::MAX),
            u64::MAX,
        ];
        let buffer = seccomp_buffer_v1(0x3fff_ffff, arguments);
        let decoded =
            decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1, &buffer)
                .expect("canonical seccomp frame rejected");
        let DecodedPtraceSyscallInfoX8664V1::Seccomp(frame) = decoded else {
            panic!("seccomp operation decoded as exit");
        };
        assert_eq!(frame.instruction_pointer(), 0x0123_4567_89ab_cdef);
        assert_eq!(frame.syscall_number(), 0x3fff_ffff);
        assert_eq!(frame.arguments(), &arguments);
    }

    #[test]
    fn canonical_exit_success_and_error_boundaries_decode() {
        for return_value in [i64::MIN, -4_096, 0, 1, i64::MAX] {
            let buffer = exit_buffer_v1(return_value, 0);
            let decoded =
                decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &buffer)
                    .expect("canonical successful exit rejected");
            let DecodedPtraceSyscallInfoX8664V1::Exit(frame) = decoded else {
                panic!("exit operation decoded as seccomp");
            };
            assert_eq!(frame.instruction_pointer(), 0x0123_4567_89ab_cdef);
            assert_eq!(frame.return_value(), return_value);
        }

        for errno in 1..=MAX_X86_64_ERRNO_V1 {
            let buffer = exit_buffer_v1(-errno, 1);
            let decoded =
                decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &buffer)
                    .expect("canonical x86_64 errno exit rejected");
            let DecodedPtraceSyscallInfoX8664V1::Exit(frame) = decoded else {
                panic!("exit operation decoded as seccomp");
            };
            assert_eq!(frame.return_value(), -errno);
        }
    }

    #[test]
    fn every_unknown_operation_is_rejected() {
        for operation in u8::MIN..=u8::MAX {
            if operation == PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1
                || operation == PTRACE_SYSCALL_INFO_SECCOMP_OPERATION_V1
            {
                continue;
            }
            let buffer = common_buffer_v1(operation);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &buffer,)
                    .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::UnsupportedOperation)
            );
        }
    }

    #[test]
    fn returned_lengths_are_exact_and_operation_specific() {
        let exit = exit_buffer_v1(0, 0);
        let seccomp = seccomp_buffer_v1(0, [0; 6]);
        for returned_byte_count in [0, 1, 24, 32, 34, 83, 85, usize::MAX] {
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(returned_byte_count, &exit).err(),
                Some(PtraceSyscallInfoDecodeErrorV1::UnsupportedReturnedByteCount)
            );
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(returned_byte_count, &seccomp).err(),
                Some(PtraceSyscallInfoDecodeErrorV1::UnsupportedReturnedByteCount)
            );
        }
        assert_eq!(
            decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1, &exit,)
                .err(),
            Some(PtraceSyscallInfoDecodeErrorV1::ExitReturnedByteCountMismatch)
        );
        assert_eq!(
            decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &seccomp).err(),
            Some(PtraceSyscallInfoDecodeErrorV1::SeccompReturnedByteCountMismatch)
        );
    }

    #[test]
    fn every_reserved_and_flag_bit_is_rejected() {
        for operation_and_length in [
            (
                PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1,
                PTRACE_SYSCALL_INFO_EXIT_BYTES_V1,
            ),
            (
                PTRACE_SYSCALL_INFO_SECCOMP_OPERATION_V1,
                PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1,
            ),
        ] {
            let (operation, returned_byte_count) = operation_and_length;
            let mut reserved = if operation == PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1 {
                exit_buffer_v1(0, 0)
            } else {
                seccomp_buffer_v1(0, [0; 6])
            };
            reserved[RESERVED_OFFSET_V1] = 1;
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(returned_byte_count, &reserved).err(),
                Some(PtraceSyscallInfoDecodeErrorV1::HeaderReservedByteNonzero)
            );

            for flag_bit in 0..u16::BITS {
                let mut flags = if operation == PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1 {
                    exit_buffer_v1(0, 0)
                } else {
                    seccomp_buffer_v1(0, [0; 6])
                };
                write_u16_le_v1(&mut flags, FLAGS_OFFSET_V1, 1_u16 << flag_bit);
                assert_eq!(
                    decode_ptrace_syscall_info_x86_64_v1(returned_byte_count, &flags).err(),
                    Some(PtraceSyscallInfoDecodeErrorV1::HeaderFlagsNonzero)
                );
            }
        }
    }

    #[test]
    fn wrong_architectures_are_rejected_for_both_operations() {
        for architecture in [0, 0x4000_0003, AUDIT_ARCH_X86_64_V1 ^ 1, u32::MAX] {
            for operation_and_length in [
                (
                    PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1,
                    PTRACE_SYSCALL_INFO_EXIT_BYTES_V1,
                ),
                (
                    PTRACE_SYSCALL_INFO_SECCOMP_OPERATION_V1,
                    PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1,
                ),
            ] {
                let (operation, returned_byte_count) = operation_and_length;
                let mut buffer = if operation == PTRACE_SYSCALL_INFO_EXIT_OPERATION_V1 {
                    exit_buffer_v1(0, 0)
                } else {
                    seccomp_buffer_v1(0, [0; 6])
                };
                write_u32_le_v1(&mut buffer, ARCHITECTURE_OFFSET_V1, architecture);
                assert_eq!(
                    decode_ptrace_syscall_info_x86_64_v1(returned_byte_count, &buffer).err(),
                    Some(PtraceSyscallInfoDecodeErrorV1::ArchitectureMismatch)
                );
            }
        }
    }

    #[test]
    fn syscall_number_range_x32_and_zero_extension_shapes_are_distinct() {
        for syscall_number in [u64::from(u32::MAX) + 1, u64::MAX] {
            let buffer = seccomp_buffer_v1(syscall_number, [0; 6]);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(
                    PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1,
                    &buffer,
                )
                .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::SeccompSyscallNumberDoesNotFitU32)
            );
        }

        for syscall_number in [
            u64::from(X32_SYSCALL_BIT_V1),
            u64::from(X32_SYSCALL_BIT_V1 | 1),
            u64::from(i32::MAX as u32),
            u64::from(u32::MAX),
        ] {
            let buffer = seccomp_buffer_v1(syscall_number, [0; 6]);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(
                    PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1,
                    &buffer,
                )
                .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::SeccompSyscallNumberUsesX32Abi)
            );
        }

        for syscall_number in [0x8000_0000_u64, 0x8000_0001, 0xbfff_ffff] {
            let buffer = seccomp_buffer_v1(syscall_number, [0; 6]);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(
                    PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1,
                    &buffer,
                )
                .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::SeccompSyscallNumberNotCanonicalNative)
            );
        }

        for syscall_number in [0_u64, 1, 0x3fff_ffff] {
            let buffer = seccomp_buffer_v1(syscall_number, [0; 6]);
            assert!(decode_ptrace_syscall_info_x86_64_v1(
                PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1,
                &buffer,
            )
            .is_ok());
        }
    }

    #[test]
    fn seccomp_cookie_is_read_from_the_frozen_policy_summary_and_is_exact() {
        let expected_cookie =
            super::super::tracer_seccomp::TRACE_ALL_NATIVE_SECCOMP_POLICY_SUMMARY_V1.trace_cookie();
        assert_eq!(expected_cookie, 0xa731);
        for return_data in [
            0,
            u32::from(expected_cookie) - 1,
            u32::from(expected_cookie) + 1,
            u32::from(expected_cookie) | 0x0001_0000,
            u32::MAX,
        ] {
            let mut buffer = seccomp_buffer_v1(0, [0; 6]);
            write_u32_le_v1(&mut buffer, SECCOMP_RETURN_DATA_OFFSET_V1, return_data);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(
                    PTRACE_SYSCALL_INFO_SECCOMP_BYTES_V1,
                    &buffer,
                )
                .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::SeccompCookieMismatch)
            );
        }
    }

    #[test]
    fn each_unwritten_exit_tail_byte_is_required_to_remain_zero() {
        for tail_index in EXIT_TAIL_OFFSET_V1..PTRACE_SYSCALL_INFO_BUFFER_BYTES_V1 {
            let mut buffer = exit_buffer_v1(0, 0);
            buffer[tail_index] = 0xff;
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &buffer,)
                    .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::ExitTailNonzero),
                "tail byte {tail_index} was not rejected"
            );
        }
    }

    #[test]
    fn every_non_boolean_exit_error_flag_is_rejected() {
        for is_error in 2_u8..=u8::MAX {
            let buffer = exit_buffer_v1(0, is_error);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &buffer,)
                    .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::ExitIsErrorInvalid)
            );
        }
    }

    #[test]
    fn exit_error_flag_and_x86_64_result_shape_must_agree() {
        for error_shaped_success in [-MAX_X86_64_ERRNO_V1, -1] {
            let buffer = exit_buffer_v1(error_shaped_success, 0);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &buffer,)
                    .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::ExitResultShapeMismatch)
            );
        }

        for non_error_shaped_failure in [i64::MIN, -4_096, 0, 1, i64::MAX] {
            let buffer = exit_buffer_v1(non_error_shaped_failure, 1);
            assert_eq!(
                decode_ptrace_syscall_info_x86_64_v1(PTRACE_SYSCALL_INFO_EXIT_BYTES_V1, &buffer,)
                    .err(),
                Some(PtraceSyscallInfoDecodeErrorV1::ExitResultShapeMismatch)
            );
        }
    }

    #[test]
    fn summary_is_allocation_free_and_grants_no_authority() {
        let summary = &PTRACE_SYSCALL_INFO_DECODER_SUMMARY_V1;
        assert_eq!(size_of::<PtraceSyscallInfoDecoderSummaryV1>(), 0);
        assert_eq!(
            summary.decoder_id(),
            "x86_64-ptrace-syscall-info-seccomp-exit-v1"
        );
        assert_eq!(summary.buffer_byte_count(), 84);
        assert_eq!(summary.seccomp_returned_byte_count(), 84);
        assert_eq!(summary.exit_returned_byte_count(), 33);
        assert!(summary.allocation_free());
        assert!(!summary.contains_task_identity());
        assert!(!summary.observation_completeness_authority());
        assert!(!summary.effect_ir_authority());
        assert!(!summary.execution_authority());
        assert!(!summary.reuse_authority());
    }
}
