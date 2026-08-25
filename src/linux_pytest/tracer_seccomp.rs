//! Frozen trace-all seccomp filter foundation for the future Linux tracer.
//!
//! This module contains only a static x86_64 cBPF policy and pure validation.
//! It does not install a filter, invoke `seccomp`, accept a command, or qualify
//! a workload. Wrong audit architectures and x32-tagged syscall numbers are
//! killed; every other syscall number produces one fixed `SECCOMP_RET_TRACE`
//! cookie. That gives a future ptrace supervisor a syscall-entry stop, not a
//! syscall-exit observation. It says nothing about vDSO calls, task following,
//! observation completeness, EffectIR, execution authority, or reuse authority.

const LINUX_SECCOMP_DATA_SYSCALL_NUMBER_OFFSET_V1: u32 = 0;
const LINUX_SECCOMP_DATA_ARCHITECTURE_OFFSET_V1: u32 = 4;

const LINUX_BPF_LD_W_ABS_V1: u16 = 0x20;
const LINUX_BPF_JMP_JEQ_K_V1: u16 = 0x15;
const LINUX_BPF_JMP_JSET_K_V1: u16 = 0x45;
const LINUX_BPF_RET_K_V1: u16 = 0x06;

const LINUX_AUDIT_ARCH_X86_64_V1: u32 = 0xc000_003e;
const LINUX_X32_SYSCALL_BIT_V1: u32 = 0x4000_0000;

const LINUX_SECCOMP_RET_KILL_PROCESS_V1: u32 = 0x8000_0000;
const LINUX_SECCOMP_RET_TRACE_V1: u32 = 0x7ff0_0000;
#[allow(dead_code)] // Used by a compile-time invariant and pure tests.
const LINUX_SECCOMP_RET_DATA_MASK_V1: u32 = 0x0000_ffff;

const TRACE_ALL_NATIVE_SECCOMP_COOKIE_V1: u16 = 0xa731;
const TRACE_ALL_NATIVE_SECCOMP_RESULT_V1: u32 =
    LINUX_SECCOMP_RET_TRACE_V1 | TRACE_ALL_NATIVE_SECCOMP_COOKIE_V1 as u32;
const TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1: usize = 7;
const TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTE_COUNT_V1: usize =
    TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1 * 8;
const TRACE_ALL_NATIVE_SECCOMP_BYTES_FNV1A64_V1: u64 = 0x1fb7_ac42_7a7b_ad22;

/// Linux `struct seccomp_data`, frozen here only for layout and BPF offsets.
#[allow(dead_code)]
#[repr(C)]
pub(super) struct LinuxSeccompDataX8664V1 {
    syscall_number: i32,
    architecture: u32,
    instruction_pointer: u64,
    arguments: [u64; 6],
}

/// Linux `struct sock_filter`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct LinuxSockFilterV1 {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    operand: u32,
}

const TRACE_ALL_NATIVE_SECCOMP_FILTER_INSTRUCTIONS_V1: [LinuxSockFilterV1;
    TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1] = [
    LinuxSockFilterV1 {
        code: LINUX_BPF_LD_W_ABS_V1,
        jump_true: 0,
        jump_false: 0,
        operand: LINUX_SECCOMP_DATA_ARCHITECTURE_OFFSET_V1,
    },
    LinuxSockFilterV1 {
        code: LINUX_BPF_JMP_JEQ_K_V1,
        jump_true: 1,
        jump_false: 0,
        operand: LINUX_AUDIT_ARCH_X86_64_V1,
    },
    LinuxSockFilterV1 {
        code: LINUX_BPF_RET_K_V1,
        jump_true: 0,
        jump_false: 0,
        operand: LINUX_SECCOMP_RET_KILL_PROCESS_V1,
    },
    LinuxSockFilterV1 {
        code: LINUX_BPF_LD_W_ABS_V1,
        jump_true: 0,
        jump_false: 0,
        operand: LINUX_SECCOMP_DATA_SYSCALL_NUMBER_OFFSET_V1,
    },
    LinuxSockFilterV1 {
        code: LINUX_BPF_JMP_JSET_K_V1,
        jump_true: 0,
        jump_false: 1,
        operand: LINUX_X32_SYSCALL_BIT_V1,
    },
    LinuxSockFilterV1 {
        code: LINUX_BPF_RET_K_V1,
        jump_true: 0,
        jump_false: 0,
        operand: LINUX_SECCOMP_RET_KILL_PROCESS_V1,
    },
    LinuxSockFilterV1 {
        code: LINUX_BPF_RET_K_V1,
        jump_true: 0,
        jump_false: 0,
        operand: TRACE_ALL_NATIVE_SECCOMP_RESULT_V1,
    },
];

/// Allocation-free filter storage for a future, separately reviewed connector.
static TRACE_ALL_NATIVE_SECCOMP_FILTER_V1: [LinuxSockFilterV1;
    TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1] =
    TRACE_ALL_NATIVE_SECCOMP_FILTER_INSTRUCTIONS_V1;

#[allow(dead_code)] // Rust's dead-code lint does not count const assertions as uses.
const fn canonical_filter_bytes_v1(
    program: &[LinuxSockFilterV1; TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1],
) -> [u8; TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTE_COUNT_V1] {
    let mut bytes = [0_u8; TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTE_COUNT_V1];
    let mut instruction_index = 0;
    while instruction_index < program.len() {
        let instruction = program[instruction_index];
        let byte_index = instruction_index * 8;
        let code = instruction.code.to_le_bytes();
        let operand = instruction.operand.to_le_bytes();
        bytes[byte_index] = code[0];
        bytes[byte_index + 1] = code[1];
        bytes[byte_index + 2] = instruction.jump_true;
        bytes[byte_index + 3] = instruction.jump_false;
        bytes[byte_index + 4] = operand[0];
        bytes[byte_index + 5] = operand[1];
        bytes[byte_index + 6] = operand[2];
        bytes[byte_index + 7] = operand[3];
        instruction_index += 1;
    }
    bytes
}

#[allow(dead_code)] // Rust's dead-code lint does not count const assertions as uses.
const TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTES_V1: [u8;
    TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTE_COUNT_V1] =
    canonical_filter_bytes_v1(&TRACE_ALL_NATIVE_SECCOMP_FILTER_INSTRUCTIONS_V1);

#[allow(dead_code)] // Rust's dead-code lint does not count const assertions as uses.
const fn fnv1a64_v1(bytes: &[u8]) -> u64 {
    let mut fingerprint = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < bytes.len() {
        fingerprint ^= bytes[index] as u64;
        fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    fingerprint
}

#[allow(dead_code)] // Rust's dead-code lint does not count const assertions as uses.
const fn checked_forward_target_v1(instruction_index: usize, jump_offset: u8) -> Option<usize> {
    let target = instruction_index + 1 + jump_offset as usize;
    if target <= instruction_index || target >= TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1 {
        None
    } else {
        Some(target)
    }
}

#[allow(dead_code)] // Rust's dead-code lint does not count const assertions as uses.
const fn all_nodes_strictly_forward_reachable_v1(
    program: &[LinuxSockFilterV1; TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1],
) -> bool {
    let mut reachable = [false; TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1];
    reachable[0] = true;
    let mut instruction_index = 0;
    while instruction_index < program.len() {
        if reachable[instruction_index] {
            let instruction = program[instruction_index];
            if instruction.code == LINUX_BPF_LD_W_ABS_V1 {
                let Some(target) = checked_forward_target_v1(instruction_index, 0) else {
                    return false;
                };
                reachable[target] = true;
            } else if instruction.code == LINUX_BPF_JMP_JEQ_K_V1
                || instruction.code == LINUX_BPF_JMP_JSET_K_V1
            {
                let Some(true_target) =
                    checked_forward_target_v1(instruction_index, instruction.jump_true)
                else {
                    return false;
                };
                let Some(false_target) =
                    checked_forward_target_v1(instruction_index, instruction.jump_false)
                else {
                    return false;
                };
                reachable[true_target] = true;
                reachable[false_target] = true;
            } else if instruction.code != LINUX_BPF_RET_K_V1 {
                return false;
            }
        }
        instruction_index += 1;
    }

    let mut reachable_index = 0;
    while reachable_index < reachable.len() {
        if !reachable[reachable_index] {
            return false;
        }
        reachable_index += 1;
    }
    true
}

const _: [(); 1] = [(); (TRACE_ALL_NATIVE_SECCOMP_COOKIE_V1 != 0) as usize];
const _: [(); 1] = [(); ((TRACE_ALL_NATIVE_SECCOMP_RESULT_V1 & LINUX_SECCOMP_RET_DATA_MASK_V1)
    == TRACE_ALL_NATIVE_SECCOMP_COOKIE_V1 as u32) as usize];
const _: [(); 1] = [(); (fnv1a64_v1(&TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTES_V1)
    == TRACE_ALL_NATIVE_SECCOMP_BYTES_FNV1A64_V1) as usize];
const _: [(); 1] =
    [(); all_nodes_strictly_forward_reachable_v1(&TRACE_ALL_NATIVE_SECCOMP_FILTER_INSTRUCTIONS_V1)
        as usize];

/// Static facts about the filter. This value is diagnostic, never authority.
pub(super) struct TraceAllNativeSeccompPolicySummaryV1 {
    _private: (),
}

impl TraceAllNativeSeccompPolicySummaryV1 {
    pub(super) const fn policy_id(&self) -> &'static str {
        "x86_64-trace-all-native-seccomp-v1"
    }

    pub(super) const fn instruction_count(&self) -> u16 {
        TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1 as u16
    }

    pub(super) const fn canonical_byte_count(&self) -> u16 {
        TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTE_COUNT_V1 as u16
    }

    pub(super) const fn byte_fingerprint_fnv1a64(&self) -> u64 {
        TRACE_ALL_NATIVE_SECCOMP_BYTES_FNV1A64_V1
    }

    pub(super) const fn trace_cookie(&self) -> u16 {
        TRACE_ALL_NATIVE_SECCOMP_COOKIE_V1
    }

    pub(super) const fn allow_count(&self) -> u16 {
        0
    }

    pub(super) const fn trace_all_native(&self) -> bool {
        true
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

pub(super) static TRACE_ALL_NATIVE_SECCOMP_POLICY_SUMMARY_V1: TraceAllNativeSeccompPolicySummaryV1 =
    TraceAllNativeSeccompPolicySummaryV1 { _private: () };

/// A sealed permit for a future connector review.
///
/// Sibling modules can name this type but cannot construct it. Adding a real
/// issuer requires an explicit edit in this module; merely importing the
/// static policy can never be mistaken for runtime qualification.
#[allow(dead_code)]
pub(super) struct FutureTracerSeccompConnectorPermitV1(());

/// Borrowed static program view for a future, separately reviewed connector.
#[allow(dead_code)]
pub(super) struct TraceAllNativeSeccompProgramV1 {
    _private: (),
}

#[allow(dead_code)]
impl TraceAllNativeSeccompProgramV1 {
    pub(super) const fn instructions(
        &self,
    ) -> &'static [LinuxSockFilterV1; TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1] {
        &TRACE_ALL_NATIVE_SECCOMP_FILTER_V1
    }

    pub(super) const fn byte_fingerprint_fnv1a64(&self) -> u64 {
        TRACE_ALL_NATIVE_SECCOMP_BYTES_FNV1A64_V1
    }
}

#[allow(dead_code)]
pub(super) const fn trace_all_native_seccomp_program_v1(
    _permit: FutureTracerSeccompConnectorPermitV1,
) -> TraceAllNativeSeccompProgramV1 {
    TraceAllNativeSeccompProgramV1 { _private: () }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    const TEST_EVALUATION_STEP_CAP_V1: usize = TRACE_ALL_NATIVE_SECCOMP_INSTRUCTION_COUNT_V1 + 1;

    fn evaluate_filter_v1(architecture: u32, syscall_number: u32) -> Option<u32> {
        let mut accumulator = 0_u32;
        let mut instruction_index = 0_usize;
        let mut steps = 0_usize;

        while instruction_index < TRACE_ALL_NATIVE_SECCOMP_FILTER_V1.len()
            && steps < TEST_EVALUATION_STEP_CAP_V1
        {
            let instruction = TRACE_ALL_NATIVE_SECCOMP_FILTER_V1[instruction_index];
            steps += 1;
            match instruction.code {
                LINUX_BPF_LD_W_ABS_V1 => {
                    accumulator = match instruction.operand {
                        LINUX_SECCOMP_DATA_SYSCALL_NUMBER_OFFSET_V1 => syscall_number,
                        LINUX_SECCOMP_DATA_ARCHITECTURE_OFFSET_V1 => architecture,
                        _ => return None,
                    };
                    instruction_index += 1;
                }
                LINUX_BPF_JMP_JEQ_K_V1 => {
                    let jump = if accumulator == instruction.operand {
                        instruction.jump_true
                    } else {
                        instruction.jump_false
                    };
                    instruction_index = checked_forward_target_v1(instruction_index, jump)?;
                }
                LINUX_BPF_JMP_JSET_K_V1 => {
                    let jump = if accumulator & instruction.operand != 0 {
                        instruction.jump_true
                    } else {
                        instruction.jump_false
                    };
                    instruction_index = checked_forward_target_v1(instruction_index, jump)?;
                }
                LINUX_BPF_RET_K_V1 => return Some(instruction.operand),
                _ => return None,
            }
        }
        None
    }

    #[test]
    fn linux_uapi_layout_and_offsets_are_frozen() {
        assert_eq!(size_of::<LinuxSeccompDataX8664V1>(), 64);
        assert_eq!(align_of::<LinuxSeccompDataX8664V1>(), 8);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, syscall_number), 0);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, architecture), 4);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, instruction_pointer), 8);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, arguments), 16);

        assert_eq!(size_of::<LinuxSockFilterV1>(), 8);
        assert_eq!(align_of::<LinuxSockFilterV1>(), 4);
        assert_eq!(offset_of!(LinuxSockFilterV1, code), 0);
        assert_eq!(offset_of!(LinuxSockFilterV1, jump_true), 2);
        assert_eq!(offset_of!(LinuxSockFilterV1, jump_false), 3);
        assert_eq!(offset_of!(LinuxSockFilterV1, operand), 4);
    }

    #[test]
    fn instruction_bytes_fingerprint_and_cfg_are_frozen() {
        assert_eq!(TRACE_ALL_NATIVE_SECCOMP_FILTER_V1.len(), 7);
        assert_eq!(TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTES_V1.len(), 56);
        assert_eq!(
            fnv1a64_v1(&TRACE_ALL_NATIVE_SECCOMP_CANONICAL_BYTES_V1),
            TRACE_ALL_NATIVE_SECCOMP_BYTES_FNV1A64_V1
        );
        assert!(all_nodes_strictly_forward_reachable_v1(
            &TRACE_ALL_NATIVE_SECCOMP_FILTER_V1
        ));
        assert_eq!(
            TRACE_ALL_NATIVE_SECCOMP_FILTER_V1,
            TRACE_ALL_NATIVE_SECCOMP_FILTER_INSTRUCTIONS_V1
        );

        let program = trace_all_native_seccomp_program_v1(FutureTracerSeccompConnectorPermitV1(()));
        assert_eq!(program.instructions(), &TRACE_ALL_NATIVE_SECCOMP_FILTER_V1);
        assert_eq!(
            program.byte_fingerprint_fnv1a64(),
            TRACE_ALL_NATIVE_SECCOMP_BYTES_FNV1A64_V1
        );
        assert_eq!(size_of::<FutureTracerSeccompConnectorPermitV1>(), 0);
        assert_eq!(size_of::<TraceAllNativeSeccompProgramV1>(), 0);
    }

    #[test]
    fn wrong_audit_architecture_kills_the_process() {
        for architecture in [0_u32, 0x4000_0003, LINUX_AUDIT_ARCH_X86_64_V1 ^ 1, u32::MAX] {
            assert_eq!(
                evaluate_filter_v1(architecture, 39),
                Some(LINUX_SECCOMP_RET_KILL_PROCESS_V1)
            );
        }
    }

    #[test]
    fn x32_tagged_syscall_numbers_kill_the_process() {
        for syscall_number in [
            LINUX_X32_SYSCALL_BIT_V1,
            LINUX_X32_SYSCALL_BIT_V1 | 1,
            LINUX_X32_SYSCALL_BIT_V1 | 39,
            LINUX_X32_SYSCALL_BIT_V1 | (LINUX_X32_SYSCALL_BIT_V1 - 1),
            u32::MAX,
        ] {
            assert_eq!(
                evaluate_filter_v1(LINUX_AUDIT_ARCH_X86_64_V1, syscall_number),
                Some(LINUX_SECCOMP_RET_KILL_PROCESS_V1)
            );
        }
    }

    #[test]
    fn representative_boundary_and_unknown_native_syscalls_trace_one_cookie() {
        let expected = LINUX_SECCOMP_RET_TRACE_V1 | u32::from(TRACE_ALL_NATIVE_SECCOMP_COOKIE_V1);
        for syscall_number in [
            0_u32,
            1,
            39,
            60,
            231,
            999_999,
            LINUX_X32_SYSCALL_BIT_V1 - 2,
            LINUX_X32_SYSCALL_BIT_V1 - 1,
        ] {
            assert_eq!(
                evaluate_filter_v1(LINUX_AUDIT_ARCH_X86_64_V1, syscall_number),
                Some(expected)
            );
        }
        assert_ne!(TRACE_ALL_NATIVE_SECCOMP_COOKIE_V1, 0);
        assert_eq!(expected & LINUX_SECCOMP_RET_DATA_MASK_V1, 0xa731);
    }

    #[test]
    fn static_summary_has_no_allowlist_or_authority() {
        let summary = &TRACE_ALL_NATIVE_SECCOMP_POLICY_SUMMARY_V1;
        assert_eq!(size_of::<TraceAllNativeSeccompPolicySummaryV1>(), 0);
        assert_eq!(summary.policy_id(), "x86_64-trace-all-native-seccomp-v1");
        assert_eq!(summary.instruction_count(), 7);
        assert_eq!(summary.canonical_byte_count(), 56);
        assert_eq!(
            summary.byte_fingerprint_fnv1a64(),
            TRACE_ALL_NATIVE_SECCOMP_BYTES_FNV1A64_V1
        );
        assert_eq!(summary.trace_cookie(), 0xa731);
        assert_eq!(summary.allow_count(), 0);
        assert!(summary.trace_all_native());
        assert!(!summary.effect_ir_authority());
        assert!(!summary.execution_authority());
        assert!(!summary.reuse_authority());
    }
}
