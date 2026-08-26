//! Frozen workload-seccomp plan for the first execute-only pytest fixture:
//! `.venv/bin/python -I -m pytest tests/test_smoke.py::test_smoke`.
//!
//! This module is deliberately only a plan and a pure verifier. It does not
//! invoke `prctl`, `seccomp`, or `ptrace`; it accepts no command, path,
//! environment, descriptor, PID, or callback. Required native x86_64 workload
//! syscalls route to `SECCOMP_RET_TRACE`, while only the irreducible
//! sigreturn/exit control calls return `SECCOMP_RET_ALLOW`. Wrong audit
//! architectures, x32-tagged calls, and every unlisted native call fail closed.
//! The opaque installed witness has no production issuer until a future child
//! kernel connector supplies exact install and readback evidence.

#![allow(
    dead_code,
    reason = "the frozen plan has no production consumer until the future kernel connector is composed"
)]

use core::fmt;

const SECCOMP_DATA_NR_OFFSET_V1: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET_V1: u32 = 4;

const BPF_LD_W_ABS_V1: u16 = 0x20;
const BPF_JMP_JEQ_K_V1: u16 = 0x15;
const BPF_JMP_JSET_K_V1: u16 = 0x45;
const BPF_RET_K_V1: u16 = 0x06;

const AUDIT_ARCH_X86_64_V1: u32 = 0xc000_003e;
const X32_SYSCALL_BIT_V1: u32 = 0x4000_0000;
const SECCOMP_RET_KILL_PROCESS_V1: u32 = 0x8000_0000;
const SECCOMP_RET_TRACE_V1: u32 = 0x7ff0_0000;
const SECCOMP_RET_ALLOW_V1: u32 = 0x7fff_0000;
const WORKLOAD_TRACE_COOKIE_V1: u16 = 0xb503;
const WORKLOAD_TRACE_RESULT_V1: u32 = SECCOMP_RET_TRACE_V1 | WORKLOAD_TRACE_COOKIE_V1 as u32;

const NR_RT_SIGRETURN_X86_64_V1: u32 = 15;
const NR_EXIT_X86_64_V1: u32 = 60;
const NR_EXIT_GROUP_X86_64_V1: u32 = 231;
const CONTROL_SYSCALLS_V1: [u32; 3] = [
    NR_RT_SIGRETURN_X86_64_V1,
    NR_EXIT_X86_64_V1,
    NR_EXIT_GROUP_X86_64_V1,
];

#[derive(Clone, Copy)]
struct TraceSyscallV1 {
    number: u32,
    name: &'static str,
}

const TRACE_SYSCALLS_V1: &[TraceSyscallV1] = &[
    TraceSyscallV1 {
        number: 0,
        name: "read",
    },
    TraceSyscallV1 {
        number: 1,
        name: "write",
    },
    TraceSyscallV1 {
        number: 2,
        name: "open",
    },
    TraceSyscallV1 {
        number: 3,
        name: "close",
    },
    TraceSyscallV1 {
        number: 4,
        name: "stat",
    },
    TraceSyscallV1 {
        number: 5,
        name: "fstat",
    },
    TraceSyscallV1 {
        number: 6,
        name: "lstat",
    },
    TraceSyscallV1 {
        number: 7,
        name: "poll",
    },
    TraceSyscallV1 {
        number: 8,
        name: "lseek",
    },
    TraceSyscallV1 {
        number: 9,
        name: "mmap",
    },
    TraceSyscallV1 {
        number: 10,
        name: "mprotect",
    },
    TraceSyscallV1 {
        number: 11,
        name: "munmap",
    },
    TraceSyscallV1 {
        number: 12,
        name: "brk",
    },
    TraceSyscallV1 {
        number: 13,
        name: "rt_sigaction",
    },
    TraceSyscallV1 {
        number: 14,
        name: "rt_sigprocmask",
    },
    TraceSyscallV1 {
        number: 16,
        name: "ioctl",
    },
    TraceSyscallV1 {
        number: 17,
        name: "pread64",
    },
    TraceSyscallV1 {
        number: 19,
        name: "readv",
    },
    TraceSyscallV1 {
        number: 20,
        name: "writev",
    },
    TraceSyscallV1 {
        number: 21,
        name: "access",
    },
    TraceSyscallV1 {
        number: 22,
        name: "pipe",
    },
    TraceSyscallV1 {
        number: 23,
        name: "select",
    },
    TraceSyscallV1 {
        number: 24,
        name: "sched_yield",
    },
    TraceSyscallV1 {
        number: 25,
        name: "mremap",
    },
    TraceSyscallV1 {
        number: 28,
        name: "madvise",
    },
    TraceSyscallV1 {
        number: 32,
        name: "dup",
    },
    TraceSyscallV1 {
        number: 33,
        name: "dup2",
    },
    TraceSyscallV1 {
        number: 35,
        name: "nanosleep",
    },
    TraceSyscallV1 {
        number: 36,
        name: "getitimer",
    },
    TraceSyscallV1 {
        number: 38,
        name: "setitimer",
    },
    TraceSyscallV1 {
        number: 39,
        name: "getpid",
    },
    TraceSyscallV1 {
        number: 56,
        name: "clone",
    },
    TraceSyscallV1 {
        number: 57,
        name: "fork",
    },
    TraceSyscallV1 {
        number: 58,
        name: "vfork",
    },
    TraceSyscallV1 {
        number: 59,
        name: "execve",
    },
    TraceSyscallV1 {
        number: 61,
        name: "wait4",
    },
    TraceSyscallV1 {
        number: 62,
        name: "kill",
    },
    TraceSyscallV1 {
        number: 63,
        name: "uname",
    },
    TraceSyscallV1 {
        number: 72,
        name: "fcntl",
    },
    TraceSyscallV1 {
        number: 73,
        name: "flock",
    },
    TraceSyscallV1 {
        number: 74,
        name: "fsync",
    },
    TraceSyscallV1 {
        number: 75,
        name: "fdatasync",
    },
    TraceSyscallV1 {
        number: 79,
        name: "getcwd",
    },
    TraceSyscallV1 {
        number: 80,
        name: "chdir",
    },
    TraceSyscallV1 {
        number: 81,
        name: "fchdir",
    },
    TraceSyscallV1 {
        number: 82,
        name: "rename",
    },
    TraceSyscallV1 {
        number: 83,
        name: "mkdir",
    },
    TraceSyscallV1 {
        number: 84,
        name: "rmdir",
    },
    TraceSyscallV1 {
        number: 87,
        name: "unlink",
    },
    TraceSyscallV1 {
        number: 89,
        name: "readlink",
    },
    TraceSyscallV1 {
        number: 90,
        name: "chmod",
    },
    TraceSyscallV1 {
        number: 91,
        name: "fchmod",
    },
    TraceSyscallV1 {
        number: 95,
        name: "umask",
    },
    TraceSyscallV1 {
        number: 96,
        name: "gettimeofday",
    },
    TraceSyscallV1 {
        number: 97,
        name: "getrlimit",
    },
    TraceSyscallV1 {
        number: 98,
        name: "getrusage",
    },
    TraceSyscallV1 {
        number: 99,
        name: "sysinfo",
    },
    TraceSyscallV1 {
        number: 100,
        name: "times",
    },
    TraceSyscallV1 {
        number: 102,
        name: "getuid",
    },
    TraceSyscallV1 {
        number: 104,
        name: "getgid",
    },
    TraceSyscallV1 {
        number: 107,
        name: "geteuid",
    },
    TraceSyscallV1 {
        number: 108,
        name: "getegid",
    },
    TraceSyscallV1 {
        number: 110,
        name: "getppid",
    },
    TraceSyscallV1 {
        number: 111,
        name: "getpgrp",
    },
    TraceSyscallV1 {
        number: 115,
        name: "getgroups",
    },
    TraceSyscallV1 {
        number: 131,
        name: "sigaltstack",
    },
    TraceSyscallV1 {
        number: 137,
        name: "statfs",
    },
    TraceSyscallV1 {
        number: 138,
        name: "fstatfs",
    },
    TraceSyscallV1 {
        number: 158,
        name: "arch_prctl",
    },
    TraceSyscallV1 {
        number: 186,
        name: "gettid",
    },
    TraceSyscallV1 {
        number: 202,
        name: "futex",
    },
    TraceSyscallV1 {
        number: 217,
        name: "getdents64",
    },
    TraceSyscallV1 {
        number: 218,
        name: "set_tid_address",
    },
    TraceSyscallV1 {
        number: 228,
        name: "clock_gettime",
    },
    TraceSyscallV1 {
        number: 230,
        name: "clock_nanosleep",
    },
    TraceSyscallV1 {
        number: 232,
        name: "epoll_wait",
    },
    TraceSyscallV1 {
        number: 233,
        name: "epoll_ctl",
    },
    TraceSyscallV1 {
        number: 257,
        name: "openat",
    },
    TraceSyscallV1 {
        number: 262,
        name: "newfstatat",
    },
    TraceSyscallV1 {
        number: 263,
        name: "unlinkat",
    },
    TraceSyscallV1 {
        number: 264,
        name: "renameat",
    },
    TraceSyscallV1 {
        number: 265,
        name: "linkat",
    },
    TraceSyscallV1 {
        number: 266,
        name: "symlinkat",
    },
    TraceSyscallV1 {
        number: 267,
        name: "readlinkat",
    },
    TraceSyscallV1 {
        number: 268,
        name: "fchmodat",
    },
    TraceSyscallV1 {
        number: 269,
        name: "faccessat",
    },
    TraceSyscallV1 {
        number: 270,
        name: "pselect6",
    },
    TraceSyscallV1 {
        number: 271,
        name: "ppoll",
    },
    TraceSyscallV1 {
        number: 273,
        name: "set_robust_list",
    },
    TraceSyscallV1 {
        number: 280,
        name: "utimensat",
    },
    TraceSyscallV1 {
        number: 281,
        name: "epoll_pwait",
    },
    TraceSyscallV1 {
        number: 291,
        name: "epoll_create1",
    },
    TraceSyscallV1 {
        number: 292,
        name: "dup3",
    },
    TraceSyscallV1 {
        number: 293,
        name: "pipe2",
    },
    TraceSyscallV1 {
        number: 302,
        name: "prlimit64",
    },
    TraceSyscallV1 {
        number: 316,
        name: "renameat2",
    },
    TraceSyscallV1 {
        number: 318,
        name: "getrandom",
    },
    TraceSyscallV1 {
        number: 322,
        name: "execveat",
    },
    TraceSyscallV1 {
        number: 332,
        name: "statx",
    },
    TraceSyscallV1 {
        number: 334,
        name: "rseq",
    },
    TraceSyscallV1 {
        number: 435,
        name: "clone3",
    },
    TraceSyscallV1 {
        number: 436,
        name: "close_range",
    },
    TraceSyscallV1 {
        number: 437,
        name: "openat2",
    },
    TraceSyscallV1 {
        number: 439,
        name: "faccessat2",
    },
    TraceSyscallV1 {
        number: 441,
        name: "epoll_pwait2",
    },
];

const WORKLOAD_FILTER_PREFIX_INSTRUCTIONS_V1: usize = 6;
const WORKLOAD_FILTER_SUFFIX_INSTRUCTIONS_V1: usize = CONTROL_SYSCALLS_V1.len() * 2 + 1;
const WORKLOAD_FILTER_INSTRUCTION_COUNT_V1: usize = WORKLOAD_FILTER_PREFIX_INSTRUCTIONS_V1
    + TRACE_SYSCALLS_V1.len() * 2
    + WORKLOAD_FILTER_SUFFIX_INSTRUCTIONS_V1;
const WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1: usize = WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 * 8;
const WORKLOAD_FILTER_FNV1A64_V1: u64 = 0x33f2_5684_e1cb_db3f;
const WORKLOAD_FILTER_MAX_INSTRUCTIONS_V1: usize = 256;

/// Linux `struct seccomp_data`, frozen for layout checks and cBPF offsets.
#[repr(C)]
#[allow(dead_code)]
struct LinuxSeccompDataX8664V1 {
    syscall_number: i32,
    architecture: u32,
    instruction_pointer: u64,
    arguments: [u64; 6],
}

/// Linux `struct sock_filter` using only stable UAPI scalar fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkloadSockFilterV1 {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    operand: u32,
}

const ZERO_FILTER_V1: WorkloadSockFilterV1 = WorkloadSockFilterV1 {
    code: 0,
    jump_true: 0,
    jump_false: 0,
    operand: 0,
};

const fn stmt_v1(code: u16, operand: u32) -> WorkloadSockFilterV1 {
    WorkloadSockFilterV1 {
        code,
        jump_true: 0,
        jump_false: 0,
        operand,
    }
}

const fn jump_v1(code: u16, operand: u32, jump_true: u8, jump_false: u8) -> WorkloadSockFilterV1 {
    WorkloadSockFilterV1 {
        code,
        jump_true,
        jump_false,
        operand,
    }
}

const fn build_workload_filter_v1() -> [WorkloadSockFilterV1; WORKLOAD_FILTER_INSTRUCTION_COUNT_V1]
{
    let mut output = [ZERO_FILTER_V1; WORKLOAD_FILTER_INSTRUCTION_COUNT_V1];
    output[0] = stmt_v1(BPF_LD_W_ABS_V1, SECCOMP_DATA_ARCH_OFFSET_V1);
    output[1] = jump_v1(BPF_JMP_JEQ_K_V1, AUDIT_ARCH_X86_64_V1, 1, 0);
    output[2] = stmt_v1(BPF_RET_K_V1, SECCOMP_RET_KILL_PROCESS_V1);
    output[3] = stmt_v1(BPF_LD_W_ABS_V1, SECCOMP_DATA_NR_OFFSET_V1);
    output[4] = jump_v1(BPF_JMP_JSET_K_V1, X32_SYSCALL_BIT_V1, 0, 1);
    output[5] = stmt_v1(BPF_RET_K_V1, SECCOMP_RET_KILL_PROCESS_V1);
    let mut output_index = WORKLOAD_FILTER_PREFIX_INSTRUCTIONS_V1;
    let mut syscall_index = 0;
    while syscall_index < TRACE_SYSCALLS_V1.len() {
        output[output_index] = jump_v1(
            BPF_JMP_JEQ_K_V1,
            TRACE_SYSCALLS_V1[syscall_index].number,
            0,
            1,
        );
        output[output_index + 1] = stmt_v1(BPF_RET_K_V1, WORKLOAD_TRACE_RESULT_V1);
        output_index += 2;
        syscall_index += 1;
    }
    let mut control_index = 0;
    while control_index < CONTROL_SYSCALLS_V1.len() {
        output[output_index] = jump_v1(BPF_JMP_JEQ_K_V1, CONTROL_SYSCALLS_V1[control_index], 0, 1);
        output[output_index + 1] = stmt_v1(BPF_RET_K_V1, SECCOMP_RET_ALLOW_V1);
        output_index += 2;
        control_index += 1;
    }
    output[output_index] = stmt_v1(BPF_RET_K_V1, SECCOMP_RET_KILL_PROCESS_V1);
    output
}

static WORKLOAD_FILTER_V1: [WorkloadSockFilterV1; WORKLOAD_FILTER_INSTRUCTION_COUNT_V1] =
    build_workload_filter_v1();

const fn canonical_filter_bytes_v1(
    program: &[WorkloadSockFilterV1; WORKLOAD_FILTER_INSTRUCTION_COUNT_V1],
) -> [u8; WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1] {
    let mut output = [0; WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1];
    let mut index = 0;
    while index < program.len() {
        let instruction = program[index];
        let offset = index * 8;
        let code = instruction.code.to_le_bytes();
        let operand = instruction.operand.to_le_bytes();
        output[offset] = code[0];
        output[offset + 1] = code[1];
        output[offset + 2] = instruction.jump_true;
        output[offset + 3] = instruction.jump_false;
        output[offset + 4] = operand[0];
        output[offset + 5] = operand[1];
        output[offset + 6] = operand[2];
        output[offset + 7] = operand[3];
        index += 1;
    }
    output
}

const WORKLOAD_FILTER_CANONICAL_BYTES_V1: [u8; WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1] =
    canonical_filter_bytes_v1(&WORKLOAD_FILTER_V1);

const fn fnv1a64_v1(bytes: &[u8]) -> u64 {
    let mut value = 0xcbf2_9ce4_8422_2325;
    let mut index = 0;
    while index < bytes.len() {
        value = (value ^ bytes[index] as u64).wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    value
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilterVerificationRefusalV1 {
    InstructionCount,
    InvalidOpcode,
    InvalidLoad,
    InvalidJump,
    InvalidReturn,
    UnreachableInstruction,
    Fingerprint,
    ProgramMismatch,
}

fn verify_filter_v1(program: &[WorkloadSockFilterV1]) -> Result<(), FilterVerificationRefusalV1> {
    if program.len() != WORKLOAD_FILTER_INSTRUCTION_COUNT_V1
        || program.len() > WORKLOAD_FILTER_MAX_INSTRUCTIONS_V1
    {
        return Err(FilterVerificationRefusalV1::InstructionCount);
    }
    let mut reachable = [false; WORKLOAD_FILTER_MAX_INSTRUCTIONS_V1];
    reachable[0] = true;
    let mut index = 0;
    while index < program.len() {
        let instruction = program[index];
        if reachable[index] {
            match instruction.code {
                BPF_LD_W_ABS_V1 => {
                    if instruction.jump_true != 0
                        || instruction.jump_false != 0
                        || !matches!(
                            instruction.operand,
                            SECCOMP_DATA_NR_OFFSET_V1 | SECCOMP_DATA_ARCH_OFFSET_V1
                        )
                    {
                        return Err(FilterVerificationRefusalV1::InvalidLoad);
                    }
                    if index + 1 >= program.len() {
                        return Err(FilterVerificationRefusalV1::InvalidJump);
                    }
                    reachable[index + 1] = true;
                }
                BPF_JMP_JEQ_K_V1 | BPF_JMP_JSET_K_V1 => {
                    for jump in [instruction.jump_true, instruction.jump_false] {
                        let target = index
                            .checked_add(1 + usize::from(jump))
                            .filter(|target| *target > index && *target < program.len())
                            .ok_or(FilterVerificationRefusalV1::InvalidJump)?;
                        reachable[target] = true;
                    }
                }
                BPF_RET_K_V1 => {
                    if instruction.jump_true != 0
                        || instruction.jump_false != 0
                        || !matches!(
                            instruction.operand,
                            SECCOMP_RET_KILL_PROCESS_V1
                                | WORKLOAD_TRACE_RESULT_V1
                                | SECCOMP_RET_ALLOW_V1
                        )
                    {
                        return Err(FilterVerificationRefusalV1::InvalidReturn);
                    }
                }
                _ => return Err(FilterVerificationRefusalV1::InvalidOpcode),
            }
        }
        index += 1;
    }
    if reachable[..program.len()].iter().any(|entry| !entry) {
        return Err(FilterVerificationRefusalV1::UnreachableInstruction);
    }
    let mut canonical = [0; WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1];
    for (index, instruction) in program.iter().copied().enumerate() {
        let offset = index * 8;
        canonical[offset..offset + 2].copy_from_slice(&instruction.code.to_le_bytes());
        canonical[offset + 2] = instruction.jump_true;
        canonical[offset + 3] = instruction.jump_false;
        canonical[offset + 4..offset + 8].copy_from_slice(&instruction.operand.to_le_bytes());
    }
    if fnv1a64_v1(&canonical) != WORKLOAD_FILTER_FNV1A64_V1 {
        return Err(FilterVerificationRefusalV1::Fingerprint);
    }
    if program != WORKLOAD_FILTER_V1 {
        return Err(FilterVerificationRefusalV1::ProgramMismatch);
    }
    Ok(())
}

/// Exact future install/readback sequence. It performs no operation itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkloadSeccompOperationV1 {
    VerifySingleTask,
    ReadNoNewPrivileges,
    ReadInitialSeccompMode,
    InstallTsyncFilter,
    ReadInstalledSeccompMode,
    PtraceReadbackCount,
    PtraceReadbackInstructions,
}

const WORKLOAD_SECCOMP_OPERATIONS_V1: [WorkloadSeccompOperationV1; 7] = [
    WorkloadSeccompOperationV1::VerifySingleTask,
    WorkloadSeccompOperationV1::ReadNoNewPrivileges,
    WorkloadSeccompOperationV1::ReadInitialSeccompMode,
    WorkloadSeccompOperationV1::InstallTsyncFilter,
    WorkloadSeccompOperationV1::ReadInstalledSeccompMode,
    WorkloadSeccompOperationV1::PtraceReadbackCount,
    WorkloadSeccompOperationV1::PtraceReadbackInstructions,
];
const PR_GET_SECCOMP_V1: u32 = 21;
const PR_GET_NO_NEW_PRIVS_V1: u32 = 39;
const SECCOMP_SET_MODE_FILTER_V1: u32 = 1;
const SECCOMP_FILTER_FLAG_TSYNC_V1: u32 = 1;
const PTRACE_SECCOMP_GET_FILTER_V1: u32 = 0x420c;
const PTRACE_SECCOMP_FILTER_INDEX_V1: u64 = 0;
const SECCOMP_MODE_DISABLED_V1: u8 = 0;
const SECCOMP_MODE_FILTER_V1: u8 = 2;

/// Borrowed static plan. It is policy data, never proof of installation.
pub(super) struct WorkloadSeccompPlanV1 {
    _private: (),
}

impl WorkloadSeccompPlanV1 {
    pub(super) const fn policy_id(&self) -> &'static str {
        "x86_64-execute-only-pytest-workload-seccomp-v1"
    }

    pub(super) const fn operations(&self) -> &'static [WorkloadSeccompOperationV1; 7] {
        &WORKLOAD_SECCOMP_OPERATIONS_V1
    }

    pub(super) const fn instructions(
        &self,
    ) -> &'static [WorkloadSockFilterV1; WORKLOAD_FILTER_INSTRUCTION_COUNT_V1] {
        &WORKLOAD_FILTER_V1
    }

    pub(super) const fn install_flags(&self) -> u32 {
        SECCOMP_FILTER_FLAG_TSYNC_V1
    }

    pub(super) const fn no_new_privileges_read_operation(&self) -> u32 {
        PR_GET_NO_NEW_PRIVS_V1
    }

    pub(super) const fn seccomp_mode_read_operation(&self) -> u32 {
        PR_GET_SECCOMP_V1
    }

    pub(super) const fn seccomp_install_operation(&self) -> u32 {
        SECCOMP_SET_MODE_FILTER_V1
    }

    pub(super) const fn ptrace_readback_request(&self) -> u32 {
        PTRACE_SECCOMP_GET_FILTER_V1
    }

    pub(super) const fn ptrace_readback_filter_index(&self) -> u64 {
        PTRACE_SECCOMP_FILTER_INDEX_V1
    }

    pub(super) const fn instruction_count(&self) -> u16 {
        WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 as u16
    }

    pub(super) const fn canonical_byte_count(&self) -> u16 {
        WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1 as u16
    }

    pub(super) const fn byte_fingerprint_fnv1a64(&self) -> u64 {
        WORKLOAD_FILTER_FNV1A64_V1
    }

    pub(super) const fn trace_cookie(&self) -> u16 {
        WORKLOAD_TRACE_COOKIE_V1
    }

    pub(super) const fn trace_syscall_count(&self) -> u16 {
        TRACE_SYSCALLS_V1.len() as u16
    }

    pub(super) const fn allow_syscall_count(&self) -> u8 {
        CONTROL_SYSCALLS_V1.len() as u8
    }

    pub(super) const fn command_authority(&self) -> bool {
        false
    }

    pub(super) const fn execution_authority(&self) -> bool {
        false
    }

    pub(super) const fn profile_authority(&self) -> bool {
        false
    }

    pub(super) const fn candidate_or_reuse_authority(&self) -> bool {
        false
    }
}

pub(super) static FIRST_EXECUTE_ONLY_WORKLOAD_SECCOMP_PLAN_V1: WorkloadSeccompPlanV1 =
    WorkloadSeccompPlanV1 { _private: () };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstalledWitnessRefusalV1 {
    OperationSequence,
    TaskCount,
    NoNewPrivileges,
    InitialSeccompMode,
    InstallResult,
    InstalledSeccompMode,
    ReadbackCount,
    ClaimedFingerprint,
    Filter(FilterVerificationRefusalV1),
}

struct InstalledFilterEvidenceV1<'program> {
    completed_operations: &'program [WorkloadSeccompOperationV1],
    task_count: u32,
    no_new_privileges: u8,
    initial_seccomp_mode: u8,
    install_result: i64,
    installed_seccomp_mode: u8,
    readback_count: usize,
    claimed_fingerprint: u64,
    readback: &'program [WorkloadSockFilterV1],
}

/// Opaque linear proof shape reserved for the future kernel connector.
///
/// No current production function can construct this value. It contains no
/// PID, descriptor, path, command, program bytes, or execution permit.
#[must_use = "an installed workload filter witness must be consumed by future connector composition"]
pub(super) struct InstalledWorkloadSeccompWitnessV1 {
    _seal: InstalledWitnessSealV1,
    fingerprint: u64,
}

struct InstalledWitnessSealV1;

impl InstalledWorkloadSeccompWitnessV1 {
    pub(super) const fn byte_fingerprint_fnv1a64(&self) -> u64 {
        self.fingerprint
    }

    pub(super) const fn execution_authority(&self) -> bool {
        false
    }
}

impl fmt::Debug for InstalledWorkloadSeccompWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledWorkloadSeccompWitnessV1")
            .field("evidence", &"<redacted-kernel-readback>")
            .field("execution_authority", &false)
            .finish()
    }
}

impl Drop for InstalledWorkloadSeccompWitnessV1 {
    fn drop(&mut self) {
        self.fingerprint = 0;
    }
}

#[allow(dead_code)]
fn issue_installed_witness_v1(
    evidence: InstalledFilterEvidenceV1<'_>,
) -> Result<InstalledWorkloadSeccompWitnessV1, InstalledWitnessRefusalV1> {
    if evidence.completed_operations != WORKLOAD_SECCOMP_OPERATIONS_V1 {
        return Err(InstalledWitnessRefusalV1::OperationSequence);
    }
    if evidence.task_count != 1 {
        return Err(InstalledWitnessRefusalV1::TaskCount);
    }
    if evidence.no_new_privileges != 1 {
        return Err(InstalledWitnessRefusalV1::NoNewPrivileges);
    }
    if evidence.initial_seccomp_mode != SECCOMP_MODE_DISABLED_V1 {
        return Err(InstalledWitnessRefusalV1::InitialSeccompMode);
    }
    if evidence.install_result != 0 {
        return Err(InstalledWitnessRefusalV1::InstallResult);
    }
    if evidence.installed_seccomp_mode != SECCOMP_MODE_FILTER_V1 {
        return Err(InstalledWitnessRefusalV1::InstalledSeccompMode);
    }
    if evidence.readback_count != WORKLOAD_FILTER_INSTRUCTION_COUNT_V1
        || evidence.readback.len() != evidence.readback_count
    {
        return Err(InstalledWitnessRefusalV1::ReadbackCount);
    }
    if evidence.claimed_fingerprint != WORKLOAD_FILTER_FNV1A64_V1 {
        return Err(InstalledWitnessRefusalV1::ClaimedFingerprint);
    }
    verify_filter_v1(evidence.readback).map_err(InstalledWitnessRefusalV1::Filter)?;
    Ok(InstalledWorkloadSeccompWitnessV1 {
        _seal: InstalledWitnessSealV1,
        fingerprint: WORKLOAD_FILTER_FNV1A64_V1,
    })
}

const _: () = assert!(WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 <= WORKLOAD_FILTER_MAX_INSTRUCTIONS_V1);
const _: () = assert!(WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 == 223);
const _: () = assert!(WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1 == 1_784);
const _: () = assert!(WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1 <= u16::MAX as usize);
const _: () =
    assert!(fnv1a64_v1(&WORKLOAD_FILTER_CANONICAL_BYTES_V1) == WORKLOAD_FILTER_FNV1A64_V1);

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
const _: () = {
    assert!(libc::SYS_read == 0);
    assert!(libc::SYS_rt_sigreturn == 15);
    assert!(libc::SYS_execve == 59);
    assert!(libc::SYS_exit == 60);
    assert!(libc::SYS_exit_group == 231);
    assert!(libc::SYS_openat == 257);
    assert!(libc::SYS_getrandom == 318);
    assert!(libc::SYS_execveat == 322);
    assert!(libc::SYS_clone3 == 435);
    assert!(libc::SYS_close_range == 436);
    assert!(libc::PR_GET_SECCOMP == 21);
    assert!(libc::PR_GET_NO_NEW_PRIVS == 39);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    fn evaluate_filter_v1(architecture: u32, syscall_number: u32) -> Option<u32> {
        let mut accumulator = 0;
        let mut program_counter = 0;
        let mut steps = 0;
        while program_counter < WORKLOAD_FILTER_V1.len()
            && steps <= WORKLOAD_FILTER_INSTRUCTION_COUNT_V1
        {
            let instruction = WORKLOAD_FILTER_V1[program_counter];
            steps += 1;
            match instruction.code {
                BPF_LD_W_ABS_V1 => {
                    accumulator = match instruction.operand {
                        SECCOMP_DATA_ARCH_OFFSET_V1 => architecture,
                        SECCOMP_DATA_NR_OFFSET_V1 => syscall_number,
                        _ => return None,
                    };
                    program_counter += 1;
                }
                BPF_JMP_JEQ_K_V1 => {
                    let jump = if accumulator == instruction.operand {
                        instruction.jump_true
                    } else {
                        instruction.jump_false
                    };
                    program_counter += 1 + usize::from(jump);
                }
                BPF_JMP_JSET_K_V1 => {
                    let jump = if accumulator & instruction.operand != 0 {
                        instruction.jump_true
                    } else {
                        instruction.jump_false
                    };
                    program_counter += 1 + usize::from(jump);
                }
                BPF_RET_K_V1 => return Some(instruction.operand),
                _ => return None,
            }
        }
        None
    }

    fn reference_classification_v1(architecture: u32, syscall_number: u32) -> u32 {
        if architecture != AUDIT_ARCH_X86_64_V1 || syscall_number & X32_SYSCALL_BIT_V1 != 0 {
            return SECCOMP_RET_KILL_PROCESS_V1;
        }
        if TRACE_SYSCALLS_V1
            .iter()
            .any(|entry| entry.number == syscall_number)
        {
            return WORKLOAD_TRACE_RESULT_V1;
        }
        if CONTROL_SYSCALLS_V1.contains(&syscall_number) {
            return SECCOMP_RET_ALLOW_V1;
        }
        SECCOMP_RET_KILL_PROCESS_V1
    }

    fn valid_evidence_v1(program: &[WorkloadSockFilterV1]) -> InstalledFilterEvidenceV1<'_> {
        InstalledFilterEvidenceV1 {
            completed_operations: &WORKLOAD_SECCOMP_OPERATIONS_V1,
            task_count: 1,
            no_new_privileges: 1,
            initial_seccomp_mode: SECCOMP_MODE_DISABLED_V1,
            install_result: 0,
            installed_seccomp_mode: SECCOMP_MODE_FILTER_V1,
            readback_count: WORKLOAD_FILTER_INSTRUCTION_COUNT_V1,
            claimed_fingerprint: WORKLOAD_FILTER_FNV1A64_V1,
            readback: program,
        }
    }

    #[test]
    fn linux_uapi_layout_and_plan_are_frozen() {
        assert_eq!(size_of::<LinuxSeccompDataX8664V1>(), 64);
        assert_eq!(align_of::<LinuxSeccompDataX8664V1>(), 8);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, syscall_number), 0);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, architecture), 4);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, instruction_pointer), 8);
        assert_eq!(offset_of!(LinuxSeccompDataX8664V1, arguments), 16);
        assert_eq!(size_of::<WorkloadSockFilterV1>(), 8);
        assert_eq!(align_of::<WorkloadSockFilterV1>(), 4);
        assert_eq!(offset_of!(WorkloadSockFilterV1, code), 0);
        assert_eq!(offset_of!(WorkloadSockFilterV1, jump_true), 2);
        assert_eq!(offset_of!(WorkloadSockFilterV1, jump_false), 3);
        assert_eq!(offset_of!(WorkloadSockFilterV1, operand), 4);

        let plan = &FIRST_EXECUTE_ONLY_WORKLOAD_SECCOMP_PLAN_V1;
        assert_eq!(plan.operations(), &WORKLOAD_SECCOMP_OPERATIONS_V1);
        assert_eq!(plan.no_new_privileges_read_operation(), 39);
        assert_eq!(plan.seccomp_mode_read_operation(), 21);
        assert_eq!(plan.seccomp_install_operation(), 1);
        assert_eq!(plan.install_flags(), 1);
        assert_eq!(plan.ptrace_readback_request(), 0x420c);
        assert_eq!(plan.ptrace_readback_filter_index(), 0);
        assert_eq!(
            usize::from(plan.instruction_count()),
            WORKLOAD_FILTER_V1.len()
        );
        assert_eq!(
            usize::from(plan.canonical_byte_count()),
            WORKLOAD_FILTER_CANONICAL_BYTES_V1.len()
        );
        assert_eq!(plan.instructions(), &WORKLOAD_FILTER_V1);
    }

    #[test]
    fn syscall_table_is_sorted_unique_named_and_disjoint_from_controls() {
        for pair in TRACE_SYSCALLS_V1.windows(2) {
            assert!(pair[0].number < pair[1].number);
        }
        for entry in TRACE_SYSCALLS_V1 {
            assert!(!entry.name.is_empty());
            assert!(!CONTROL_SYSCALLS_V1.contains(&entry.number));
        }
    }

    #[test]
    fn every_frozen_syscall_and_every_native_gap_has_one_classification() {
        for syscall_number in 0..=1024 {
            assert_eq!(
                evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, syscall_number),
                Some(reference_classification_v1(
                    AUDIT_ARCH_X86_64_V1,
                    syscall_number
                )),
                "syscall {syscall_number}"
            );
        }
        for entry in TRACE_SYSCALLS_V1 {
            assert_eq!(
                evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, entry.number),
                Some(WORKLOAD_TRACE_RESULT_V1),
                "{}",
                entry.name
            );
        }
        for syscall_number in CONTROL_SYSCALLS_V1 {
            assert_eq!(
                evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, syscall_number),
                Some(SECCOMP_RET_ALLOW_V1)
            );
        }
    }

    #[test]
    fn differential_policy_rejects_wrong_arch_x32_and_unknowns() {
        for architecture in [0, 0x4000_0003, AUDIT_ARCH_X86_64_V1 ^ 1, u32::MAX] {
            for syscall_number in [0, 15, 59, 60, 231, 441, 442, u32::MAX] {
                assert_eq!(
                    evaluate_filter_v1(architecture, syscall_number),
                    Some(reference_classification_v1(architecture, syscall_number))
                );
            }
        }
        for syscall_number in 0..=u16::MAX as u32 {
            for candidate in [syscall_number, syscall_number | X32_SYSCALL_BIT_V1] {
                assert_eq!(
                    evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, candidate),
                    Some(reference_classification_v1(AUDIT_ARCH_X86_64_V1, candidate))
                );
            }
        }
        for unknown in [
            18,
            26,
            27,
            31,
            101,
            200,
            442,
            512,
            1025,
            999_999,
            0x8000_0000,
        ] {
            assert_eq!(
                evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, unknown),
                Some(SECCOMP_RET_KILL_PROCESS_V1)
            );
        }
    }

    #[test]
    fn instruction_count_bytes_fingerprint_and_mutation_are_frozen() {
        assert_eq!(
            WORKLOAD_FILTER_V1.len(),
            WORKLOAD_FILTER_INSTRUCTION_COUNT_V1
        );
        assert_eq!(
            WORKLOAD_FILTER_CANONICAL_BYTES_V1.len(),
            WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1
        );
        assert_eq!(
            fnv1a64_v1(&WORKLOAD_FILTER_CANONICAL_BYTES_V1),
            WORKLOAD_FILTER_FNV1A64_V1
        );
        assert_eq!(verify_filter_v1(&WORKLOAD_FILTER_V1), Ok(()));

        let mut mutation = WORKLOAD_FILTER_V1;
        mutation[6].operand ^= 1;
        assert_eq!(
            verify_filter_v1(&mutation),
            Err(FilterVerificationRefusalV1::Fingerprint)
        );
        assert_eq!(
            verify_filter_v1(&WORKLOAD_FILTER_V1[..WORKLOAD_FILTER_V1.len() - 1]),
            Err(FilterVerificationRefusalV1::InstructionCount)
        );

        for instruction_index in 0..WORKLOAD_FILTER_V1.len() {
            let mut code = WORKLOAD_FILTER_V1;
            code[instruction_index].code ^= 1;
            assert!(verify_filter_v1(&code).is_err());
            let mut jump_true = WORKLOAD_FILTER_V1;
            jump_true[instruction_index].jump_true ^= 1;
            assert!(verify_filter_v1(&jump_true).is_err());
            let mut jump_false = WORKLOAD_FILTER_V1;
            jump_false[instruction_index].jump_false ^= 1;
            assert!(verify_filter_v1(&jump_false).is_err());
            let mut operand = WORKLOAD_FILTER_V1;
            operand[instruction_index].operand ^= 1;
            assert!(verify_filter_v1(&operand).is_err());
        }
    }

    #[test]
    fn bounded_verifier_rejects_malformed_control_flow_and_actions() {
        let mut opcode = WORKLOAD_FILTER_V1;
        opcode[0].code = u16::MAX;
        assert_eq!(
            verify_filter_v1(&opcode),
            Err(FilterVerificationRefusalV1::InvalidOpcode)
        );

        let mut load = WORKLOAD_FILTER_V1;
        load[0].operand = 8;
        assert_eq!(
            verify_filter_v1(&load),
            Err(FilterVerificationRefusalV1::InvalidLoad)
        );

        let mut jump = WORKLOAD_FILTER_V1;
        jump[1].jump_true = u8::MAX;
        assert_eq!(
            verify_filter_v1(&jump),
            Err(FilterVerificationRefusalV1::InvalidJump)
        );

        let mut action = WORKLOAD_FILTER_V1;
        action[2].operand = 0;
        assert_eq!(
            verify_filter_v1(&action),
            Err(FilterVerificationRefusalV1::InvalidReturn)
        );
    }

    #[test]
    fn installed_witness_requires_every_exact_readback_dimension() {
        let witness = issue_installed_witness_v1(valid_evidence_v1(&WORKLOAD_FILTER_V1)).unwrap();
        assert_eq!(
            witness.byte_fingerprint_fnv1a64(),
            WORKLOAD_FILTER_FNV1A64_V1
        );
        assert!(!witness.execution_authority());
        let debug = format!("{witness:?}");
        assert!(debug.contains("redacted-kernel-readback"));
        assert!(!debug.contains(&format!("{WORKLOAD_FILTER_FNV1A64_V1:x}")));

        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.completed_operations = &WORKLOAD_SECCOMP_OPERATIONS_V1[..6];
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::OperationSequence
        );
        let mut reordered_operations = WORKLOAD_SECCOMP_OPERATIONS_V1;
        reordered_operations.swap(0, 1);
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.completed_operations = &reordered_operations;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::OperationSequence
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.task_count = 2;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::TaskCount
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.no_new_privileges = 0;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::NoNewPrivileges
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.initial_seccomp_mode = 2;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::InitialSeccompMode
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.install_result = -1;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::InstallResult
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.installed_seccomp_mode = 0;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::InstalledSeccompMode
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.readback_count -= 1;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::ReadbackCount
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.claimed_fingerprint ^= 1;
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::ClaimedFingerprint
        );

        let mut mutated = WORKLOAD_FILTER_V1;
        mutated[6].operand ^= 1;
        let evidence = valid_evidence_v1(&mutated);
        assert_eq!(
            issue_installed_witness_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::Filter(FilterVerificationRefusalV1::Fingerprint)
        );
    }

    #[test]
    fn plan_and_witness_are_non_authoritative_and_linear() {
        let plan = &FIRST_EXECUTE_ONLY_WORKLOAD_SECCOMP_PLAN_V1;
        assert_eq!(
            plan.policy_id(),
            "x86_64-execute-only-pytest-workload-seccomp-v1"
        );
        assert_eq!(plan.trace_cookie(), WORKLOAD_TRACE_COOKIE_V1);
        assert_eq!(plan.trace_syscall_count(), 105);
        assert_eq!(plan.allow_syscall_count(), 3);
        assert!(!plan.command_authority());
        assert!(!plan.execution_authority());
        assert!(!plan.profile_authority());
        assert!(!plan.candidate_or_reuse_authority());

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
        <InstalledWorkloadSeccompWitnessV1 as AmbiguousIfClone<_>>::probe();
        <InstalledWorkloadSeccompWitnessV1 as AmbiguousIfCopy<_>>::probe();
        assert!(core::mem::needs_drop::<InstalledWorkloadSeccompWitnessV1>());
    }
}
