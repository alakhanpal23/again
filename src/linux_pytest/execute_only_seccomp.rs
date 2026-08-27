//! Frozen workload-seccomp plan for the first execute-only pytest fixture:
//! `.venv/bin/python -I -m pytest tests/test_smoke.py::test_smoke`.
//!
//! The frozen plan and pure verifier accept no command, path, environment,
//! descriptor, PID, or callback. A crate-private connector submodule may return
//! a completed diagnostic probe only after operating on its own stopped
//! disposable child, reading the exact filter back, and terminally reaping that
//! child. Required
//! native x86_64 workload
//! syscalls, including sigreturn and exit control calls, route to
//! `SECCOMP_RET_TRACE`. Wrong audit architectures, x32-tagged calls, and every
//! unlisted native call fail closed. The syscall table is provisional: a future
//! connector may consume it only after the exact pinned runtime and fixed smoke
//! workload have produced a reviewed live syscall corpus. Missing calls remain
//! fatal rather than being added speculatively.
//!
//! The pure transcript verifier below is not kernel evidence and cannot issue a
//! witness. The connector-owned stopped-child permit returns only a completed
//! disposable probe; production issuance of a live-child witness remains
//! impossible until a future connector retains the stopped child and cleanup
//! owner.

#![allow(
    dead_code,
    reason = "the frozen plan and disposable probe remain crate-private until live-child filter and supervisor composition"
)]

use core::fmt;

mod connector;

#[allow(
    unused_imports,
    reason = "the future live-child orchestrator has not yet consumed this crate-private diagnostic checkpoint"
)]
pub(in crate::linux_pytest) use connector::{
    CompletedDisposableWorkloadFilterProbeV1, WorkloadSeccompConnectorFailureV1,
    qualify_stopped_workload_filter_live_v1,
};

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
const SECCOMP_RET_ACTION_FULL_V1: u32 = 0xffff_0000;
const SECCOMP_RET_DATA_V1: u32 = 0x0000_ffff;
const WORKLOAD_TRACE_COOKIE_V1: u16 = 0xb503;
const WORKLOAD_TRACE_RESULT_V1: u32 = SECCOMP_RET_TRACE_V1 | WORKLOAD_TRACE_COOKIE_V1 as u32;
const WORKLOAD_POLICY_DIGEST_DOMAIN_V1: &str =
    "again linux pytest provisional workload seccomp program v1";
const RESERVED_SECCOMP_TRACE_COOKIES_V1: [u16; 4] = [
    WORKLOAD_TRACE_COOKIE_V1,
    super::tracer_seccomp::trace_all_native_seccomp_cookie_spec_v1(),
    super::trace_protocol::PTRACE_TRANSPORT_GETPID_COOKIE_V1,
    super::trace_protocol::PTRACE_TRANSPORT_GETPPID_COOKIE_V1,
];

const fn trace_cookies_are_nonzero_and_unique_v1(cookies: &[u16]) -> bool {
    let mut left = 0;
    while left < cookies.len() {
        if cookies[left] == 0 {
            return false;
        }
        let mut right = left + 1;
        while right < cookies.len() {
            if cookies[left] == cookies[right] {
                return false;
            }
            right += 1;
        }
        left += 1;
    }
    true
}

const NR_RT_SIGRETURN_X86_64_V1: u32 = 15;
const NR_EXIT_X86_64_V1: u32 = 60;
const NR_EXIT_GROUP_X86_64_V1: u32 = 231;
const CONTROL_TRACE_SYSCALLS_V1: [u32; 3] = [
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
const WORKLOAD_FILTER_SUFFIX_INSTRUCTIONS_V1: usize = CONTROL_TRACE_SYSCALLS_V1.len() * 2 + 1;
const WORKLOAD_FILTER_INSTRUCTION_COUNT_V1: usize = WORKLOAD_FILTER_PREFIX_INSTRUCTIONS_V1
    + TRACE_SYSCALLS_V1.len() * 2
    + WORKLOAD_FILTER_SUFFIX_INSTRUCTIONS_V1;
const WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1: usize = WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 * 8;
// Diagnostic drift checksum only. Security identity uses the domain-separated
// BLAKE3 digest below.
const WORKLOAD_FILTER_FNV1A64_V1: u64 = 0xa45e_17a1_5003_1340;
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
    while control_index < CONTROL_TRACE_SYSCALLS_V1.len() {
        output[output_index] = jump_v1(
            BPF_JMP_JEQ_K_V1,
            CONTROL_TRACE_SYSCALLS_V1[control_index],
            0,
            1,
        );
        output[output_index + 1] = stmt_v1(BPF_RET_K_V1, WORKLOAD_TRACE_RESULT_V1);
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

fn workload_policy_digest_blake3_v1() -> [u8; 32] {
    workload_policy_digest_for_bytes_v1(&WORKLOAD_FILTER_CANONICAL_BYTES_V1)
}

fn workload_policy_digest_for_bytes_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(WORKLOAD_POLICY_DIGEST_DOMAIN_V1);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
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
                            SECCOMP_RET_KILL_PROCESS_V1 | WORKLOAD_TRACE_RESULT_V1
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
    PtraceReadbackCount,
    PtraceReadbackInstructions,
}

const WORKLOAD_SECCOMP_OPERATIONS_V1: [WorkloadSeccompOperationV1; 6] = [
    WorkloadSeccompOperationV1::VerifySingleTask,
    WorkloadSeccompOperationV1::ReadNoNewPrivileges,
    WorkloadSeccompOperationV1::ReadInitialSeccompMode,
    WorkloadSeccompOperationV1::InstallTsyncFilter,
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

/// Borrowed static plan. It is policy data, never proof of installation.
pub(super) struct WorkloadSeccompPlanV1 {
    _private: (),
}

impl WorkloadSeccompPlanV1 {
    pub(super) const fn policy_id(&self) -> &'static str {
        "x86_64-execute-only-pytest-workload-seccomp-v1"
    }

    pub(super) const fn operations(&self) -> &'static [WorkloadSeccompOperationV1; 6] {
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

    /// Domain-separated security identity of the exact canonical cBPF bytes.
    pub(super) fn policy_digest_blake3(&self) -> [u8; 32] {
        workload_policy_digest_blake3_v1()
    }

    pub(super) const fn trace_cookie(&self) -> u16 {
        WORKLOAD_TRACE_COOKIE_V1
    }

    pub(super) const fn trace_syscall_count(&self) -> u16 {
        TRACE_SYSCALLS_V1.len() as u16
    }

    pub(super) const fn traced_control_syscall_count(&self) -> u8 {
        CONTROL_TRACE_SYSCALLS_V1.len() as u8
    }

    pub(super) const fn allow_syscall_count(&self) -> u8 {
        0
    }

    pub(super) const fn syscall_table_is_provisional(&self) -> bool {
        true
    }

    pub(super) const fn requires_exact_runtime_and_live_corpus_qualification(&self) -> bool {
        true
    }

    pub(super) const fn production_target_supported(&self) -> bool {
        cfg!(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_env = "gnu",
            target_pointer_width = "64"
        ))
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

#[cfg(any(
    test,
    all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    )
))]
pub(super) static FIRST_EXECUTE_ONLY_WORKLOAD_SECCOMP_PLAN_V1: WorkloadSeccompPlanV1 =
    WorkloadSeccompPlanV1 { _private: () };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstalledWitnessRefusalV1 {
    OperationSequence,
    TaskCount,
    NoNewPrivileges,
    InitialSeccompMode,
    InstallResult,
    ReadbackCount,
    ClaimedPolicyDigest,
    Filter(FilterVerificationRefusalV1),
}

struct InstalledFilterEvidenceV1<'program> {
    completed_operations: &'program [WorkloadSeccompOperationV1],
    task_count: u32,
    no_new_privileges: u8,
    initial_seccomp_mode: u8,
    install_result: i64,
    readback_count: usize,
    claimed_policy_digest: [u8; 32],
    readback: &'program [WorkloadSockFilterV1],
}

/// Opaque linear proof shape reserved for a future live-child kernel connector.
///
/// No production function can construct this value. It contains no PID,
/// descriptor, path, command, program bytes, or execution permit. A completed
/// disposable probe is intentionally not convertible to this type.
#[must_use = "an installed workload filter witness must be consumed by future connector composition"]
pub(super) struct InstalledWorkloadSeccompWitnessV1 {
    _seal: InstalledWitnessSealV1,
    policy_digest: [u8; 32],
}

struct InstalledWitnessSealV1;

impl InstalledWorkloadSeccompWitnessV1 {
    pub(super) const fn policy_digest_blake3(&self) -> &[u8; 32] {
        &self.policy_digest
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
        self.policy_digest.fill(0);
    }
}

/// Pure transcript consistency check. Passing it proves only that caller-held
/// bytes describe the frozen plan; it does not prove a kernel operation ran.
fn verify_installed_transcript_v1(
    evidence: InstalledFilterEvidenceV1<'_>,
) -> Result<(), InstalledWitnessRefusalV1> {
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
    if evidence.readback_count != WORKLOAD_FILTER_INSTRUCTION_COUNT_V1
        || evidence.readback.len() != evidence.readback_count
    {
        return Err(InstalledWitnessRefusalV1::ReadbackCount);
    }
    if evidence.claimed_policy_digest != workload_policy_digest_blake3_v1() {
        return Err(InstalledWitnessRefusalV1::ClaimedPolicyDigest);
    }
    verify_filter_v1(evidence.readback).map_err(InstalledWitnessRefusalV1::Filter)?;
    Ok(())
}

/// Test-only constructor. Production issuance intentionally does not exist:
/// the future connector must add a separate issuer that consumes its sealed
/// stopped-child and completed-operation evidence before calling the pure
/// verifier and constructing this witness.
#[cfg(test)]
fn issue_installed_witness_for_test_v1(
    evidence: InstalledFilterEvidenceV1<'_>,
) -> Result<InstalledWorkloadSeccompWitnessV1, InstalledWitnessRefusalV1> {
    verify_installed_transcript_v1(evidence)?;
    Ok(InstalledWorkloadSeccompWitnessV1 {
        _seal: InstalledWitnessSealV1,
        policy_digest: workload_policy_digest_blake3_v1(),
    })
}

const _: () = assert!(WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 <= WORKLOAD_FILTER_MAX_INSTRUCTIONS_V1);
const _: () = assert!(WORKLOAD_FILTER_INSTRUCTION_COUNT_V1 == 223);
const _: () = assert!(WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1 == 1_784);
const _: () = assert!(WORKLOAD_FILTER_CANONICAL_BYTE_COUNT_V1 <= u16::MAX as usize);
const _: () =
    assert!(fnv1a64_v1(&WORKLOAD_FILTER_CANONICAL_BYTES_V1) == WORKLOAD_FILTER_FNV1A64_V1);
const _: () = assert!(trace_cookies_are_nonzero_and_unique_v1(
    &RESERVED_SECCOMP_TRACE_COOKIES_V1
));
const _: () =
    assert!(WORKLOAD_TRACE_RESULT_V1 & SECCOMP_RET_ACTION_FULL_V1 == SECCOMP_RET_TRACE_V1);
const _: () =
    assert!(WORKLOAD_TRACE_RESULT_V1 & SECCOMP_RET_DATA_V1 == WORKLOAD_TRACE_COOKIE_V1 as u32);

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
const _: () = {
    assert!(BPF_LD_W_ABS_V1 == 0x20);
    assert!(BPF_JMP_JEQ_K_V1 == 0x15);
    assert!(BPF_JMP_JSET_K_V1 == 0x45);
    assert!(BPF_RET_K_V1 == 0x06);
    assert!(AUDIT_ARCH_X86_64_V1 == 0xc000_003e);
    assert!(X32_SYSCALL_BIT_V1 == 0x4000_0000);
    assert!(libc::SECCOMP_RET_KILL_PROCESS == SECCOMP_RET_KILL_PROCESS_V1);
    assert!(libc::SECCOMP_RET_TRACE == SECCOMP_RET_TRACE_V1);
    assert!(libc::SECCOMP_RET_ACTION_FULL == SECCOMP_RET_ACTION_FULL_V1);
    assert!(libc::SECCOMP_RET_DATA == SECCOMP_RET_DATA_V1);
    assert!(libc::SECCOMP_SET_MODE_FILTER == SECCOMP_SET_MODE_FILTER_V1);
    assert!(libc::SECCOMP_FILTER_FLAG_TSYNC as u32 == SECCOMP_FILTER_FLAG_TSYNC_V1);
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
    assert!(libc::SYS_openat2 == 437);
    assert!(libc::SYS_faccessat2 == 439);
    assert!(libc::SYS_epoll_pwait2 == 441);
    assert!(libc::PR_GET_SECCOMP == 21);
    assert!(libc::PR_GET_NO_NEW_PRIVS == 39);
    assert!(PTRACE_SECCOMP_GET_FILTER_V1 == 0x420c);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    // Plausible runtime/library calls deliberately absent pending exact live
    // corpus evidence. Their presence here is a regression tripwire, not a
    // proposal to admit them.
    const PLAUSIBLE_BUT_UNQUALIFIED_SYSCALLS_V1: &[(u32, &str)] = &[
        (18, "pwrite64"),
        (27, "mincore"),
        (41, "socket"),
        (42, "connect"),
        (309, "getcpu"),
        (324, "membarrier"),
        (326, "copy_file_range"),
        (327, "preadv2"),
        (328, "pwritev2"),
        (434, "pidfd_open"),
        (449, "futex_waitv"),
    ];

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
        if CONTROL_TRACE_SYSCALLS_V1.contains(&syscall_number) {
            return WORKLOAD_TRACE_RESULT_V1;
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
            readback_count: WORKLOAD_FILTER_INSTRUCTION_COUNT_V1,
            claimed_policy_digest: workload_policy_digest_blake3_v1(),
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
        assert!(!format!("{:?}", plan.operations()).contains("InstalledSeccompMode"));
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

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn linux_libc_sock_filter_layout_and_seccomp_uapi_match() {
        assert_eq!(
            size_of::<WorkloadSockFilterV1>(),
            size_of::<libc::sock_filter>()
        );
        assert_eq!(
            align_of::<WorkloadSockFilterV1>(),
            align_of::<libc::sock_filter>()
        );
        assert_eq!(offset_of!(libc::sock_filter, code), 0);
        assert_eq!(offset_of!(libc::sock_filter, jt), 2);
        assert_eq!(offset_of!(libc::sock_filter, jf), 3);
        assert_eq!(offset_of!(libc::sock_filter, k), 4);
        assert_eq!(libc::SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_PROCESS_V1);
        assert_eq!(libc::SECCOMP_RET_TRACE, SECCOMP_RET_TRACE_V1);
        assert_eq!(libc::SECCOMP_RET_ACTION_FULL, SECCOMP_RET_ACTION_FULL_V1);
        assert_eq!(libc::SECCOMP_RET_DATA, SECCOMP_RET_DATA_V1);
        assert_eq!(
            libc::SECCOMP_FILTER_FLAG_TSYNC as u32,
            SECCOMP_FILTER_FLAG_TSYNC_V1
        );
    }

    #[test]
    fn syscall_table_is_sorted_unique_named_and_disjoint_from_controls() {
        for pair in TRACE_SYSCALLS_V1.windows(2) {
            assert!(pair[0].number < pair[1].number);
        }
        for entry in TRACE_SYSCALLS_V1 {
            assert!(!entry.name.is_empty());
            assert!(!CONTROL_TRACE_SYSCALLS_V1.contains(&entry.number));
        }
    }

    #[test]
    fn provisional_table_keeps_plausible_absent_calls_fail_closed() {
        for &(number, name) in PLAUSIBLE_BUT_UNQUALIFIED_SYSCALLS_V1 {
            assert!(
                !TRACE_SYSCALLS_V1.iter().any(|entry| entry.number == number),
                "{name} was added without live-corpus qualification"
            );
            assert!(!CONTROL_TRACE_SYSCALLS_V1.contains(&number), "{name}");
            assert_eq!(
                evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, number),
                Some(SECCOMP_RET_KILL_PROCESS_V1),
                "{name}"
            );
        }
    }

    #[test]
    fn all_listed_and_control_calls_trace_with_no_allow_return() {
        for number in TRACE_SYSCALLS_V1
            .iter()
            .map(|entry| entry.number)
            .chain(CONTROL_TRACE_SYSCALLS_V1)
        {
            assert_eq!(
                evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, number),
                Some(WORKLOAD_TRACE_RESULT_V1)
            );
        }
        for instruction in WORKLOAD_FILTER_V1 {
            if instruction.code == BPF_RET_K_V1 {
                assert!(matches!(
                    instruction.operand,
                    SECCOMP_RET_KILL_PROCESS_V1 | WORKLOAD_TRACE_RESULT_V1
                ));
            }
        }
    }

    #[test]
    fn workload_cookie_is_reserved_and_cross_protocol_unique() {
        assert_eq!(
            RESERVED_SECCOMP_TRACE_COOKIES_V1,
            [
                WORKLOAD_TRACE_COOKIE_V1,
                super::super::tracer_seccomp::trace_all_native_seccomp_cookie_spec_v1(),
                super::super::trace_protocol::PTRACE_TRANSPORT_GETPID_COOKIE_V1,
                super::super::trace_protocol::PTRACE_TRANSPORT_GETPPID_COOKIE_V1,
            ]
        );
        assert!(trace_cookies_are_nonzero_and_unique_v1(
            &RESERVED_SECCOMP_TRACE_COOKIES_V1
        ));
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
        for syscall_number in CONTROL_TRACE_SYSCALLS_V1 {
            assert_eq!(
                evaluate_filter_v1(AUDIT_ARCH_X86_64_V1, syscall_number),
                Some(WORKLOAD_TRACE_RESULT_V1)
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
        assert_eq!(WORKLOAD_FILTER_FNV1A64_V1, 0xa45e_17a1_5003_1340);
        assert_eq!(
            workload_policy_digest_blake3_v1(),
            [
                90, 104, 114, 5, 238, 106, 101, 165, 52, 152, 102, 131, 19, 91, 28, 10, 97, 221, 3,
                167, 225, 156, 28, 130, 72, 104, 162, 206, 110, 43, 14, 136,
            ]
        );
        assert_eq!(verify_filter_v1(&WORKLOAD_FILTER_V1), Ok(()));

        let mut mutation = WORKLOAD_FILTER_V1;
        mutation[6].operand ^= 1;
        let mutation_bytes = canonical_filter_bytes_v1(&mutation);
        assert_ne!(
            workload_policy_digest_for_bytes_v1(&mutation_bytes),
            workload_policy_digest_blake3_v1()
        );
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
        let witness =
            issue_installed_witness_for_test_v1(valid_evidence_v1(&WORKLOAD_FILTER_V1)).unwrap();
        assert_eq!(
            witness.policy_digest_blake3(),
            &workload_policy_digest_blake3_v1()
        );
        assert!(!witness.execution_authority());
        let debug = format!("{witness:?}");
        assert!(debug.contains("redacted-kernel-readback"));
        assert!(!debug.contains(&format!("{WORKLOAD_FILTER_FNV1A64_V1:x}")));

        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.completed_operations = &WORKLOAD_SECCOMP_OPERATIONS_V1[..5];
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::OperationSequence
        );
        let mut reordered_operations = WORKLOAD_SECCOMP_OPERATIONS_V1;
        reordered_operations.swap(0, 1);
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.completed_operations = &reordered_operations;
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::OperationSequence
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.task_count = 2;
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::TaskCount
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.no_new_privileges = 0;
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::NoNewPrivileges
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.initial_seccomp_mode = 2;
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::InitialSeccompMode
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.install_result = -1;
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::InstallResult
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.readback_count -= 1;
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::ReadbackCount
        );
        let mut evidence = valid_evidence_v1(&WORKLOAD_FILTER_V1);
        evidence.claimed_policy_digest[0] ^= 1;
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
            InstalledWitnessRefusalV1::ClaimedPolicyDigest
        );

        let mut mutated = WORKLOAD_FILTER_V1;
        mutated[6].operand ^= 1;
        let evidence = valid_evidence_v1(&mutated);
        assert_eq!(
            issue_installed_witness_for_test_v1(evidence).unwrap_err(),
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
        assert_eq!(plan.traced_control_syscall_count(), 3);
        assert_eq!(plan.allow_syscall_count(), 0);
        assert!(plan.syscall_table_is_provisional());
        assert!(plan.requires_exact_runtime_and_live_corpus_qualification());
        assert_eq!(
            plan.production_target_supported(),
            cfg!(all(
                target_os = "linux",
                target_arch = "x86_64",
                target_env = "gnu",
                target_pointer_width = "64"
            ))
        );
        assert_eq!(
            plan.policy_digest_blake3(),
            workload_policy_digest_blake3_v1()
        );
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
