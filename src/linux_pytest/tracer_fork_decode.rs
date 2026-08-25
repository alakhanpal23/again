//! Pure fork-family entry decoder for the future Linux x86_64 tracer.
//!
//! The decoder consumes one exact seccomp-entry frame, an already-classified
//! ptrace event, and (for `clone3`) a caller-owned exact copy made while the
//! tracee was still stopped. It follows the UAPI layouts in
//! `include/uapi/linux/sched.h`, the native syscall numbers in
//! `arch/x86/entry/syscalls/syscall_64.tbl`, and the event selection in
//! `kernel/fork.c`.
//!
//! No process-memory read occurs here. Raw syscall arguments and `clone_args`
//! bytes are accepted only as borrowed input and are never returned. The
//! output is a non-authoritative lifecycle observation; it cannot authorize a
//! resume, tracing completeness, EffectIR, execution, or reuse.

use super::tracer_task_state::{
    TRACER_TASK_CLONE_NR_X86_64_V1, TRACER_TASK_CLONE3_NR_X86_64_V1, TRACER_TASK_FORK_NR_X86_64_V1,
    TRACER_TASK_VFORK_NR_X86_64_V1, TracerTaskChildBirthKindV1, TracerTaskGroupRelationV1,
};
use super::tracer_wait_status::LinuxPtraceEventV1;

const CLONE3_ARGS_SIZE_VER0_V1: usize = 64;
const CLONE3_ARGS_SIZE_VER1_V1: usize = 80;
const CLONE3_ARGS_SIZE_VER2_V1: usize = 88;
const CLONE3_ARGS_BUFFER_BYTES_V1: usize = CLONE3_ARGS_SIZE_VER2_V1;

const CLONE3_FLAGS_OFFSET_V1: usize = 0;
const CLONE3_PIDFD_OFFSET_V1: usize = 8;
const CLONE3_CHILD_TID_OFFSET_V1: usize = 16;
const CLONE3_PARENT_TID_OFFSET_V1: usize = 24;
const CLONE3_EXIT_SIGNAL_OFFSET_V1: usize = 32;
const CLONE3_STACK_OFFSET_V1: usize = 40;
const CLONE3_STACK_SIZE_OFFSET_V1: usize = 48;
const CLONE3_TLS_OFFSET_V1: usize = 56;
const CLONE3_SET_TID_OFFSET_V1: usize = 64;
const CLONE3_SET_TID_SIZE_OFFSET_V1: usize = 72;
const CLONE3_CGROUP_OFFSET_V1: usize = 80;

const LINUX_CSIGNAL_MASK_V1: u64 = 0x0000_00ff;
const LINUX_SIGCHLD_V1: u64 = 17;
const LINUX_X86_64_MAX_SIGNAL_V1: u64 = 64;

const LINUX_CLONE_VM_V1: u64 = 0x0000_0100;
const LINUX_CLONE_FS_V1: u64 = 0x0000_0200;
const LINUX_CLONE_FILES_V1: u64 = 0x0000_0400;
const LINUX_CLONE_SIGHAND_V1: u64 = 0x0000_0800;
const LINUX_CLONE_PIDFD_V1: u64 = 0x0000_1000;
const LINUX_CLONE_VFORK_V1: u64 = 0x0000_4000;
const LINUX_CLONE_PARENT_V1: u64 = 0x0000_8000;
const LINUX_CLONE_THREAD_V1: u64 = 0x0001_0000;
const LINUX_CLONE_NEWNS_V1: u64 = 0x0002_0000;
const LINUX_CLONE_SYSVSEM_V1: u64 = 0x0004_0000;
const LINUX_CLONE_SETTLS_V1: u64 = 0x0008_0000;
const LINUX_CLONE_PARENT_SETTID_V1: u64 = 0x0010_0000;
const LINUX_CLONE_CHILD_CLEARTID_V1: u64 = 0x0020_0000;
const LINUX_CLONE_DETACHED_V1: u64 = 0x0040_0000;
const LINUX_CLONE_UNTRACED_V1: u64 = 0x0080_0000;
const LINUX_CLONE_CHILD_SETTID_V1: u64 = 0x0100_0000;
const LINUX_CLONE_NEWCGROUP_V1: u64 = 0x0200_0000;
const LINUX_CLONE_NEWUTS_V1: u64 = 0x0400_0000;
const LINUX_CLONE_NEWIPC_V1: u64 = 0x0800_0000;
const LINUX_CLONE_NEWUSER_V1: u64 = 0x1000_0000;
const LINUX_CLONE_NEWPID_V1: u64 = 0x2000_0000;
const LINUX_CLONE_NEWNET_V1: u64 = 0x4000_0000;
const LINUX_CLONE_IO_V1: u64 = 0x8000_0000;

// `CLONE_NEWTIME` intentionally overlaps the legacy clone CSIGNAL byte and is
// admitted only in clone3's separate flags field.
const LINUX_CLONE_NEWTIME_V1: u64 = 0x0000_0080;
const LINUX_CLONE_CLEAR_SIGHAND_V1: u64 = 1_u64 << 32;
const LINUX_CLONE_INTO_CGROUP_V1: u64 = 1_u64 << 33;

const LEGACY_CLONE_ADMITTED_FLAGS_V1: u64 = LINUX_CLONE_VM_V1
    | LINUX_CLONE_FS_V1
    | LINUX_CLONE_FILES_V1
    | LINUX_CLONE_SIGHAND_V1
    | LINUX_CLONE_PIDFD_V1
    | LINUX_CLONE_VFORK_V1
    | LINUX_CLONE_PARENT_V1
    | LINUX_CLONE_THREAD_V1
    | LINUX_CLONE_NEWNS_V1
    | LINUX_CLONE_SYSVSEM_V1
    | LINUX_CLONE_SETTLS_V1
    | LINUX_CLONE_PARENT_SETTID_V1
    | LINUX_CLONE_CHILD_CLEARTID_V1
    | LINUX_CLONE_CHILD_SETTID_V1
    | LINUX_CLONE_NEWCGROUP_V1
    | LINUX_CLONE_NEWUTS_V1
    | LINUX_CLONE_NEWIPC_V1
    | LINUX_CLONE_NEWUSER_V1
    | LINUX_CLONE_NEWPID_V1
    | LINUX_CLONE_NEWNET_V1
    | LINUX_CLONE_IO_V1;

const CLONE3_ADMITTED_FLAGS_V1: u64 = LEGACY_CLONE_ADMITTED_FLAGS_V1
    | LINUX_CLONE_NEWTIME_V1
    | LINUX_CLONE_CLEAR_SIGHAND_V1
    | LINUX_CLONE_INTO_CGROUP_V1;

const _: [(); CLONE3_ARGS_SIZE_VER0_V1] = [(); CLONE3_TLS_OFFSET_V1 + size_of::<u64>()];
const _: [(); CLONE3_ARGS_SIZE_VER1_V1] = [(); CLONE3_SET_TID_SIZE_OFFSET_V1 + size_of::<u64>()];
const _: [(); CLONE3_ARGS_SIZE_VER2_V1] = [(); CLONE3_CGROUP_OFFSET_V1 + size_of::<u64>()];
const _: () = assert!(CLONE3_ARGS_BUFFER_BYTES_V1 == 88);
const _: () = assert!(LINUX_CLONE_NEWTIME_V1 & LINUX_CSIGNAL_MASK_V1 != 0);
const _: () = assert!(CLONE3_ADMITTED_FLAGS_V1 & LINUX_CLONE_DETACHED_V1 == 0);
const _: () = assert!(CLONE3_ADMITTED_FLAGS_V1 & LINUX_CLONE_UNTRACED_V1 == 0);

/// Clone3 bytes captured by the future connector at the same seccomp stop as
/// the syscall entry. `Exact` requires a caller-zeroed 88-byte buffer and the
/// exact successful byte count of the bounded copy. This input deliberately
/// has no `Debug`, `Clone`, or `Copy` implementation because it may contain
/// tracee pointers.
#[allow(dead_code)] // Consumed by the future ptrace connector after integration.
pub(super) enum Clone3ArgsCaptureV1<'a> {
    NotApplicable,
    Unavailable,
    Exact {
        copied_byte_count: usize,
        buffer: &'a [u8; CLONE3_ARGS_BUFFER_BYTES_V1],
    },
}

/// Data-minimized lifecycle facts derived from a fork-family entry and event.
///
/// This is an observation only. In particular, `Clone` does not imply that the
/// child shares its creator's thread group; callers must consume `relation`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ForkFamilyBirthObservationV1 {
    pub(super) kind: TracerTaskChildBirthKindV1,
    pub(super) relation: TracerTaskGroupRelationV1,
}

/// Typed, data-free fail-closed outcomes in decoder precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ForkFamilyDecodeErrorV1 {
    UnsupportedSyscall,
    UnexpectedClone3Capture,
    Clone3ArgsUnavailable,
    Clone3NullArgsPointer,
    Clone3DeclaredSizeTooSmall,
    Clone3DeclaredSizeTooLarge,
    Clone3DeclaredSizeAmbiguous,
    Clone3CopiedByteCountMismatch,
    Clone3UncopiedTailNonzero,
    LegacyCloneHighFlagBitsNonzero,
    ExitSignalOutOfRange,
    Clone3SignalBitsInFlags,
    TraceSuppressionFlag,
    ReservedCloneFlag,
    UnsupportedCloneFlags,
    InvalidCloneFlagCombination,
    SharedThreadGroupWithExitSignal,
    VforkSharedThreadGroupUnsupported,
    LegacyCloneInactiveFieldNonzero,
    Clone3InactiveFieldNonzero,
    Clone3ActiveFieldZero,
    Clone3SetTidExternalReadUnsupported,
    Clone3FlagRequiresNewerVersion,
    Clone3StackShapeInvalid,
    Clone3PidfdParentTidAlias,
    PtraceEventMismatch,
}

/// Static decoder facts. This zero-sized diagnostic value is not authority.
pub(super) struct ForkFamilyDecoderSummaryV1 {
    _private: (),
}

#[allow(dead_code)] // Kept as a reviewable connector contract.
impl ForkFamilyDecoderSummaryV1 {
    pub(super) const fn decoder_id(&self) -> &'static str {
        "linux-x86_64-fork-family-entry-v1"
    }

    pub(super) const fn clone3_buffer_byte_count(&self) -> u8 {
        CLONE3_ARGS_BUFFER_BYTES_V1 as u8
    }

    pub(super) const fn allocation_free(&self) -> bool {
        true
    }

    pub(super) const fn performs_process_memory_reads(&self) -> bool {
        false
    }

    pub(super) const fn output_contains_raw_pointer(&self) -> bool {
        false
    }

    pub(super) const fn tracing_authority(&self) -> bool {
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

#[allow(dead_code)] // Read by the future connector and pure tests.
pub(super) static FORK_FAMILY_DECODER_SUMMARY_V1: ForkFamilyDecoderSummaryV1 =
    ForkFamilyDecoderSummaryV1 { _private: () };

/// Decode one exact native x86_64 fork-family syscall-entry observation.
///
/// `arguments` are the six native syscall argument words from the validated
/// seccomp frame. For clone3, the connector must copy exactly the declared
/// bytes into a zeroed fixed buffer before resuming the tracee. This function
/// is pure, bounded, allocation-free, and returns no raw syscall word.
#[allow(dead_code)] // Called by the future ptrace connector after integration.
pub(super) fn decode_fork_family_entry_x86_64_v1(
    syscall_number: u32,
    arguments: &[u64; 6],
    clone3_capture: Clone3ArgsCaptureV1<'_>,
    ptrace_event: LinuxPtraceEventV1,
) -> Result<ForkFamilyBirthObservationV1, ForkFamilyDecodeErrorV1> {
    let observation = match syscall_number {
        TRACER_TASK_FORK_NR_X86_64_V1 => {
            require_no_clone3_capture_v1(clone3_capture)?;
            ForkFamilyBirthObservationV1 {
                kind: TracerTaskChildBirthKindV1::Fork,
                relation: TracerTaskGroupRelationV1::NewThreadGroup,
            }
        }
        TRACER_TASK_VFORK_NR_X86_64_V1 => {
            require_no_clone3_capture_v1(clone3_capture)?;
            ForkFamilyBirthObservationV1 {
                kind: TracerTaskChildBirthKindV1::Vfork,
                relation: TracerTaskGroupRelationV1::NewThreadGroup,
            }
        }
        TRACER_TASK_CLONE_NR_X86_64_V1 => {
            require_no_clone3_capture_v1(clone3_capture)?;
            decode_legacy_clone_v1(arguments)?
        }
        TRACER_TASK_CLONE3_NR_X86_64_V1 => decode_clone3_v1(arguments, clone3_capture)?,
        _ => return Err(ForkFamilyDecodeErrorV1::UnsupportedSyscall),
    };

    if !ptrace_event_matches_birth_kind_v1(ptrace_event, observation.kind) {
        return Err(ForkFamilyDecodeErrorV1::PtraceEventMismatch);
    }
    Ok(observation)
}

fn require_no_clone3_capture_v1(
    capture: Clone3ArgsCaptureV1<'_>,
) -> Result<(), ForkFamilyDecodeErrorV1> {
    match capture {
        Clone3ArgsCaptureV1::NotApplicable => Ok(()),
        Clone3ArgsCaptureV1::Unavailable | Clone3ArgsCaptureV1::Exact { .. } => {
            Err(ForkFamilyDecodeErrorV1::UnexpectedClone3Capture)
        }
    }
}

fn decode_legacy_clone_v1(
    arguments: &[u64; 6],
) -> Result<ForkFamilyBirthObservationV1, ForkFamilyDecodeErrorV1> {
    let raw_flags = arguments[0];
    if raw_flags >> 32 != 0 {
        return Err(ForkFamilyDecodeErrorV1::LegacyCloneHighFlagBitsNonzero);
    }
    let exit_signal = raw_flags & LINUX_CSIGNAL_MASK_V1;
    if exit_signal > LINUX_X86_64_MAX_SIGNAL_V1 {
        return Err(ForkFamilyDecodeErrorV1::ExitSignalOutOfRange);
    }
    let flags = raw_flags & !LINUX_CSIGNAL_MASK_V1;
    validate_common_flags_v1(flags, exit_signal, false)?;
    validate_legacy_clone_fields_v1(flags, arguments)?;
    Ok(classify_clone_birth_v1(flags, exit_signal))
}

fn decode_clone3_v1(
    arguments: &[u64; 6],
    capture: Clone3ArgsCaptureV1<'_>,
) -> Result<ForkFamilyBirthObservationV1, ForkFamilyDecodeErrorV1> {
    if arguments[0] == 0 {
        return Err(ForkFamilyDecodeErrorV1::Clone3NullArgsPointer);
    }
    let declared_size = arguments[1];
    if declared_size < CLONE3_ARGS_SIZE_VER0_V1 as u64 {
        return Err(ForkFamilyDecodeErrorV1::Clone3DeclaredSizeTooSmall);
    }
    if declared_size > CLONE3_ARGS_SIZE_VER2_V1 as u64 {
        return Err(ForkFamilyDecodeErrorV1::Clone3DeclaredSizeTooLarge);
    }
    if !matches!(
        declared_size as usize,
        CLONE3_ARGS_SIZE_VER0_V1 | CLONE3_ARGS_SIZE_VER1_V1 | CLONE3_ARGS_SIZE_VER2_V1
    ) {
        return Err(ForkFamilyDecodeErrorV1::Clone3DeclaredSizeAmbiguous);
    }

    let (copied_byte_count, buffer) = match capture {
        Clone3ArgsCaptureV1::Exact {
            copied_byte_count,
            buffer,
        } => (copied_byte_count, buffer),
        Clone3ArgsCaptureV1::NotApplicable | Clone3ArgsCaptureV1::Unavailable => {
            return Err(ForkFamilyDecodeErrorV1::Clone3ArgsUnavailable);
        }
    };
    if copied_byte_count != declared_size as usize {
        return Err(ForkFamilyDecodeErrorV1::Clone3CopiedByteCountMismatch);
    }
    if buffer[copied_byte_count..].iter().any(|byte| *byte != 0) {
        return Err(ForkFamilyDecodeErrorV1::Clone3UncopiedTailNonzero);
    }

    let fields = Clone3FieldsV1::decode(buffer);
    if fields.exit_signal > LINUX_X86_64_MAX_SIGNAL_V1 {
        return Err(ForkFamilyDecodeErrorV1::ExitSignalOutOfRange);
    }
    if fields.flags & (LINUX_CSIGNAL_MASK_V1 & !LINUX_CLONE_NEWTIME_V1) != 0 {
        return Err(ForkFamilyDecodeErrorV1::Clone3SignalBitsInFlags);
    }
    validate_common_flags_v1(fields.flags, fields.exit_signal, true)?;
    validate_clone3_fields_v1(&fields, declared_size as usize)?;
    Ok(classify_clone_birth_v1(fields.flags, fields.exit_signal))
}

struct Clone3FieldsV1 {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

impl Clone3FieldsV1 {
    fn decode(buffer: &[u8; CLONE3_ARGS_BUFFER_BYTES_V1]) -> Self {
        Self {
            flags: read_u64_le_v1(buffer, CLONE3_FLAGS_OFFSET_V1),
            pidfd: read_u64_le_v1(buffer, CLONE3_PIDFD_OFFSET_V1),
            child_tid: read_u64_le_v1(buffer, CLONE3_CHILD_TID_OFFSET_V1),
            parent_tid: read_u64_le_v1(buffer, CLONE3_PARENT_TID_OFFSET_V1),
            exit_signal: read_u64_le_v1(buffer, CLONE3_EXIT_SIGNAL_OFFSET_V1),
            stack: read_u64_le_v1(buffer, CLONE3_STACK_OFFSET_V1),
            stack_size: read_u64_le_v1(buffer, CLONE3_STACK_SIZE_OFFSET_V1),
            tls: read_u64_le_v1(buffer, CLONE3_TLS_OFFSET_V1),
            set_tid: read_u64_le_v1(buffer, CLONE3_SET_TID_OFFSET_V1),
            set_tid_size: read_u64_le_v1(buffer, CLONE3_SET_TID_SIZE_OFFSET_V1),
            cgroup: read_u64_le_v1(buffer, CLONE3_CGROUP_OFFSET_V1),
        }
    }
}

fn validate_common_flags_v1(
    flags: u64,
    exit_signal: u64,
    clone3: bool,
) -> Result<(), ForkFamilyDecodeErrorV1> {
    if flags & LINUX_CLONE_UNTRACED_V1 != 0 {
        return Err(ForkFamilyDecodeErrorV1::TraceSuppressionFlag);
    }
    if flags & LINUX_CLONE_DETACHED_V1 != 0 {
        return Err(ForkFamilyDecodeErrorV1::ReservedCloneFlag);
    }
    let admitted_flags = if clone3 {
        CLONE3_ADMITTED_FLAGS_V1
    } else {
        LEGACY_CLONE_ADMITTED_FLAGS_V1
    };
    if flags & !admitted_flags != 0 {
        return Err(ForkFamilyDecodeErrorV1::UnsupportedCloneFlags);
    }

    if flags & LINUX_CLONE_SIGHAND_V1 != 0 && flags & LINUX_CLONE_VM_V1 == 0
        || flags & LINUX_CLONE_THREAD_V1 != 0 && flags & LINUX_CLONE_SIGHAND_V1 == 0
        || flags & LINUX_CLONE_THREAD_V1 != 0
            && flags & (LINUX_CLONE_NEWUSER_V1 | LINUX_CLONE_NEWPID_V1) != 0
        || flags & LINUX_CLONE_NEWNS_V1 != 0 && flags & LINUX_CLONE_FS_V1 != 0
        || flags & LINUX_CLONE_NEWUSER_V1 != 0 && flags & LINUX_CLONE_FS_V1 != 0
        || flags & LINUX_CLONE_CLEAR_SIGHAND_V1 != 0 && flags & LINUX_CLONE_SIGHAND_V1 != 0
    {
        return Err(ForkFamilyDecodeErrorV1::InvalidCloneFlagCombination);
    }
    if flags & LINUX_CLONE_THREAD_V1 != 0 && exit_signal != 0 {
        return Err(ForkFamilyDecodeErrorV1::SharedThreadGroupWithExitSignal);
    }
    if flags & (LINUX_CLONE_THREAD_V1 | LINUX_CLONE_VFORK_V1)
        == (LINUX_CLONE_THREAD_V1 | LINUX_CLONE_VFORK_V1)
    {
        // Linux permits this combination, but the current lifecycle contract
        // intentionally admits shared groups only for a `Clone` birth. The
        // kernel selects `PTRACE_EVENT_VFORK`, so V1 must fail closed.
        return Err(ForkFamilyDecodeErrorV1::VforkSharedThreadGroupUnsupported);
    }
    if clone3 && flags & LINUX_CLONE_PARENT_V1 != 0 && exit_signal != 0 {
        return Err(ForkFamilyDecodeErrorV1::InvalidCloneFlagCombination);
    }
    Ok(())
}

fn validate_legacy_clone_fields_v1(
    flags: u64,
    arguments: &[u64; 6],
) -> Result<(), ForkFamilyDecodeErrorV1> {
    if flags & (LINUX_CLONE_PIDFD_V1 | LINUX_CLONE_PARENT_SETTID_V1)
        == (LINUX_CLONE_PIDFD_V1 | LINUX_CLONE_PARENT_SETTID_V1)
    {
        return Err(ForkFamilyDecodeErrorV1::InvalidCloneFlagCombination);
    }

    let parent_word_is_active = flags & (LINUX_CLONE_PIDFD_V1 | LINUX_CLONE_PARENT_SETTID_V1) != 0;
    let child_word_is_active =
        flags & (LINUX_CLONE_CHILD_SETTID_V1 | LINUX_CLONE_CHILD_CLEARTID_V1) != 0;
    let tls_word_is_active = flags & LINUX_CLONE_SETTLS_V1 != 0;
    if !parent_word_is_active && arguments[2] != 0
        || !child_word_is_active && arguments[3] != 0
        || !tls_word_is_active && arguments[4] != 0
    {
        return Err(ForkFamilyDecodeErrorV1::LegacyCloneInactiveFieldNonzero);
    }
    Ok(())
}

fn validate_clone3_fields_v1(
    fields: &Clone3FieldsV1,
    declared_size: usize,
) -> Result<(), ForkFamilyDecodeErrorV1> {
    if fields.flags & LINUX_CLONE_INTO_CGROUP_V1 != 0 && declared_size < CLONE3_ARGS_SIZE_VER2_V1 {
        return Err(ForkFamilyDecodeErrorV1::Clone3FlagRequiresNewerVersion);
    }
    if fields.flags & LINUX_CLONE_INTO_CGROUP_V1 != 0 && fields.cgroup > i32::MAX as u64 {
        return Err(ForkFamilyDecodeErrorV1::InvalidCloneFlagCombination);
    }

    let pidfd_is_active = fields.flags & LINUX_CLONE_PIDFD_V1 != 0;
    let child_tid_is_active =
        fields.flags & (LINUX_CLONE_CHILD_SETTID_V1 | LINUX_CLONE_CHILD_CLEARTID_V1) != 0;
    let parent_tid_is_active = fields.flags & LINUX_CLONE_PARENT_SETTID_V1 != 0;
    let tls_is_active = fields.flags & LINUX_CLONE_SETTLS_V1 != 0;
    let cgroup_is_active = fields.flags & LINUX_CLONE_INTO_CGROUP_V1 != 0;

    if !pidfd_is_active && fields.pidfd != 0
        || !child_tid_is_active && fields.child_tid != 0
        || !parent_tid_is_active && fields.parent_tid != 0
        || !tls_is_active && fields.tls != 0
        || !cgroup_is_active && fields.cgroup != 0
    {
        return Err(ForkFamilyDecodeErrorV1::Clone3InactiveFieldNonzero);
    }
    if pidfd_is_active && fields.pidfd == 0
        || child_tid_is_active && fields.child_tid == 0
        || parent_tid_is_active && fields.parent_tid == 0
        || tls_is_active && fields.tls == 0
    {
        return Err(ForkFamilyDecodeErrorV1::Clone3ActiveFieldZero);
    }
    if fields.set_tid != 0 || fields.set_tid_size != 0 {
        return Err(ForkFamilyDecodeErrorV1::Clone3SetTidExternalReadUnsupported);
    }
    if (fields.stack == 0) != (fields.stack_size == 0) {
        return Err(ForkFamilyDecodeErrorV1::Clone3StackShapeInvalid);
    }
    if pidfd_is_active && parent_tid_is_active && fields.pidfd == fields.parent_tid {
        return Err(ForkFamilyDecodeErrorV1::Clone3PidfdParentTidAlias);
    }
    Ok(())
}

fn classify_clone_birth_v1(flags: u64, exit_signal: u64) -> ForkFamilyBirthObservationV1 {
    let kind = if flags & LINUX_CLONE_VFORK_V1 != 0 {
        TracerTaskChildBirthKindV1::Vfork
    } else if exit_signal != LINUX_SIGCHLD_V1 {
        TracerTaskChildBirthKindV1::Clone
    } else {
        TracerTaskChildBirthKindV1::Fork
    };
    let relation = if flags & LINUX_CLONE_THREAD_V1 != 0 {
        TracerTaskGroupRelationV1::SharesParentThreadGroup
    } else {
        TracerTaskGroupRelationV1::NewThreadGroup
    };
    ForkFamilyBirthObservationV1 { kind, relation }
}

const fn ptrace_event_matches_birth_kind_v1(
    event: LinuxPtraceEventV1,
    kind: TracerTaskChildBirthKindV1,
) -> bool {
    matches!(
        (event, kind),
        (LinuxPtraceEventV1::Fork, TracerTaskChildBirthKindV1::Fork)
            | (LinuxPtraceEventV1::Vfork, TracerTaskChildBirthKindV1::Vfork)
            | (LinuxPtraceEventV1::Clone, TracerTaskChildBirthKindV1::Clone)
    )
}

fn read_u64_le_v1(buffer: &[u8; CLONE3_ARGS_BUFFER_BYTES_V1], offset: usize) -> u64 {
    let mut bytes = [0_u8; size_of::<u64>()];
    bytes.copy_from_slice(&buffer[offset..offset + size_of::<u64>()]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_clone3_capture_v1(
        copied_byte_count: usize,
        buffer: &[u8; CLONE3_ARGS_BUFFER_BYTES_V1],
    ) -> Clone3ArgsCaptureV1<'_> {
        Clone3ArgsCaptureV1::Exact {
            copied_byte_count,
            buffer,
        }
    }

    fn clone3_arguments_v1(declared_size: u64) -> [u64; 6] {
        [0x1000, declared_size, 0, 0, 0, 0]
    }

    fn write_u64_le_v1(buffer: &mut [u8; CLONE3_ARGS_BUFFER_BYTES_V1], offset: usize, value: u64) {
        buffer[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
    }

    fn clone3_buffer_v1(flags: u64, exit_signal: u64) -> [u8; CLONE3_ARGS_BUFFER_BYTES_V1] {
        let mut buffer = [0_u8; CLONE3_ARGS_BUFFER_BYTES_V1];
        write_u64_le_v1(&mut buffer, CLONE3_FLAGS_OFFSET_V1, flags);
        write_u64_le_v1(&mut buffer, CLONE3_EXIT_SIGNAL_OFFSET_V1, exit_signal);
        buffer
    }

    fn legacy_clone_arguments_v1(flags: u64) -> [u64; 6] {
        [flags, 0, 0, 0, 0, 0]
    }

    fn decode_legacy_v1(
        flags: u64,
        event: LinuxPtraceEventV1,
    ) -> Result<ForkFamilyBirthObservationV1, ForkFamilyDecodeErrorV1> {
        decode_fork_family_entry_x86_64_v1(
            TRACER_TASK_CLONE_NR_X86_64_V1,
            &legacy_clone_arguments_v1(flags),
            Clone3ArgsCaptureV1::NotApplicable,
            event,
        )
    }

    fn decode_clone3_buffer_v1(
        declared_size: usize,
        buffer: &[u8; CLONE3_ARGS_BUFFER_BYTES_V1],
        event: LinuxPtraceEventV1,
    ) -> Result<ForkFamilyBirthObservationV1, ForkFamilyDecodeErrorV1> {
        decode_fork_family_entry_x86_64_v1(
            TRACER_TASK_CLONE3_NR_X86_64_V1,
            &clone3_arguments_v1(declared_size as u64),
            exact_clone3_capture_v1(declared_size, buffer),
            event,
        )
    }

    #[test]
    fn syscall_numbers_are_the_frozen_native_x86_64_values() {
        assert_eq!(TRACER_TASK_CLONE_NR_X86_64_V1, 56);
        assert_eq!(TRACER_TASK_FORK_NR_X86_64_V1, 57);
        assert_eq!(TRACER_TASK_VFORK_NR_X86_64_V1, 58);
        assert_eq!(TRACER_TASK_CLONE3_NR_X86_64_V1, 435);
    }

    #[test]
    fn fork_and_vfork_have_exact_event_matrices_and_new_groups() {
        let arguments = [u64::MAX; 6];
        for (syscall_number, expected_kind, expected_event) in [
            (
                TRACER_TASK_FORK_NR_X86_64_V1,
                TracerTaskChildBirthKindV1::Fork,
                LinuxPtraceEventV1::Fork,
            ),
            (
                TRACER_TASK_VFORK_NR_X86_64_V1,
                TracerTaskChildBirthKindV1::Vfork,
                LinuxPtraceEventV1::Vfork,
            ),
        ] {
            for event in [
                LinuxPtraceEventV1::Fork,
                LinuxPtraceEventV1::Vfork,
                LinuxPtraceEventV1::Clone,
                LinuxPtraceEventV1::Exec,
                LinuxPtraceEventV1::Exit,
                LinuxPtraceEventV1::Seccomp,
            ] {
                let result = decode_fork_family_entry_x86_64_v1(
                    syscall_number,
                    &arguments,
                    Clone3ArgsCaptureV1::NotApplicable,
                    event,
                );
                if event == expected_event {
                    assert_eq!(
                        result,
                        Ok(ForkFamilyBirthObservationV1 {
                            kind: expected_kind,
                            relation: TracerTaskGroupRelationV1::NewThreadGroup,
                        })
                    );
                } else {
                    assert_eq!(result, Err(ForkFamilyDecodeErrorV1::PtraceEventMismatch));
                }
            }
        }
    }

    #[test]
    fn clone_event_kind_and_thread_group_relation_are_independent() {
        let cases = [
            (
                LINUX_SIGCHLD_V1,
                LinuxPtraceEventV1::Fork,
                TracerTaskChildBirthKindV1::Fork,
                TracerTaskGroupRelationV1::NewThreadGroup,
            ),
            (
                0,
                LinuxPtraceEventV1::Clone,
                TracerTaskChildBirthKindV1::Clone,
                TracerTaskGroupRelationV1::NewThreadGroup,
            ),
            (
                10,
                LinuxPtraceEventV1::Clone,
                TracerTaskChildBirthKindV1::Clone,
                TracerTaskGroupRelationV1::NewThreadGroup,
            ),
            (
                LINUX_CLONE_THREAD_V1 | LINUX_CLONE_SIGHAND_V1 | LINUX_CLONE_VM_V1,
                LinuxPtraceEventV1::Clone,
                TracerTaskChildBirthKindV1::Clone,
                TracerTaskGroupRelationV1::SharesParentThreadGroup,
            ),
        ];
        for (flags, event, kind, relation) in cases {
            assert_eq!(
                decode_legacy_v1(flags, event),
                Ok(ForkFamilyBirthObservationV1 { kind, relation })
            );
        }
    }

    #[test]
    fn clone_vfork_overrides_exit_signal_for_ptrace_event_selection() {
        for exit_signal in [0, LINUX_SIGCHLD_V1, 10] {
            assert_eq!(
                decode_legacy_v1(
                    LINUX_CLONE_VFORK_V1 | LINUX_CLONE_VM_V1 | exit_signal,
                    LinuxPtraceEventV1::Vfork,
                ),
                Ok(ForkFamilyBirthObservationV1 {
                    kind: TracerTaskChildBirthKindV1::Vfork,
                    relation: TracerTaskGroupRelationV1::NewThreadGroup,
                })
            );
        }
    }

    #[test]
    fn every_clone_birth_kind_rejects_every_wrong_ptrace_event() {
        let cases = [
            (LINUX_SIGCHLD_V1, LinuxPtraceEventV1::Fork),
            (LINUX_CLONE_VFORK_V1, LinuxPtraceEventV1::Vfork),
            (0, LinuxPtraceEventV1::Clone),
        ];
        let events = [
            LinuxPtraceEventV1::Fork,
            LinuxPtraceEventV1::Vfork,
            LinuxPtraceEventV1::Clone,
            LinuxPtraceEventV1::Exec,
            LinuxPtraceEventV1::Exit,
            LinuxPtraceEventV1::Seccomp,
        ];
        for (flags, expected_event) in cases {
            for event in events {
                let result = decode_legacy_v1(flags, event);
                if event == expected_event {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(result, Err(ForkFamilyDecodeErrorV1::PtraceEventMismatch));
                }
            }
        }
    }

    #[test]
    fn clone3_admits_only_exact_published_struct_sizes() {
        for size in [
            CLONE3_ARGS_SIZE_VER0_V1,
            CLONE3_ARGS_SIZE_VER1_V1,
            CLONE3_ARGS_SIZE_VER2_V1,
        ] {
            let buffer = clone3_buffer_v1(0, LINUX_SIGCHLD_V1);
            assert_eq!(
                decode_clone3_buffer_v1(size, &buffer, LinuxPtraceEventV1::Fork),
                Ok(ForkFamilyBirthObservationV1 {
                    kind: TracerTaskChildBirthKindV1::Fork,
                    relation: TracerTaskGroupRelationV1::NewThreadGroup,
                })
            );
        }

        for size in [0, 1, 63] {
            let arguments = clone3_arguments_v1(size);
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    TRACER_TASK_CLONE3_NR_X86_64_V1,
                    &arguments,
                    Clone3ArgsCaptureV1::Unavailable,
                    LinuxPtraceEventV1::Fork,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3DeclaredSizeTooSmall)
            );
        }
        for size in [65, 79, 81, 87] {
            let arguments = clone3_arguments_v1(size);
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    TRACER_TASK_CLONE3_NR_X86_64_V1,
                    &arguments,
                    Clone3ArgsCaptureV1::Unavailable,
                    LinuxPtraceEventV1::Fork,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3DeclaredSizeAmbiguous)
            );
        }
        for size in [89, 4096, u64::MAX] {
            let arguments = clone3_arguments_v1(size);
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    TRACER_TASK_CLONE3_NR_X86_64_V1,
                    &arguments,
                    Clone3ArgsCaptureV1::Unavailable,
                    LinuxPtraceEventV1::Fork,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3DeclaredSizeTooLarge)
            );
        }
    }

    #[test]
    fn clone3_requires_nonnull_pointer_and_an_exact_available_copy() {
        let buffer = clone3_buffer_v1(0, LINUX_SIGCHLD_V1);
        let mut arguments = clone3_arguments_v1(CLONE3_ARGS_SIZE_VER2_V1 as u64);
        arguments[0] = 0;
        assert_eq!(
            decode_fork_family_entry_x86_64_v1(
                TRACER_TASK_CLONE3_NR_X86_64_V1,
                &arguments,
                exact_clone3_capture_v1(CLONE3_ARGS_SIZE_VER2_V1, &buffer),
                LinuxPtraceEventV1::Fork,
            ),
            Err(ForkFamilyDecodeErrorV1::Clone3NullArgsPointer)
        );

        let arguments = clone3_arguments_v1(CLONE3_ARGS_SIZE_VER2_V1 as u64);
        for capture in [
            Clone3ArgsCaptureV1::NotApplicable,
            Clone3ArgsCaptureV1::Unavailable,
        ] {
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    TRACER_TASK_CLONE3_NR_X86_64_V1,
                    &arguments,
                    capture,
                    LinuxPtraceEventV1::Fork,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3ArgsUnavailable)
            );
        }

        for copied_byte_count in [0, 63, 64, 80, 87] {
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    TRACER_TASK_CLONE3_NR_X86_64_V1,
                    &arguments,
                    exact_clone3_capture_v1(copied_byte_count, &buffer),
                    LinuxPtraceEventV1::Fork,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3CopiedByteCountMismatch)
            );
        }
    }

    #[test]
    fn every_uncopied_clone3_tail_byte_must_be_zero() {
        for declared_size in [CLONE3_ARGS_SIZE_VER0_V1, CLONE3_ARGS_SIZE_VER1_V1] {
            for index in declared_size..CLONE3_ARGS_BUFFER_BYTES_V1 {
                let mut buffer = clone3_buffer_v1(0, LINUX_SIGCHLD_V1);
                buffer[index] = 1;
                assert_eq!(
                    decode_clone3_buffer_v1(declared_size, &buffer, LinuxPtraceEventV1::Fork,),
                    Err(ForkFamilyDecodeErrorV1::Clone3UncopiedTailNonzero),
                    "tail byte {index} for declared size {declared_size} was admitted"
                );
            }
        }
    }

    #[test]
    fn clone3_exit_signal_range_and_flag_signal_space_are_distinct() {
        for signal in 0..=LINUX_X86_64_MAX_SIGNAL_V1 {
            let buffer = clone3_buffer_v1(0, signal);
            let expected_event = if signal == LINUX_SIGCHLD_V1 {
                LinuxPtraceEventV1::Fork
            } else {
                LinuxPtraceEventV1::Clone
            };
            assert!(
                decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER2_V1, &buffer, expected_event,).is_ok()
            );
        }
        for signal in [65, 255, 256, u64::MAX] {
            let buffer = clone3_buffer_v1(0, signal);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &buffer,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::ExitSignalOutOfRange)
            );
        }

        for bit in 0..7 {
            let buffer = clone3_buffer_v1(1_u64 << bit, 0);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &buffer,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3SignalBitsInFlags)
            );
        }
        let buffer = clone3_buffer_v1(LINUX_CLONE_NEWTIME_V1, 0);
        assert!(
            decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER2_V1, &buffer, LinuxPtraceEventV1::Clone,)
                .is_ok()
        );
    }

    #[test]
    fn legacy_clone_rejects_ignored_high_bits_and_invalid_signal_byte() {
        assert_eq!(
            decode_legacy_v1(1_u64 << 32, LinuxPtraceEventV1::Clone),
            Err(ForkFamilyDecodeErrorV1::LegacyCloneHighFlagBitsNonzero)
        );
        for signal in [65, 127, 128, 255] {
            assert_eq!(
                decode_legacy_v1(signal, LinuxPtraceEventV1::Clone),
                Err(ForkFamilyDecodeErrorV1::ExitSignalOutOfRange)
            );
        }
    }

    #[test]
    fn trace_control_reserved_and_future_flags_fail_closed() {
        for (flag, error) in [
            (
                LINUX_CLONE_UNTRACED_V1,
                ForkFamilyDecodeErrorV1::TraceSuppressionFlag,
            ),
            (
                LINUX_CLONE_DETACHED_V1,
                ForkFamilyDecodeErrorV1::ReservedCloneFlag,
            ),
            (0x0000_2000, ForkFamilyDecodeErrorV1::UnsupportedCloneFlags),
            (1_u64 << 34, ForkFamilyDecodeErrorV1::UnsupportedCloneFlags),
            (1_u64 << 63, ForkFamilyDecodeErrorV1::UnsupportedCloneFlags),
        ] {
            let buffer = clone3_buffer_v1(flag, 0);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &buffer,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(error)
            );
        }
    }

    #[test]
    fn structural_flag_combinations_fail_closed() {
        let invalid = [
            LINUX_CLONE_SIGHAND_V1,
            LINUX_CLONE_THREAD_V1 | LINUX_CLONE_VM_V1,
            LINUX_CLONE_THREAD_V1
                | LINUX_CLONE_SIGHAND_V1
                | LINUX_CLONE_VM_V1
                | LINUX_CLONE_NEWUSER_V1,
            LINUX_CLONE_THREAD_V1
                | LINUX_CLONE_SIGHAND_V1
                | LINUX_CLONE_VM_V1
                | LINUX_CLONE_NEWPID_V1,
            LINUX_CLONE_NEWNS_V1 | LINUX_CLONE_FS_V1,
            LINUX_CLONE_NEWUSER_V1 | LINUX_CLONE_FS_V1,
            LINUX_CLONE_CLEAR_SIGHAND_V1 | LINUX_CLONE_SIGHAND_V1 | LINUX_CLONE_VM_V1,
        ];
        for flags in invalid {
            let buffer = clone3_buffer_v1(flags, 0);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &buffer,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::InvalidCloneFlagCombination)
            );
        }
    }

    #[test]
    fn shared_group_requires_zero_exit_signal_and_non_vfork_birth() {
        let thread_flags = LINUX_CLONE_THREAD_V1 | LINUX_CLONE_SIGHAND_V1 | LINUX_CLONE_VM_V1;
        assert_eq!(
            decode_legacy_v1(thread_flags | LINUX_SIGCHLD_V1, LinuxPtraceEventV1::Fork),
            Err(ForkFamilyDecodeErrorV1::SharedThreadGroupWithExitSignal)
        );
        assert_eq!(
            decode_legacy_v1(
                thread_flags | LINUX_CLONE_VFORK_V1,
                LinuxPtraceEventV1::Vfork,
            ),
            Err(ForkFamilyDecodeErrorV1::VforkSharedThreadGroupUnsupported)
        );
    }

    #[test]
    fn legacy_clone_inactive_words_and_pidfd_alias_shape_fail_closed() {
        for argument_index in [2, 3, 4] {
            let mut arguments = legacy_clone_arguments_v1(0);
            arguments[argument_index] = 1;
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    TRACER_TASK_CLONE_NR_X86_64_V1,
                    &arguments,
                    Clone3ArgsCaptureV1::NotApplicable,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::LegacyCloneInactiveFieldNonzero)
            );
        }
        assert_eq!(
            decode_legacy_v1(
                LINUX_CLONE_PIDFD_V1 | LINUX_CLONE_PARENT_SETTID_V1,
                LinuxPtraceEventV1::Clone,
            ),
            Err(ForkFamilyDecodeErrorV1::InvalidCloneFlagCombination)
        );
    }

    #[test]
    fn clone3_inactive_and_active_pointer_fields_are_exact() {
        let fields = [
            (CLONE3_PIDFD_OFFSET_V1, LINUX_CLONE_PIDFD_V1),
            (CLONE3_CHILD_TID_OFFSET_V1, LINUX_CLONE_CHILD_SETTID_V1),
            (CLONE3_PARENT_TID_OFFSET_V1, LINUX_CLONE_PARENT_SETTID_V1),
            (CLONE3_TLS_OFFSET_V1, LINUX_CLONE_SETTLS_V1),
        ];
        for (offset, flag) in fields {
            let mut inactive = clone3_buffer_v1(0, 0);
            write_u64_le_v1(&mut inactive, offset, 0x1000);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &inactive,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3InactiveFieldNonzero)
            );

            let active_zero = clone3_buffer_v1(flag, 0);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &active_zero,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3ActiveFieldZero)
            );

            let mut active = clone3_buffer_v1(flag, 0);
            write_u64_le_v1(&mut active, offset, 0x1000);
            assert!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &active,
                    LinuxPtraceEventV1::Clone,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn clone3_set_tid_is_rejected_without_an_external_array_read() {
        for (set_tid, set_tid_size) in [(1, 0), (0, 1), (1, 1), (u64::MAX, u64::MAX)] {
            let mut buffer = clone3_buffer_v1(0, 0);
            write_u64_le_v1(&mut buffer, CLONE3_SET_TID_OFFSET_V1, set_tid);
            write_u64_le_v1(&mut buffer, CLONE3_SET_TID_SIZE_OFFSET_V1, set_tid_size);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER1_V1,
                    &buffer,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3SetTidExternalReadUnsupported)
            );
        }
    }

    #[test]
    fn clone3_stack_and_cgroup_shapes_are_bounded() {
        for (stack, stack_size) in [(1, 0), (0, 1)] {
            let mut buffer = clone3_buffer_v1(0, 0);
            write_u64_le_v1(&mut buffer, CLONE3_STACK_OFFSET_V1, stack);
            write_u64_le_v1(&mut buffer, CLONE3_STACK_SIZE_OFFSET_V1, stack_size);
            assert_eq!(
                decode_clone3_buffer_v1(
                    CLONE3_ARGS_SIZE_VER2_V1,
                    &buffer,
                    LinuxPtraceEventV1::Clone,
                ),
                Err(ForkFamilyDecodeErrorV1::Clone3StackShapeInvalid)
            );
        }

        let buffer = clone3_buffer_v1(LINUX_CLONE_INTO_CGROUP_V1, 0);
        assert_eq!(
            decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER1_V1, &buffer, LinuxPtraceEventV1::Clone,),
            Err(ForkFamilyDecodeErrorV1::Clone3FlagRequiresNewerVersion)
        );

        let mut buffer = clone3_buffer_v1(LINUX_CLONE_INTO_CGROUP_V1, 0);
        write_u64_le_v1(&mut buffer, CLONE3_CGROUP_OFFSET_V1, i32::MAX as u64 + 1);
        assert_eq!(
            decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER2_V1, &buffer, LinuxPtraceEventV1::Clone,),
            Err(ForkFamilyDecodeErrorV1::InvalidCloneFlagCombination)
        );
    }

    #[test]
    fn clone3_pidfd_and_parent_tid_must_not_alias() {
        let flags = LINUX_CLONE_PIDFD_V1 | LINUX_CLONE_PARENT_SETTID_V1;
        let mut buffer = clone3_buffer_v1(flags, 0);
        write_u64_le_v1(&mut buffer, CLONE3_PIDFD_OFFSET_V1, 0x1000);
        write_u64_le_v1(&mut buffer, CLONE3_PARENT_TID_OFFSET_V1, 0x1000);
        assert_eq!(
            decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER2_V1, &buffer, LinuxPtraceEventV1::Clone,),
            Err(ForkFamilyDecodeErrorV1::Clone3PidfdParentTidAlias)
        );
        write_u64_le_v1(&mut buffer, CLONE3_PARENT_TID_OFFSET_V1, 0x2000);
        assert!(
            decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER2_V1, &buffer, LinuxPtraceEventV1::Clone,)
                .is_ok()
        );
    }

    #[test]
    fn clone3_version_gated_fields_cannot_be_smuggled_in_the_zero_tail() {
        let mut buffer = clone3_buffer_v1(0, 0);
        write_u64_le_v1(&mut buffer, CLONE3_SET_TID_OFFSET_V1, 1);
        assert_eq!(
            decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER0_V1, &buffer, LinuxPtraceEventV1::Clone,),
            Err(ForkFamilyDecodeErrorV1::Clone3UncopiedTailNonzero)
        );
        let mut buffer = clone3_buffer_v1(0, 0);
        write_u64_le_v1(&mut buffer, CLONE3_CGROUP_OFFSET_V1, 1);
        assert_eq!(
            decode_clone3_buffer_v1(CLONE3_ARGS_SIZE_VER1_V1, &buffer, LinuxPtraceEventV1::Clone,),
            Err(ForkFamilyDecodeErrorV1::Clone3UncopiedTailNonzero)
        );
    }

    #[test]
    fn unsupported_syscalls_and_capture_cross_wiring_fail_closed() {
        for syscall_number in [0, 55, 59, u32::MAX] {
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    syscall_number,
                    &[0; 6],
                    Clone3ArgsCaptureV1::NotApplicable,
                    LinuxPtraceEventV1::Fork,
                ),
                Err(ForkFamilyDecodeErrorV1::UnsupportedSyscall)
            );
        }
        let buffer = [0_u8; CLONE3_ARGS_BUFFER_BYTES_V1];
        for syscall_number in [
            TRACER_TASK_FORK_NR_X86_64_V1,
            TRACER_TASK_VFORK_NR_X86_64_V1,
            TRACER_TASK_CLONE_NR_X86_64_V1,
        ] {
            assert_eq!(
                decode_fork_family_entry_x86_64_v1(
                    syscall_number,
                    &[0; 6],
                    exact_clone3_capture_v1(CLONE3_ARGS_SIZE_VER2_V1, &buffer),
                    LinuxPtraceEventV1::Fork,
                ),
                Err(ForkFamilyDecodeErrorV1::UnexpectedClone3Capture)
            );
        }
    }

    #[test]
    fn rejection_precedence_is_stable() {
        let buffer = [0xff_u8; CLONE3_ARGS_BUFFER_BYTES_V1];
        assert_eq!(
            decode_fork_family_entry_x86_64_v1(
                TRACER_TASK_CLONE3_NR_X86_64_V1,
                &[0, 1, 0, 0, 0, 0],
                exact_clone3_capture_v1(1, &buffer),
                LinuxPtraceEventV1::Exec,
            ),
            Err(ForkFamilyDecodeErrorV1::Clone3NullArgsPointer)
        );
        assert_eq!(
            decode_fork_family_entry_x86_64_v1(
                TRACER_TASK_CLONE3_NR_X86_64_V1,
                &[1, CLONE3_ARGS_SIZE_VER0_V1 as u64, 0, 0, 0, 0],
                Clone3ArgsCaptureV1::Unavailable,
                LinuxPtraceEventV1::Exec,
            ),
            Err(ForkFamilyDecodeErrorV1::Clone3ArgsUnavailable)
        );
    }

    #[test]
    fn summary_is_data_free_and_grants_no_authority() {
        let summary = &FORK_FAMILY_DECODER_SUMMARY_V1;
        assert_eq!(size_of::<ForkFamilyDecoderSummaryV1>(), 0);
        assert_eq!(summary.decoder_id(), "linux-x86_64-fork-family-entry-v1");
        assert_eq!(summary.clone3_buffer_byte_count(), 88);
        assert!(summary.allocation_free());
        assert!(!summary.performs_process_memory_reads());
        assert!(!summary.output_contains_raw_pointer());
        assert!(!summary.tracing_authority());
        assert!(!summary.observation_completeness_authority());
        assert!(!summary.effect_ir_authority());
        assert!(!summary.execution_authority());
        assert!(!summary.reuse_authority());
    }
}
