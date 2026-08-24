//! One fail-closed resource contract for Linux snapshot construction.
//!
//! This is the connector-level snapshot resource authority.
//! `snapshot_connector` performs one fallible, pre-filesystem static
//! projection into the current leaf policies. A successful static projection
//! proves representability only; it grants no execution, allocation,
//! descriptor, or operation authority. Production execution must retain and
//! charge this same mutable resource authority alongside those policies. Leaf
//! constructors remain independently available for tests and defense in
//! depth. Projection never applies defaults or resets a whole-snapshot work
//! budget.

use std::cell::Cell;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};

const PUBLICATION_CONTAINER_LEVELS: u16 = 2;
const HARD_MAX_DEPTH: u16 = 256;
const HARD_MAX_ENTRIES: u32 = 1024 * 1024;
const HARD_MAX_NAME_BYTES: u16 = 255;
const HARD_MAX_RELATIVE_PATH_BYTES: u32 = 1024 * 1024;
const HARD_MAX_SYMLINK_TARGET_BYTES: u32 = 1024 * 1024;
const HARD_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_MAX_TOTAL_FILE_BYTES: u64 = HARD_MAX_FILE_BYTES * HARD_MAX_ENTRIES as u64;
const HARD_MAX_DATA_EXTENTS_PER_FILE: u32 = 1024 * 1024;
const HARD_MAX_TOTAL_DATA_EXTENTS: u64 =
    HARD_MAX_DATA_EXTENTS_PER_FILE as u64 * HARD_MAX_ENTRIES as u64;
// A nonempty Linux xattr name plus its terminating NUL consumes at least two
// bytes in the 64-KiB list returned by listxattr.
const HARD_MAX_XATTRS_PER_ENTRY: u16 = (64 * 1024 / 2) as u16;
const HARD_MAX_TOTAL_XATTRS: u64 = HARD_MAX_XATTRS_PER_ENTRY as u64 * HARD_MAX_ENTRIES as u64;
const HARD_MAX_XATTR_NAME_BYTES: u16 = 255;
const HARD_MAX_XATTR_VALUE_BYTES: u32 = 64 * 1024;
const HARD_MAX_XATTR_LIST_BYTES: u32 = 64 * 1024;
const HARD_MAX_TOTAL_XATTR_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
const HARD_MAX_RETAINED_VIEW_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_TRANSIENT_HEAP_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_FOUR_VIEW_HEAP_BYTES: u64 =
    2 * HARD_MAX_RETAINED_VIEW_BYTES + HARD_MAX_TRANSIENT_HEAP_BYTES;
const HARD_MAX_OPERATION_ATTEMPTS: u64 = 1 << 40;
const HARD_MAX_ATTEMPTS_PER_CALL: u8 = 32;

const TREE_FIXED_FDS: u32 = 4;
const MATERIALIZER_MIN_FDS: u32 = 4;
const REGULAR_COPY_TRANSIENT_FDS: u32 = 3;
const STAGED_PUBLISHER_FDS: u32 = 1;
const PUBLISH_TRANSIENT_FDS: u32 = 2;

// Cleanup is deliberately charged before a staging directory is created.
// These constants are the frozen conservative equation for the publisher's
// fixed-size raw-`getdents64` batches. It covers exact-full-batch EOF probes,
// dot-only reads for empty directories, every explicit raw directory-read
// attempt, and identity/chmod/unlink work: `(5E + 3)` open-family calls and
// `(12E + 12)` generic calls. Infallible RAII close calls are structurally
// bounded by successful opens and are not retry-budgeted.
const CLEANUP_FIXED_OPEN_CALLS: u64 = 3;
const CLEANUP_FIXED_SYSCALL_CALLS: u64 = 12;
const CLEANUP_OPEN_CALLS_PER_ENTRY: u64 = 5;
const CLEANUP_SYSCALL_CALLS_PER_ENTRY: u64 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotResourcePolicyFieldV1 {
    Depth,
    Entries,
    NameBytes,
    RelativePathBytes,
    SymlinkTargetBytes,
    FileBytes,
    TotalFileBytes,
    DataExtentsPerFile,
    TotalDataExtents,
    XattrsPerEntry,
    TotalXattrs,
    XattrNameBytes,
    XattrValueBytes,
    XattrListBytes,
    TotalXattrPayloadBytes,
    RetainedViewBytes,
    TransientHeapBytes,
    FourViewHeapBytes,
    OperationAttempts,
    Openat2Attempts,
    SyscallAttempts,
    XattrStabilityRounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotResourcePolicyErrorV1 {
    AboveHardCeiling(SnapshotResourcePolicyFieldV1),
    Inconsistent(SnapshotResourcePolicyFieldV1),
    ArithmeticOverflow,
    CleanupReserveExceedsOperationBudget,
}

/// Coarse forward phase used only for whole-pipeline resource diagnostics.
///
/// Leaf-specific failure stages remain owned by their leaf. Keeping this enum
/// deliberately coarse lets every leaf charge the same ledger without making
/// the resource layer depend on any leaf error type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPipelineForwardStageV1 {
    SourceEnumeration,
    RegularCopy,
    Materialization,
    Publication,
    SourceObservation,
    DestinationObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPipelineStageV1 {
    Forward(SnapshotPipelineForwardStageV1),
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPipelinePreflightResourceV1 {
    FileDescriptors,
    FourViewHeapBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPipelineAttemptBucketV1 {
    Forward,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPipelineResourceErrorV1 {
    PreflightArithmeticOverflow {
        resource: SnapshotPipelinePreflightResourceV1,
    },
    PreflightCapacityExceeded {
        resource: SnapshotPipelinePreflightResourceV1,
        required: u64,
        available: u64,
    },
    OperationBudgetExhausted {
        stage: SnapshotPipelineStageV1,
        bucket: SnapshotPipelineAttemptBucketV1,
    },
    TransientHeapArithmeticOverflow {
        stage: SnapshotPipelineStageV1,
        live: u64,
        requested: u64,
    },
    TransientHeapCapacityExceeded {
        stage: SnapshotPipelineStageV1,
        live: u64,
        requested: u64,
        limit: u64,
    },
    ContainerCapacityArithmeticOverflow {
        stage: SnapshotPipelineStageV1,
    },
    ContainerCapacityLimitExceeded {
        stage: SnapshotPipelineStageV1,
        required: u64,
        limit: u64,
    },
    ContainerAllocationFailed {
        stage: SnapshotPipelineStageV1,
    },
    AllocatorCapacityExceededPrecharge {
        stage: SnapshotPipelineStageV1,
        observed: u64,
        precharged: u64,
    },
}

/// Validated limits shared by every phase and every stability view.
///
/// Byte limits are inclusive. Zero is meaningful for optional resource
/// classes: it disables nonempty extents, xattrs, symlinks, or transient heap
/// rather than being silently replaced with a default. The root entry itself
/// is mandatory, so `max_entries` remains nonzero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotResourcePolicyV1 {
    max_depth: u16,
    max_entries: NonZeroU32,
    max_name_bytes: NonZeroU16,
    max_relative_path_bytes: u32,
    max_symlink_target_bytes: u32,
    max_file_bytes: u64,
    max_total_file_bytes: u64,
    max_data_extents_per_file: u32,
    max_total_data_extents: u64,
    max_xattrs_per_entry: u16,
    max_total_xattrs: u64,
    max_xattr_name_bytes: u16,
    max_xattr_value_bytes: u32,
    max_xattr_list_bytes: u32,
    max_total_xattr_payload_bytes: u64,
    max_retained_view_bytes: NonZeroU64,
    max_transient_heap_bytes: u64,
    max_operation_attempts: NonZeroU64,
    openat2_attempts: NonZeroU8,
    syscall_attempts: NonZeroU8,
    xattr_stability_rounds: NonZeroU8,
    max_cleanup_depth: u16,
    max_live_tree_fds: u32,
    max_live_materializer_fds: u32,
    max_live_publisher_cleanup_fds: u32,
    max_live_snapshot_fds: u32,
    max_four_view_heap_bytes: u64,
    cleanup_operation_reserve: u64,
    max_forward_operation_attempts: u64,
}

/// A single, preflighted capability shared by the entire snapshot pipeline.
///
/// This type intentionally implements neither `Clone` nor `Copy`. Its private
/// cells are the only mutable authorities for forward work, cleanup work, and
/// concurrently live transient heap. A connector must create one instance and
/// lend it to every phase through the end of publication or RAII cleanup.
#[derive(Debug)]
pub(super) struct SnapshotPipelineResourcesV1 {
    policy: SnapshotResourcePolicyV1,
    forward_attempts_remaining: Cell<u64>,
    cleanup_attempts_remaining: Cell<u64>,
    transient_heap_live: Cell<u64>,
}

/// Temporary RAII precharge held while an allocation is attempted.
#[must_use = "dropping the charge releases its transient-heap bytes"]
struct SnapshotTransientChargeV1<'resources> {
    resources: &'resources SnapshotPipelineResourcesV1,
    bytes: u64,
}

/// A byte vector structurally bound to its exact container-observed capacity.
///
/// Requested capacity is precharged before allocation. A supported allocator
/// must then report that exact logical capacity; allocator overcapacity is
/// immediately dropped and becomes a typed compatibility refusal. The raw
/// `Vec` is never exposed, so callers cannot grow it outside the ledger or
/// detach it from its charge. Drop destroys the backing storage before
/// releasing the charge. Restricting this type to bytes prevents nested owned
/// allocations from escaping the ledger. Allocator-private metadata is outside
/// this contract.
pub(super) struct SnapshotChargedBytesV1<'resources> {
    values: Vec<u8>,
    resources: &'resources SnapshotPipelineResourcesV1,
    stage: SnapshotPipelineStageV1,
    charged_bytes: u64,
}

impl std::fmt::Debug for SnapshotChargedBytesV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotChargedBytesV1")
            .field("values", &"<redacted>")
            .field("len", &self.values.len())
            .field("capacity", &self.values.capacity())
            .field("stage", &self.stage)
            .field("charged_bytes", &self.charged_bytes)
            .finish()
    }
}

impl SnapshotResourcePolicyV1 {
    /// Validates the entire resource contract before any filesystem work.
    ///
    /// The long argument list is intentional: there are no defaults and no
    /// independently constructible sub-policies whose values could diverge.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn checked(
        max_depth: u16,
        max_entries: NonZeroU32,
        max_name_bytes: NonZeroU16,
        max_relative_path_bytes: u32,
        max_symlink_target_bytes: u32,
        max_file_bytes: u64,
        max_total_file_bytes: u64,
        max_data_extents_per_file: u32,
        max_total_data_extents: u64,
        max_xattrs_per_entry: u16,
        max_total_xattrs: u64,
        max_xattr_name_bytes: u16,
        max_xattr_value_bytes: u32,
        max_xattr_list_bytes: u32,
        max_total_xattr_payload_bytes: u64,
        max_retained_view_bytes: NonZeroU64,
        max_transient_heap_bytes: u64,
        max_operation_attempts: NonZeroU64,
        openat2_attempts: NonZeroU8,
        syscall_attempts: NonZeroU8,
        xattr_stability_rounds: NonZeroU8,
    ) -> Result<Self, SnapshotResourcePolicyErrorV1> {
        use SnapshotResourcePolicyErrorV1::{AboveHardCeiling, Inconsistent};
        use SnapshotResourcePolicyFieldV1 as Field;

        if max_depth > HARD_MAX_DEPTH {
            return Err(AboveHardCeiling(Field::Depth));
        }
        if max_entries.get() > HARD_MAX_ENTRIES {
            return Err(AboveHardCeiling(Field::Entries));
        }
        if max_name_bytes.get() > HARD_MAX_NAME_BYTES {
            return Err(AboveHardCeiling(Field::NameBytes));
        }
        if max_relative_path_bytes > HARD_MAX_RELATIVE_PATH_BYTES {
            return Err(AboveHardCeiling(Field::RelativePathBytes));
        }
        if max_symlink_target_bytes > HARD_MAX_SYMLINK_TARGET_BYTES {
            return Err(AboveHardCeiling(Field::SymlinkTargetBytes));
        }
        if max_file_bytes > HARD_MAX_FILE_BYTES {
            return Err(AboveHardCeiling(Field::FileBytes));
        }
        if max_total_file_bytes > HARD_MAX_TOTAL_FILE_BYTES {
            return Err(AboveHardCeiling(Field::TotalFileBytes));
        }
        if max_data_extents_per_file > HARD_MAX_DATA_EXTENTS_PER_FILE {
            return Err(AboveHardCeiling(Field::DataExtentsPerFile));
        }
        if max_total_data_extents > HARD_MAX_TOTAL_DATA_EXTENTS {
            return Err(AboveHardCeiling(Field::TotalDataExtents));
        }
        if max_xattrs_per_entry > HARD_MAX_XATTRS_PER_ENTRY {
            return Err(AboveHardCeiling(Field::XattrsPerEntry));
        }
        if max_total_xattrs > HARD_MAX_TOTAL_XATTRS {
            return Err(AboveHardCeiling(Field::TotalXattrs));
        }
        if max_xattr_name_bytes > HARD_MAX_XATTR_NAME_BYTES {
            return Err(AboveHardCeiling(Field::XattrNameBytes));
        }
        if max_xattr_value_bytes > HARD_MAX_XATTR_VALUE_BYTES {
            return Err(AboveHardCeiling(Field::XattrValueBytes));
        }
        if max_xattr_list_bytes > HARD_MAX_XATTR_LIST_BYTES {
            return Err(AboveHardCeiling(Field::XattrListBytes));
        }
        if max_total_xattr_payload_bytes > HARD_MAX_TOTAL_XATTR_PAYLOAD_BYTES {
            return Err(AboveHardCeiling(Field::TotalXattrPayloadBytes));
        }
        if max_retained_view_bytes.get() > HARD_MAX_RETAINED_VIEW_BYTES {
            return Err(AboveHardCeiling(Field::RetainedViewBytes));
        }
        if max_transient_heap_bytes > HARD_MAX_TRANSIENT_HEAP_BYTES {
            return Err(AboveHardCeiling(Field::TransientHeapBytes));
        }
        if max_operation_attempts.get() > HARD_MAX_OPERATION_ATTEMPTS {
            return Err(AboveHardCeiling(Field::OperationAttempts));
        }
        if openat2_attempts.get() > HARD_MAX_ATTEMPTS_PER_CALL {
            return Err(AboveHardCeiling(Field::Openat2Attempts));
        }
        if syscall_attempts.get() > HARD_MAX_ATTEMPTS_PER_CALL {
            return Err(AboveHardCeiling(Field::SyscallAttempts));
        }
        if xattr_stability_rounds.get() > HARD_MAX_ATTEMPTS_PER_CALL {
            return Err(AboveHardCeiling(Field::XattrStabilityRounds));
        }

        if max_entries.get() > 1 && max_relative_path_bytes < u32::from(max_name_bytes.get()) {
            return Err(Inconsistent(Field::RelativePathBytes));
        }
        if max_file_bytes > max_total_file_bytes {
            return Err(Inconsistent(Field::TotalFileBytes));
        }

        let entry_extent_capacity = u64::from(max_entries.get())
            .checked_mul(u64::from(max_data_extents_per_file))
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        if max_total_data_extents > entry_extent_capacity
            || max_total_data_extents > max_total_file_bytes
        {
            return Err(Inconsistent(Field::TotalDataExtents));
        }
        if (max_total_data_extents == 0) != (max_data_extents_per_file == 0) {
            return Err(Inconsistent(Field::TotalDataExtents));
        }

        let entry_xattr_capacity = u64::from(max_entries.get())
            .checked_mul(u64::from(max_xattrs_per_entry))
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        if max_total_xattrs > entry_xattr_capacity {
            return Err(Inconsistent(Field::TotalXattrs));
        }
        if (max_total_xattrs == 0) != (max_xattrs_per_entry == 0) {
            return Err(Inconsistent(Field::TotalXattrs));
        }
        if max_total_xattrs == 0 {
            if max_xattr_name_bytes != 0 {
                return Err(Inconsistent(Field::XattrNameBytes));
            }
            if max_xattr_value_bytes != 0 {
                return Err(Inconsistent(Field::XattrValueBytes));
            }
            if max_xattr_list_bytes != 0 {
                return Err(Inconsistent(Field::XattrListBytes));
            }
            if max_total_xattr_payload_bytes != 0 {
                return Err(Inconsistent(Field::TotalXattrPayloadBytes));
            }
        } else {
            if max_xattr_name_bytes == 0 {
                return Err(Inconsistent(Field::XattrNameBytes));
            }
            let one_list_entry = u32::from(max_xattr_name_bytes)
                .checked_add(1)
                .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
            if max_xattr_list_bytes < one_list_entry {
                return Err(Inconsistent(Field::XattrListBytes));
            }
            if u64::from(max_xattr_name_bytes) > max_total_xattr_payload_bytes {
                return Err(Inconsistent(Field::TotalXattrPayloadBytes));
            }
            if u64::from(max_xattr_value_bytes) > max_total_xattr_payload_bytes {
                return Err(Inconsistent(Field::TotalXattrPayloadBytes));
            }
        }

        let max_cleanup_depth = max_depth
            .checked_add(PUBLICATION_CONTAINER_LEVELS)
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        let max_live_tree_fds = u32::from(max_depth)
            .checked_mul(2)
            .and_then(|value| value.checked_add(TREE_FIXED_FDS))
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        let max_live_materializer_fds = u32::from(max_depth)
            .checked_add(1)
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?
            .max(MATERIALIZER_MIN_FDS);
        let build_fds = max_live_tree_fds
            .checked_add(max_live_materializer_fds)
            .and_then(|value| value.checked_add(REGULAR_COPY_TRANSIENT_FDS))
            .and_then(|value| value.checked_add(STAGED_PUBLISHER_FDS))
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        let max_live_publisher_cleanup_fds = u32::from(max_cleanup_depth)
            .checked_mul(2)
            .and_then(|value| value.checked_add(4))
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        let max_live_snapshot_fds = build_fds
            .max(max_live_tree_fds)
            .max(max_live_publisher_cleanup_fds)
            .max(PUBLISH_TRANSIENT_FDS);

        // A streaming four-view comparison retains only S1 and D1. S2 and D2
        // are compared as streams and must not allocate a third full view.
        let max_four_view_heap_bytes =
            checked_four_view_heap_bytes(max_retained_view_bytes.get(), max_transient_heap_bytes)?;

        let open_attempts = u64::from(openat2_attempts.get());
        let generic_attempts = u64::from(syscall_attempts.get());
        let fixed_cleanup = CLEANUP_FIXED_OPEN_CALLS
            .checked_mul(open_attempts)
            .and_then(|value| {
                CLEANUP_FIXED_SYSCALL_CALLS
                    .checked_mul(generic_attempts)
                    .and_then(|generic| value.checked_add(generic))
            })
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        let cleanup_per_entry = CLEANUP_OPEN_CALLS_PER_ENTRY
            .checked_mul(open_attempts)
            .and_then(|value| {
                CLEANUP_SYSCALL_CALLS_PER_ENTRY
                    .checked_mul(generic_attempts)
                    .and_then(|generic| value.checked_add(generic))
            })
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        let cleanup_operation_reserve = u64::from(max_entries.get())
            .checked_mul(cleanup_per_entry)
            .and_then(|value| value.checked_add(fixed_cleanup))
            .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
        let max_forward_operation_attempts = max_operation_attempts
            .get()
            .checked_sub(cleanup_operation_reserve)
            .ok_or(SnapshotResourcePolicyErrorV1::CleanupReserveExceedsOperationBudget)?;

        Ok(Self {
            max_depth,
            max_entries,
            max_name_bytes,
            max_relative_path_bytes,
            max_symlink_target_bytes,
            max_file_bytes,
            max_total_file_bytes,
            max_data_extents_per_file,
            max_total_data_extents,
            max_xattrs_per_entry,
            max_total_xattrs,
            max_xattr_name_bytes,
            max_xattr_value_bytes,
            max_xattr_list_bytes,
            max_total_xattr_payload_bytes,
            max_retained_view_bytes,
            max_transient_heap_bytes,
            max_operation_attempts,
            openat2_attempts,
            syscall_attempts,
            xattr_stability_rounds,
            max_cleanup_depth,
            max_live_tree_fds,
            max_live_materializer_fds,
            max_live_publisher_cleanup_fds,
            max_live_snapshot_fds,
            max_four_view_heap_bytes,
            cleanup_operation_reserve,
            max_forward_operation_attempts,
        })
    }

    pub(super) const fn max_depth(self) -> u16 {
        self.max_depth
    }

    pub(super) const fn max_entries(self) -> NonZeroU32 {
        self.max_entries
    }

    pub(super) const fn max_name_bytes(self) -> NonZeroU16 {
        self.max_name_bytes
    }

    pub(super) const fn max_relative_path_bytes(self) -> u32 {
        self.max_relative_path_bytes
    }

    pub(super) const fn max_symlink_target_bytes(self) -> u32 {
        self.max_symlink_target_bytes
    }

    pub(super) const fn max_file_bytes(self) -> u64 {
        self.max_file_bytes
    }

    pub(super) const fn max_total_file_bytes(self) -> u64 {
        self.max_total_file_bytes
    }

    pub(super) const fn max_data_extents_per_file(self) -> u32 {
        self.max_data_extents_per_file
    }

    pub(super) const fn max_total_data_extents(self) -> u64 {
        self.max_total_data_extents
    }

    pub(super) const fn max_xattrs_per_entry(self) -> u16 {
        self.max_xattrs_per_entry
    }

    pub(super) const fn max_total_xattrs(self) -> u64 {
        self.max_total_xattrs
    }

    pub(super) const fn max_xattr_name_bytes(self) -> u16 {
        self.max_xattr_name_bytes
    }

    pub(super) const fn max_xattr_value_bytes(self) -> u32 {
        self.max_xattr_value_bytes
    }

    pub(super) const fn max_xattr_list_bytes(self) -> u32 {
        self.max_xattr_list_bytes
    }

    pub(super) const fn max_total_xattr_payload_bytes(self) -> u64 {
        self.max_total_xattr_payload_bytes
    }

    pub(super) const fn max_retained_view_bytes(self) -> NonZeroU64 {
        self.max_retained_view_bytes
    }

    pub(super) const fn max_transient_heap_bytes(self) -> u64 {
        self.max_transient_heap_bytes
    }

    pub(super) const fn max_operation_attempts(self) -> NonZeroU64 {
        self.max_operation_attempts
    }

    pub(super) const fn openat2_attempts(self) -> NonZeroU8 {
        self.openat2_attempts
    }

    pub(super) const fn syscall_attempts(self) -> NonZeroU8 {
        self.syscall_attempts
    }

    pub(super) const fn xattr_stability_rounds(self) -> NonZeroU8 {
        self.xattr_stability_rounds
    }

    pub(super) const fn max_cleanup_depth(self) -> u16 {
        self.max_cleanup_depth
    }

    pub(super) const fn max_live_tree_fds(self) -> u32 {
        self.max_live_tree_fds
    }

    pub(super) const fn max_live_materializer_fds(self) -> u32 {
        self.max_live_materializer_fds
    }

    pub(super) const fn max_live_regular_copy_fds(self) -> u32 {
        REGULAR_COPY_TRANSIENT_FDS
    }

    pub(super) const fn max_live_staged_publisher_fds(self) -> u32 {
        STAGED_PUBLISHER_FDS
    }

    pub(super) const fn max_live_publication_fds(self) -> u32 {
        PUBLISH_TRANSIENT_FDS
    }

    pub(super) const fn max_live_publisher_cleanup_fds(self) -> u32 {
        self.max_live_publisher_cleanup_fds
    }

    pub(super) const fn max_live_snapshot_fds(self) -> u32 {
        self.max_live_snapshot_fds
    }

    pub(super) const fn max_four_view_heap_bytes(self) -> u64 {
        self.max_four_view_heap_bytes
    }

    pub(super) const fn cleanup_operation_reserve(self) -> u64 {
        self.cleanup_operation_reserve
    }

    pub(super) const fn max_forward_operation_attempts(self) -> u64 {
        self.max_forward_operation_attempts
    }
}

impl SnapshotPipelineResourcesV1 {
    /// Checks process capacity once, before any filesystem work, and creates
    /// the pipeline's sole mutable resource authority.
    ///
    /// `baseline_live_fds` includes every descriptor already live in the
    /// worker. `available_heap_bytes` is allocator/cgroup headroom assigned to
    /// this snapshot, not total host memory. Both capacities are inclusive.
    pub(super) fn preflight(
        policy: SnapshotResourcePolicyV1,
        baseline_live_fds: u64,
        file_descriptor_limit: u64,
        available_heap_bytes: u64,
    ) -> Result<Self, SnapshotPipelineResourceErrorV1> {
        use SnapshotPipelinePreflightResourceV1::{FileDescriptors, FourViewHeapBytes};

        let required_fds = baseline_live_fds
            .checked_add(u64::from(policy.max_live_snapshot_fds()))
            .ok_or(
                SnapshotPipelineResourceErrorV1::PreflightArithmeticOverflow {
                    resource: FileDescriptors,
                },
            )?;
        if required_fds > file_descriptor_limit {
            return Err(SnapshotPipelineResourceErrorV1::PreflightCapacityExceeded {
                resource: FileDescriptors,
                required: required_fds,
                available: file_descriptor_limit,
            });
        }

        let required_heap = policy.max_four_view_heap_bytes();
        if required_heap > available_heap_bytes {
            return Err(SnapshotPipelineResourceErrorV1::PreflightCapacityExceeded {
                resource: FourViewHeapBytes,
                required: required_heap,
                available: available_heap_bytes,
            });
        }

        Ok(Self {
            policy,
            forward_attempts_remaining: Cell::new(policy.max_forward_operation_attempts()),
            cleanup_attempts_remaining: Cell::new(policy.cleanup_operation_reserve()),
            transient_heap_live: Cell::new(0),
        })
    }

    /// Returns the immutable, already-validated policy for fallible static
    /// projection. The mutable resource authority remains in `self`.
    pub(super) const fn policy(&self) -> SnapshotResourcePolicyV1 {
        self.policy
    }

    /// Charges one forward attempt before invoking `attempt`.
    ///
    /// The closure is never invoked when the forward bucket is exhausted.
    /// Call this once for every raw attempt, including every EINTR retry.
    pub(super) fn run_forward_attempt<T>(
        &self,
        stage: SnapshotPipelineForwardStageV1,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.charge_attempt(
            &self.forward_attempts_remaining,
            SnapshotPipelineStageV1::Forward(stage),
            SnapshotPipelineAttemptBucketV1::Forward,
        )?;
        Ok(attempt())
    }

    /// Charges one cleanup attempt before invoking `attempt`.
    ///
    /// Cleanup draws only from the reserve committed before staging creation;
    /// forward exhaustion therefore cannot prevent fail-closed RAII cleanup.
    pub(super) fn run_cleanup_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.charge_attempt(
            &self.cleanup_attempts_remaining,
            SnapshotPipelineStageV1::Cleanup,
            SnapshotPipelineAttemptBucketV1::Cleanup,
        )?;
        Ok(attempt())
    }

    pub(super) fn charged_forward_bytes(
        &self,
        stage: SnapshotPipelineForwardStageV1,
        max_capacity: usize,
    ) -> Result<SnapshotChargedBytesV1<'_>, SnapshotPipelineResourceErrorV1> {
        SnapshotChargedBytesV1::with_capacity(
            self,
            SnapshotPipelineStageV1::Forward(stage),
            max_capacity,
        )
    }

    pub(super) fn charged_cleanup_bytes(
        &self,
        max_capacity: usize,
    ) -> Result<SnapshotChargedBytesV1<'_>, SnapshotPipelineResourceErrorV1> {
        SnapshotChargedBytesV1::with_capacity(self, SnapshotPipelineStageV1::Cleanup, max_capacity)
    }

    #[cfg(test)]
    pub(super) fn forward_attempts_remaining_for_test(&self) -> u64 {
        self.forward_attempts_remaining.get()
    }

    #[cfg(test)]
    pub(super) fn cleanup_attempts_remaining_for_test(&self) -> u64 {
        self.cleanup_attempts_remaining.get()
    }

    fn charge_attempt(
        &self,
        remaining: &Cell<u64>,
        stage: SnapshotPipelineStageV1,
        bucket: SnapshotPipelineAttemptBucketV1,
    ) -> Result<(), SnapshotPipelineResourceErrorV1> {
        let Some(next) = remaining.get().checked_sub(1) else {
            return Err(SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                stage,
                bucket,
            });
        };
        remaining.set(next);
        Ok(())
    }

    fn reserve_transient(
        &self,
        stage: SnapshotPipelineStageV1,
        bytes: u64,
    ) -> Result<SnapshotTransientChargeV1<'_>, SnapshotPipelineResourceErrorV1> {
        let live = self.transient_heap_live.get();
        let Some(next) = live.checked_add(bytes) else {
            return Err(
                SnapshotPipelineResourceErrorV1::TransientHeapArithmeticOverflow {
                    stage,
                    live,
                    requested: bytes,
                },
            );
        };
        let limit = self.policy.max_transient_heap_bytes();
        if next > limit {
            return Err(
                SnapshotPipelineResourceErrorV1::TransientHeapCapacityExceeded {
                    stage,
                    live,
                    requested: bytes,
                    limit,
                },
            );
        }
        self.transient_heap_live.set(next);
        Ok(SnapshotTransientChargeV1 {
            resources: self,
            bytes,
        })
    }

    fn release_transient(&self, bytes: u64) {
        let live = self.transient_heap_live.get();
        let restored = live
            .checked_sub(bytes)
            .expect("a private transient charge cannot release uncharged bytes");
        self.transient_heap_live.set(restored);
    }
}

impl Drop for SnapshotTransientChargeV1<'_> {
    fn drop(&mut self) {
        self.resources.release_transient(self.bytes);
    }
}

impl<'resources> SnapshotChargedBytesV1<'resources> {
    fn with_capacity(
        resources: &'resources SnapshotPipelineResourcesV1,
        stage: SnapshotPipelineStageV1,
        max_capacity: usize,
    ) -> Result<Self, SnapshotPipelineResourceErrorV1> {
        Self::with_capacity_using(resources, stage, max_capacity, |values, capacity| {
            values.try_reserve_exact(capacity).map_err(|_| ())
        })
    }

    fn with_capacity_using(
        resources: &'resources SnapshotPipelineResourcesV1,
        stage: SnapshotPipelineStageV1,
        max_capacity: usize,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), ()>,
    ) -> Result<Self, SnapshotPipelineResourceErrorV1> {
        let precharged = observed_capacity_bytes(max_capacity, stage)?;
        let mut charge = resources.reserve_transient(stage, precharged)?;
        let mut values = Vec::new();
        if reserve(&mut values, max_capacity).is_err() {
            return Err(SnapshotPipelineResourceErrorV1::ContainerAllocationFailed { stage });
        }
        let observed = observed_capacity_bytes(values.capacity(), stage)?;
        if observed > precharged {
            drop(values);
            return Err(
                SnapshotPipelineResourceErrorV1::AllocatorCapacityExceededPrecharge {
                    stage,
                    observed,
                    precharged,
                },
            );
        }
        debug_assert_eq!(observed, precharged);
        charge.bytes = 0;
        Ok(Self {
            values,
            resources,
            stage,
            charged_bytes: observed,
        })
    }

    pub(super) fn try_push(&mut self, value: u8) -> Result<(), SnapshotPipelineResourceErrorV1> {
        let required = self.values.len().checked_add(1).ok_or(
            SnapshotPipelineResourceErrorV1::ContainerCapacityArithmeticOverflow {
                stage: self.stage,
            },
        )?;
        self.require_capacity(required)?;
        self.values.push(value);
        Ok(())
    }

    pub(super) fn try_extend_from_slice(
        &mut self,
        values: &[u8],
    ) -> Result<(), SnapshotPipelineResourceErrorV1> {
        let required = self.values.len().checked_add(values.len()).ok_or(
            SnapshotPipelineResourceErrorV1::ContainerCapacityArithmeticOverflow {
                stage: self.stage,
            },
        )?;
        self.require_capacity(required)?;
        self.values.extend_from_slice(values);
        Ok(())
    }

    fn require_capacity(&self, required: usize) -> Result<(), SnapshotPipelineResourceErrorV1> {
        let capacity = self.values.capacity();
        if required > capacity {
            return Err(
                SnapshotPipelineResourceErrorV1::ContainerCapacityLimitExceeded {
                    stage: self.stage,
                    required: u64::try_from(required).unwrap_or(u64::MAX),
                    limit: u64::try_from(capacity).unwrap_or(u64::MAX),
                },
            );
        }
        Ok(())
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.values
    }
}

impl Drop for SnapshotChargedBytesV1<'_> {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.values));
        self.resources.release_transient(self.charged_bytes);
    }
}

fn observed_capacity_bytes(
    capacity: usize,
    stage: SnapshotPipelineStageV1,
) -> Result<u64, SnapshotPipelineResourceErrorV1> {
    u64::try_from(capacity)
        .map_err(|_| SnapshotPipelineResourceErrorV1::ContainerCapacityArithmeticOverflow { stage })
}

fn checked_four_view_heap_bytes(
    retained_view_bytes: u64,
    transient_heap_bytes: u64,
) -> Result<u64, SnapshotResourcePolicyErrorV1> {
    let total = retained_view_bytes
        .checked_mul(2)
        .and_then(|value| value.checked_add(transient_heap_bytes))
        .ok_or(SnapshotResourcePolicyErrorV1::ArithmeticOverflow)?;
    if total > HARD_MAX_FOUR_VIEW_HEAP_BYTES {
        return Err(SnapshotResourcePolicyErrorV1::AboveHardCeiling(
            SnapshotResourcePolicyFieldV1::FourViewHeapBytes,
        ));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz8(value: u8) -> NonZeroU8 {
        NonZeroU8::new(value).unwrap()
    }

    fn nz16(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn nz32(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).unwrap()
    }

    fn nz64(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn policy(
        depth: u16,
        entries: u32,
        retained: u64,
        transient: u64,
        operations: u64,
        open_attempts: u8,
        syscall_attempts: u8,
    ) -> Result<SnapshotResourcePolicyV1, SnapshotResourcePolicyErrorV1> {
        let aggregate_items = u64::from(entries) * 64;
        SnapshotResourcePolicyV1::checked(
            depth,
            nz32(entries),
            nz16(255),
            4096,
            4096,
            16 * 1024 * 1024,
            64 * 1024 * 1024,
            64,
            aggregate_items,
            64,
            aggregate_items,
            255,
            64 * 1024,
            64 * 1024,
            1024 * 1024,
            nz64(retained),
            transient,
            nz64(operations),
            nz8(open_attempts),
            nz8(syscall_attempts),
            nz8(4),
        )
    }

    #[test]
    fn exact_current_fd_and_four_view_heap_equations_are_frozen() {
        let policy = policy(
            16,
            4096,
            128 * 1024 * 1024,
            32 * 1024 * 1024,
            1_000_000,
            4,
            3,
        )
        .unwrap();

        assert_eq!(policy.max_cleanup_depth(), 18);
        assert_eq!(policy.max_live_tree_fds(), 2 * 16 + 4);
        assert_eq!(policy.max_live_materializer_fds(), 17);
        assert_eq!(policy.max_live_regular_copy_fds(), 3);
        assert_eq!(policy.max_live_staged_publisher_fds(), 1);
        assert_eq!(policy.max_live_publication_fds(), 2);
        assert_eq!(policy.max_live_publisher_cleanup_fds(), 2 * 18 + 4);
        assert_eq!(policy.max_live_snapshot_fds(), 2 * 16 + 8 + 17);
        assert_eq!(
            policy.max_four_view_heap_bytes(),
            2 * 128 * 1024 * 1024 + 32 * 1024 * 1024
        );
    }

    #[test]
    fn cleanup_reserve_is_removed_from_one_whole_snapshot_budget() {
        let entries = 10u64;
        let open_attempts = 4u64;
        let syscall_attempts = 3u64;
        let expected = 3 * open_attempts
            + 12 * syscall_attempts
            + entries * (5 * open_attempts + 12 * syscall_attempts);
        let total = expected + 77;
        let committed_policy = policy(2, entries as u32, 1024, 512, total, 4, 3).unwrap();

        assert_eq!(committed_policy.cleanup_operation_reserve(), expected);
        assert_eq!(committed_policy.max_forward_operation_attempts(), 77);
        assert_eq!(committed_policy.max_operation_attempts().get(), total);

        assert_eq!(
            policy(2, entries as u32, 1024, 512, expected - 1, 4, 3),
            Err(SnapshotResourcePolicyErrorV1::CleanupReserveExceedsOperationBudget)
        );
    }

    #[test]
    fn aggregate_four_view_heap_ceiling_is_explicit() {
        assert_eq!(
            checked_four_view_heap_bytes(
                HARD_MAX_RETAINED_VIEW_BYTES,
                HARD_MAX_TRANSIENT_HEAP_BYTES
            ),
            Ok(HARD_MAX_FOUR_VIEW_HEAP_BYTES)
        );
        assert_eq!(
            checked_four_view_heap_bytes(
                HARD_MAX_RETAINED_VIEW_BYTES,
                HARD_MAX_TRANSIENT_HEAP_BYTES + 1
            ),
            Err(SnapshotResourcePolicyErrorV1::AboveHardCeiling(
                SnapshotResourcePolicyFieldV1::FourViewHeapBytes
            ))
        );
    }

    #[test]
    fn optional_zero_classes_are_explicit_and_never_defaulted() {
        let policy = SnapshotResourcePolicyV1::checked(
            0,
            nz32(1),
            nz16(1),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            nz64(1),
            0,
            nz64(32),
            nz8(1),
            nz8(1),
            nz8(1),
        )
        .unwrap();

        assert_eq!(policy.max_relative_path_bytes(), 0);
        assert_eq!(policy.max_symlink_target_bytes(), 0);
        assert_eq!(policy.max_file_bytes(), 0);
        assert_eq!(policy.max_total_file_bytes(), 0);
        assert_eq!(policy.max_data_extents_per_file(), 0);
        assert_eq!(policy.max_total_data_extents(), 0);
        assert_eq!(policy.max_xattrs_per_entry(), 0);
        assert_eq!(policy.max_total_xattrs(), 0);
        assert_eq!(policy.max_xattr_name_bytes(), 0);
        assert_eq!(policy.max_xattr_value_bytes(), 0);
        assert_eq!(policy.max_xattr_list_bytes(), 0);
        assert_eq!(policy.max_total_xattr_payload_bytes(), 0);
        assert_eq!(policy.max_transient_heap_bytes(), 0);
    }

    #[test]
    fn aggregate_counts_cannot_exceed_per_entry_products_or_payload_bytes() {
        let base = |total_extents, total_xattrs, total_file_bytes| {
            SnapshotResourcePolicyV1::checked(
                1,
                nz32(2),
                nz16(8),
                8,
                8,
                8,
                total_file_bytes,
                2,
                total_extents,
                2,
                total_xattrs,
                8,
                8,
                9,
                16,
                nz64(1024),
                1024,
                nz64(1000),
                nz8(1),
                nz8(1),
                nz8(1),
            )
        };

        assert_eq!(
            base(5, 4, 8),
            Err(SnapshotResourcePolicyErrorV1::Inconsistent(
                SnapshotResourcePolicyFieldV1::TotalDataExtents
            ))
        );
        assert_eq!(
            base(4, 5, 8),
            Err(SnapshotResourcePolicyErrorV1::Inconsistent(
                SnapshotResourcePolicyFieldV1::TotalXattrs
            ))
        );
        assert_eq!(
            base(4, 4, 3),
            Err(SnapshotResourcePolicyErrorV1::Inconsistent(
                SnapshotResourcePolicyFieldV1::TotalFileBytes
            ))
        );
    }

    #[test]
    fn hard_ceiling_values_are_accepted_without_cartesian_heap_preflight() {
        let cleanup = (CLEANUP_FIXED_OPEN_CALLS * u64::from(HARD_MAX_ATTEMPTS_PER_CALL)
            + CLEANUP_FIXED_SYSCALL_CALLS * u64::from(HARD_MAX_ATTEMPTS_PER_CALL))
            + u64::from(HARD_MAX_ENTRIES)
                * (CLEANUP_OPEN_CALLS_PER_ENTRY * u64::from(HARD_MAX_ATTEMPTS_PER_CALL)
                    + CLEANUP_SYSCALL_CALLS_PER_ENTRY * u64::from(HARD_MAX_ATTEMPTS_PER_CALL));
        let policy = SnapshotResourcePolicyV1::checked(
            HARD_MAX_DEPTH,
            nz32(HARD_MAX_ENTRIES),
            nz16(HARD_MAX_NAME_BYTES),
            HARD_MAX_RELATIVE_PATH_BYTES,
            HARD_MAX_SYMLINK_TARGET_BYTES,
            HARD_MAX_FILE_BYTES,
            HARD_MAX_TOTAL_FILE_BYTES,
            HARD_MAX_DATA_EXTENTS_PER_FILE,
            HARD_MAX_TOTAL_DATA_EXTENTS,
            HARD_MAX_XATTRS_PER_ENTRY,
            HARD_MAX_TOTAL_XATTRS,
            HARD_MAX_XATTR_NAME_BYTES,
            HARD_MAX_XATTR_VALUE_BYTES,
            HARD_MAX_XATTR_LIST_BYTES,
            HARD_MAX_TOTAL_XATTR_PAYLOAD_BYTES,
            nz64(HARD_MAX_RETAINED_VIEW_BYTES),
            HARD_MAX_TRANSIENT_HEAP_BYTES,
            nz64(cleanup),
            nz8(HARD_MAX_ATTEMPTS_PER_CALL),
            nz8(HARD_MAX_ATTEMPTS_PER_CALL),
            nz8(HARD_MAX_ATTEMPTS_PER_CALL),
        )
        .unwrap();

        assert_eq!(policy.max_forward_operation_attempts(), 0);
        assert_eq!(
            policy.max_four_view_heap_bytes(),
            2 * HARD_MAX_RETAINED_VIEW_BYTES + HARD_MAX_TRANSIENT_HEAP_BYTES
        );
    }

    #[test]
    fn each_representative_hard_ceiling_plus_one_is_rejected() {
        let above = |depth,
                     entries,
                     name,
                     path,
                     symlink,
                     file,
                     retained,
                     transient,
                     operations,
                     open,
                     syscall,
                     stability| {
            SnapshotResourcePolicyV1::checked(
                depth,
                nz32(entries),
                nz16(name),
                path,
                symlink,
                file,
                HARD_MAX_TOTAL_FILE_BYTES,
                1,
                1,
                1,
                1,
                1,
                1,
                2,
                2,
                nz64(retained),
                transient,
                nz64(operations),
                nz8(open),
                nz8(syscall),
                nz8(stability),
            )
        };

        assert_eq!(
            above(HARD_MAX_DEPTH + 1, 1, 1, 0, 0, 0, 1, 0, 100, 1, 1, 1),
            Err(SnapshotResourcePolicyErrorV1::AboveHardCeiling(
                SnapshotResourcePolicyFieldV1::Depth
            ))
        );
        assert!(
            above(
                0,
                HARD_MAX_ENTRIES + 1,
                1,
                0,
                0,
                0,
                1,
                0,
                HARD_MAX_OPERATION_ATTEMPTS,
                1,
                1,
                1
            )
            .is_err()
        );
        assert!(above(0, 1, HARD_MAX_NAME_BYTES + 1, 0, 0, 0, 1, 0, 100, 1, 1, 1).is_err());
        assert!(
            above(
                0,
                1,
                1,
                HARD_MAX_RELATIVE_PATH_BYTES + 1,
                0,
                0,
                1,
                0,
                100,
                1,
                1,
                1
            )
            .is_err()
        );
        assert!(
            above(
                0,
                1,
                1,
                0,
                HARD_MAX_SYMLINK_TARGET_BYTES + 1,
                0,
                1,
                0,
                100,
                1,
                1,
                1
            )
            .is_err()
        );
        assert!(above(0, 1, 1, 0, 0, HARD_MAX_FILE_BYTES + 1, 1, 0, 100, 1, 1, 1).is_err());
        assert!(
            above(
                0,
                1,
                1,
                0,
                0,
                0,
                HARD_MAX_RETAINED_VIEW_BYTES + 1,
                0,
                100,
                1,
                1,
                1
            )
            .is_err()
        );
        assert!(
            above(
                0,
                1,
                1,
                0,
                0,
                0,
                1,
                HARD_MAX_TRANSIENT_HEAP_BYTES + 1,
                100,
                1,
                1,
                1
            )
            .is_err()
        );
        assert!(
            above(
                0,
                1,
                1,
                0,
                0,
                0,
                1,
                0,
                HARD_MAX_OPERATION_ATTEMPTS + 1,
                1,
                1,
                1
            )
            .is_err()
        );
        assert!(
            above(
                0,
                1,
                1,
                0,
                0,
                0,
                1,
                0,
                1000,
                HARD_MAX_ATTEMPTS_PER_CALL + 1,
                1,
                1
            )
            .is_err()
        );
        assert!(
            above(
                0,
                1,
                1,
                0,
                0,
                0,
                1,
                0,
                1000,
                1,
                HARD_MAX_ATTEMPTS_PER_CALL + 1,
                1
            )
            .is_err()
        );
        assert!(
            above(
                0,
                1,
                1,
                0,
                0,
                0,
                1,
                0,
                1000,
                1,
                1,
                HARD_MAX_ATTEMPTS_PER_CALL + 1
            )
            .is_err()
        );
    }

    #[test]
    fn derived_peaks_are_monotonic_in_their_source_limits() {
        let mut previous_fds = 0;
        for depth in 0..=32 {
            let policy = policy(depth, 64, 4096, 1024, 100_000, 2, 2).unwrap();
            assert!(policy.max_live_snapshot_fds() >= previous_fds);
            previous_fds = policy.max_live_snapshot_fds();
        }

        let mut previous_cleanup = 0;
        for entries in 1..=128 {
            let policy = policy(4, entries, 4096, 1024, 100_000, 2, 2).unwrap();
            assert!(policy.cleanup_operation_reserve() >= previous_cleanup);
            previous_cleanup = policy.cleanup_operation_reserve();
        }

        let small = policy(4, 64, 4096, 1024, 100_000, 2, 2).unwrap();
        let large = policy(4, 64, 8192, 2048, 100_000, 2, 2).unwrap();
        assert!(small.max_four_view_heap_bytes() <= large.max_four_view_heap_bytes());
    }

    #[test]
    fn getters_preserve_exact_caller_values() {
        let policy = policy(7, 31, 8192, 2048, 50_000, 3, 2).unwrap();
        assert_eq!(policy.max_depth(), 7);
        assert_eq!(policy.max_entries().get(), 31);
        assert_eq!(policy.max_name_bytes().get(), 255);
        assert_eq!(policy.max_retained_view_bytes().get(), 8192);
        assert_eq!(policy.openat2_attempts().get(), 3);
        assert_eq!(policy.syscall_attempts().get(), 2);
        assert_eq!(policy.xattr_stability_rounds().get(), 4);
    }

    fn pipeline_policy(
        forward_attempts: u64,
        transient_heap_bytes: u64,
    ) -> SnapshotResourcePolicyV1 {
        let entries = 2u64;
        let open_attempts = 2u64;
        let syscall_attempts = 2u64;
        let cleanup = CLEANUP_FIXED_OPEN_CALLS * open_attempts
            + CLEANUP_FIXED_SYSCALL_CALLS * syscall_attempts
            + entries
                * (CLEANUP_OPEN_CALLS_PER_ENTRY * open_attempts
                    + CLEANUP_SYSCALL_CALLS_PER_ENTRY * syscall_attempts);
        policy(
            2,
            entries as u32,
            4096,
            transient_heap_bytes,
            cleanup + forward_attempts,
            open_attempts as u8,
            syscall_attempts as u8,
        )
        .unwrap()
    }

    fn pipeline_resources(
        forward_attempts: u64,
        transient_heap_bytes: u64,
    ) -> SnapshotPipelineResourcesV1 {
        let policy = pipeline_policy(forward_attempts, transient_heap_bytes);
        let baseline = 7;
        let file_descriptor_limit = baseline + u64::from(policy.max_live_snapshot_fds());
        SnapshotPipelineResourcesV1::preflight(
            policy,
            baseline,
            file_descriptor_limit,
            policy.max_four_view_heap_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn pipeline_preflight_accepts_exact_capacity_and_rejects_one_more_demand() {
        let policy = pipeline_policy(8, 1024);
        let baseline = 11;
        let exact_fds = baseline + u64::from(policy.max_live_snapshot_fds());
        let exact_heap = policy.max_four_view_heap_bytes();

        let resources =
            SnapshotPipelineResourcesV1::preflight(policy, baseline, exact_fds, exact_heap)
                .unwrap();
        assert_eq!(resources.policy(), policy);

        assert_eq!(
            SnapshotPipelineResourcesV1::preflight(policy, baseline + 1, exact_fds, exact_heap)
                .unwrap_err(),
            SnapshotPipelineResourceErrorV1::PreflightCapacityExceeded {
                resource: SnapshotPipelinePreflightResourceV1::FileDescriptors,
                required: exact_fds + 1,
                available: exact_fds,
            }
        );
        assert_eq!(
            SnapshotPipelineResourcesV1::preflight(policy, baseline, exact_fds, exact_heap - 1)
                .unwrap_err(),
            SnapshotPipelineResourceErrorV1::PreflightCapacityExceeded {
                resource: SnapshotPipelinePreflightResourceV1::FourViewHeapBytes,
                required: exact_heap,
                available: exact_heap - 1,
            }
        );
    }

    #[test]
    fn pipeline_preflight_and_transient_reservation_fail_closed_on_overflow() {
        let policy = pipeline_policy(1, 8);
        assert_eq!(
            SnapshotPipelineResourcesV1::preflight(
                policy,
                u64::MAX,
                u64::MAX,
                policy.max_four_view_heap_bytes()
            )
            .unwrap_err(),
            SnapshotPipelineResourceErrorV1::PreflightArithmeticOverflow {
                resource: SnapshotPipelinePreflightResourceV1::FileDescriptors,
            }
        );

        let resources = pipeline_resources(1, 8);
        let one = resources
            .reserve_transient(
                SnapshotPipelineStageV1::Forward(SnapshotPipelineForwardStageV1::SourceEnumeration),
                1,
            )
            .unwrap();
        assert_eq!(
            resources
                .reserve_transient(SnapshotPipelineStageV1::Cleanup, u64::MAX)
                .err()
                .unwrap(),
            SnapshotPipelineResourceErrorV1::TransientHeapArithmeticOverflow {
                stage: SnapshotPipelineStageV1::Cleanup,
                live: 1,
                requested: u64::MAX,
            }
        );
        assert_eq!(resources.transient_heap_live.get(), 1);
        drop(one);
        assert_eq!(resources.transient_heap_live.get(), 0);
    }

    #[test]
    fn operation_buckets_are_disjoint_charge_before_running_and_exhaust_exactly() {
        let resources = pipeline_resources(1, 8);
        let forward_ran = Cell::new(0);

        let value = resources
            .run_forward_attempt(SnapshotPipelineForwardStageV1::Materialization, || {
                assert_eq!(resources.forward_attempts_remaining.get(), 0);
                forward_ran.set(forward_ran.get() + 1);
                37
            })
            .unwrap();
        assert_eq!(value, 37);
        assert_eq!(forward_ran.get(), 1);

        assert_eq!(
            resources
                .run_forward_attempt(SnapshotPipelineForwardStageV1::Publication, || {
                    forward_ran.set(forward_ran.get() + 1);
                })
                .unwrap_err(),
            SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                stage: SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::Publication
                ),
                bucket: SnapshotPipelineAttemptBucketV1::Forward,
            }
        );
        assert_eq!(forward_ran.get(), 1);

        let cleanup_before = resources.cleanup_attempts_remaining.get();
        resources
            .run_cleanup_attempt(|| {
                assert_eq!(
                    resources.cleanup_attempts_remaining.get(),
                    cleanup_before - 1
                );
            })
            .unwrap();
        assert_eq!(resources.forward_attempts_remaining.get(), 0);

        for _ in 1..cleanup_before {
            resources.run_cleanup_attempt(|| ()).unwrap();
        }
        let cleanup_ran = Cell::new(false);
        assert_eq!(
            resources
                .run_cleanup_attempt(|| cleanup_ran.set(true))
                .unwrap_err(),
            SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                stage: SnapshotPipelineStageV1::Cleanup,
                bucket: SnapshotPipelineAttemptBucketV1::Cleanup,
            }
        );
        assert!(!cleanup_ran.get());

        let resources = pipeline_resources(1, 8);
        let cleanup_attempts = resources.cleanup_attempts_remaining.get();
        for _ in 0..cleanup_attempts {
            resources.run_cleanup_attempt(|| ()).unwrap();
        }
        resources
            .run_forward_attempt(SnapshotPipelineForwardStageV1::RegularCopy, || ())
            .unwrap();
    }

    #[test]
    fn transient_reservations_compose_across_phases_and_restore_on_any_drop_order() {
        let resources = pipeline_resources(1, 10);
        let first = resources
            .reserve_transient(
                SnapshotPipelineStageV1::Forward(SnapshotPipelineForwardStageV1::RegularCopy),
                4,
            )
            .unwrap();
        let second = resources
            .reserve_transient(SnapshotPipelineStageV1::Cleanup, 6)
            .unwrap();
        assert_eq!(resources.transient_heap_live.get(), 10);

        assert_eq!(
            resources
                .reserve_transient(
                    SnapshotPipelineStageV1::Forward(
                        SnapshotPipelineForwardStageV1::DestinationObservation,
                    ),
                    1
                )
                .err()
                .unwrap(),
            SnapshotPipelineResourceErrorV1::TransientHeapCapacityExceeded {
                stage: SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::DestinationObservation
                ),
                live: 10,
                requested: 1,
                limit: 10,
            }
        );

        drop(first);
        assert_eq!(resources.transient_heap_live.get(), 6);
        let replacement = resources
            .reserve_transient(
                SnapshotPipelineStageV1::Forward(SnapshotPipelineForwardStageV1::SourceObservation),
                4,
            )
            .unwrap();
        assert_eq!(resources.transient_heap_live.get(), 10);
        drop(second);
        assert_eq!(resources.transient_heap_live.get(), 4);
        drop(replacement);
        assert_eq!(resources.transient_heap_live.get(), 0);

        let zero = resources
            .reserve_transient(SnapshotPipelineStageV1::Cleanup, 0)
            .unwrap();
        assert_eq!(resources.transient_heap_live.get(), 0);
        drop(zero);
        assert_eq!(resources.transient_heap_live.get(), 0);
    }

    #[test]
    fn charged_bytes_own_exact_capacity_refuse_growth_and_release_on_drop() {
        let resources = pipeline_resources(1, 8);
        let mut bytes = resources.charged_cleanup_bytes(4).unwrap();
        assert_eq!(resources.transient_heap_live.get(), 4);
        bytes.try_extend_from_slice(b"name").unwrap();
        assert_eq!(bytes.as_slice(), b"name");
        assert_eq!(
            bytes.try_push(b'!').unwrap_err(),
            SnapshotPipelineResourceErrorV1::ContainerCapacityLimitExceeded {
                stage: SnapshotPipelineStageV1::Cleanup,
                required: 5,
                limit: 4,
            }
        );
        assert_eq!(bytes.as_slice(), b"name");
        drop(bytes);
        assert_eq!(resources.transient_heap_live.get(), 0);
    }

    #[test]
    fn charged_bytes_refuse_insufficient_precharge_before_allocation() {
        let resources = pipeline_resources(1, 4);
        let allocator_ran = Cell::new(false);
        assert_eq!(
            SnapshotChargedBytesV1::with_capacity_using(
                &resources,
                SnapshotPipelineStageV1::Cleanup,
                5,
                |_, _| {
                    allocator_ran.set(true);
                    Ok(())
                },
            )
            .unwrap_err(),
            SnapshotPipelineResourceErrorV1::TransientHeapCapacityExceeded {
                stage: SnapshotPipelineStageV1::Cleanup,
                live: 0,
                requested: 5,
                limit: 4,
            }
        );
        assert!(!allocator_ran.get());
        assert_eq!(resources.transient_heap_live.get(), 0);
    }

    #[test]
    fn charged_byte_allocation_failures_and_unwind_release_precharge() {
        let resources = pipeline_resources(1, 16);
        let stage = SnapshotPipelineStageV1::Cleanup;
        let error = SnapshotChargedBytesV1::with_capacity_using(&resources, stage, 8, |_, _| {
            assert_eq!(resources.transient_heap_live.get(), 8);
            Err(())
        })
        .unwrap_err();
        assert_eq!(
            error,
            SnapshotPipelineResourceErrorV1::ContainerAllocationFailed { stage }
        );
        assert_eq!(resources.transient_heap_live.get(), 0);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = SnapshotChargedBytesV1::with_capacity_using(&resources, stage, 8, |_, _| {
                panic!("injected allocator unwind")
            });
        }));
        assert!(panic.is_err());
        assert_eq!(resources.transient_heap_live.get(), 0);
    }

    #[test]
    fn allocator_capacity_above_precharge_is_dropped_and_refused() {
        let resources = pipeline_resources(1, 16);
        let stage = SnapshotPipelineStageV1::Cleanup;
        let error =
            SnapshotChargedBytesV1::with_capacity_using(&resources, stage, 4, |values, _| {
                values.try_reserve_exact(8).map_err(|_| ())
            })
            .unwrap_err();
        assert!(matches!(
            error,
            SnapshotPipelineResourceErrorV1::AllocatorCapacityExceededPrecharge {
                stage: SnapshotPipelineStageV1::Cleanup,
                observed,
                precharged: 4,
            } if observed >= 8
        ));
        assert_eq!(resources.transient_heap_live.get(), 0);
    }

    #[test]
    fn pipeline_capability_and_reservations_cannot_gain_clone_copy_or_default() {
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

        trait AmbiguousIfDefault<A> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfDefault<()> for T {}
        impl<T: Default> AmbiguousIfDefault<u8> for T {}

        <SnapshotPipelineResourcesV1 as AmbiguousIfClone<_>>::probe();
        <SnapshotPipelineResourcesV1 as AmbiguousIfCopy<_>>::probe();
        <SnapshotPipelineResourcesV1 as AmbiguousIfDefault<_>>::probe();
        <SnapshotChargedBytesV1<'static> as AmbiguousIfClone<_>>::probe();
        <SnapshotChargedBytesV1<'static> as AmbiguousIfCopy<_>>::probe();
        <SnapshotChargedBytesV1<'static> as AmbiguousIfDefault<_>>::probe();
        assert!(std::mem::needs_drop::<SnapshotChargedBytesV1<'static>>());
    }
}
