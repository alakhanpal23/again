//! Descriptor-stable source-tree enumeration for `linux-pytest-v1`.
//!
//! This leaf turns one trusted parent descriptor plus one raw C basename into
//! one independently revalidated source view. The parent must already belong
//! to the profile-qualified no-atime acquisition view: `readlinkat` can update
//! symlink atime on an ordinary host mount. A trusted visitor may consume each
//! entry only while its descriptor is pinned; the returned normalized plan is
//! FD-free. This module does not compare the required source and destination
//! views, compute manifest node digests, publish a snapshot, or claim that a
//! source tree is sealed.

use std::ffi::CStr;
use std::fmt;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::fd::BorrowedFd;

use super::snapshot_regular::{CopiedRegularV1, RegularCopyPolicyV1, SnapshotRegularFailureV1};
use super::{ExtentV1, FileContentDigest, RefusalCode, TimespecV1};

const HARD_MAX_DEPTH: u16 = 256;
const HARD_MAX_NAME_BYTES: u16 = 255;
const HARD_MAX_PATH_BYTES: u32 = 1024 * 1024;
const HARD_MAX_ENTRIES: u32 = 1024 * 1024;
const HARD_MAX_DATA_EXTENTS: u32 = 1024 * 1024;
const HARD_MAX_SYMLINK_TARGET_BYTES: u32 = 1024 * 1024;
const HARD_MAX_XATTR_NAME_BYTES: u16 = 255;
const HARD_MAX_XATTR_VALUE_BYTES: u32 = 64 * 1024;
const HARD_MAX_XATTR_LIST_BYTES: u32 = 64 * 1024;
const HARD_MAX_TOTAL_XATTR_BYTES: u64 = 256 * 1024 * 1024;
const HARD_MAX_PLAN_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_ATTEMPTS: u8 = 32;

/// Capability supplied only after the backend has functionally verified a
/// mount/view on which directory, regular-file, and symlink acquisition cannot
/// mutate host atime. This wrapper records that semantic precondition; this
/// leaf does not create or verify the mount itself.
#[derive(Clone, Copy)]
pub(super) struct QualifiedNoAtimeSourceViewV1<'a> {
    trusted_parent: BorrowedFd<'a>,
}

impl<'a> QualifiedNoAtimeSourceViewV1<'a> {
    /// The execution connector is the sole intended caller, after its
    /// functional no-atime qualification succeeds. No atime-restoration
    /// workaround satisfies this precondition.
    ///
    /// # Safety
    ///
    /// `trusted_parent` must name the exact mount/view that passed the
    /// profile's functional zero-host-metadata-mutation qualification for
    /// directory reads, regular-file reads, symlink reads, and xattr reads.
    /// The qualification must remain valid for this borrow's full lifetime.
    pub(super) const unsafe fn from_functionally_verified_mount(
        trusted_parent: BorrowedFd<'a>,
    ) -> Self {
        Self { trusted_parent }
    }

    const fn trusted_parent(self) -> BorrowedFd<'a> {
        self.trusted_parent
    }
}

/// Traversal and logical-byte limits committed by the snapshot policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceTraversalLimitsV1 {
    max_depth: u16,
    max_name_bytes: NonZeroU16,
    max_relative_path_bytes: NonZeroU32,
    max_entries: NonZeroU32,
    max_symlink_target_bytes: NonZeroU32,
    max_file_bytes: NonZeroU64,
    max_total_file_bytes: NonZeroU64,
}

impl SourceTraversalLimitsV1 {
    pub(super) const fn checked(
        max_depth: u16,
        max_name_bytes: NonZeroU16,
        max_relative_path_bytes: NonZeroU32,
        max_entries: NonZeroU32,
        max_symlink_target_bytes: NonZeroU32,
        max_file_bytes: NonZeroU64,
        max_total_file_bytes: NonZeroU64,
    ) -> Option<Self> {
        if max_depth > HARD_MAX_DEPTH
            || max_name_bytes.get() > HARD_MAX_NAME_BYTES
            || max_relative_path_bytes.get() > HARD_MAX_PATH_BYTES
            || max_entries.get() > HARD_MAX_ENTRIES
            || max_symlink_target_bytes.get() > HARD_MAX_SYMLINK_TARGET_BYTES
        {
            return None;
        }
        Some(Self {
            max_depth,
            max_name_bytes,
            max_relative_path_bytes,
            max_entries,
            max_symlink_target_bytes,
            max_file_bytes,
            max_total_file_bytes,
        })
    }
}

/// Bounds for the complete two-pass visible-xattr capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceXattrLimitsV1 {
    max_per_entry: NonZeroU16,
    max_name_bytes: NonZeroU16,
    max_value_bytes: NonZeroU32,
    max_list_bytes: NonZeroU32,
    max_total_bytes: NonZeroU64,
}

impl SourceXattrLimitsV1 {
    pub(super) const fn checked(
        max_per_entry: NonZeroU16,
        max_name_bytes: NonZeroU16,
        max_value_bytes: NonZeroU32,
        max_list_bytes: NonZeroU32,
        max_total_bytes: NonZeroU64,
    ) -> Option<Self> {
        if max_name_bytes.get() > HARD_MAX_XATTR_NAME_BYTES
            || max_value_bytes.get() > HARD_MAX_XATTR_VALUE_BYTES
            || max_list_bytes.get() > HARD_MAX_XATTR_LIST_BYTES
            || max_total_bytes.get() > HARD_MAX_TOTAL_XATTR_BYTES
        {
            return None;
        }
        Some(Self {
            max_per_entry,
            max_name_bytes,
            max_value_bytes,
            max_list_bytes,
            max_total_bytes,
        })
    }
}

/// Every retry count is explicit and must be included in snapshot policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceEnumerationPolicyV1 {
    traversal: SourceTraversalLimitsV1,
    xattrs: SourceXattrLimitsV1,
    max_plan_bytes: NonZeroU64,
    max_data_extents: NonZeroU32,
    openat2_attempts: NonZeroU8,
    syscall_attempts: NonZeroU8,
    xattr_stability_attempts: NonZeroU8,
    regular_copy: RegularCopyPolicyV1,
}

impl SourceEnumerationPolicyV1 {
    pub(super) const fn checked(
        traversal: SourceTraversalLimitsV1,
        xattrs: SourceXattrLimitsV1,
        max_plan_bytes: NonZeroU64,
        max_data_extents: NonZeroU32,
        openat2_attempts: NonZeroU8,
        syscall_attempts: NonZeroU8,
        xattr_stability_attempts: NonZeroU8,
    ) -> Option<Self> {
        let regular_copy = match RegularCopyPolicyV1::checked(
            traversal.max_file_bytes,
            max_data_extents,
            openat2_attempts,
        ) {
            Some(policy) => policy,
            None => return None,
        };
        let path_and_name_bound = match (traversal.max_relative_path_bytes.get() as u64)
            .saturating_mul(2)
            .checked_add((traversal.max_name_bytes.get() as u64).saturating_mul(2))
        {
            Some(value) => value,
            None => return None,
        };
        // `readlinkat` does not report the required size. Each stable-read
        // buffer therefore needs one byte beyond the accepted target limit to
        // distinguish an exact-limit target from truncation. The retained
        // target keeps that capacity, and a second buffer is live while source
        // stability is checked below.
        let symlink_read_buffer_bound =
            match (traversal.max_symlink_target_bytes.get() as u64).checked_add(1) {
                Some(value) => value,
                None => return None,
            };
        let per_entry_bound = match path_and_name_bound.checked_add(symlink_read_buffer_bound) {
            Some(value) => value,
            None => return None,
        };
        let entry_bound = match (traversal.max_entries.get() as u64).checked_mul(per_entry_bound) {
            Some(value) => value,
            None => return None,
        };
        let extent_count =
            match (traversal.max_entries.get() as u64).checked_mul(max_data_extents.get() as u64) {
                Some(value) => value,
                None => return None,
            };
        let extent_bound = match extent_count.checked_mul(std::mem::size_of::<ExtentV1>() as u64) {
            Some(value) => value,
            None => return None,
        };
        let retained_with_extents = match entry_bound.checked_add(extent_bound) {
            Some(value) => value,
            None => return None,
        };
        let entry_count = traversal.max_entries.get() as u64;
        let per_entry_fixed = (std::mem::size_of::<SourceTreeEntryV1>()
            + std::mem::size_of::<SourceInodeKeyV1>()
            + std::mem::size_of::<usize>() * 4
            + std::mem::size_of::<u32>() * 2) as u64;
        let fixed_entries = match entry_count.checked_mul(per_entry_fixed) {
            Some(value) => value,
            None => return None,
        };
        let xattr_slots = match entry_count.checked_mul(xattrs.max_per_entry.get() as u64) {
            Some(value) => value,
            None => return None,
        };
        let fixed_xattrs =
            match xattr_slots.checked_mul(std::mem::size_of::<CapturedXattrV1>() as u64) {
                Some(value) => value,
                None => return None,
            };
        // One completed xattr pass remains live while the comparison pass is
        // built. The retained-plan bound below already includes all first-pass
        // `CapturedXattrV1` slots, so charge one additional entry's slots for
        // the second pass. During that pass, the parsed-name vector also owns
        // one `Box<[u8]>` slot per permitted name. Dynamic name/value bytes are
        // covered by the second `max_total_bytes` charge below.
        let transient_xattr_slots = match (xattrs.max_per_entry.get() as u64).checked_mul(
            (std::mem::size_of::<CapturedXattrV1>() + std::mem::size_of::<Box<[u8]>>()) as u64,
        ) {
            Some(value) => value,
            None => return None,
        };
        // Bound the raw list, the largest temporary NUL-terminated name, and
        // the one-byte allocation used while validating an empty xattr value.
        // These are per-entry scratch buffers, not retained-plan bytes.
        let transient_xattr_scratch = match (xattrs.max_list_bytes.get() as u64)
            .checked_add(xattrs.max_name_bytes.get() as u64)
        {
            Some(value) => match value.checked_add(2) {
                Some(value) => value,
                None => return None,
            },
            None => return None,
        };
        let retained_bound = match retained_with_extents.checked_add(xattrs.max_total_bytes.get()) {
            Some(value) => value,
            None => return None,
        };
        let retained_bound = match retained_bound.checked_add(fixed_entries) {
            Some(value) => value,
            None => return None,
        };
        let retained_bound = match retained_bound.checked_add(fixed_xattrs) {
            Some(value) => value,
            None => return None,
        };
        // A stable xattr pass holds one retained capture while building the
        // comparison capture. Charge its dynamic bytes, fixed slots, parsed
        // name slots, and bounded syscall scratch storage too.
        let retained_bound = match retained_bound.checked_add(xattrs.max_total_bytes.get()) {
            Some(value) => value,
            None => return None,
        };
        let retained_bound = match retained_bound.checked_add(transient_xattr_slots) {
            Some(value) => value,
            None => return None,
        };
        let retained_bound = match retained_bound.checked_add(transient_xattr_scratch) {
            Some(value) => value,
            None => return None,
        };
        let retained_bound = match retained_bound.checked_add(symlink_read_buffer_bound) {
            Some(value) => value,
            None => return None,
        };
        let retained_bound =
            match retained_bound.checked_add(std::mem::size_of::<SourceTreePlanV1>() as u64) {
                Some(value) => value,
                None => return None,
            };
        if max_plan_bytes.get() > HARD_MAX_PLAN_BYTES
            || max_data_extents.get() > HARD_MAX_DATA_EXTENTS
            || retained_bound > max_plan_bytes.get()
            || openat2_attempts.get() > HARD_MAX_ATTEMPTS
            || syscall_attempts.get() > HARD_MAX_ATTEMPTS
            || xattr_stability_attempts.get() > HARD_MAX_ATTEMPTS
        {
            return None;
        }
        Some(Self {
            traversal,
            xattrs,
            max_plan_bytes,
            max_data_extents,
            openat2_attempts,
            syscall_attempts,
            xattr_stability_attempts,
            regular_copy,
        })
    }

    /// Maximum source descriptors owned concurrently by this walker. The
    /// caller-owned trusted-parent FD and any visitor destination FDs are
    /// additional and must be included in the backend RLIMIT preflight.
    pub(super) const fn max_live_source_fds(self) -> u32 {
        self.traversal.max_depth as u32 * 2 + 4
    }

    pub(super) const fn max_depth(self) -> u16 {
        self.traversal.max_depth
    }

    pub(super) const fn max_entries(self) -> u32 {
        self.traversal.max_entries.get()
    }

    pub(super) const fn max_basename_bytes(self) -> u16 {
        self.traversal.max_name_bytes.get()
    }

    pub(super) const fn max_total_xattr_bytes(self) -> u64 {
        self.xattrs.max_total_bytes.get()
    }

    pub(super) const fn max_total_xattrs(self) -> u64 {
        self.traversal.max_entries.get() as u64 * self.xattrs.max_per_entry.get() as u64
    }

    pub(super) const fn max_plan_bytes(self) -> u64 {
        self.max_plan_bytes.get()
    }

    pub(super) const fn openat2_attempts(self) -> u8 {
        self.openat2_attempts.get()
    }

    pub(super) const fn syscall_attempts(self) -> u8 {
        self.syscall_attempts.get()
    }

    pub(super) const fn xattr_stability_attempts(self) -> u8 {
        self.xattr_stability_attempts.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceNodeKindV1 {
    Directory,
    Regular,
    Symlink,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct SourceInodeKeyV1 {
    mount_id: u64,
    device_major: u32,
    device_minor: u32,
    inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SourceStatxV1 {
    inode_key: SourceInodeKeyV1,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    atime: TimespecV1,
    mtime: TimespecV1,
    ctime: TimespecV1,
    btime: Option<TimespecV1>,
}

impl SourceStatxV1 {
    /// Fixed, allocation-free canonical bytes for connector-side event/plan
    /// commitments. Byte zero is the format version; every integer is little
    /// endian and optional birth time has an explicit presence byte.
    pub(super) fn commitment_bytes_v1(&self) -> [u8; 102] {
        let mut output = [0u8; 102];
        output[0] = 1;
        output[1..9].copy_from_slice(&self.inode_key.mount_id.to_le_bytes());
        output[9..13].copy_from_slice(&self.inode_key.device_major.to_le_bytes());
        output[13..17].copy_from_slice(&self.inode_key.device_minor.to_le_bytes());
        output[17..25].copy_from_slice(&self.inode_key.inode.to_le_bytes());
        output[25..29].copy_from_slice(&self.mode.to_le_bytes());
        output[29..33].copy_from_slice(&self.uid.to_le_bytes());
        output[33..37].copy_from_slice(&self.gid.to_le_bytes());
        output[37..45].copy_from_slice(&self.nlink.to_le_bytes());
        output[45..53].copy_from_slice(&self.size.to_le_bytes());
        output[53..61].copy_from_slice(&self.atime.seconds.to_le_bytes());
        output[61..65].copy_from_slice(&self.atime.nanoseconds.to_le_bytes());
        output[65..73].copy_from_slice(&self.mtime.seconds.to_le_bytes());
        output[73..77].copy_from_slice(&self.mtime.nanoseconds.to_le_bytes());
        output[77..85].copy_from_slice(&self.ctime.seconds.to_le_bytes());
        output[85..89].copy_from_slice(&self.ctime.nanoseconds.to_le_bytes());
        if let Some(btime) = &self.btime {
            output[89] = 1;
            output[90..98].copy_from_slice(&btime.seconds.to_le_bytes());
            output[98..102].copy_from_slice(&btime.nanoseconds.to_le_bytes());
        }
        output
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn for_test(
        mount_id: u64,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u64,
        size: u64,
        atime: TimespecV1,
        mtime: TimespecV1,
        ctime: TimespecV1,
        btime: Option<TimespecV1>,
    ) -> Self {
        Self {
            inode_key: SourceInodeKeyV1 {
                mount_id,
                device_major,
                device_minor,
                inode,
            },
            mode,
            uid,
            gid,
            nlink,
            size,
            atime,
            mtime,
            ctime,
            btime,
        }
    }

    pub(super) const fn inode_key(&self) -> &SourceInodeKeyV1 {
        &self.inode_key
    }

    pub(super) const fn mode(&self) -> u32 {
        self.mode
    }

    pub(super) const fn uid(&self) -> u32 {
        self.uid
    }

    pub(super) const fn gid(&self) -> u32 {
        self.gid
    }

    pub(super) const fn nlink(&self) -> u64 {
        self.nlink
    }

    pub(super) const fn size(&self) -> u64 {
        self.size
    }

    pub(super) const fn atime(&self) -> &TimespecV1 {
        &self.atime
    }

    pub(super) const fn mtime(&self) -> &TimespecV1 {
        &self.mtime
    }

    pub(super) const fn ctime(&self) -> &TimespecV1 {
        &self.ctime
    }

    pub(super) const fn btime(&self) -> Option<&TimespecV1> {
        self.btime.as_ref()
    }
}

/// A listed attribute whose value cannot be read is never silently dropped.
/// The sentinel makes the plan non-materializable until policy rejects it or
/// a privileged, separately qualified materializer proves exact replay.
#[derive(Eq, PartialEq)]
pub(super) enum CapturedXattrValueV1 {
    Bytes(Box<[u8]>),
    VisibleButUnsettable { errno: i32 },
}

#[derive(Eq, PartialEq)]
pub(super) struct CapturedXattrV1 {
    name: Box<[u8]>,
    value: CapturedXattrValueV1,
}

impl CapturedXattrV1 {
    #[cfg(test)]
    pub(super) fn bytes_for_test(name: &[u8], value: &[u8]) -> Self {
        Self {
            name: name.into(),
            value: CapturedXattrValueV1::Bytes(value.into()),
        }
    }

    #[cfg(test)]
    pub(super) fn unsettable_for_test(name: &[u8], errno: i32) -> Self {
        Self {
            name: name.into(),
            value: CapturedXattrValueV1::VisibleButUnsettable { errno },
        }
    }

    pub(super) fn name(&self) -> &[u8] {
        &self.name
    }

    pub(super) const fn value(&self) -> &CapturedXattrValueV1 {
        &self.value
    }
}

impl fmt::Debug for CapturedXattrV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match &self.value {
            CapturedXattrValueV1::Bytes(bytes) => ("bytes", bytes.len(), None),
            CapturedXattrValueV1::VisibleButUnsettable { errno } => {
                ("visible-but-unsettable", 0, Some(*errno))
            }
        };
        formatter
            .debug_struct("CapturedXattrV1")
            .field("name", &self.name)
            .field("value_kind", &value.0)
            .field("value_bytes", &value.1)
            .field("errno", &value.2)
            .finish()
    }
}

#[derive(Eq, PartialEq)]
pub(super) enum SourcePlanPayloadV1 {
    Directory {
        /// Final plan indices, sorted by raw basename bytes.
        children: Box<[u32]>,
    },
    Regular {
        evidence: SourceRegularEvidenceV1,
    },
    Symlink {
        target: Vec<u8>,
    },
}

impl SourcePlanPayloadV1 {
    pub(super) const fn kind(&self) -> SourceNodeKindV1 {
        match self {
            Self::Directory { .. } => SourceNodeKindV1::Directory,
            Self::Regular { .. } => SourceNodeKindV1::Regular,
            Self::Symlink { .. } => SourceNodeKindV1::Symlink,
        }
    }
}

#[derive(Eq, PartialEq)]
pub(super) struct SourceRegularEvidenceV1 {
    content_digest: FileContentDigest,
    data_extents: Vec<ExtentV1>,
}

impl SourceRegularEvidenceV1 {
    pub(super) fn checked(
        content_digest: FileContentDigest,
        data_extents: Vec<ExtentV1>,
        logical_size: u64,
    ) -> Option<Self> {
        if !valid_extent_sequence(&data_extents, logical_size) {
            return None;
        }
        Some(Self {
            content_digest,
            data_extents,
        })
    }

    fn validates_for(&self, logical_size: u64) -> bool {
        valid_extent_sequence(&self.data_extents, logical_size)
    }

    pub(super) const fn content_digest(&self) -> FileContentDigest {
        self.content_digest
    }

    pub(super) fn data_extents(&self) -> &[ExtentV1] {
        &self.data_extents
    }
}

fn valid_extent_sequence(data_extents: &[ExtentV1], logical_size: u64) -> bool {
    !data_extents.iter().any(|extent| {
        extent.length == 0
            || extent
                .offset
                .checked_add(extent.length)
                .is_none_or(|end| end > logical_size)
    }) && !data_extents.windows(2).any(|pair| {
        pair[0]
            .offset
            .checked_add(pair[0].length)
            .is_none_or(|end| end >= pair[1].offset)
    })
}

fn validate_regular_evidence(
    evidence: &SourceRegularEvidenceV1,
    logical_size: u64,
    max_data_extents: u32,
    max_retained_extent_bytes: u64,
) -> Result<u64, SourceTreeFailureV1> {
    if evidence.data_extents.len() > max_data_extents as usize {
        return Err(SourceTreeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            SourceTreeStageV1::VisitRegular,
            SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::DataExtents),
            None,
        ));
    }
    if !evidence.validates_for(logical_size) {
        return Err(SourceTreeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            SourceTreeStageV1::VisitRegular,
            SourceTreeFailureReasonV1::SourceChanged,
            None,
        ));
    }
    let retained_extent_bytes = (evidence.data_extents.len() as u64)
        .checked_mul(std::mem::size_of::<ExtentV1>() as u64)
        .ok_or_else(|| {
            SourceTreeFailureV1::new(
                RefusalCode::SnapshotConstructionFailed,
                SourceTreeStageV1::VisitRegular,
                SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::PlanBytes),
                None,
            )
        })?;
    if retained_extent_bytes > max_retained_extent_bytes {
        return Err(SourceTreeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            SourceTreeStageV1::VisitRegular,
            SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::PlanBytes),
            None,
        ));
    }
    Ok(retained_extent_bytes)
}

#[derive(Eq, PartialEq)]
pub(super) struct SourceTreeEntryV1 {
    relative_path: Box<[u8]>,
    basename: Box<[u8]>,
    parent_index: Option<u32>,
    statx: SourceStatxV1,
    xattrs: Box<[CapturedXattrV1]>,
    payload: SourcePlanPayloadV1,
    hardlink_group: Option<u32>,
}

impl SourceTreeEntryV1 {
    pub(super) fn relative_path(&self) -> &[u8] {
        &self.relative_path
    }

    pub(super) fn basename(&self) -> &[u8] {
        &self.basename
    }

    pub(super) const fn parent_index(&self) -> Option<u32> {
        self.parent_index
    }

    pub(super) const fn statx(&self) -> &SourceStatxV1 {
        &self.statx
    }

    pub(super) fn xattrs(&self) -> &[CapturedXattrV1] {
        &self.xattrs
    }

    pub(super) const fn payload(&self) -> &SourcePlanPayloadV1 {
        &self.payload
    }

    pub(super) const fn hardlink_group(&self) -> Option<u32> {
        self.hardlink_group
    }
}

#[derive(Eq, PartialEq)]
pub(super) struct SourceHardlinkGroupV1 {
    inode_key: SourceInodeKeyV1,
    member_indices: Box<[u32]>,
}

impl SourceHardlinkGroupV1 {
    pub(super) const fn inode_key(&self) -> &SourceInodeKeyV1 {
        &self.inode_key
    }

    pub(super) fn member_indices(&self) -> &[u32] {
        &self.member_indices
    }
}

impl fmt::Debug for SourceHardlinkGroupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceHardlinkGroupV1")
            .field("inode_key", &self.inode_key)
            .field("member_count", &self.member_indices.len())
            .finish()
    }
}

/// An immutable, FD-free record of one independently revalidated source view.
/// It does not freeze bytes or directory membership and is not snapshot
/// publication authority.
#[derive(Eq, PartialEq)]
pub(super) struct SourceTreePlanV1 {
    root_name: Box<[u8]>,
    root_mount_id: u64,
    entries: Box<[SourceTreeEntryV1]>,
    hardlink_groups: Box<[SourceHardlinkGroupV1]>,
    has_unsettable_xattrs: bool,
    max_live_source_fds: u32,
}

impl fmt::Debug for SourceTreePlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceTreePlanV1")
            .field("root_mount_id", &self.root_mount_id)
            .field("entry_count", &self.entries.len())
            .field("hardlink_group_count", &self.hardlink_groups.len())
            .field("has_unsettable_xattrs", &self.has_unsettable_xattrs)
            .field("max_live_source_fds", &self.max_live_source_fds)
            .finish()
    }
}

impl SourceTreePlanV1 {
    pub(super) fn root_name(&self) -> &[u8] {
        &self.root_name
    }

    pub(super) const fn root_mount_id(&self) -> u64 {
        self.root_mount_id
    }

    pub(super) fn entries(&self) -> &[SourceTreeEntryV1] {
        &self.entries
    }

    pub(super) fn hardlink_groups(&self) -> &[SourceHardlinkGroupV1] {
        &self.hardlink_groups
    }

    pub(super) const fn has_unsettable_xattrs(&self) -> bool {
        self.has_unsettable_xattrs
    }

    pub(super) const fn max_live_source_fds(&self) -> u32 {
        self.max_live_source_fds
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceTreeStageV1 {
    ValidatePolicy,
    DuplicateParent,
    OpenEntry,
    InspectEntry,
    OpenDirectory,
    EnumerateDirectory,
    CaptureXattrs,
    CaptureSymlink,
    VisitDirectoryEnter,
    VisitRegular,
    VisitSymlink,
    VisitDirectoryLeave,
    RevalidateEntry,
    RevalidateDirectory,
    BuildHardlinks,
    NormalizePlan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceTreeLimitV1 {
    Depth,
    NameBytes,
    RelativePathBytes,
    Entries,
    FileBytes,
    TotalFileBytes,
    SymlinkTargetBytes,
    DataExtents,
    XattrsPerEntry,
    XattrNameBytes,
    XattrValueBytes,
    XattrListBytes,
    TotalXattrBytes,
    PlanBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceTreeFailureReasonV1 {
    InvalidPolicy,
    InvalidBasename,
    RequiredKernelCapability,
    MountCrossing,
    UnsupportedObject,
    ResourceLimit(SourceTreeLimitV1),
    DuplicateDirectoryName,
    DuplicateDirectoryIdentity,
    MalformedKernelResponse,
    SourceChanged,
    ExternalHardlink,
    Io,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SourceTreeFailureV1 {
    code: RefusalCode,
    stage: SourceTreeStageV1,
    reason: SourceTreeFailureReasonV1,
    errno: Option<i32>,
}

impl SourceTreeFailureV1 {
    fn new(
        code: RefusalCode,
        stage: SourceTreeStageV1,
        reason: SourceTreeFailureReasonV1,
        errno: Option<i32>,
    ) -> Self {
        Self {
            code,
            stage,
            reason,
            errno,
        }
    }

    pub(super) const fn code(&self) -> RefusalCode {
        self.code
    }

    pub(super) const fn stage(&self) -> SourceTreeStageV1 {
        self.stage
    }

    pub(super) const fn reason(&self) -> SourceTreeFailureReasonV1 {
        self.reason
    }

    pub(super) const fn errno(&self) -> Option<i32> {
        self.errno
    }
}

impl fmt::Display for SourceTreeFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({:?}) during {:?}",
            self.code.as_str(),
            self.reason,
            self.stage
        )?;
        if let Some(errno) = self.errno {
            write!(formatter, " (errno {errno})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SourceTreeFailureV1 {}

#[derive(Clone, Copy)]
pub(super) struct SourceVisitCommonV1<'a> {
    relative_path: &'a [u8],
    name: &'a CStr,
    parent: BorrowedFd<'a>,
    handle: BorrowedFd<'a>,
    statx: &'a SourceStatxV1,
    xattrs: &'a [CapturedXattrV1],
}

impl<'a> SourceVisitCommonV1<'a> {
    pub(super) const fn relative_path(self) -> &'a [u8] {
        self.relative_path
    }

    pub(super) const fn name(self) -> &'a CStr {
        self.name
    }

    pub(super) const fn statx(self) -> &'a SourceStatxV1 {
        self.statx
    }

    pub(super) const fn xattrs(self) -> &'a [CapturedXattrV1] {
        self.xattrs
    }
}

#[derive(Clone, Copy)]
pub(super) struct SourceDirectoryVisitV1<'a> {
    common: SourceVisitCommonV1<'a>,
    membership: &'a [Box<[u8]>],
}

impl<'a> SourceDirectoryVisitV1<'a> {
    pub(super) const fn common(self) -> SourceVisitCommonV1<'a> {
        self.common
    }

    pub(super) const fn membership(self) -> &'a [Box<[u8]>] {
        self.membership
    }
}

pub(super) struct SourceRegularVisitV1<'a> {
    common: SourceVisitCommonV1<'a>,
    copy_policy: RegularCopyPolicyV1,
}

impl<'a> SourceRegularVisitV1<'a> {
    pub(super) const fn common(&self) -> SourceVisitCommonV1<'a> {
        self.common
    }

    /// Materialize this exact, already-pinned source leaf without exposing its
    /// descriptors. The copy leaf binds both the pinned inode and current name
    /// before and after copying, closing pathname-replacement and ABA windows.
    pub(super) fn copy_to(
        self,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
    ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
        // SAFETY: this visit can only be constructed by the qualified source
        // walker, and its three source capabilities remain borrowed from the
        // same callback-scoped view for this call's duration.
        unsafe {
            super::snapshot_regular::copy_regular_from_qualified_pinned_at(
                self.common.parent,
                self.common.name,
                self.common.handle,
                destination_parent,
                destination_name,
                self.copy_policy,
            )
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct SourceSymlinkVisitV1<'a> {
    common: SourceVisitCommonV1<'a>,
    target: &'a [u8],
}

impl<'a> SourceSymlinkVisitV1<'a> {
    pub(super) const fn common(self) -> SourceVisitCommonV1<'a> {
        self.common
    }

    pub(super) const fn target(self) -> &'a [u8] {
        self.target
    }
}

/// Deterministic event order is directory-enter, raw-name-sorted children,
/// directory-leave; regular and symlink leaves each emit once.  Callbacks run
/// only while both the trusted parent and pinned entry descriptors are live.
pub(super) trait SourceTreeVisitorV1 {
    type Error;

    fn directory_enter(&mut self, visit: SourceDirectoryVisitV1<'_>) -> Result<(), Self::Error>;

    fn regular(
        &mut self,
        visit: SourceRegularVisitV1<'_>,
    ) -> Result<SourceRegularEvidenceV1, Self::Error>;

    fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error>;

    fn directory_leave(&mut self, visit: SourceDirectoryVisitV1<'_>) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub(super) enum SourceTreeAcquireFailureV1<E> {
    Source(SourceTreeFailureV1),
    Visitor {
        stage: SourceTreeStageV1,
        relative_path: Box<[u8]>,
        source: E,
    },
}

impl<E> From<SourceTreeFailureV1> for SourceTreeAcquireFailureV1<E> {
    fn from(value: SourceTreeFailureV1) -> Self {
        Self::Source(value)
    }
}

pub(super) fn enumerate_source_tree_view_at<V: SourceTreeVisitorV1>(
    source_view: QualifiedNoAtimeSourceViewV1<'_>,
    root_name: &CStr,
    policy: SourceEnumerationPolicyV1,
    visitor: &mut V,
) -> Result<SourceTreePlanV1, SourceTreeAcquireFailureV1<V::Error>> {
    platform::enumerate_source_tree_view_at(source_view, root_name, policy, visitor)
}

fn valid_basename(name: &[u8], max_bytes: u16) -> bool {
    !name.is_empty()
        && name != b"."
        && name != b".."
        && !name.contains(&b'/')
        && !name.contains(&0)
        && name.len() <= max_bytes as usize
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod platform {
    use std::collections::HashSet;
    use std::ffi::CString;
    use std::io;
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

    use super::*;

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    const SOURCE_RESOLVE: u64 = RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const STATX_MNT_ID: u32 = 0x1000;
    const SYS_GETXATTRAT_X86_64: libc::c_long = 464;
    const SYS_LISTXATTRAT_X86_64: libc::c_long = 465;
    const GETDENTS_BUFFER_BYTES: usize = 32 * 1024;
    const DIRENT64_NAME_OFFSET: usize = 19;
    const ENTRY_FIXED_PLAN_BYTES: u64 = (std::mem::size_of::<BuildEntry>()
        + std::mem::size_of::<SourceTreeEntryV1>()
        + std::mem::size_of::<usize>()
        + std::mem::size_of::<u32>()) as u64;
    const DIRECTORY_MEMBER_FIXED_BYTES: u64 =
        (std::mem::size_of::<Box<[u8]>>() + std::mem::size_of::<usize>()) as u64;
    const REQUIRED_STATX_MASK: u32 = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_NLINK
        | libc::STATX_UID
        | libc::STATX_GID
        | libc::STATX_ATIME
        | libc::STATX_MTIME
        | libc::STATX_CTIME
        | libc::STATX_INO
        | libc::STATX_SIZE
        | STATX_MNT_ID;
    const REQUESTED_STATX_MASK: u32 = REQUIRED_STATX_MASK | libc::STATX_BTIME;

    #[derive(Debug)]
    enum BoundedPushReserveError {
        Full,
        Allocation,
    }

    fn try_reserve_bounded_for_push<T>(
        values: &mut Vec<T>,
        max_len: usize,
    ) -> Result<(), BoundedPushReserveError> {
        if values.len() >= max_len {
            return Err(BoundedPushReserveError::Full);
        }
        if values.len() < values.capacity() {
            return Ok(());
        }
        let target = if values.capacity() == 0 {
            1
        } else {
            values.capacity().saturating_mul(2)
        }
        .min(max_len);
        values
            .try_reserve_exact(target - values.len())
            .map_err(|_| BoundedPushReserveError::Allocation)
    }

    fn bounded_push_failure(
        relative_path: &[u8],
        error: BoundedPushReserveError,
        full_limit: SourceTreeLimitV1,
    ) -> SourceTreeFailureV1 {
        match error {
            BoundedPushReserveError::Full => limit(relative_path, full_limit),
            BoundedPushReserveError::Allocation => {
                limit(relative_path, SourceTreeLimitV1::PlanBytes)
            }
        }
    }

    const fn source_directory_open_flags() -> i32 {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    struct XattrArgs {
        value: u64,
        size: u32,
        flags: u32,
    }

    trait EnumerationHooks {
        fn list_xattrs(&self, fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize>;

        fn get_xattr(&self, fd: RawFd, name: &CStr, output: Option<&mut [u8]>)
        -> io::Result<usize>;

        fn after_directory_children(&self, _relative_path: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn after_leaf_visitor(&self, _relative_path: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn observe_live_source_fds(&self, _depth: u16, _upper_bound: u32) {}
    }

    struct KernelHooks;

    impl EnumerationHooks for KernelHooks {
        fn list_xattrs(&self, fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
            let (pointer, length) = output
                .map(|buffer| (buffer.as_mut_ptr().cast::<libc::c_char>(), buffer.len()))
                .unwrap_or((std::ptr::null_mut::<libc::c_char>(), 0));
            let result = unsafe {
                libc::syscall(
                    SYS_LISTXATTRAT_X86_64,
                    fd,
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    pointer,
                    length,
                )
            };
            syscall_size(result)
        }

        fn get_xattr(
            &self,
            fd: RawFd,
            name: &CStr,
            output: Option<&mut [u8]>,
        ) -> io::Result<usize> {
            let (pointer, length) = output
                .map(|buffer| (buffer.as_mut_ptr() as usize as u64, buffer.len()))
                .unwrap_or((0, 0));
            let size =
                u32::try_from(length).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            let mut args = XattrArgs {
                value: pointer,
                size,
                flags: 0,
            };
            let result = unsafe {
                libc::syscall(
                    SYS_GETXATTRAT_X86_64,
                    fd,
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    name.as_ptr(),
                    &mut args,
                    mem::size_of::<XattrArgs>(),
                )
            };
            syscall_size(result)
        }
    }

    fn syscall_size(result: libc::c_long) -> io::Result<usize> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            usize::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
        }
    }

    fn try_boxed_bytes(
        bytes: &[u8],
        relative_path: &[u8],
    ) -> Result<Box<[u8]>, SourceTreeFailureV1> {
        let mut owned = Vec::new();
        try_reserve_plan(&mut owned, bytes.len(), relative_path)?;
        owned.extend_from_slice(bytes);
        Ok(owned.into_boxed_slice())
    }

    fn try_reserve_plan<T>(
        values: &mut Vec<T>,
        additional: usize,
        relative_path: &[u8],
    ) -> Result<(), SourceTreeFailureV1> {
        values
            .try_reserve_exact(additional)
            .map_err(|_| limit(relative_path, SourceTreeLimitV1::PlanBytes))
    }

    fn try_cstring(
        bytes: &[u8],
        relative_path: &[u8],
        stage: SourceTreeStageV1,
    ) -> Result<CString, SourceTreeFailureV1> {
        if bytes.contains(&0) {
            return Err(malformed(stage, relative_path));
        }
        let capacity = bytes
            .len()
            .checked_add(1)
            .ok_or_else(|| limit(relative_path, SourceTreeLimitV1::PlanBytes))?;
        let mut nul_terminated = Vec::new();
        try_reserve_plan(&mut nul_terminated, capacity, relative_path)?;
        nul_terminated.extend_from_slice(bytes);
        nul_terminated.push(0);
        CString::from_vec_with_nul(nul_terminated).map_err(|_| malformed(stage, relative_path))
    }

    struct BuildEntry {
        original_index: u32,
        relative_path: Box<[u8]>,
        basename: Box<[u8]>,
        parent: Option<u32>,
        statx: SourceStatxV1,
        xattrs: Box<[CapturedXattrV1]>,
        payload: BuildPayload,
    }

    enum BuildPayload {
        Directory { children: Vec<u32> },
        Regular { evidence: SourceRegularEvidenceV1 },
        Symlink { target: Vec<u8> },
    }

    struct Builder<'a, 'v, H, V> {
        root_parent: OwnedFd,
        root_name: &'a CStr,
        policy: SourceEnumerationPolicyV1,
        hooks: &'a H,
        visitor: &'v mut V,
        root_mount_id: Option<u64>,
        entries: Vec<BuildEntry>,
        directory_identities: HashSet<SourceInodeKeyV1>,
        total_file_bytes: u64,
        total_xattr_bytes: u64,
        total_plan_bytes: u64,
    }

    pub(super) fn enumerate_source_tree_view_at<V: SourceTreeVisitorV1>(
        source_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
        policy: SourceEnumerationPolicyV1,
        visitor: &mut V,
    ) -> Result<SourceTreePlanV1, SourceTreeAcquireFailureV1<V::Error>> {
        enumerate_source_tree_view_at_with(
            source_view.trusted_parent(),
            root_name,
            policy,
            &KernelHooks,
            visitor,
        )
    }

    fn enumerate_source_tree_view_at_with<H: EnumerationHooks, V: SourceTreeVisitorV1>(
        trusted_parent: BorrowedFd<'_>,
        root_name: &CStr,
        policy: SourceEnumerationPolicyV1,
        hooks: &H,
        visitor: &mut V,
    ) -> Result<SourceTreePlanV1, SourceTreeAcquireFailureV1<V::Error>> {
        if !valid_basename(root_name.to_bytes(), policy.traversal.max_name_bytes.get()) {
            return Err(failure(
                SourceTreeStageV1::ValidatePolicy,
                SourceTreeFailureReasonV1::InvalidBasename,
                None,
                b"",
            )
            .into());
        }
        let root_parent = duplicate_fd(trusted_parent)
            .map_err(|error| io_failure(SourceTreeStageV1::DuplicateParent, b"", error))?;
        let initial_plan_bytes = (root_name.to_bytes().len() as u64)
            .checked_add(std::mem::size_of::<SourceTreePlanV1>() as u64)
            .ok_or_else(|| limit(b"", SourceTreeLimitV1::PlanBytes))?;
        if initial_plan_bytes > policy.max_plan_bytes.get() {
            return Err(limit(b"", SourceTreeLimitV1::PlanBytes).into());
        }
        let mut builder = Builder {
            root_parent,
            root_name,
            policy,
            hooks,
            visitor,
            root_mount_id: None,
            entries: Vec::new(),
            directory_identities: HashSet::new(),
            total_file_bytes: 0,
            total_xattr_bytes: 0,
            total_plan_bytes: initial_plan_bytes,
        };
        builder
            .entries
            .try_reserve_exact(1)
            .map_err(|_| limit(b"", SourceTreeLimitV1::PlanBytes))?;
        let parent_fd = duplicate_fd(builder.root_parent.as_fd())
            .map_err(|error| io_failure(SourceTreeStageV1::DuplicateParent, b"", error))?;
        let root_index =
            builder.enumerate_entry(parent_fd.as_fd(), root_name, Vec::new(), None, 0)?;
        if root_index != 0 || !matches!(builder.entries[0].payload, BuildPayload::Directory { .. })
        {
            return Err(failure(
                SourceTreeStageV1::InspectEntry,
                SourceTreeFailureReasonV1::UnsupportedObject,
                None,
                b"",
            )
            .into());
        }
        Ok(normalize_plan(builder)?)
    }

    impl<H: EnumerationHooks, V: SourceTreeVisitorV1> Builder<'_, '_, H, V> {
        fn enumerate_entry(
            &mut self,
            parent_fd: BorrowedFd<'_>,
            name: &CStr,
            relative_path: Vec<u8>,
            parent: Option<usize>,
            depth: u16,
        ) -> Result<usize, SourceTreeAcquireFailureV1<V::Error>> {
            self.check_entry_limits(name.to_bytes(), &relative_path, depth)?;
            let handle = openat2_owned(
                parent_fd,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                SOURCE_RESOLVE,
                self.policy.openat2_attempts.get(),
            )
            .map_err(|error| map_open_error(SourceTreeStageV1::OpenEntry, &relative_path, error))?;
            let statx = statx_identity(handle.as_fd()).map_err(|error| {
                map_statx_error(SourceTreeStageV1::InspectEntry, &relative_path, error)
            })?;
            self.hooks
                .observe_live_source_fds(depth, u32::from(depth) * 2 + 3);
            let mount_id = statx.inode_key.mount_id;
            match self.root_mount_id {
                Some(root) if root != mount_id => {
                    return Err(failure(
                        SourceTreeStageV1::InspectEntry,
                        SourceTreeFailureReasonV1::MountCrossing,
                        None,
                        &relative_path,
                    )
                    .into());
                }
                None => self.root_mount_id = Some(mount_id),
                _ => {}
            }
            let xattrs = capture_stable_xattrs(
                self.hooks,
                handle.as_raw_fd(),
                &relative_path,
                self.policy.xattrs,
                self.policy.xattr_stability_attempts.get(),
                self.policy
                    .xattrs
                    .max_total_bytes
                    .get()
                    .saturating_sub(self.total_xattr_bytes),
                self.remaining_plan_bytes(),
            )?;
            let (xattr_bytes, xattr_plan_bytes) = xattr_storage_bytes(&xattrs)?;
            self.total_xattr_bytes = self
                .total_xattr_bytes
                .checked_add(xattr_bytes)
                .ok_or_else(|| limit(&relative_path, SourceTreeLimitV1::TotalXattrBytes))?;
            if self.total_xattr_bytes > self.policy.xattrs.max_total_bytes.get() {
                return Err(limit(&relative_path, SourceTreeLimitV1::TotalXattrBytes).into());
            }
            self.reserve_plan_bytes(&relative_path, xattr_plan_bytes)?;

            let file_type = statx.mode & libc::S_IFMT;
            let index = self.entries.len();
            let original_index = u32::try_from(index)
                .map_err(|_| limit(&relative_path, SourceTreeLimitV1::Entries))?;
            let parent = parent
                .map(u32::try_from)
                .transpose()
                .map_err(|_| limit(&relative_path, SourceTreeLimitV1::Entries))?;
            let basename = try_boxed_bytes(name.to_bytes(), &relative_path)?;
            match file_type {
                libc::S_IFDIR => {
                    self.directory_identities
                        .try_reserve(1)
                        .map_err(|_| limit(&relative_path, SourceTreeLimitV1::PlanBytes))?;
                    if !self.directory_identities.insert(statx.inode_key.clone()) {
                        return Err(failure(
                            SourceTreeStageV1::InspectEntry,
                            SourceTreeFailureReasonV1::DuplicateDirectoryIdentity,
                            None,
                            &relative_path,
                        )
                        .into());
                    }
                    let directory = openat2_owned(
                        parent_fd,
                        name,
                        source_directory_open_flags(),
                        SOURCE_RESOLVE,
                        self.policy.openat2_attempts.get(),
                    )
                    .map_err(|error| map_directory_open_error(&relative_path, error))?;
                    self.hooks
                        .observe_live_source_fds(depth, u32::from(depth) * 2 + 4);
                    let read_statx = statx_identity(directory.as_fd()).map_err(|error| {
                        map_statx_error(SourceTreeStageV1::OpenDirectory, &relative_path, error)
                    })?;
                    if read_statx != statx {
                        return Err(source_changed(
                            SourceTreeStageV1::OpenDirectory,
                            &relative_path,
                        )
                        .into());
                    }
                    let membership = read_directory_names(
                        directory.as_fd(),
                        &relative_path,
                        self.policy.traversal,
                        self.remaining_plan_bytes(),
                        self.policy.syscall_attempts.get(),
                    )?;
                    let membership_bytes = membership
                        .iter()
                        .try_fold(0u64, |total, name| total.checked_add(name.len() as u64))
                        .ok_or_else(|| limit(&relative_path, SourceTreeLimitV1::PlanBytes))?;
                    let membership_fixed = (membership.len() as u64)
                        .checked_mul(DIRECTORY_MEMBER_FIXED_BYTES)
                        .ok_or_else(|| limit(&relative_path, SourceTreeLimitV1::PlanBytes))?;
                    self.reserve_plan_bytes(
                        &relative_path,
                        membership_bytes
                            .checked_add(membership_fixed)
                            .ok_or_else(|| limit(&relative_path, SourceTreeLimitV1::PlanBytes))?,
                    )?;
                    let additional = u32::try_from(membership.len()).unwrap_or(u32::MAX);
                    if (self.entries.len() as u32)
                        .checked_add(1)
                        .and_then(|count| count.checked_add(additional))
                        .is_none_or(|count| count > self.policy.traversal.max_entries.get())
                    {
                        return Err(limit(&relative_path, SourceTreeLimitV1::Entries).into());
                    }
                    let enter = SourceDirectoryVisitV1 {
                        common: SourceVisitCommonV1 {
                            relative_path: &relative_path,
                            name,
                            parent: parent_fd,
                            handle: handle.as_fd(),
                            statx: &statx,
                            xattrs: &xattrs,
                        },
                        membership: &membership,
                    };
                    let visitor_error_path = try_boxed_bytes(&relative_path, &relative_path)?;
                    self.visitor.directory_enter(enter).map_err(|source| {
                        SourceTreeAcquireFailureV1::Visitor {
                            stage: SourceTreeStageV1::VisitDirectoryEnter,
                            relative_path: visitor_error_path,
                            source,
                        }
                    })?;
                    try_reserve_bounded_for_push(
                        &mut self.entries,
                        self.policy.traversal.max_entries.get() as usize,
                    )
                    .map_err(|error| {
                        bounded_push_failure(&relative_path, error, SourceTreeLimitV1::Entries)
                    })?;
                    self.entries.push(BuildEntry {
                        original_index,
                        relative_path: try_boxed_bytes(&relative_path, &relative_path)?,
                        basename,
                        parent,
                        statx: statx.clone(),
                        xattrs,
                        payload: BuildPayload::Directory {
                            children: Vec::new(),
                        },
                    });
                    let mut children = Vec::new();
                    children
                        .try_reserve_exact(membership.len())
                        .map_err(|_| limit(&relative_path, SourceTreeLimitV1::PlanBytes))?;
                    for child_name in &membership {
                        let child_path = self.join_relative_path(&relative_path, child_name)?;
                        if (child_name.len() as u64)
                            .checked_add(1)
                            .is_none_or(|bytes| bytes > self.remaining_plan_bytes())
                        {
                            return Err(limit(&relative_path, SourceTreeLimitV1::PlanBytes).into());
                        }
                        let child_c = try_cstring(
                            child_name,
                            &relative_path,
                            SourceTreeStageV1::EnumerateDirectory,
                        )?;
                        let child_index = self.enumerate_entry(
                            directory.as_fd(),
                            &child_c,
                            child_path,
                            Some(index),
                            depth + 1,
                        )?;
                        children.push(
                            u32::try_from(child_index)
                                .map_err(|_| limit(&relative_path, SourceTreeLimitV1::Entries))?,
                        );
                    }
                    self.hooks
                        .after_directory_children(&relative_path)
                        .map_err(|error| {
                            io_failure(
                                SourceTreeStageV1::RevalidateDirectory,
                                &relative_path,
                                error,
                            )
                        })?;
                    let membership_storage_bytes =
                        membership_bytes
                            .checked_add(membership_fixed)
                            .ok_or_else(|| limit(&relative_path, SourceTreeLimitV1::PlanBytes))?;
                    if membership_storage_bytes > self.remaining_plan_bytes() {
                        return Err(limit(&relative_path, SourceTreeLimitV1::PlanBytes).into());
                    }
                    let membership_after = read_directory_names(
                        directory.as_fd(),
                        &relative_path,
                        self.policy.traversal,
                        membership_storage_bytes,
                        self.policy.syscall_attempts.get(),
                    )?;
                    let statx_after = statx_identity(directory.as_fd()).map_err(|error| {
                        map_statx_error(
                            SourceTreeStageV1::RevalidateDirectory,
                            &relative_path,
                            error,
                        )
                    })?;
                    let handle_after = statx_identity(handle.as_fd()).map_err(|error| {
                        map_statx_error(
                            SourceTreeStageV1::RevalidateDirectory,
                            &relative_path,
                            error,
                        )
                    })?;
                    if membership_after != membership
                        || statx_after != statx
                        || handle_after != statx
                    {
                        return Err(source_changed(
                            SourceTreeStageV1::RevalidateDirectory,
                            &relative_path,
                        )
                        .into());
                    }
                    match &mut self.entries[index].payload {
                        BuildPayload::Directory { children: stored } => *stored = children,
                        _ => unreachable!("directory payload was inserted above"),
                    }
                    let entry = &self.entries[index];
                    let leave = SourceDirectoryVisitV1 {
                        common: SourceVisitCommonV1 {
                            relative_path: &entry.relative_path,
                            name,
                            parent: parent_fd,
                            handle: handle.as_fd(),
                            statx: &entry.statx,
                            xattrs: &entry.xattrs,
                        },
                        membership: &membership,
                    };
                    let visitor_error_path = try_boxed_bytes(&relative_path, &relative_path)?;
                    self.visitor.directory_leave(leave).map_err(|source| {
                        SourceTreeAcquireFailureV1::Visitor {
                            stage: SourceTreeStageV1::VisitDirectoryLeave,
                            relative_path: visitor_error_path,
                            source,
                        }
                    })?;
                }
                libc::S_IFREG => {
                    if statx.size > self.policy.traversal.max_file_bytes.get() {
                        return Err(limit(&relative_path, SourceTreeLimitV1::FileBytes).into());
                    }
                    self.total_file_bytes = self
                        .total_file_bytes
                        .checked_add(statx.size)
                        .ok_or_else(|| limit(&relative_path, SourceTreeLimitV1::TotalFileBytes))?;
                    if self.total_file_bytes > self.policy.traversal.max_total_file_bytes.get() {
                        return Err(limit(&relative_path, SourceTreeLimitV1::TotalFileBytes).into());
                    }
                    let visitor_error_path = try_boxed_bytes(&relative_path, &relative_path)?;
                    let evidence = self
                        .visitor
                        .regular(SourceRegularVisitV1 {
                            common: SourceVisitCommonV1 {
                                relative_path: &relative_path,
                                name,
                                parent: parent_fd,
                                handle: handle.as_fd(),
                                statx: &statx,
                                xattrs: &xattrs,
                            },
                            copy_policy: self.policy.regular_copy,
                        })
                        .map_err(|source| SourceTreeAcquireFailureV1::Visitor {
                            stage: SourceTreeStageV1::VisitRegular,
                            relative_path: visitor_error_path,
                            source,
                        })?;
                    let retained_extent_bytes = validate_regular_evidence(
                        &evidence,
                        statx.size,
                        self.policy.max_data_extents.get(),
                        self.remaining_plan_bytes(),
                    )?;
                    self.reserve_plan_bytes(&relative_path, retained_extent_bytes)?;
                    self.hooks
                        .after_leaf_visitor(&relative_path)
                        .map_err(|error| {
                            SourceTreeAcquireFailureV1::Source(io_failure(
                                SourceTreeStageV1::RevalidateEntry,
                                &relative_path,
                                error,
                            ))
                        })?;
                    self.revalidate_one(parent_fd, name, handle.as_fd(), &relative_path, &statx)?;
                    try_reserve_bounded_for_push(
                        &mut self.entries,
                        self.policy.traversal.max_entries.get() as usize,
                    )
                    .map_err(|error| {
                        bounded_push_failure(&relative_path, error, SourceTreeLimitV1::Entries)
                    })?;
                    self.entries.push(BuildEntry {
                        original_index,
                        relative_path: try_boxed_bytes(&relative_path, &relative_path)?,
                        basename,
                        parent,
                        statx: statx.clone(),
                        xattrs,
                        payload: BuildPayload::Regular { evidence },
                    });
                }
                libc::S_IFLNK => {
                    let target_cap = self
                        .policy
                        .traversal
                        .max_symlink_target_bytes
                        .get()
                        .min(u32::try_from(self.remaining_plan_bytes()).unwrap_or(u32::MAX));
                    let target = read_stable_symlink_target(
                        &handle,
                        &relative_path,
                        target_cap,
                        self.remaining_plan_bytes(),
                    )?;
                    self.reserve_plan_bytes(&relative_path, target.capacity() as u64)?;
                    let visitor_error_path = try_boxed_bytes(&relative_path, &relative_path)?;
                    self.visitor
                        .symlink(SourceSymlinkVisitV1 {
                            common: SourceVisitCommonV1 {
                                relative_path: &relative_path,
                                name,
                                parent: parent_fd,
                                handle: handle.as_fd(),
                                statx: &statx,
                                xattrs: &xattrs,
                            },
                            target: &target,
                        })
                        .map_err(|source| SourceTreeAcquireFailureV1::Visitor {
                            stage: SourceTreeStageV1::VisitSymlink,
                            relative_path: visitor_error_path,
                            source,
                        })?;
                    self.hooks
                        .after_leaf_visitor(&relative_path)
                        .map_err(|error| {
                            SourceTreeAcquireFailureV1::Source(io_failure(
                                SourceTreeStageV1::RevalidateEntry,
                                &relative_path,
                                error,
                            ))
                        })?;
                    self.revalidate_one(parent_fd, name, handle.as_fd(), &relative_path, &statx)?;
                    try_reserve_bounded_for_push(
                        &mut self.entries,
                        self.policy.traversal.max_entries.get() as usize,
                    )
                    .map_err(|error| {
                        bounded_push_failure(&relative_path, error, SourceTreeLimitV1::Entries)
                    })?;
                    self.entries.push(BuildEntry {
                        original_index,
                        relative_path: try_boxed_bytes(&relative_path, &relative_path)?,
                        basename,
                        parent,
                        statx: statx.clone(),
                        xattrs,
                        payload: BuildPayload::Symlink { target },
                    });
                }
                _ => {
                    return Err(failure(
                        SourceTreeStageV1::InspectEntry,
                        SourceTreeFailureReasonV1::UnsupportedObject,
                        None,
                        &relative_path,
                    )
                    .into());
                }
            }
            Ok(index)
        }

        fn check_entry_limits(
            &mut self,
            name: &[u8],
            relative_path: &[u8],
            depth: u16,
        ) -> Result<(), SourceTreeAcquireFailureV1<V::Error>> {
            if depth > self.policy.traversal.max_depth {
                return Err(limit(relative_path, SourceTreeLimitV1::Depth).into());
            }
            if !valid_basename(name, self.policy.traversal.max_name_bytes.get()) {
                return Err(limit(relative_path, SourceTreeLimitV1::NameBytes).into());
            }
            if relative_path.len() > self.policy.traversal.max_relative_path_bytes.get() as usize {
                return Err(limit(relative_path, SourceTreeLimitV1::RelativePathBytes).into());
            }
            if self.entries.len() >= self.policy.traversal.max_entries.get() as usize {
                return Err(limit(relative_path, SourceTreeLimitV1::Entries).into());
            }
            self.reserve_plan_bytes(
                relative_path,
                (name.len() as u64)
                    .checked_add(ENTRY_FIXED_PLAN_BYTES)
                    .ok_or_else(|| limit(relative_path, SourceTreeLimitV1::PlanBytes))?,
            )?;
            Ok(())
        }

        fn remaining_plan_bytes(&self) -> u64 {
            self.policy
                .max_plan_bytes
                .get()
                .saturating_sub(self.total_plan_bytes)
        }

        fn reserve_plan_bytes(
            &mut self,
            relative_path: &[u8],
            additional: u64,
        ) -> Result<(), SourceTreeFailureV1> {
            let total = self
                .total_plan_bytes
                .checked_add(additional)
                .ok_or_else(|| limit(relative_path, SourceTreeLimitV1::PlanBytes))?;
            if total > self.policy.max_plan_bytes.get() {
                return Err(limit(relative_path, SourceTreeLimitV1::PlanBytes));
            }
            self.total_plan_bytes = total;
            Ok(())
        }

        fn join_relative_path(
            &mut self,
            parent: &[u8],
            name: &[u8],
        ) -> Result<Vec<u8>, SourceTreeFailureV1> {
            let separator = usize::from(!parent.is_empty());
            let length = parent
                .len()
                .checked_add(separator)
                .and_then(|value| value.checked_add(name.len()))
                .ok_or_else(|| limit(parent, SourceTreeLimitV1::RelativePathBytes))?;
            if length > self.policy.traversal.max_relative_path_bytes.get() as usize {
                return Err(limit(parent, SourceTreeLimitV1::RelativePathBytes));
            }
            self.reserve_plan_bytes(parent, length as u64)?;
            let mut path = Vec::new();
            path.try_reserve_exact(length)
                .map_err(|_| limit(parent, SourceTreeLimitV1::PlanBytes))?;
            path.extend_from_slice(parent);
            if separator != 0 {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            Ok(path)
        }

        fn revalidate_one(
            &self,
            parent_fd: BorrowedFd<'_>,
            name: &CStr,
            handle: BorrowedFd<'_>,
            relative_path: &[u8],
            expected: &SourceStatxV1,
        ) -> Result<(), SourceTreeFailureV1> {
            let reopened = openat2_owned(
                parent_fd,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                SOURCE_RESOLVE,
                self.policy.openat2_attempts.get(),
            )
            .map_err(|error| map_reopen_error(relative_path, error))?;
            let pinned = statx_identity(handle).map_err(|error| {
                map_statx_error(SourceTreeStageV1::RevalidateEntry, relative_path, error)
            })?;
            let named = statx_identity(reopened.as_fd()).map_err(|error| {
                map_statx_error(SourceTreeStageV1::RevalidateEntry, relative_path, error)
            })?;
            if &pinned != expected || &named != expected {
                return Err(source_changed(
                    SourceTreeStageV1::RevalidateEntry,
                    relative_path,
                ));
            }
            Ok(())
        }
    }

    fn normalize_plan<H: EnumerationHooks, V: SourceTreeVisitorV1>(
        builder: Builder<'_, '_, H, V>,
    ) -> Result<SourceTreePlanV1, SourceTreeFailureV1> {
        let remaining_plan_bytes = builder
            .policy
            .max_plan_bytes
            .get()
            .saturating_sub(builder.total_plan_bytes);
        let mut build_entries = builder.entries;
        build_entries.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if build_entries
            .windows(2)
            .any(|pair| pair[0].relative_path >= pair[1].relative_path)
        {
            return Err(failure(
                SourceTreeStageV1::NormalizePlan,
                SourceTreeFailureReasonV1::DuplicateDirectoryName,
                None,
                b"",
            ));
        }
        let mut remap = Vec::new();
        remap
            .try_reserve_exact(build_entries.len())
            .map_err(|_| limit(b"", SourceTreeLimitV1::PlanBytes))?;
        remap.resize(build_entries.len(), 0u32);
        for (new, entry) in build_entries.iter().enumerate() {
            remap[entry.original_index as usize] =
                u32::try_from(new).map_err(|_| limit(b"", SourceTreeLimitV1::Entries))?;
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(build_entries.len())
            .map_err(|_| limit(b"", SourceTreeLimitV1::PlanBytes))?;
        for entry in build_entries {
            let parent_index = entry.parent.map(|old| remap[old as usize]);
            let payload = match entry.payload {
                BuildPayload::Directory { mut children } => {
                    for old in &mut children {
                        *old = remap[*old as usize];
                    }
                    children.sort_unstable();
                    SourcePlanPayloadV1::Directory {
                        children: children.into_boxed_slice(),
                    }
                }
                BuildPayload::Regular { evidence } => SourcePlanPayloadV1::Regular { evidence },
                BuildPayload::Symlink { target } => SourcePlanPayloadV1::Symlink { target },
            };
            entries.push(SourceTreeEntryV1 {
                relative_path: entry.relative_path,
                basename: entry.basename,
                parent_index,
                statx: entry.statx,
                xattrs: entry.xattrs,
                payload,
                hardlink_group: None,
            });
        }
        let hardlink_groups = build_hardlink_groups(&mut entries, remaining_plan_bytes)?;
        let has_unsettable_xattrs = entries.iter().any(|entry| {
            entry.xattrs.iter().any(|xattr| {
                matches!(
                    xattr.value,
                    CapturedXattrValueV1::VisibleButUnsettable { .. }
                )
            })
        });
        Ok(SourceTreePlanV1 {
            root_name: try_boxed_bytes(builder.root_name.to_bytes(), b"")?,
            root_mount_id: builder.root_mount_id.ok_or_else(|| {
                failure(
                    SourceTreeStageV1::NormalizePlan,
                    SourceTreeFailureReasonV1::SourceChanged,
                    None,
                    b"",
                )
            })?,
            entries: entries.into_boxed_slice(),
            hardlink_groups: hardlink_groups.into_boxed_slice(),
            has_unsettable_xattrs,
            max_live_source_fds: builder.policy.max_live_source_fds(),
        })
    }

    fn build_hardlink_groups(
        entries: &mut [SourceTreeEntryV1],
        max_additional_bytes: u64,
    ) -> Result<Vec<SourceHardlinkGroupV1>, SourceTreeFailureV1> {
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(entries.len())
            .map_err(|_| limit(b"", SourceTreeLimitV1::PlanBytes))?;
        for (index, entry) in entries.iter().enumerate() {
            if matches!(
                entry.payload,
                SourcePlanPayloadV1::Regular { .. } | SourcePlanPayloadV1::Symlink { .. }
            ) {
                candidates.push(index);
            }
        }
        candidates.sort_unstable_by(|left, right| {
            entries[*left]
                .statx
                .inode_key
                .cmp(&entries[*right].statx.inode_key)
                .then_with(|| {
                    entries[*left]
                        .relative_path
                        .cmp(&entries[*right].relative_path)
                })
        });
        let mut groups = Vec::new();
        let mut retained_bytes = 0u64;
        let mut start = 0usize;
        while start < candidates.len() {
            let mut end = start + 1;
            while end < candidates.len()
                && entries[candidates[end]].statx.inode_key
                    == entries[candidates[start]].statx.inode_key
            {
                end += 1;
            }
            let members = &candidates[start..end];
            let expected_nlink = entries[members[0]].statx.nlink;
            let member_count = members.len() as u64;
            if expected_nlink != member_count {
                let reason = if expected_nlink > member_count {
                    SourceTreeFailureReasonV1::ExternalHardlink
                } else {
                    SourceTreeFailureReasonV1::SourceChanged
                };
                return Err(failure(
                    SourceTreeStageV1::BuildHardlinks,
                    reason,
                    None,
                    &entries[members[0]].relative_path,
                ));
            }
            if members.iter().any(|index| {
                entries[*index].statx != entries[members[0]].statx
                    || entries[*index].payload != entries[members[0]].payload
                    || entries[*index].xattrs != entries[members[0]].xattrs
            }) {
                return Err(source_changed(
                    SourceTreeStageV1::BuildHardlinks,
                    &entries[members[0]].relative_path,
                ));
            }
            if member_count == 1 {
                start = end;
                continue;
            }
            let retained_index_bytes = (members.len() as u64)
                .checked_mul(std::mem::size_of::<u32>() as u64)
                .ok_or_else(|| limit(b"", SourceTreeLimitV1::PlanBytes))?;
            retained_bytes = retained_bytes
                .checked_add(retained_index_bytes)
                .and_then(|value| {
                    value.checked_add(std::mem::size_of::<SourceHardlinkGroupV1>() as u64)
                })
                .ok_or_else(|| limit(b"", SourceTreeLimitV1::PlanBytes))?;
            if retained_bytes > max_additional_bytes {
                return Err(limit(b"", SourceTreeLimitV1::PlanBytes));
            }
            let mut member_indices = Vec::new();
            member_indices
                .try_reserve_exact(members.len())
                .map_err(|_| limit(b"", SourceTreeLimitV1::PlanBytes))?;
            for index in members {
                member_indices.push(
                    u32::try_from(*index).map_err(|_| limit(b"", SourceTreeLimitV1::Entries))?,
                );
            }
            try_reserve_bounded_for_push(&mut groups, entries.len() / 2)
                .map_err(|error| bounded_push_failure(b"", error, SourceTreeLimitV1::Entries))?;
            groups.push(SourceHardlinkGroupV1 {
                inode_key: entries[members[0]].statx.inode_key.clone(),
                member_indices: member_indices.into_boxed_slice(),
            });
            start = end;
        }
        // Entries are globally raw-path sorted, so member-index ordering is
        // exactly the former member-path ordering without retaining paths twice.
        groups.sort_unstable_by(|left, right| left.member_indices.cmp(&right.member_indices));
        // The canonical path ordering above defines group indices only now.
        for (group_index, group) in groups.iter().enumerate() {
            let group_index =
                u32::try_from(group_index).map_err(|_| limit(b"", SourceTreeLimitV1::Entries))?;
            for member in &group.member_indices {
                entries[*member as usize].hardlink_group = Some(group_index);
            }
        }
        Ok(groups)
    }

    fn read_directory_names(
        fd: BorrowedFd<'_>,
        relative_path: &[u8],
        limits: SourceTraversalLimitsV1,
        max_retained_storage_bytes: u64,
        syscall_attempts: u8,
    ) -> Result<Vec<Box<[u8]>>, SourceTreeFailureV1> {
        if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
            return Err(io_failure(
                SourceTreeStageV1::EnumerateDirectory,
                relative_path,
                io::Error::last_os_error(),
            ));
        }
        let mut output = Vec::new();
        let mut retained_name_bytes = 0u64;
        let mut buffer = [0u8; GETDENTS_BUFFER_BYTES];
        loop {
            let used = getdents64_with_retry(syscall_attempts, || unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            })
            .map_err(|error| {
                io_failure(SourceTreeStageV1::EnumerateDirectory, relative_path, error)
            })?;
            if used == 0 {
                break;
            }
            if used > buffer.len() {
                return Err(malformed(
                    SourceTreeStageV1::EnumerateDirectory,
                    relative_path,
                ));
            }
            parse_dirent_chunk(
                &buffer[..used],
                &mut output,
                relative_path,
                limits,
                max_retained_storage_bytes,
                &mut retained_name_bytes,
            )?;
        }
        normalize_directory_names(output, relative_path)
    }

    fn getdents64_with_retry(
        attempts: u8,
        mut operation: impl FnMut() -> libc::c_long,
    ) -> io::Result<usize> {
        for _ in 0..attempts {
            let result = operation();
            if result >= 0 {
                return usize::try_from(result)
                    .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Err(io::Error::from_raw_os_error(libc::EINTR))
    }

    fn normalize_directory_names(
        mut output: Vec<Box<[u8]>>,
        relative_path: &[u8],
    ) -> Result<Vec<Box<[u8]>>, SourceTreeFailureV1> {
        output.sort_unstable();
        if output.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(failure(
                SourceTreeStageV1::EnumerateDirectory,
                SourceTreeFailureReasonV1::DuplicateDirectoryName,
                None,
                relative_path,
            ));
        }
        Ok(output)
    }

    fn parse_dirent_chunk(
        mut bytes: &[u8],
        output: &mut Vec<Box<[u8]>>,
        relative_path: &[u8],
        limits: SourceTraversalLimitsV1,
        max_retained_storage_bytes: u64,
        retained_name_bytes: &mut u64,
    ) -> Result<(), SourceTreeFailureV1> {
        while !bytes.is_empty() {
            if bytes.len() < DIRENT64_NAME_OFFSET + 1 {
                return Err(malformed(
                    SourceTreeStageV1::EnumerateDirectory,
                    relative_path,
                ));
            }
            let record_length = u16::from_ne_bytes([bytes[16], bytes[17]]) as usize;
            if record_length < DIRENT64_NAME_OFFSET + 1 || record_length > bytes.len() {
                return Err(malformed(
                    SourceTreeStageV1::EnumerateDirectory,
                    relative_path,
                ));
            }
            let record = &bytes[..record_length];
            let name_region = &record[DIRENT64_NAME_OFFSET..];
            let nul = name_region
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| malformed(SourceTreeStageV1::EnumerateDirectory, relative_path))?;
            let name = &name_region[..nul];
            if name != b"." && name != b".." {
                if !valid_basename(name, limits.max_name_bytes.get()) {
                    return Err(limit(relative_path, SourceTreeLimitV1::NameBytes));
                }
                if output.len() >= limits.max_entries.get() as usize {
                    return Err(limit(relative_path, SourceTreeLimitV1::Entries));
                }
                let retained = retained_name_bytes.checked_add(name.len() as u64);
                let storage = retained.and_then(|bytes| {
                    ((output.len() + 1) as u64)
                        .checked_mul(std::mem::size_of::<Box<[u8]>>() as u64)
                        .and_then(|fixed| bytes.checked_add(fixed))
                });
                if storage.is_none_or(|bytes| bytes > max_retained_storage_bytes) {
                    return Err(limit(relative_path, SourceTreeLimitV1::PlanBytes));
                }
                *retained_name_bytes = retained.expect("checked above");
                // `d_type` at byte 18 is deliberately ignored.
                try_reserve_bounded_for_push(output, limits.max_entries.get() as usize).map_err(
                    |error| bounded_push_failure(relative_path, error, SourceTreeLimitV1::Entries),
                )?;
                output.push(try_boxed_bytes(name, relative_path)?);
            }
            bytes = &bytes[record_length..];
        }
        Ok(())
    }

    enum XattrPassError {
        Retry(Option<i32>),
        Fatal(SourceTreeFailureV1),
    }

    fn capture_stable_xattrs<H: EnumerationHooks>(
        hooks: &H,
        fd: RawFd,
        relative_path: &[u8],
        limits: SourceXattrLimitsV1,
        attempts: u8,
        max_xattr_bytes: u64,
        max_plan_bytes: u64,
    ) -> Result<Box<[CapturedXattrV1]>, SourceTreeFailureV1> {
        let mut last_errno = None;
        for _ in 0..attempts {
            let first = match capture_xattr_pass(
                hooks,
                fd,
                relative_path,
                limits,
                max_xattr_bytes,
                max_plan_bytes,
            ) {
                Ok(value) => value,
                Err(XattrPassError::Retry(errno)) => {
                    last_errno = errno;
                    continue;
                }
                Err(XattrPassError::Fatal(error)) => return Err(error),
            };
            let second = match capture_xattr_pass(
                hooks,
                fd,
                relative_path,
                limits,
                max_xattr_bytes,
                max_plan_bytes,
            ) {
                Ok(value) => value,
                Err(XattrPassError::Retry(errno)) => {
                    last_errno = errno;
                    continue;
                }
                Err(XattrPassError::Fatal(error)) => return Err(error),
            };
            let (_, first_plan_bytes) = xattr_storage_bytes(&first)?;
            let (_, second_plan_bytes) = xattr_storage_bytes(&second)?;
            let combined_plan_bytes = first_plan_bytes
                .checked_add(second_plan_bytes)
                .ok_or_else(|| limit(relative_path, SourceTreeLimitV1::PlanBytes))?;
            if combined_plan_bytes > max_plan_bytes {
                return Err(limit(relative_path, SourceTreeLimitV1::PlanBytes));
            }
            if first == second {
                return Ok(first.into_boxed_slice());
            }
        }
        Err(SourceTreeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            SourceTreeStageV1::CaptureXattrs,
            SourceTreeFailureReasonV1::SourceChanged,
            last_errno,
        ))
    }

    fn capture_xattr_pass<H: EnumerationHooks>(
        hooks: &H,
        fd: RawFd,
        relative_path: &[u8],
        limits: SourceXattrLimitsV1,
        max_xattr_bytes: u64,
        max_plan_bytes: u64,
    ) -> Result<Vec<CapturedXattrV1>, XattrPassError> {
        let list_size = hooks
            .list_xattrs(fd, None)
            .map_err(|error| map_xattr_call(relative_path, error))?;
        if list_size > limits.max_list_bytes.get() as usize {
            return Err(XattrPassError::Fatal(limit(
                relative_path,
                SourceTreeLimitV1::XattrListBytes,
            )));
        }
        if list_size as u64 > max_xattr_bytes {
            return Err(XattrPassError::Fatal(limit(
                relative_path,
                SourceTreeLimitV1::TotalXattrBytes,
            )));
        }
        if list_size as u64 > max_plan_bytes {
            return Err(XattrPassError::Fatal(limit(
                relative_path,
                SourceTreeLimitV1::PlanBytes,
            )));
        }
        let mut list = Vec::new();
        list.try_reserve_exact(list_size.max(1)).map_err(|_| {
            XattrPassError::Fatal(limit(relative_path, SourceTreeLimitV1::PlanBytes))
        })?;
        list.resize(list_size.max(1), 0);
        let used = hooks
            .list_xattrs(fd, Some(&mut list))
            .map_err(|error| map_xattr_call(relative_path, error))?;
        if used > list_size {
            return Err(XattrPassError::Retry(Some(libc::ERANGE)));
        }
        list.truncate(used);
        let mut names = parse_xattr_names(&list, relative_path, limits)?;
        // Names must be unique, so stable ordering has no semantic value.
        // Keep sorting in-place so the preflight does not need a hidden
        // allocator-dependent stable-sort scratch term.
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(XattrPassError::Fatal(failure(
                SourceTreeStageV1::CaptureXattrs,
                SourceTreeFailureReasonV1::MalformedKernelResponse,
                None,
                relative_path,
            )));
        }
        let mut captured = Vec::new();
        captured.try_reserve_exact(names.len()).map_err(|_| {
            XattrPassError::Fatal(limit(relative_path, SourceTreeLimitV1::PlanBytes))
        })?;
        let mut retained_bytes = names
            .iter()
            .try_fold(0u64, |total, name| total.checked_add(name.len() as u64))
            .ok_or_else(|| {
                XattrPassError::Fatal(limit(relative_path, SourceTreeLimitV1::TotalXattrBytes))
            })?;
        if retained_bytes > max_xattr_bytes {
            return Err(XattrPassError::Fatal(limit(
                relative_path,
                SourceTreeLimitV1::TotalXattrBytes,
            )));
        }
        let fixed_bytes = (names.len() as u64)
            .checked_mul(std::mem::size_of::<CapturedXattrV1>() as u64)
            .ok_or_else(|| {
                XattrPassError::Fatal(limit(relative_path, SourceTreeLimitV1::PlanBytes))
            })?;
        if retained_bytes
            .checked_add(fixed_bytes)
            .is_none_or(|bytes| bytes > max_plan_bytes)
        {
            return Err(XattrPassError::Fatal(limit(
                relative_path,
                SourceTreeLimitV1::PlanBytes,
            )));
        }
        for name in names {
            if retained_bytes
                .checked_add(fixed_bytes)
                .and_then(|bytes| bytes.checked_add(name.len() as u64 + 1))
                .is_none_or(|bytes| bytes > max_plan_bytes)
            {
                return Err(XattrPassError::Fatal(limit(
                    relative_path,
                    SourceTreeLimitV1::PlanBytes,
                )));
            }
            let c_name = try_cstring(&name, relative_path, SourceTreeStageV1::CaptureXattrs)
                .map_err(XattrPassError::Fatal)?;
            let value = match hooks.get_xattr(fd, &c_name, None) {
                Ok(size) => {
                    if size > limits.max_value_bytes.get() as usize {
                        return Err(XattrPassError::Fatal(limit(
                            relative_path,
                            SourceTreeLimitV1::XattrValueBytes,
                        )));
                    }
                    retained_bytes = retained_bytes.checked_add(size as u64).ok_or_else(|| {
                        XattrPassError::Fatal(limit(
                            relative_path,
                            SourceTreeLimitV1::TotalXattrBytes,
                        ))
                    })?;
                    if retained_bytes > max_xattr_bytes {
                        return Err(XattrPassError::Fatal(limit(
                            relative_path,
                            SourceTreeLimitV1::TotalXattrBytes,
                        )));
                    }
                    if retained_bytes
                        .checked_add(fixed_bytes)
                        .is_none_or(|bytes| bytes > max_plan_bytes)
                    {
                        return Err(XattrPassError::Fatal(limit(
                            relative_path,
                            SourceTreeLimitV1::PlanBytes,
                        )));
                    }
                    let mut value = Vec::new();
                    value.try_reserve_exact(size.max(1)).map_err(|_| {
                        XattrPassError::Fatal(limit(relative_path, SourceTreeLimitV1::PlanBytes))
                    })?;
                    value.resize(size.max(1), 0);
                    let used = hooks
                        .get_xattr(fd, &c_name, Some(&mut value))
                        .map_err(|error| map_xattr_call(relative_path, error))?;
                    if used > size {
                        return Err(XattrPassError::Retry(Some(libc::ERANGE)));
                    }
                    value.truncate(used);
                    CapturedXattrValueV1::Bytes(value.into_boxed_slice())
                }
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EACCES | libc::EPERM | libc::EOPNOTSUPP)
                    ) =>
                {
                    CapturedXattrValueV1::VisibleButUnsettable {
                        errno: error.raw_os_error().expect("matched Some errno"),
                    }
                }
                Err(error) => return Err(map_xattr_call(relative_path, error)),
            };
            captured.push(CapturedXattrV1 { name, value });
        }
        Ok(captured)
    }

    fn parse_xattr_names(
        bytes: &[u8],
        relative_path: &[u8],
        limits: SourceXattrLimitsV1,
    ) -> Result<Vec<Box<[u8]>>, XattrPassError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        if *bytes.last().expect("nonempty") != 0 {
            return Err(XattrPassError::Fatal(malformed(
                SourceTreeStageV1::CaptureXattrs,
                relative_path,
            )));
        }
        let mut names = Vec::new();
        for name in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
            if name.is_empty() {
                return Err(XattrPassError::Fatal(malformed(
                    SourceTreeStageV1::CaptureXattrs,
                    relative_path,
                )));
            }
            if name.len() > limits.max_name_bytes.get() as usize {
                return Err(XattrPassError::Fatal(limit(
                    relative_path,
                    SourceTreeLimitV1::XattrNameBytes,
                )));
            }
            try_reserve_bounded_for_push(&mut names, limits.max_per_entry.get() as usize).map_err(
                |error| {
                    XattrPassError::Fatal(bounded_push_failure(
                        relative_path,
                        error,
                        SourceTreeLimitV1::XattrsPerEntry,
                    ))
                },
            )?;
            let mut owned = Vec::new();
            owned.try_reserve_exact(name.len()).map_err(|_| {
                XattrPassError::Fatal(limit(relative_path, SourceTreeLimitV1::PlanBytes))
            })?;
            owned.extend_from_slice(name);
            names.push(owned.into_boxed_slice());
        }
        Ok(names)
    }

    fn map_xattr_call(relative_path: &[u8], error: io::Error) -> XattrPassError {
        match error.raw_os_error() {
            Some(libc::ERANGE | libc::ENODATA) => XattrPassError::Retry(error.raw_os_error()),
            Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG) => {
                XattrPassError::Fatal(SourceTreeFailureV1::new(
                    RefusalCode::RequiredKernelCapabilityMissing,
                    SourceTreeStageV1::CaptureXattrs,
                    SourceTreeFailureReasonV1::RequiredKernelCapability,
                    error.raw_os_error(),
                ))
            }
            _ => XattrPassError::Fatal(io_failure(
                SourceTreeStageV1::CaptureXattrs,
                relative_path,
                error,
            )),
        }
    }

    fn xattr_storage_bytes(xattrs: &[CapturedXattrV1]) -> Result<(u64, u64), SourceTreeFailureV1> {
        let dynamic = xattrs.iter().try_fold(0u64, |total, xattr| {
            let value = match &xattr.value {
                CapturedXattrValueV1::Bytes(value) => value.len(),
                CapturedXattrValueV1::VisibleButUnsettable { .. } => 0,
            };
            total
                .checked_add((xattr.name.len() + value) as u64)
                .ok_or_else(|| limit(b"", SourceTreeLimitV1::TotalXattrBytes))
        })?;
        let plan = dynamic
            .checked_add(
                (xattrs.len() as u64)
                    .checked_mul(std::mem::size_of::<CapturedXattrV1>() as u64)
                    .ok_or_else(|| limit(b"", SourceTreeLimitV1::PlanBytes))?,
            )
            .ok_or_else(|| limit(b"", SourceTreeLimitV1::PlanBytes))?;
        Ok((dynamic, plan))
    }

    fn read_stable_symlink_target(
        handle: &OwnedFd,
        relative_path: &[u8],
        max_bytes: u32,
        max_plan_bytes: u64,
    ) -> Result<Vec<u8>, SourceTreeFailureV1> {
        let first = read_symlink_target_once(handle.as_fd(), relative_path, max_bytes)?;
        let second = read_symlink_target_once(handle.as_fd(), relative_path, max_bytes)?;
        if (first.capacity() as u64)
            .checked_add(second.capacity() as u64)
            .is_none_or(|bytes| bytes > max_plan_bytes)
        {
            return Err(limit(relative_path, SourceTreeLimitV1::PlanBytes));
        }
        if first != second {
            return Err(source_changed(
                SourceTreeStageV1::CaptureSymlink,
                relative_path,
            ));
        }
        Ok(first)
    }

    fn read_symlink_target_once(
        fd: BorrowedFd<'_>,
        relative_path: &[u8],
        max_bytes: u32,
    ) -> Result<Vec<u8>, SourceTreeFailureV1> {
        let maximum_capacity = usize::try_from(max_bytes)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| limit(relative_path, SourceTreeLimitV1::SymlinkTargetBytes))?;
        let mut capacity = maximum_capacity.min(256);
        loop {
            let mut output = Vec::new();
            output
                .try_reserve_exact(capacity)
                .map_err(|_| limit(relative_path, SourceTreeLimitV1::PlanBytes))?;
            output.resize(capacity, 0);
            let result = unsafe {
                libc::readlinkat(
                    fd.as_raw_fd(),
                    c"".as_ptr(),
                    output.as_mut_ptr().cast(),
                    output.len(),
                )
            };
            if result < 0 {
                return Err(io_failure(
                    SourceTreeStageV1::CaptureSymlink,
                    relative_path,
                    io::Error::last_os_error(),
                ));
            }
            let used = result as usize;
            if used < capacity {
                if used == 0 || output[..used].contains(&0) {
                    return Err(malformed(SourceTreeStageV1::CaptureSymlink, relative_path));
                }
                output.truncate(used);
                return Ok(output);
            }
            if capacity == maximum_capacity {
                return Err(limit(relative_path, SourceTreeLimitV1::SymlinkTargetBytes));
            }
            capacity = capacity
                .checked_mul(2)
                .unwrap_or(maximum_capacity)
                .min(maximum_capacity);
        }
    }

    fn duplicate_fd(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
        let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(result) })
        }
    }

    fn openat2_owned(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        resolve: u64,
        attempts: u8,
    ) -> io::Result<OwnedFd> {
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve,
        };
        let mut last = io::Error::from_raw_os_error(libc::EAGAIN);
        for _ in 0..attempts {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    &how,
                    mem::size_of::<OpenHow>(),
                )
            };
            if result >= 0 {
                return Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) });
            }
            last = io::Error::last_os_error();
            if last.raw_os_error() != Some(libc::EAGAIN) {
                return Err(last);
            }
        }
        Err(last)
    }

    fn statx_identity(fd: BorrowedFd<'_>) -> io::Result<SourceStatxV1> {
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                fd.as_raw_fd(),
                c"".as_ptr(),
                AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                REQUESTED_STATX_MASK,
                raw.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe { raw.assume_init() };
        if raw.stx_mask & REQUIRED_STATX_MASK != REQUIRED_STATX_MASK {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        Ok(SourceStatxV1 {
            inode_key: SourceInodeKeyV1 {
                mount_id: raw.stx_mnt_id,
                device_major: raw.stx_dev_major,
                device_minor: raw.stx_dev_minor,
                inode: raw.stx_ino,
            },
            mode: u32::from(raw.stx_mode),
            uid: raw.stx_uid,
            gid: raw.stx_gid,
            nlink: u64::from(raw.stx_nlink),
            size: raw.stx_size,
            atime: TimespecV1 {
                seconds: raw.stx_atime.tv_sec,
                nanoseconds: raw.stx_atime.tv_nsec,
            },
            mtime: TimespecV1 {
                seconds: raw.stx_mtime.tv_sec,
                nanoseconds: raw.stx_mtime.tv_nsec,
            },
            ctime: TimespecV1 {
                seconds: raw.stx_ctime.tv_sec,
                nanoseconds: raw.stx_ctime.tv_nsec,
            },
            btime: (raw.stx_mask & libc::STATX_BTIME != 0).then_some(TimespecV1 {
                seconds: raw.stx_btime.tv_sec,
                nanoseconds: raw.stx_btime.tv_nsec,
            }),
        })
    }

    fn map_open_error(
        stage: SourceTreeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SourceTreeFailureV1 {
        let errno = error.raw_os_error();
        match errno {
            Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG) => failure(
                stage,
                SourceTreeFailureReasonV1::RequiredKernelCapability,
                errno,
                relative_path,
            ),
            Some(libc::EXDEV | libc::ELOOP) => failure(
                stage,
                SourceTreeFailureReasonV1::MountCrossing,
                errno,
                relative_path,
            ),
            _ => io_failure(stage, relative_path, error),
        }
    }

    fn map_directory_open_error(relative_path: &[u8], error: io::Error) -> SourceTreeFailureV1 {
        if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
            failure(
                SourceTreeStageV1::OpenDirectory,
                SourceTreeFailureReasonV1::UnsupportedObject,
                error.raw_os_error(),
                relative_path,
            )
        } else {
            map_open_error(SourceTreeStageV1::OpenDirectory, relative_path, error)
        }
    }

    fn map_reopen_error(relative_path: &[u8], error: io::Error) -> SourceTreeFailureV1 {
        match error.raw_os_error() {
            Some(libc::ENOENT | libc::ESTALE | libc::EAGAIN) => failure(
                SourceTreeStageV1::RevalidateEntry,
                SourceTreeFailureReasonV1::SourceChanged,
                error.raw_os_error(),
                relative_path,
            ),
            _ => map_open_error(SourceTreeStageV1::RevalidateEntry, relative_path, error),
        }
    }

    fn map_statx_error(
        stage: SourceTreeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SourceTreeFailureV1 {
        match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP) => failure(
                stage,
                SourceTreeFailureReasonV1::RequiredKernelCapability,
                error.raw_os_error(),
                relative_path,
            ),
            _ => io_failure(stage, relative_path, error),
        }
    }

    fn malformed(stage: SourceTreeStageV1, relative_path: &[u8]) -> SourceTreeFailureV1 {
        failure(
            stage,
            SourceTreeFailureReasonV1::MalformedKernelResponse,
            None,
            relative_path,
        )
    }

    fn source_changed(stage: SourceTreeStageV1, relative_path: &[u8]) -> SourceTreeFailureV1 {
        failure(
            stage,
            SourceTreeFailureReasonV1::SourceChanged,
            None,
            relative_path,
        )
    }

    fn limit(relative_path: &[u8], limit: SourceTreeLimitV1) -> SourceTreeFailureV1 {
        failure(
            SourceTreeStageV1::ValidatePolicy,
            SourceTreeFailureReasonV1::ResourceLimit(limit),
            None,
            relative_path,
        )
    }

    fn io_failure(
        stage: SourceTreeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SourceTreeFailureV1 {
        failure(
            stage,
            SourceTreeFailureReasonV1::Io,
            error.raw_os_error(),
            relative_path,
        )
    }

    fn failure(
        stage: SourceTreeStageV1,
        reason: SourceTreeFailureReasonV1,
        errno: Option<i32>,
        _relative_path: &[u8],
    ) -> SourceTreeFailureV1 {
        let code = match reason {
            SourceTreeFailureReasonV1::RequiredKernelCapability => {
                RefusalCode::RequiredKernelCapabilityMissing
            }
            SourceTreeFailureReasonV1::MountCrossing
            | SourceTreeFailureReasonV1::UnsupportedObject
            | SourceTreeFailureReasonV1::ExternalHardlink => {
                RefusalCode::SnapshotRequiredObjectUnsupported
            }
            _ => RefusalCode::SnapshotConstructionFailed,
        };
        SourceTreeFailureV1::new(code, stage, reason, errno)
    }

    #[cfg(test)]
    mod tests {
        use std::cell::{Cell, RefCell};
        use std::collections::BTreeMap;
        use std::convert::Infallible;
        use std::ffi::OsString;
        use std::fs::{self, File, OpenOptions};
        use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::*;

        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

        #[test]
        fn bounded_push_reserve_accepts_last_slot_and_reports_exact_ceiling() {
            let mut zero_capacity: Vec<()> = Vec::new();
            assert!(matches!(
                try_reserve_bounded_for_push(&mut zero_capacity, 0),
                Err(BoundedPushReserveError::Full)
            ));

            let mut maximum_ceiling = Vec::new();
            assert!(try_reserve_bounded_for_push(&mut maximum_ceiling, usize::MAX).is_ok());
            maximum_ceiling.push(());

            let mut values = Vec::new();
            for expected_len in 0..3 {
                assert!(try_reserve_bounded_for_push(&mut values, 3).is_ok());
                values.push(expected_len);
            }
            assert!(matches!(
                try_reserve_bounded_for_push(&mut values, 3),
                Err(BoundedPushReserveError::Full)
            ));
            assert!(matches!(
                bounded_push_failure(
                    b"path",
                    BoundedPushReserveError::Full,
                    SourceTreeLimitV1::Entries
                )
                .reason(),
                SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::Entries)
            ));
            assert!(matches!(
                bounded_push_failure(
                    b"path",
                    BoundedPushReserveError::Allocation,
                    SourceTreeLimitV1::Entries,
                )
                .reason(),
                SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::PlanBytes)
            ));
        }

        struct TestTree {
            parent: PathBuf,
            root: PathBuf,
        }

        impl TestTree {
            fn new() -> Self {
                let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let parent = std::env::temp_dir().join(format!(
                    "again-snapshot-tree-{}-{serial}",
                    std::process::id()
                ));
                let root = parent.join("tree");
                fs::create_dir_all(&root).unwrap();
                Self { parent, root }
            }

            fn open_parent(&self) -> File {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                    .open(&self.parent)
                    .unwrap()
            }
        }

        impl Drop for TestTree {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.parent);
            }
        }

        type BarrierAction = Box<dyn FnOnce() -> io::Result<()>>;

        #[derive(Default)]
        struct TestHooks {
            directory_action: RefCell<Option<(Vec<u8>, BarrierAction)>>,
            leaf_action: RefCell<Option<(Vec<u8>, BarrierAction)>>,
            fd_observations: RefCell<Vec<(u16, u32)>>,
        }

        impl TestHooks {
            fn mutate_directory(
                relative_path: &[u8],
                action: impl FnOnce() -> io::Result<()> + 'static,
            ) -> Self {
                Self {
                    directory_action: RefCell::new(Some((
                        relative_path.to_vec(),
                        Box::new(action),
                    ))),
                    ..Self::default()
                }
            }

            fn mutate_leaf(
                relative_path: &[u8],
                action: impl FnOnce() -> io::Result<()> + 'static,
            ) -> Self {
                Self {
                    leaf_action: RefCell::new(Some((relative_path.to_vec(), Box::new(action)))),
                    ..Self::default()
                }
            }
        }

        impl EnumerationHooks for TestHooks {
            fn list_xattrs(&self, _fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
                if let Some(output) = output {
                    assert!(!output.is_empty());
                }
                Ok(0)
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                _name: &CStr,
                _output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(libc::ENODATA))
            }

            fn after_directory_children(&self, relative_path: &[u8]) -> io::Result<()> {
                let should_run = self
                    .directory_action
                    .borrow()
                    .as_ref()
                    .is_some_and(|(target, _)| target == relative_path);
                if should_run {
                    let (_, action) = self
                        .directory_action
                        .borrow_mut()
                        .take()
                        .expect("checked above");
                    action()?;
                }
                Ok(())
            }

            fn after_leaf_visitor(&self, relative_path: &[u8]) -> io::Result<()> {
                let should_run = self
                    .leaf_action
                    .borrow()
                    .as_ref()
                    .is_some_and(|(target, _)| target == relative_path);
                if should_run {
                    let (_, action) = self.leaf_action.borrow_mut().take().expect("checked above");
                    action()?;
                }
                Ok(())
            }

            fn observe_live_source_fds(&self, depth: u16, live: u32) {
                self.fd_observations.borrow_mut().push((depth, live));
            }
        }

        #[derive(Default)]
        struct RecordingVisitor {
            events: Vec<(u8, Vec<u8>)>,
        }

        impl SourceTreeVisitorV1 for RecordingVisitor {
            type Error = Infallible;

            fn directory_enter(
                &mut self,
                visit: SourceDirectoryVisitV1<'_>,
            ) -> Result<(), Self::Error> {
                self.events
                    .push((b'E', visit.common().relative_path().to_vec()));
                Ok(())
            }

            fn regular(
                &mut self,
                visit: SourceRegularVisitV1<'_>,
            ) -> Result<SourceRegularEvidenceV1, Self::Error> {
                let common = visit.common();
                self.events.push((b'R', common.relative_path().to_vec()));
                let size = common.statx().size();
                let extents = if size == 0 {
                    Vec::new()
                } else {
                    vec![ExtentV1 {
                        offset: 0,
                        length: size,
                    }]
                };
                let seed = common.statx().inode_key().inode as u8;
                Ok(
                    SourceRegularEvidenceV1::checked(FileContentDigest([seed; 32]), extents, size)
                        .unwrap(),
                )
            }

            fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error> {
                self.events
                    .push((b'S', visit.common().relative_path().to_vec()));
                Ok(())
            }

            fn directory_leave(
                &mut self,
                visit: SourceDirectoryVisitV1<'_>,
            ) -> Result<(), Self::Error> {
                self.events
                    .push((b'L', visit.common().relative_path().to_vec()));
                Ok(())
            }
        }

        fn policy(max_depth: u16, max_entries: u32) -> SourceEnumerationPolicyV1 {
            let traversal = SourceTraversalLimitsV1::checked(
                max_depth,
                NonZeroU16::new(255).unwrap(),
                NonZeroU32::new(4096).unwrap(),
                NonZeroU32::new(max_entries).unwrap(),
                NonZeroU32::new(4096).unwrap(),
                NonZeroU64::new(1024 * 1024).unwrap(),
                NonZeroU64::new(16 * 1024 * 1024).unwrap(),
            )
            .unwrap();
            let xattrs = SourceXattrLimitsV1::checked(
                NonZeroU16::new(64).unwrap(),
                NonZeroU16::new(255).unwrap(),
                NonZeroU32::new(64 * 1024).unwrap(),
                NonZeroU32::new(64 * 1024).unwrap(),
                NonZeroU64::new(1024 * 1024).unwrap(),
            )
            .unwrap();
            SourceEnumerationPolicyV1::checked(
                traversal,
                xattrs,
                NonZeroU64::new(64 * 1024 * 1024).unwrap(),
                NonZeroU32::new(64).unwrap(),
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(3).unwrap(),
                NonZeroU8::new(2).unwrap(),
            )
            .unwrap()
        }

        fn enumerate(
            tree: &TestTree,
            policy: SourceEnumerationPolicyV1,
            hooks: &impl EnumerationHooks,
            visitor: &mut RecordingVisitor,
        ) -> Result<SourceTreePlanV1, SourceTreeAcquireFailureV1<Infallible>> {
            let parent = tree.open_parent();
            enumerate_source_tree_view_at_with(parent.as_fd(), c"tree", policy, hooks, visitor)
        }

        fn source_failure<E>(failure: SourceTreeAcquireFailureV1<E>) -> SourceTreeFailureV1 {
            match failure {
                SourceTreeAcquireFailureV1::Source(failure) => failure,
                SourceTreeAcquireFailureV1::Visitor { .. } => {
                    panic!("unexpected visitor failure")
                }
            }
        }

        fn event(kind: u8, path: &[u8]) -> (u8, Vec<u8>) {
            (kind, path.to_vec())
        }

        #[test]
        fn raw_names_sort_strictly_and_duplicates_are_refused() {
            let names = vec![
                Box::<[u8]>::from(b"z".as_slice()),
                Box::<[u8]>::from(b"\xff".as_slice()),
                Box::<[u8]>::from(b"a".as_slice()),
            ];
            assert_eq!(
                normalize_directory_names(names, b"dir").unwrap(),
                vec![
                    Box::<[u8]>::from(b"a".as_slice()),
                    Box::<[u8]>::from(b"z".as_slice()),
                    Box::<[u8]>::from(b"\xff".as_slice()),
                ]
            );
            let duplicate = normalize_directory_names(
                vec![
                    Box::<[u8]>::from(b"same".as_slice()),
                    Box::<[u8]>::from(b"same".as_slice()),
                ],
                b"dir",
            )
            .unwrap_err();
            assert_eq!(
                duplicate.reason(),
                SourceTreeFailureReasonV1::DuplicateDirectoryName
            );
        }

        #[test]
        fn getdents_retry_succeeds_on_exact_n_and_exhausts_after_n_interrupts() {
            let mut success_calls = 0;
            let size = getdents64_with_retry(3, || {
                success_calls += 1;
                if success_calls == 3 {
                    17
                } else {
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    -1
                }
            })
            .unwrap();
            assert_eq!(size, 17);
            assert_eq!(success_calls, 3);

            let mut exhausted_calls = 0;
            let error = getdents64_with_retry(3, || {
                exhausted_calls += 1;
                unsafe { *libc::__errno_location() = libc::EINTR };
                -1
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(exhausted_calls, 3);

            let failure = io_failure(SourceTreeStageV1::EnumerateDirectory, b"dir", error);
            assert_eq!(failure.stage(), SourceTreeStageV1::EnumerateDirectory);
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::Io);
            assert_eq!(failure.errno(), Some(libc::EINTR));
        }

        #[test]
        fn impossible_allocation_is_a_typed_plan_limit() {
            let mut values = Vec::<u8>::new();
            let failure = try_reserve_plan(&mut values, usize::MAX, b"attacker-count")
                .expect_err("capacity overflow must not abort");
            assert_eq!(failure.stage(), SourceTreeStageV1::ValidatePolicy);
            assert_eq!(
                failure.reason(),
                SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::PlanBytes)
            );
        }

        #[test]
        fn qualified_source_directory_flags_do_not_require_file_ownership() {
            assert_eq!(source_directory_open_flags() & libc::O_NOATIME, 0);
            assert_ne!(source_directory_open_flags() & libc::O_DIRECTORY, 0);
            assert_ne!(source_directory_open_flags() & libc::O_NOFOLLOW, 0);
        }

        #[test]
        fn open_error_mapping_preserves_the_call_site_stage() {
            for stage in [
                SourceTreeStageV1::OpenEntry,
                SourceTreeStageV1::OpenDirectory,
                SourceTreeStageV1::RevalidateEntry,
            ] {
                let failure =
                    map_open_error(stage, b"entry", io::Error::from_raw_os_error(libc::EIO));
                assert_eq!(failure.stage(), stage);
                assert_eq!(failure.reason(), SourceTreeFailureReasonV1::Io);
            }
        }

        #[test]
        fn actual_proc_mount_crossing_is_rejected_before_source_reads() {
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open("/")
                .unwrap();
            let mut visitor = RecordingVisitor::default();
            let failure = source_failure(
                enumerate_source_tree_view_at_with(
                    root.as_fd(),
                    c"proc",
                    policy(2, 2),
                    &TestHooks::default(),
                    &mut visitor,
                )
                .unwrap_err(),
            );
            assert_eq!(failure.stage(), SourceTreeStageV1::OpenEntry);
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::MountCrossing);
            assert_eq!(failure.errno(), Some(libc::EXDEV));
            assert!(visitor.events.is_empty());
        }

        #[test]
        fn raw_order_and_all_supported_kinds_produce_normalized_fd_free_plan() {
            let tree = TestTree::new();
            fs::write(tree.root.join("z"), b"z").unwrap();
            fs::write(tree.root.join("a"), b"a").unwrap();
            fs::hard_link(tree.root.join("a"), tree.root.join("h")).unwrap();
            fs::create_dir(tree.root.join("d")).unwrap();
            fs::write(tree.root.join("d/q"), b"q").unwrap();
            std::os::unix::fs::symlink("target", tree.root.join("s")).unwrap();
            let raw_name = OsString::from_vec(vec![0xff]);
            fs::write(tree.root.join(&raw_name), b"raw").unwrap();

            let hooks = TestHooks::default();
            let mut visitor = RecordingVisitor::default();
            let plan = enumerate(&tree, policy(16, 64), &hooks, &mut visitor).unwrap();

            assert_eq!(
                visitor.events,
                vec![
                    event(b'E', b""),
                    event(b'R', b"a"),
                    event(b'E', b"d"),
                    event(b'R', b"d/q"),
                    event(b'L', b"d"),
                    event(b'R', b"h"),
                    event(b'S', b"s"),
                    event(b'R', b"z"),
                    event(b'R', b"\xff"),
                    event(b'L', b""),
                ]
            );
            let paths = plan
                .entries()
                .iter()
                .map(|entry| entry.relative_path().to_vec())
                .collect::<Vec<_>>();
            assert_eq!(
                paths,
                vec![
                    b"".to_vec(),
                    b"a".to_vec(),
                    b"d".to_vec(),
                    b"d/q".to_vec(),
                    b"h".to_vec(),
                    b"s".to_vec(),
                    b"z".to_vec(),
                    b"\xff".to_vec(),
                ]
            );
            assert_eq!(plan.hardlink_groups().len(), 1);
            assert_eq!(plan.hardlink_groups()[0].member_indices(), &[1, 4]);
            let symlink = plan
                .entries()
                .iter()
                .find(|entry| entry.relative_path() == b"s")
                .unwrap();
            assert!(matches!(
                symlink.payload(),
                SourcePlanPayloadV1::Symlink { target } if target.as_slice() == b"target"
            ));
        }

        #[test]
        fn external_hardlink_is_refused() {
            let tree = TestTree::new();
            fs::write(tree.root.join("inside"), b"x").unwrap();
            fs::hard_link(tree.root.join("inside"), tree.parent.join("outside")).unwrap();
            let mut visitor = RecordingVisitor::default();
            let failure = source_failure(
                enumerate(&tree, policy(4, 8), &TestHooks::default(), &mut visitor).unwrap_err(),
            );
            assert_eq!(failure.stage(), SourceTreeStageV1::BuildHardlinks);
            assert_eq!(
                failure.reason(),
                SourceTreeFailureReasonV1::ExternalHardlink
            );
        }

        #[test]
        fn directory_membership_mutation_at_barrier_is_refused() {
            let tree = TestTree::new();
            let added = tree.root.join("added");
            let hooks = TestHooks::mutate_directory(b"", move || fs::write(added, b"x"));
            let mut visitor = RecordingVisitor::default();
            let failure =
                source_failure(enumerate(&tree, policy(4, 8), &hooks, &mut visitor).unwrap_err());
            assert_eq!(failure.stage(), SourceTreeStageV1::RevalidateDirectory);
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::SourceChanged);
        }

        #[test]
        fn final_name_replacement_after_leaf_visitor_is_refused() {
            let tree = TestTree::new();
            fs::write(tree.root.join("victim"), b"old").unwrap();
            let victim = tree.root.join("victim");
            let displaced = tree.parent.join("displaced");
            let hooks = TestHooks::mutate_leaf(b"victim", move || {
                fs::rename(&victim, displaced)?;
                fs::write(victim, b"new")
            });
            let mut visitor = RecordingVisitor::default();
            let failure =
                source_failure(enumerate(&tree, policy(4, 8), &hooks, &mut visitor).unwrap_err());
            assert_eq!(failure.stage(), SourceTreeStageV1::RevalidateEntry);
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::SourceChanged);
        }

        #[derive(Clone)]
        enum MockXattrValue {
            Bytes(Vec<u8>),
            Errno(i32),
        }

        struct StableXattrHooks {
            list: Vec<u8>,
            values: BTreeMap<Vec<u8>, MockXattrValue>,
        }

        impl StableXattrHooks {
            fn copy_response(bytes: &[u8], output: Option<&mut [u8]>) -> io::Result<usize> {
                let Some(output) = output else {
                    return Ok(bytes.len());
                };
                if output.len() < bytes.len() {
                    return Err(io::Error::from_raw_os_error(libc::ERANGE));
                }
                output[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
        }

        impl EnumerationHooks for StableXattrHooks {
            fn list_xattrs(&self, _fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
                Self::copy_response(&self.list, output)
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                name: &CStr,
                output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                match self.values.get(name.to_bytes()).expect("mocked name") {
                    MockXattrValue::Bytes(bytes) => Self::copy_response(bytes.as_slice(), output),
                    MockXattrValue::Errno(errno) => {
                        Err(io::Error::from_raw_os_error(errno.to_owned()))
                    }
                }
            }
        }

        struct AlternatingXattrHooks {
            pass: Cell<usize>,
        }

        impl EnumerationHooks for AlternatingXattrHooks {
            fn list_xattrs(&self, _fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
                if output.is_none() {
                    self.pass.set(self.pass.get() + 1);
                }
                StableXattrHooks::copy_response(b"user.a\0", output)
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                _name: &CStr,
                output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                let value = if self.pass.get() % 2 == 0 { b"b" } else { b"a" };
                StableXattrHooks::copy_response(value, output)
            }
        }

        struct MissingXattrHooks;

        impl EnumerationHooks for MissingXattrHooks {
            fn list_xattrs(&self, _fd: RawFd, _output: Option<&mut [u8]>) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(libc::ENOSYS))
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                _name: &CStr,
                _output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                unreachable!()
            }
        }

        fn xattr_limits(total: u64) -> SourceXattrLimitsV1 {
            SourceXattrLimitsV1::checked(
                NonZeroU16::new(8).unwrap(),
                NonZeroU16::new(64).unwrap(),
                NonZeroU32::new(1024).unwrap(),
                NonZeroU32::new(1024).unwrap(),
                NonZeroU64::new(total).unwrap(),
            )
            .unwrap()
        }

        #[test]
        fn xattrs_are_sorted_and_preserve_unsettable_sentinel() {
            let hooks = StableXattrHooks {
                list: b"user.z\0user.a\0".to_vec(),
                values: BTreeMap::from([
                    (b"user.a".to_vec(), MockXattrValue::Bytes(b"value".to_vec())),
                    (b"user.z".to_vec(), MockXattrValue::Errno(libc::EPERM)),
                ]),
            };
            let captured =
                capture_stable_xattrs(&hooks, -1, b"file", xattr_limits(64), 2, 64, 1024).unwrap();
            assert_eq!(captured[0].name(), b"user.a");
            assert_eq!(captured[1].name(), b"user.z");
            assert!(matches!(
                captured[1].value(),
                CapturedXattrValueV1::VisibleButUnsettable { errno } if *errno == libc::EPERM
            ));
        }

        #[test]
        fn xattr_capture_accepts_empty_value_with_one_byte_read_scratch() {
            let hooks = StableXattrHooks {
                list: b"user.a\0".to_vec(),
                values: BTreeMap::from([(b"user.a".to_vec(), MockXattrValue::Bytes(Vec::new()))]),
            };
            let exact_dynamic_bytes = b"user.a".len() as u64;
            let two_pass_plan =
                2 * (exact_dynamic_bytes + std::mem::size_of::<CapturedXattrV1>() as u64);
            let captured = capture_stable_xattrs(
                &hooks,
                -1,
                b"file",
                xattr_limits(exact_dynamic_bytes),
                1,
                exact_dynamic_bytes,
                two_pass_plan,
            )
            .unwrap();
            assert!(matches!(
                captured[0].value(),
                CapturedXattrValueV1::Bytes(value) if value.is_empty()
            ));
        }

        #[test]
        fn xattr_instability_malformed_payload_and_missing_syscall_fail_closed() {
            let unstable = capture_stable_xattrs(
                &AlternatingXattrHooks { pass: Cell::new(0) },
                -1,
                b"file",
                xattr_limits(64),
                2,
                64,
                1024,
            )
            .unwrap_err();
            assert_eq!(unstable.reason(), SourceTreeFailureReasonV1::SourceChanged);

            for list in [b"user.a".to_vec(), b"user.a\0user.a\0".to_vec()] {
                let malformed_hooks = StableXattrHooks {
                    list,
                    values: BTreeMap::new(),
                };
                let malformed = capture_stable_xattrs(
                    &malformed_hooks,
                    -1,
                    b"file",
                    xattr_limits(64),
                    1,
                    64,
                    1024,
                )
                .unwrap_err();
                assert_eq!(
                    malformed.reason(),
                    SourceTreeFailureReasonV1::MalformedKernelResponse
                );
            }

            let missing = capture_stable_xattrs(
                &MissingXattrHooks,
                -1,
                b"file",
                xattr_limits(64),
                1,
                64,
                1024,
            )
            .unwrap_err();
            assert_eq!(
                missing.reason(),
                SourceTreeFailureReasonV1::RequiredKernelCapability
            );
            assert_eq!(missing.code(), RefusalCode::RequiredKernelCapabilityMissing);
        }

        #[test]
        fn xattr_retained_byte_cap_accepts_exact_and_rejects_cap_plus_one() {
            let hooks = StableXattrHooks {
                list: b"user.a\0".to_vec(),
                values: BTreeMap::from([(
                    b"user.a".to_vec(),
                    MockXattrValue::Bytes(b"1234".to_vec()),
                )]),
            };
            let exact = b"user.a".len() as u64 + 4;
            assert!(
                capture_stable_xattrs(&hooks, -1, b"file", xattr_limits(exact), 1, exact, 1024,)
                    .is_ok()
            );
            let failure =
                capture_stable_xattrs(&hooks, -1, b"file", xattr_limits(exact), 1, exact - 1, 1024)
                    .unwrap_err();
            assert_eq!(
                failure.reason(),
                SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::TotalXattrBytes)
            );
            let two_pass_plan = 2 * (exact + std::mem::size_of::<CapturedXattrV1>() as u64);
            assert!(
                capture_stable_xattrs(
                    &hooks,
                    -1,
                    b"file",
                    xattr_limits(exact),
                    1,
                    exact,
                    two_pass_plan,
                )
                .is_ok()
            );
            let plan_failure = capture_stable_xattrs(
                &hooks,
                -1,
                b"file",
                xattr_limits(exact),
                1,
                exact,
                two_pass_plan - 1,
            )
            .unwrap_err();
            assert_eq!(
                plan_failure.reason(),
                SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::PlanBytes)
            );
        }

        fn synthetic_statx(inode: u64, mode: u32, nlink: u64, size: u64) -> SourceStatxV1 {
            let time = TimespecV1 {
                seconds: 1,
                nanoseconds: 2,
            };
            SourceStatxV1 {
                inode_key: SourceInodeKeyV1 {
                    mount_id: 3,
                    device_major: 4,
                    device_minor: 5,
                    inode,
                },
                mode,
                uid: 6,
                gid: 7,
                nlink,
                size,
                atime: time.clone(),
                mtime: time.clone(),
                ctime: time.clone(),
                btime: Some(time),
            }
        }

        fn synthetic_entry(
            path: &[u8],
            statx: SourceStatxV1,
            payload: SourcePlanPayloadV1,
        ) -> SourceTreeEntryV1 {
            SourceTreeEntryV1 {
                relative_path: path.into(),
                basename: path.into(),
                parent_index: None,
                statx,
                xattrs: Box::new([]),
                payload,
                hardlink_group: None,
            }
        }

        #[test]
        fn hardlink_members_require_exact_regular_evidence_and_symlink_target() {
            let statx = synthetic_statx(11, libc::S_IFREG | 0o644, 2, 1);
            let regular = |seed| SourcePlanPayloadV1::Regular {
                evidence: SourceRegularEvidenceV1::checked(
                    FileContentDigest([seed; 32]),
                    vec![ExtentV1 {
                        offset: 0,
                        length: 1,
                    }],
                    1,
                )
                .unwrap(),
            };
            let mut entries = vec![
                synthetic_entry(b"a", statx.clone(), regular(1)),
                synthetic_entry(b"b", statx, regular(2)),
            ];
            let failure = build_hardlink_groups(&mut entries, 16).unwrap_err();
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::SourceChanged);

            let statx = synthetic_statx(12, libc::S_IFLNK | 0o777, 2, 1);
            let mut entries = vec![
                synthetic_entry(
                    b"a",
                    statx.clone(),
                    SourcePlanPayloadV1::Symlink {
                        target: b"x".to_vec(),
                    },
                ),
                synthetic_entry(
                    b"b",
                    statx,
                    SourcePlanPayloadV1::Symlink {
                        target: b"y".to_vec(),
                    },
                ),
            ];
            let failure = build_hardlink_groups(&mut entries, 16).unwrap_err();
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::SourceChanged);
        }

        #[test]
        fn entry_cap_and_deep_tree_source_fd_peak_are_exact() {
            let tree = TestTree::new();
            fs::write(tree.root.join("file"), b"").unwrap();
            let mut visitor = RecordingVisitor::default();
            assert!(enumerate(&tree, policy(2, 2), &TestHooks::default(), &mut visitor,).is_ok());
            let mut visitor = RecordingVisitor::default();
            let failure = source_failure(
                enumerate(&tree, policy(2, 1), &TestHooks::default(), &mut visitor).unwrap_err(),
            );
            assert_eq!(
                failure.reason(),
                SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::Entries)
            );

            let deep = TestTree::new();
            let mut cursor = deep.root.clone();
            for index in 0..8 {
                cursor = cursor.join(format!("d{index}"));
                fs::create_dir(&cursor).unwrap();
            }
            let hooks = TestHooks::default();
            let mut visitor = RecordingVisitor::default();
            let plan = enumerate(&deep, policy(8, 16), &hooks, &mut visitor).unwrap();
            let committed_bound = 2 * 8 + 4;
            assert_eq!(plan.max_live_source_fds(), committed_bound);
            let observations = hooks.fd_observations.borrow();
            assert_eq!(
                observations.iter().map(|(_, live)| *live).max(),
                Some(committed_bound)
            );
            assert!(
                observations
                    .iter()
                    .all(|(_, live)| *live <= committed_bound)
            );
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod platform {
    use super::*;

    pub(super) fn enumerate_source_tree_view_at<V: SourceTreeVisitorV1>(
        _source_view: QualifiedNoAtimeSourceViewV1<'_>,
        _root_name: &CStr,
        _policy: SourceEnumerationPolicyV1,
        _visitor: &mut V,
    ) -> Result<SourceTreePlanV1, SourceTreeAcquireFailureV1<V::Error>> {
        #[cfg(not(target_os = "linux"))]
        let code = RefusalCode::UnsupportedOs;
        #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
        let code = RefusalCode::UnsupportedArchitecture;
        Err(SourceTreeAcquireFailureV1::Source(
            SourceTreeFailureV1::new(
                code,
                SourceTreeStageV1::ValidatePolicy,
                SourceTreeFailureReasonV1::RequiredKernelCapability,
                None,
            ),
        ))
    }
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    fn traversal() -> SourceTraversalLimitsV1 {
        SourceTraversalLimitsV1::checked(
            16,
            NonZeroU16::new(255).unwrap(),
            NonZeroU32::new(4096).unwrap(),
            NonZeroU32::new(4096).unwrap(),
            NonZeroU32::new(4096).unwrap(),
            NonZeroU64::new(16 * 1024 * 1024).unwrap(),
            NonZeroU64::new(64 * 1024 * 1024).unwrap(),
        )
        .unwrap()
    }

    fn xattrs() -> SourceXattrLimitsV1 {
        SourceXattrLimitsV1::checked(
            NonZeroU16::new(64).unwrap(),
            NonZeroU16::new(255).unwrap(),
            NonZeroU32::new(64 * 1024).unwrap(),
            NonZeroU32::new(64 * 1024).unwrap(),
            NonZeroU64::new(1024 * 1024).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn policy_hard_ceilings_and_basename_rules_are_frozen() {
        let committed = SourceEnumerationPolicyV1::checked(
            traversal(),
            xattrs(),
            NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            NonZeroU32::new(64).unwrap(),
            NonZeroU8::new(4).unwrap(),
            NonZeroU8::new(3).unwrap(),
            NonZeroU8::new(4).unwrap(),
        )
        .unwrap();
        assert_eq!(committed.regular_copy.max_logical_bytes(), 16 * 1024 * 1024);
        assert_eq!(committed.regular_copy.max_data_extents(), 64);
        assert_eq!(committed.regular_copy.openat2_attempts(), 4);
        assert_eq!(committed.syscall_attempts(), 3);
        assert_eq!(committed.max_basename_bytes(), 255);
        assert!(valid_basename(b"raw-\xff", 255));
        for invalid in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
            assert!(!valid_basename(invalid, 255));
        }
        assert!(
            SourceTraversalLimitsV1::checked(
                HARD_MAX_DEPTH + 1,
                NonZeroU16::new(255).unwrap(),
                NonZeroU32::new(4096).unwrap(),
                NonZeroU32::new(4096).unwrap(),
                NonZeroU32::new(4096).unwrap(),
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1).unwrap(),
            )
            .is_none()
        );

        let incompatible_file = SourceTraversalLimitsV1::checked(
            1,
            NonZeroU16::new(1).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU64::new(1024 * 1024 * 1024 + 1).unwrap(),
            NonZeroU64::new(1024 * 1024 * 1024 + 1).unwrap(),
        )
        .unwrap();
        assert!(
            SourceEnumerationPolicyV1::checked(
                incompatible_file,
                xattrs(),
                NonZeroU64::new(HARD_MAX_PLAN_BYTES).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
        assert!(
            SourceEnumerationPolicyV1::checked(
                traversal(),
                xattrs(),
                NonZeroU64::new(HARD_MAX_PLAN_BYTES).unwrap(),
                NonZeroU32::new(HARD_MAX_DATA_EXTENTS + 1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
        assert!(
            SourceEnumerationPolicyV1::checked(
                traversal(),
                xattrs(),
                NonZeroU64::new(HARD_MAX_PLAN_BYTES).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(HARD_MAX_ATTEMPTS + 1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
        assert!(
            SourceEnumerationPolicyV1::checked(
                traversal(),
                xattrs(),
                NonZeroU64::new(HARD_MAX_PLAN_BYTES).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(HARD_MAX_ATTEMPTS + 1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
        assert!(
            SourceEnumerationPolicyV1::checked(
                traversal(),
                xattrs(),
                NonZeroU64::new(HARD_MAX_PLAN_BYTES).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(HARD_MAX_ATTEMPTS + 1).unwrap(),
            )
            .is_none()
        );
    }

    #[test]
    fn policy_accepts_exact_symlink_and_two_pass_xattr_peak_and_rejects_one_less() {
        let traversal = SourceTraversalLimitsV1::checked(
            2,
            NonZeroU16::new(2).unwrap(),
            NonZeroU32::new(3).unwrap(),
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(4).unwrap(),
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
        let xattrs = SourceXattrLimitsV1::checked(
            NonZeroU16::new(1).unwrap(),
            NonZeroU16::new(2).unwrap(),
            NonZeroU32::new(3).unwrap(),
            NonZeroU32::new(4).unwrap(),
            NonZeroU64::new(5).unwrap(),
        )
        .unwrap();
        let max_extents = NonZeroU32::new(1).unwrap();
        let symlink_read_buffer = traversal.max_symlink_target_bytes.get() as u64 + 1;
        let captured_xattr_slot = std::mem::size_of::<CapturedXattrV1>() as u64;
        let transient_xattr_slots = captured_xattr_slot + std::mem::size_of::<Box<[u8]>>() as u64;
        let transient_xattr_scratch =
            xattrs.max_list_bytes.get() as u64 + xattrs.max_name_bytes.get() as u64 + 2;
        let exact = 2 * 3
            + 2 * 2
            + symlink_read_buffer
            + std::mem::size_of::<ExtentV1>() as u64
            + 2 * xattrs.max_total_bytes.get()
            + (std::mem::size_of::<SourceTreeEntryV1>()
                + std::mem::size_of::<SourceInodeKeyV1>()
                + std::mem::size_of::<usize>() * 4
                + std::mem::size_of::<u32>() * 2) as u64
            + captured_xattr_slot
            + transient_xattr_slots
            + transient_xattr_scratch
            + symlink_read_buffer
            + std::mem::size_of::<SourceTreePlanV1>() as u64;
        let exact_policy = SourceEnumerationPolicyV1::checked(
            traversal,
            xattrs,
            NonZeroU64::new(exact).unwrap(),
            max_extents,
            NonZeroU8::new(1).unwrap(),
            NonZeroU8::new(1).unwrap(),
            NonZeroU8::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(exact_policy.max_basename_bytes(), 2);
        assert!(
            SourceEnumerationPolicyV1::checked(
                traversal,
                xattrs,
                NonZeroU64::new(exact - 1).unwrap(),
                max_extents,
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
    }

    #[test]
    fn regular_evidence_accepts_empty_and_all_hole_files_without_cloning() {
        let digest = FileContentDigest([7; 32]);
        let empty = SourceRegularEvidenceV1::checked(digest, Vec::new(), 0).unwrap();
        let all_hole = SourceRegularEvidenceV1::checked(digest, Vec::new(), 4096).unwrap();
        assert_eq!(validate_regular_evidence(&empty, 0, 1, 0), Ok(0));
        assert_eq!(validate_regular_evidence(&all_hole, 4096, 1, 0), Ok(0));
    }

    #[test]
    fn regular_evidence_enforces_extent_count_and_byte_boundaries() {
        let evidence = SourceRegularEvidenceV1::checked(
            FileContentDigest([9; 32]),
            vec![
                ExtentV1 {
                    offset: 0,
                    length: 1,
                },
                ExtentV1 {
                    offset: 2,
                    length: 1,
                },
            ],
            3,
        )
        .unwrap();
        let exact_bytes = 2 * std::mem::size_of::<ExtentV1>() as u64;
        assert_eq!(
            validate_regular_evidence(&evidence, 3, 2, exact_bytes),
            Ok(exact_bytes)
        );
        let count_failure =
            validate_regular_evidence(&evidence, 3, 1, exact_bytes).expect_err("cap + 1 must fail");
        assert_eq!(
            count_failure.reason(),
            SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::DataExtents)
        );
        let bytes_failure = validate_regular_evidence(&evidence, 3, 2, exact_bytes - 1)
            .expect_err("retained bytes cap + 1 must fail");
        assert_eq!(
            bytes_failure.reason(),
            SourceTreeFailureReasonV1::ResourceLimit(SourceTreeLimitV1::PlanBytes)
        );
        assert!(
            SourceRegularEvidenceV1::checked(
                FileContentDigest([1; 32]),
                vec![
                    ExtentV1 {
                        offset: 0,
                        length: 1,
                    },
                    ExtentV1 {
                        offset: 1,
                        length: 1,
                    },
                ],
                2,
            )
            .is_none()
        );
    }

    #[test]
    fn regular_visit_copy_authority_is_linear() {
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

        <SourceRegularVisitV1<'static> as AmbiguousIfClone<_>>::probe();
        <SourceRegularVisitV1<'static> as AmbiguousIfCopy<_>>::probe();
    }

    #[test]
    fn source_fd_bound_is_committed_from_depth() {
        let policy = SourceEnumerationPolicyV1::checked(
            traversal(),
            xattrs(),
            NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            NonZeroU32::new(64).unwrap(),
            NonZeroU8::new(4).unwrap(),
            NonZeroU8::new(3).unwrap(),
            NonZeroU8::new(4).unwrap(),
        )
        .unwrap();
        assert_eq!(policy.max_live_source_fds(), 2 * 16 + 4);
    }
}
