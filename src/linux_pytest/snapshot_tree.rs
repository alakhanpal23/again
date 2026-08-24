//! Descriptor-stable tree enumeration for `linux-pytest-v1`.
//!
//! This leaf turns one trusted parent descriptor plus one raw C basename into
//! one independently revalidated logical tree view. A source parent must
//! already belong to the profile-qualified no-atime acquisition view because
//! `readlinkat` can update symlink atime on an ordinary host mount. Destination
//! observation is restricted to the owner-private staging tree, uses no-atime
//! directory and regular reads, and rejects symlinks before target acquisition.
//! A trusted visitor may consume each entry only while its descriptor is
//! pinned; the returned normalized plan is FD-free. This module does not
//! compare the required views, compute manifest node digests, publish a
//! snapshot, or claim that a tree is sealed.

use std::ffi::CStr;
use std::fmt;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::fd::BorrowedFd;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_connector::{
    SnapshotDestinationObservationErrorV1, SnapshotDestinationObservationFailureV1,
    SnapshotDestinationObservationSessionV1, SnapshotMaterializationSessionV1,
};
use super::snapshot_connector::{
    SnapshotSourceObservationErrorV1, SnapshotSourceObservationSessionV1,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_policy::SnapshotPipelineResourceErrorV1;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use super::snapshot_regular::CopiedRegularV1;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_regular::SnapshotRegularMaterializationErrorV1;
use super::snapshot_regular::{
    RegularCopyEvidenceV1, RegularCopyPolicyV1, SnapshotRegularFailureV1,
};
use super::{ExtentV1, FileContentDigest, RefusalCode, TimespecV1};

#[path = "snapshot_qualification.rs"]
mod snapshot_qualification;

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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const STATX_MNT_ID_V1: u32 = 0x1000;

/// Fields required to reconstruct the complete modeled source-tree identity
/// committed by [`SourceStatxV1`]. This is deliberately stronger than the
/// publisher's separate container-identity mask.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SOURCE_TREE_REQUIRED_STATX_MASK_V1: u32 = libc::STATX_TYPE
    | libc::STATX_MODE
    | libc::STATX_NLINK
    | libc::STATX_UID
    | libc::STATX_GID
    | libc::STATX_ATIME
    | libc::STATX_MTIME
    | libc::STATX_CTIME
    | libc::STATX_INO
    | libc::STATX_SIZE
    | STATX_MNT_ID_V1;

/// Source-tree fields requested from Linux. Birth time remains optional even
/// though it is requested, and is committed only when the kernel returns it.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) const SOURCE_TREE_REQUESTED_STATX_MASK_V1: u32 =
    SOURCE_TREE_REQUIRED_STATX_MASK_V1 | libc::STATX_BTIME;

/// Capability supplied only after the backend has functionally verified a
/// mount/view on which directory, regular-file, and symlink acquisition cannot
/// mutate host atime. This wrapper records that semantic precondition; this
/// leaf does not create or verify the mount itself.
pub(super) struct QualifiedNoAtimeSourceViewV1<'a> {
    trusted_parent: BorrowedFd<'a>,
}

impl<'a> QualifiedNoAtimeSourceViewV1<'a> {
    /// Production construction is private to this module and requires the
    /// nested functional qualifier's successful control flow.
    const fn from_functionally_verified_mount(trusted_parent: BorrowedFd<'a>) -> Self {
        Self { trusted_parent }
    }

    /// Test-only escape hatch for provisioned kernel integration fixtures.
    ///
    /// # Safety
    ///
    /// `trusted_parent` must name a view that satisfies the complete
    /// production no-atime qualification contract for the borrow's lifetime.
    #[cfg(test)]
    pub(super) const unsafe fn from_functionally_verified_mount_for_test(
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
            syscall_attempts,
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
        // The regular observer retains the first extent pass as evidence while
        // building a second pass for stability comparison. The all-entry term
        // above covers the retained first pass; charge one additional file's
        // logical maximum while both vectors are live.
        let transient_extent_bound = match (max_data_extents.get() as u64)
            .checked_mul(std::mem::size_of::<ExtentV1>() as u64)
        {
            Some(value) => value,
            None => return None,
        };
        let retained_with_extents = match retained_with_extents.checked_add(transient_extent_bound)
        {
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
        self.traversal.max_depth as u32 * 2 + 5
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

    pub(super) const fn regular_copy_policy(self) -> RegularCopyPolicyV1 {
        self.regular_copy
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

impl SourceInodeKeyV1 {
    /// Fixed-width physical identity used only by stability witnesses and
    /// connector-local commitments. It is never portable manifest metadata.
    fn commitment_bytes_v1(&self) -> [u8; 24] {
        let mut output = [0u8; 24];
        output[0..8].copy_from_slice(&self.mount_id.to_le_bytes());
        output[8..12].copy_from_slice(&self.device_major.to_le_bytes());
        output[12..16].copy_from_slice(&self.device_minor.to_le_bytes());
        output[16..24].copy_from_slice(&self.inode.to_le_bytes());
        output
    }
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
    /// Decode the complete source-tree `statx(2)` response shared by traversal
    /// and post-publication root binding. Missing mandatory fields are a
    /// capability failure; malformed returned timestamps are rejected before
    /// they can enter the fixed 102-byte commitment.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn from_linux_statx_v1(raw: &libc::statx) -> std::io::Result<Self> {
        if raw.stx_mask & SOURCE_TREE_REQUIRED_STATX_MASK_V1 != SOURCE_TREE_REQUIRED_STATX_MASK_V1 {
            return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }

        fn checked_timestamp(value: &libc::statx_timestamp) -> std::io::Result<TimespecV1> {
            if value.tv_nsec >= 1_000_000_000 {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            Ok(TimespecV1 {
                seconds: value.tv_sec,
                nanoseconds: value.tv_nsec,
            })
        }

        let atime = checked_timestamp(&raw.stx_atime)?;
        let mtime = checked_timestamp(&raw.stx_mtime)?;
        let ctime = checked_timestamp(&raw.stx_ctime)?;
        let btime = if raw.stx_mask & libc::STATX_BTIME != 0 {
            Some(checked_timestamp(&raw.stx_btime)?)
        } else {
            None
        };

        Ok(Self {
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
            atime,
            mtime,
            ctime,
            btime,
        })
    }

    /// Fixed, allocation-free canonical bytes for connector-side event/plan
    /// commitments. Byte zero is the format version; every integer is little
    /// endian and optional birth time has an explicit presence byte.
    pub(super) fn commitment_bytes_v1(&self) -> [u8; 102] {
        let mut output = [0u8; 102];
        output[0] = 1;
        output[1..25].copy_from_slice(&self.inode_key.commitment_bytes_v1());
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

    /// Exact destination-only fields omitted by the logical
    /// source-to-destination projection. Keeping these raw bytes lets D1 be
    /// released before D2 without replacing equality with a hash assumption.
    fn destination_stability_bytes_v1(&self, kind: SourceNodeKindV1) -> [u8; 57] {
        let mut output = [0u8; 57];
        output[0..24].copy_from_slice(&self.inode_key.commitment_bytes_v1());
        if kind == SourceNodeKindV1::Directory {
            output[24..32].copy_from_slice(&self.size.to_le_bytes());
        }
        output[32..40].copy_from_slice(&self.ctime.seconds.to_le_bytes());
        output[40..44].copy_from_slice(&self.ctime.nanoseconds.to_le_bytes());
        if let Some(btime) = &self.btime {
            output[44] = 1;
            output[45..53].copy_from_slice(&btime.seconds.to_le_bytes());
            output[53..57].copy_from_slice(&btime.nanoseconds.to_le_bytes());
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

    /// Move the logical metadata fields that are committed by a snapshot
    /// manifest. Physical inode and mount identity deliberately stay behind:
    /// they are stability evidence, not portable snapshot semantics.
    pub(super) fn into_manifest_parts(
        self,
    ) -> (
        u32,
        u32,
        u32,
        u64,
        u64,
        TimespecV1,
        TimespecV1,
        TimespecV1,
        Option<TimespecV1>,
    ) {
        (
            self.mode, self.uid, self.gid, self.nlink, self.size, self.atime, self.mtime,
            self.ctime, self.btime,
        )
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

    pub(super) fn into_parts(self) -> (Box<[u8]>, CapturedXattrValueV1) {
        (self.name, self.value)
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

    pub(super) fn into_parts(self) -> (FileContentDigest, Vec<ExtentV1>) {
        (self.content_digest, self.data_extents)
    }
}

/// Admit the bounded regular observation shared by source and destination
/// visitors into the normalized tree-plan representation.
pub(super) fn admit_observed_regular_evidence(
    logical_size: u64,
    evidence: RegularCopyEvidenceV1,
) -> Option<SourceRegularEvidenceV1> {
    let (content_digest, data_extents) = evidence.into_parts();
    SourceRegularEvidenceV1::checked(content_digest, data_extents, logical_size)
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
    // Retain and account the allocator-observed Vec capacity, not only its
    // logical length. `try_reserve_exact` may legally overallocate.
    let retained_extent_bytes = (evidence.data_extents.capacity() as u64)
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
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn unchecked_for_test(
        relative_path: &[u8],
        basename: &[u8],
        parent_index: Option<u32>,
        statx: SourceStatxV1,
        xattrs: Vec<CapturedXattrV1>,
        payload: SourcePlanPayloadV1,
        hardlink_group: Option<u32>,
    ) -> Self {
        Self {
            relative_path: relative_path.into(),
            basename: basename.into(),
            parent_index,
            statx,
            xattrs: xattrs.into_boxed_slice(),
            payload,
            hardlink_group,
        }
    }

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

    /// Encode the exact physical fields omitted by the logical destination
    /// projection. The node kind comes from this same observation, so callers
    /// cannot splice directory-size policy from another entry.
    pub(super) fn destination_stability_bytes_v1(&self) -> [u8; 57] {
        self.statx
            .destination_stability_bytes_v1(self.payload.kind())
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn into_parts(
        self,
    ) -> (
        Box<[u8]>,
        Box<[u8]>,
        Option<u32>,
        SourceStatxV1,
        Box<[CapturedXattrV1]>,
        SourcePlanPayloadV1,
        Option<u32>,
    ) {
        (
            self.relative_path,
            self.basename,
            self.parent_index,
            self.statx,
            self.xattrs,
            self.payload,
            self.hardlink_group,
        )
    }
}

#[derive(Eq, PartialEq)]
pub(super) struct SourceHardlinkGroupV1 {
    inode_key: SourceInodeKeyV1,
    member_indices: Box<[u32]>,
}

impl SourceHardlinkGroupV1 {
    #[cfg(test)]
    pub(super) fn unchecked_for_test(
        inode_key: SourceInodeKeyV1,
        member_indices: Vec<u32>,
    ) -> Self {
        Self {
            inode_key,
            member_indices: member_indices.into_boxed_slice(),
        }
    }

    pub(super) const fn inode_key(&self) -> &SourceInodeKeyV1 {
        &self.inode_key
    }

    pub(super) fn member_indices(&self) -> &[u32] {
        &self.member_indices
    }

    pub(super) fn destination_stability_bytes_v1(&self) -> [u8; 24] {
        self.inode_key.commitment_bytes_v1()
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

/// An immutable, FD-free record of one independently revalidated logical tree
/// view, either the qualified source or owner-private staged destination. It
/// does not freeze bytes or directory membership and is not snapshot
/// publication authority.
#[derive(Eq, PartialEq)]
pub(super) struct SourceTreePlanV1 {
    root_name: Box<[u8]>,
    entries: Box<[SourceTreeEntryV1]>,
    hardlink_groups: Box<[SourceHardlinkGroupV1]>,
    has_unsettable_xattrs: bool,
}

impl fmt::Debug for SourceTreePlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceTreePlanV1")
            .field("entry_count", &self.entries.len())
            .field("hardlink_group_count", &self.hardlink_groups.len())
            .field("has_unsettable_xattrs", &self.has_unsettable_xattrs)
            .finish()
    }
}

impl SourceTreePlanV1 {
    #[cfg(test)]
    pub(super) fn unchecked_for_test(
        root_name: &[u8],
        entries: Vec<SourceTreeEntryV1>,
        hardlink_groups: Vec<SourceHardlinkGroupV1>,
        has_unsettable_xattrs: bool,
    ) -> Self {
        Self {
            root_name: root_name.into(),
            entries: entries.into_boxed_slice(),
            hardlink_groups: hardlink_groups.into_boxed_slice(),
            has_unsettable_xattrs,
        }
    }

    pub(super) fn root_name(&self) -> &[u8] {
        &self.root_name
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

    #[allow(clippy::type_complexity)]
    pub(super) fn into_parts(
        self,
    ) -> (
        Box<[u8]>,
        Box<[SourceTreeEntryV1]>,
        Box<[SourceHardlinkGroupV1]>,
        bool,
    ) {
        (
            self.root_name,
            self.entries,
            self.hardlink_groups,
            self.has_unsettable_xattrs,
        )
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

#[cfg(test)]
pub(super) struct SourceRegularVisitV1<'a> {
    common: SourceVisitCommonV1<'a>,
    copy_policy: RegularCopyPolicyV1,
}

#[cfg(test)]
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

/// A callback-scoped regular-file capability for charged source
/// materialization.
///
/// The qualified source descriptors and exact connector-minted session remain
/// inseparable for this visit. A callback can inspect only the descriptor-free
/// common metadata surface and can copy the pinned leaf only through the
/// charged regular-copy entrypoint.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct SourceMaterializedRegularVisitV1<'visit, 'resources> {
    common: SourceVisitCommonV1<'visit>,
    session: &'visit SnapshotMaterializationSessionV1<'resources>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<'visit, 'resources> SourceMaterializedRegularVisitV1<'visit, 'resources> {
    pub(super) const fn common(&self) -> SourceVisitCommonV1<'visit> {
        self.common
    }

    pub(super) fn copy_to(
        self,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
    ) -> Result<CopiedRegularV1, SnapshotRegularMaterializationErrorV1> {
        // SAFETY: only the qualified charged walker can construct this value.
        // Its source capabilities and exact connector-minted session remain
        // borrowed for this callback-scoped copy.
        unsafe {
            super::snapshot_regular::copy_regular_from_qualified_pinned_charged_at(
                self.common.parent,
                self.common.name,
                self.common.handle,
                destination_parent,
                destination_name,
                self.session,
            )
        }
    }
}

/// A regular-file callback capability for connector-owned source observation.
///
/// Unlike the test-only legacy materialization visit, this value exposes no
/// copy operation. The exact connector session is embedded by the charged
/// walker, so a callback can neither substitute another policy/stage nor
/// perform an unmetered copy while charged traversal is in progress.
pub(super) struct SourceObservedRegularVisitV1<'visit, 'resources> {
    common: SourceVisitCommonV1<'visit>,
    session: &'visit SnapshotSourceObservationSessionV1<'resources>,
}

impl<'visit, 'resources> SourceObservedRegularVisitV1<'visit, 'resources> {
    pub(super) const fn logical_size(&self) -> u64 {
        self.common.statx.size()
    }

    pub(super) fn observe(
        self,
    ) -> Result<RegularCopyEvidenceV1, SnapshotSourceObservationErrorV1<SnapshotRegularFailureV1>>
    {
        // SAFETY: only the qualified charged walker can construct this value.
        // It binds the parent, name, pinned handle, and exact connector-minted
        // session for the callback's lifetime.
        unsafe {
            super::snapshot_regular::observe_regular_from_qualified_pinned_at(
                self.common.parent,
                self.common.name,
                self.common.handle,
                self.session,
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
#[cfg(test)]
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

/// Visitor surface used only by connector-owned, charged source observation.
/// Its regular callback receives no unmetered materialization capability.
pub(super) trait SourceObservationTreeVisitorV1 {
    type Error;

    fn regular(
        &mut self,
        visit: SourceObservedRegularVisitV1<'_, '_>,
    ) -> Result<SourceRegularEvidenceV1, Self::Error>;
}

/// Charged source-materialization visitor. Event order is directory-enter,
/// raw-name-sorted children, directory-leave; regular and symlink leaves each
/// emit once while their qualified source capabilities remain live.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) trait SourceMaterializationTreeVisitorV1 {
    type Error;

    fn directory_enter(&mut self, visit: SourceDirectoryVisitV1<'_>) -> Result<(), Self::Error>;

    fn regular(
        &mut self,
        visit: SourceMaterializedRegularVisitV1<'_, '_>,
    ) -> Result<SourceRegularEvidenceV1, Self::Error>;

    fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error>;

    fn directory_leave(&mut self, visit: SourceDirectoryVisitV1<'_>) -> Result<(), Self::Error>;
}

/// A charged source-materialization failure. Resource exhaustion from the
/// connector's shared forward ledger remains distinct from traversal or
/// visitor failure, whose potentially path-bearing payload stays redacted.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) enum SourceTreeMaterializationErrorV1<E> {
    Resource(SnapshotPipelineResourceErrorV1),
    Leaf(E),
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<E> fmt::Debug for SourceTreeMaterializationErrorV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(error) => formatter.debug_tuple("Resource").field(error).finish(),
            Self::Leaf(_) => formatter.write_str("Leaf(<redacted>)"),
        }
    }
}

pub(super) enum SourceTreeAcquireFailureV1<E> {
    Source(SourceTreeFailureV1),
    Visitor {
        stage: SourceTreeStageV1,
        relative_path: Vec<u8>,
        source: E,
    },
}

impl<E> fmt::Debug for SourceTreeAcquireFailureV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => formatter.debug_tuple("Source").field(error).finish(),
            Self::Visitor { stage, .. } => formatter
                .debug_struct("Visitor")
                .field("stage", stage)
                .field("relative_path", &"<redacted>")
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

impl<E> From<SourceTreeFailureV1> for SourceTreeAcquireFailureV1<E> {
    fn from(value: SourceTreeFailureV1) -> Self {
        Self::Source(value)
    }
}

pub(super) fn enumerate_source_tree_view_charged_at<V: SourceObservationTreeVisitorV1>(
    source_view: QualifiedNoAtimeSourceViewV1<'_>,
    root_name: &CStr,
    session: &SnapshotSourceObservationSessionV1<'_>,
    visitor: &mut V,
) -> Result<SourceTreePlanV1, SnapshotSourceObservationErrorV1<SourceTreeAcquireFailureV1<V::Error>>>
{
    platform::enumerate_source_tree_view_charged_at(source_view, root_name, session, visitor)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn enumerate_destination_tree_view_charged_at(
    staged_parent: BorrowedFd<'_>,
    root_name: &CStr,
    session: &SnapshotDestinationObservationSessionV1<'_>,
) -> Result<
    SourceTreePlanV1,
    SnapshotDestinationObservationErrorV1<
        SourceTreeAcquireFailureV1<
            SnapshotDestinationObservationErrorV1<SnapshotDestinationObservationFailureV1>,
        >,
    >,
> {
    platform::enumerate_destination_tree_view_charged_at(staged_parent, root_name, session)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn enumerate_source_tree_view_materializing_at<V: SourceMaterializationTreeVisitorV1>(
    source_view: QualifiedNoAtimeSourceViewV1<'_>,
    root_name: &CStr,
    session: &SnapshotMaterializationSessionV1<'_>,
    visitor: &mut V,
) -> Result<SourceTreePlanV1, SourceTreeMaterializationErrorV1<SourceTreeAcquireFailureV1<V::Error>>>
{
    platform::enumerate_source_tree_view_materializing_at(source_view, root_name, session, visitor)
}

#[cfg(test)]
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
    #[derive(Debug)]
    enum BoundedPushReserveError {
        Full,
        Allocation,
    }

    #[derive(Debug)]
    enum TraversalFailureV1<E> {
        Resource(SnapshotPipelineResourceErrorV1),
        Leaf(E),
    }

    impl<E> TraversalFailureV1<E> {
        fn map_leaf<F>(self, map: impl FnOnce(E) -> F) -> TraversalFailureV1<F> {
            match self {
                Self::Resource(error) => TraversalFailureV1::Resource(error),
                Self::Leaf(error) => TraversalFailureV1::Leaf(map(error)),
            }
        }

        fn into_observation(self) -> SnapshotSourceObservationErrorV1<E> {
            match self {
                Self::Resource(error) => SnapshotSourceObservationErrorV1::Resource(error),
                Self::Leaf(error) => SnapshotSourceObservationErrorV1::Leaf(error),
            }
        }

        fn into_source_materialization(self) -> SourceTreeMaterializationErrorV1<E> {
            match self {
                Self::Resource(error) => SourceTreeMaterializationErrorV1::Resource(error),
                Self::Leaf(error) => SourceTreeMaterializationErrorV1::Leaf(error),
            }
        }
    }

    impl From<SourceTreeFailureV1> for TraversalFailureV1<SourceTreeFailureV1> {
        fn from(error: SourceTreeFailureV1) -> Self {
            Self::Leaf(error)
        }
    }

    impl<E> From<SourceTreeFailureV1> for TraversalFailureV1<SourceTreeAcquireFailureV1<E>> {
        fn from(error: SourceTreeFailureV1) -> Self {
            Self::Leaf(SourceTreeAcquireFailureV1::Source(error))
        }
    }

    impl<E> From<SourceTreeAcquireFailureV1<E>> for TraversalFailureV1<SourceTreeAcquireFailureV1<E>> {
        fn from(error: SourceTreeAcquireFailureV1<E>) -> Self {
            Self::Leaf(error)
        }
    }

    impl<E> From<TraversalFailureV1<SourceTreeFailureV1>>
        for TraversalFailureV1<SourceTreeAcquireFailureV1<E>>
    {
        fn from(error: TraversalFailureV1<SourceTreeFailureV1>) -> Self {
            error.map_leaf(SourceTreeAcquireFailureV1::Source)
        }
    }

    trait AttemptGateV1 {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1>;
    }

    impl AttemptGateV1 for SnapshotSourceObservationSessionV1<'_> {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            SnapshotSourceObservationSessionV1::run_attempt(self, attempt)
        }
    }

    impl AttemptGateV1 for SnapshotDestinationObservationSessionV1<'_> {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            SnapshotDestinationObservationSessionV1::run_attempt(self, attempt)
        }
    }

    impl AttemptGateV1 for SnapshotMaterializationSessionV1<'_> {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            SnapshotMaterializationSessionV1::run_materialization_attempt(self, attempt)
        }
    }

    #[cfg(test)]
    struct UnmeteredAttemptGateV1;

    #[cfg(test)]
    impl AttemptGateV1 for UnmeteredAttemptGateV1 {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            Ok(attempt())
        }
    }

    /// Internal adapter boundary shared by the one traversal implementation.
    /// Production charged observation and test/materialization visitors are
    /// converted into disjoint regular-file capabilities before reaching a
    /// callback.
    trait WalkVisitorV1 {
        type Error;

        fn directory_enter(&mut self, visit: SourceDirectoryVisitV1<'_>)
        -> Result<(), Self::Error>;

        fn regular(
            &mut self,
            common: SourceVisitCommonV1<'_>,
            copy_policy: RegularCopyPolicyV1,
        ) -> Result<SourceRegularEvidenceV1, Self::Error>;

        fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error>;

        fn directory_leave(&mut self, visit: SourceDirectoryVisitV1<'_>)
        -> Result<(), Self::Error>;
    }

    #[cfg(test)]
    struct MaterializationVisitorAdapterV1<'visitor, V> {
        visitor: &'visitor mut V,
    }

    #[cfg(test)]
    impl<V: SourceTreeVisitorV1> WalkVisitorV1 for MaterializationVisitorAdapterV1<'_, V> {
        type Error = V::Error;

        fn directory_enter(
            &mut self,
            visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            self.visitor.directory_enter(visit)
        }

        fn regular(
            &mut self,
            common: SourceVisitCommonV1<'_>,
            copy_policy: RegularCopyPolicyV1,
        ) -> Result<SourceRegularEvidenceV1, Self::Error> {
            self.visitor.regular(SourceRegularVisitV1 {
                common,
                copy_policy,
            })
        }

        fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error> {
            self.visitor.symlink(visit)
        }

        fn directory_leave(
            &mut self,
            visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            self.visitor.directory_leave(visit)
        }
    }

    struct ObservationVisitorAdapterV1<'visitor, 'session, 'resources, V> {
        visitor: &'visitor mut V,
        session: &'session SnapshotSourceObservationSessionV1<'resources>,
    }

    impl<V: SourceObservationTreeVisitorV1> WalkVisitorV1
        for ObservationVisitorAdapterV1<'_, '_, '_, V>
    {
        type Error = V::Error;

        fn directory_enter(
            &mut self,
            _visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn regular(
            &mut self,
            common: SourceVisitCommonV1<'_>,
            _copy_policy: RegularCopyPolicyV1,
        ) -> Result<SourceRegularEvidenceV1, Self::Error> {
            self.visitor.regular(SourceObservedRegularVisitV1 {
                common,
                session: self.session,
            })
        }

        fn symlink(&mut self, _visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error> {
            Ok(())
        }

        fn directory_leave(
            &mut self,
            _visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct DestinationObservationWalkVisitorV1<'session, 'resources> {
        session: &'session SnapshotDestinationObservationSessionV1<'resources>,
    }

    impl WalkVisitorV1 for DestinationObservationWalkVisitorV1<'_, '_> {
        type Error = SnapshotDestinationObservationErrorV1<SnapshotDestinationObservationFailureV1>;

        fn directory_enter(
            &mut self,
            _visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn regular(
            &mut self,
            common: SourceVisitCommonV1<'_>,
            _copy_policy: RegularCopyPolicyV1,
        ) -> Result<SourceRegularEvidenceV1, Self::Error> {
            let logical_size = common.statx.size();
            // SAFETY: this private fixed visitor is constructed only by the
            // destination entrypoint over one still-live staged-tree callback.
            let evidence = unsafe {
                super::super::snapshot_regular::observe_destination_regular_from_private_pinned_at(
                    common.parent,
                    common.name,
                    common.handle,
                    self.session,
                )
            }
            .map_err(|error| error.map_leaf(SnapshotDestinationObservationFailureV1::Regular))?;
            admit_observed_regular_evidence(logical_size, evidence).ok_or(
                SnapshotDestinationObservationErrorV1::Leaf(
                    SnapshotDestinationObservationFailureV1::InvalidRegularEvidence,
                ),
            )
        }

        fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error> {
            Err(SnapshotDestinationObservationErrorV1::Leaf(
                SnapshotDestinationObservationFailureV1::Tree(failure(
                    SourceTreeStageV1::InspectEntry,
                    SourceTreeFailureReasonV1::UnsupportedObject,
                    None,
                    visit.common().relative_path(),
                )),
            ))
        }

        fn directory_leave(
            &mut self,
            _visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct ChargedMaterializationVisitorAdapterV1<'visitor, 'session, 'resources, V> {
        visitor: &'visitor mut V,
        session: &'session SnapshotMaterializationSessionV1<'resources>,
    }

    impl<V: SourceMaterializationTreeVisitorV1> WalkVisitorV1
        for ChargedMaterializationVisitorAdapterV1<'_, '_, '_, V>
    {
        type Error = V::Error;

        fn directory_enter(
            &mut self,
            visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            self.visitor.directory_enter(visit)
        }

        fn regular(
            &mut self,
            common: SourceVisitCommonV1<'_>,
            _copy_policy: RegularCopyPolicyV1,
        ) -> Result<SourceRegularEvidenceV1, Self::Error> {
            self.visitor.regular(SourceMaterializedRegularVisitV1 {
                common,
                session: self.session,
            })
        }

        fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error> {
            self.visitor.symlink(visit)
        }

        fn directory_leave(
            &mut self,
            visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            self.visitor.directory_leave(visit)
        }
    }

    fn run_io_attempt<G: AttemptGateV1, T>(
        gate: &G,
        attempt: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, TraversalFailureV1<io::Error>> {
        gate.run_attempt(attempt)
            .map_err(TraversalFailureV1::Resource)?
            .map_err(TraversalFailureV1::Leaf)
    }

    fn run_io_with_retry<G: AttemptGateV1, T>(
        gate: &G,
        attempts: u8,
        mut retry: impl FnMut(&io::Error) -> bool,
        mut operation: impl FnMut() -> io::Result<T>,
        exhausted_errno: i32,
    ) -> Result<T, TraversalFailureV1<io::Error>> {
        let mut last = io::Error::from_raw_os_error(exhausted_errno);
        for _ in 0..attempts {
            match run_io_attempt(gate, &mut operation) {
                Ok(value) => return Ok(value),
                Err(TraversalFailureV1::Leaf(error)) if retry(&error) => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(TraversalFailureV1::Leaf(last))
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
        fn duplicate_fd_once(&self, fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
            raw_duplicate_fd_once(fd)
        }

        fn openat2_once(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            flags: i32,
            resolve: u64,
        ) -> io::Result<OwnedFd> {
            raw_openat2_once(parent, name, flags, resolve)
        }

        fn statx_once(&self, fd: BorrowedFd<'_>) -> io::Result<SourceStatxV1> {
            raw_statx_identity_once(fd)
        }

        fn lseek_once(
            &self,
            fd: BorrowedFd<'_>,
            offset: libc::off_t,
            whence: i32,
        ) -> io::Result<u64> {
            raw_lseek_once(fd, offset, whence)
        }

        fn getdents64_once(&self, fd: BorrowedFd<'_>, output: &mut [u8]) -> io::Result<usize> {
            raw_getdents64_once(fd, output)
        }

        fn list_xattrs(&self, fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize>;

        fn get_xattr(&self, fd: RawFd, name: &CStr, output: Option<&mut [u8]>)
        -> io::Result<usize>;

        fn read_symlink(
            &self,
            fd: RawFd,
            _relative_path: &[u8],
            output: &mut [u8],
        ) -> io::Result<usize> {
            readlinkat_empty_path(fd, output)
        }

        fn after_directory_children(&self, _relative_path: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn after_leaf_visitor(&self, _relative_path: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn directory_open_flags(&self) -> i32 {
            source_directory_open_flags()
        }

        fn rejects_symlinks_before_xattrs(&self) -> bool {
            false
        }

        fn observe_live_tree_fds(&self, _depth: u16, _upper_bound: u32) {}
    }

    struct KernelHooks {
        destination_observation: bool,
    }

    impl KernelHooks {
        const SOURCE: Self = Self {
            destination_observation: false,
        };
        const DESTINATION: Self = Self {
            destination_observation: true,
        };
    }

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

        fn directory_open_flags(&self) -> i32 {
            source_directory_open_flags()
                | if self.destination_observation {
                    libc::O_NOATIME
                } else {
                    0
                }
        }

        fn rejects_symlinks_before_xattrs(&self) -> bool {
            self.destination_observation
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

    struct Builder<'a, 'v, G, H, V> {
        root_parent: OwnedFd,
        root_name: &'a CStr,
        policy: SourceEnumerationPolicyV1,
        gate: &'a G,
        hooks: &'a H,
        visitor: &'v mut V,
        root_mount_id: Option<u64>,
        entries: Vec<BuildEntry>,
        directory_identities: HashSet<SourceInodeKeyV1>,
        total_file_bytes: u64,
        total_xattr_bytes: u64,
        total_plan_bytes: u64,
    }

    pub(super) fn enumerate_source_tree_view_charged_at<V: SourceObservationTreeVisitorV1>(
        source_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
        session: &SnapshotSourceObservationSessionV1<'_>,
        visitor: &mut V,
    ) -> Result<
        SourceTreePlanV1,
        SnapshotSourceObservationErrorV1<SourceTreeAcquireFailureV1<V::Error>>,
    > {
        let mut visitor = ObservationVisitorAdapterV1 { visitor, session };
        enumerate_source_tree_view_at_with(
            source_view.trusted_parent(),
            root_name,
            *session.source_policy(),
            session,
            &KernelHooks::SOURCE,
            &mut visitor,
        )
        .map_err(TraversalFailureV1::into_observation)
    }

    pub(super) fn enumerate_destination_tree_view_charged_at(
        staged_parent: BorrowedFd<'_>,
        root_name: &CStr,
        session: &SnapshotDestinationObservationSessionV1<'_>,
    ) -> Result<
        SourceTreePlanV1,
        SnapshotDestinationObservationErrorV1<
            SourceTreeAcquireFailureV1<
                SnapshotDestinationObservationErrorV1<SnapshotDestinationObservationFailureV1>,
            >,
        >,
    > {
        let mut visitor = DestinationObservationWalkVisitorV1 { session };
        enumerate_source_tree_view_at_with(
            staged_parent,
            root_name,
            *session.enumeration_policy(),
            session,
            &KernelHooks::DESTINATION,
            &mut visitor,
        )
        .map_err(TraversalFailureV1::into_observation)
    }

    pub(super) fn enumerate_source_tree_view_materializing_at<
        V: SourceMaterializationTreeVisitorV1,
    >(
        source_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
        session: &SnapshotMaterializationSessionV1<'_>,
        visitor: &mut V,
    ) -> Result<
        SourceTreePlanV1,
        SourceTreeMaterializationErrorV1<SourceTreeAcquireFailureV1<V::Error>>,
    > {
        let mut visitor = ChargedMaterializationVisitorAdapterV1 { visitor, session };
        enumerate_source_tree_view_at_with(
            source_view.trusted_parent(),
            root_name,
            *session.source_policy(),
            session,
            &KernelHooks::SOURCE,
            &mut visitor,
        )
        .map_err(TraversalFailureV1::into_source_materialization)
    }

    #[cfg(test)]
    pub(super) fn enumerate_source_tree_view_at<V: SourceTreeVisitorV1>(
        source_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
        policy: SourceEnumerationPolicyV1,
        visitor: &mut V,
    ) -> Result<SourceTreePlanV1, SourceTreeAcquireFailureV1<V::Error>> {
        let mut visitor = MaterializationVisitorAdapterV1 { visitor };
        match enumerate_source_tree_view_at_with(
            source_view.trusted_parent(),
            root_name,
            policy,
            &UnmeteredAttemptGateV1,
            &KernelHooks::SOURCE,
            &mut visitor,
        ) {
            Ok(plan) => Ok(plan),
            Err(TraversalFailureV1::Leaf(error)) => Err(error),
            Err(TraversalFailureV1::Resource(_)) => {
                unreachable!("the test-only unmetered attempt gate cannot exhaust")
            }
        }
    }

    fn enumerate_source_tree_view_at_with<
        G: AttemptGateV1,
        H: EnumerationHooks,
        V: WalkVisitorV1,
    >(
        trusted_parent: BorrowedFd<'_>,
        root_name: &CStr,
        policy: SourceEnumerationPolicyV1,
        gate: &G,
        hooks: &H,
        visitor: &mut V,
    ) -> Result<SourceTreePlanV1, TraversalFailureV1<SourceTreeAcquireFailureV1<V::Error>>> {
        if !valid_basename(root_name.to_bytes(), policy.traversal.max_name_bytes.get()) {
            return Err(failure(
                SourceTreeStageV1::ValidatePolicy,
                SourceTreeFailureReasonV1::InvalidBasename,
                None,
                b"",
            )
            .into());
        }
        let root_parent = duplicate_fd(gate, hooks, trusted_parent).map_err(|error| {
            error.map_leaf(|error| io_failure(SourceTreeStageV1::DuplicateParent, b"", error))
        })?;
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
            gate,
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
        let parent_fd = duplicate_fd(builder.gate, builder.hooks, builder.root_parent.as_fd())
            .map_err(|error| {
                error.map_leaf(|error| io_failure(SourceTreeStageV1::DuplicateParent, b"", error))
            })?;
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

    impl<G: AttemptGateV1, H: EnumerationHooks, V: WalkVisitorV1> Builder<'_, '_, G, H, V> {
        fn enumerate_entry(
            &mut self,
            parent_fd: BorrowedFd<'_>,
            name: &CStr,
            relative_path: Vec<u8>,
            parent: Option<usize>,
            depth: u16,
        ) -> Result<usize, TraversalFailureV1<SourceTreeAcquireFailureV1<V::Error>>> {
            self.check_entry_limits(name.to_bytes(), &relative_path, depth)?;
            let handle = openat2_owned(
                self.gate,
                self.hooks,
                parent_fd,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                SOURCE_RESOLVE,
                self.policy.openat2_attempts.get(),
            )
            .map_err(|error| {
                error.map_leaf(|error| {
                    map_open_error(SourceTreeStageV1::OpenEntry, &relative_path, error)
                })
            })?;
            let statx = statx_identity(self.gate, self.hooks, handle.as_fd()).map_err(|error| {
                error.map_leaf(|error| {
                    map_statx_error(SourceTreeStageV1::InspectEntry, &relative_path, error)
                })
            })?;
            let file_type = statx.mode & libc::S_IFMT;
            if file_type == libc::S_IFLNK && self.hooks.rejects_symlinks_before_xattrs() {
                return Err(failure(
                    SourceTreeStageV1::InspectEntry,
                    SourceTreeFailureReasonV1::UnsupportedObject,
                    None,
                    &relative_path,
                )
                .into());
            }
            self.hooks
                .observe_live_tree_fds(depth, u32::from(depth) * 2 + 3);
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
            let xattrs = capture_stable_xattrs_with_gate(
                self.gate,
                self.hooks,
                handle.as_raw_fd(),
                &relative_path,
                self.policy.xattrs,
                self.policy.xattr_stability_attempts.get(),
                XattrCaptureBoundsV1 {
                    max_xattr_bytes: self
                        .policy
                        .xattrs
                        .max_total_bytes
                        .get()
                        .saturating_sub(self.total_xattr_bytes),
                    max_plan_bytes: self.remaining_plan_bytes(),
                },
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
                        self.gate,
                        self.hooks,
                        parent_fd,
                        name,
                        self.hooks.directory_open_flags(),
                        SOURCE_RESOLVE,
                        self.policy.openat2_attempts.get(),
                    )
                    .map_err(|error| {
                        error.map_leaf(|error| map_directory_open_error(&relative_path, error))
                    })?;
                    self.hooks
                        .observe_live_tree_fds(depth, u32::from(depth) * 2 + 4);
                    let read_statx = statx_identity(self.gate, self.hooks, directory.as_fd())
                        .map_err(|error| {
                            error.map_leaf(|error| {
                                map_statx_error(
                                    SourceTreeStageV1::OpenDirectory,
                                    &relative_path,
                                    error,
                                )
                            })
                        })?;
                    if read_statx != statx {
                        return Err(source_changed(
                            SourceTreeStageV1::OpenDirectory,
                            &relative_path,
                        )
                        .into());
                    }
                    let membership = read_directory_names(
                        self.gate,
                        self.hooks,
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
                    if let Err(source) = self.visitor.directory_enter(enter) {
                        return Err(SourceTreeAcquireFailureV1::Visitor {
                            stage: SourceTreeStageV1::VisitDirectoryEnter,
                            relative_path,
                            source,
                        }
                        .into());
                    }
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
                    let revalidation_storage_bytes = self.remaining_plan_bytes();
                    if membership_storage_bytes > revalidation_storage_bytes {
                        return Err(limit(&relative_path, SourceTreeLimitV1::PlanBytes).into());
                    }
                    let membership_after = read_directory_names(
                        self.gate,
                        self.hooks,
                        directory.as_fd(),
                        &relative_path,
                        self.policy.traversal,
                        revalidation_storage_bytes,
                        self.policy.syscall_attempts.get(),
                    )?;
                    let statx_after = statx_identity(self.gate, self.hooks, directory.as_fd())
                        .map_err(|error| {
                            error.map_leaf(|error| {
                                map_statx_error(
                                    SourceTreeStageV1::RevalidateDirectory,
                                    &relative_path,
                                    error,
                                )
                            })
                        })?;
                    self.revalidate_one(
                        parent_fd,
                        name,
                        handle.as_fd(),
                        &relative_path,
                        &statx,
                        SourceTreeStageV1::RevalidateDirectory,
                    )?;
                    if membership_after != membership || statx_after != statx {
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
                    if let Err(source) = self.visitor.directory_leave(leave) {
                        return Err(SourceTreeAcquireFailureV1::Visitor {
                            stage: SourceTreeStageV1::VisitDirectoryLeave,
                            relative_path,
                            source,
                        }
                        .into());
                    }
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
                    let evidence = match self.visitor.regular(
                        SourceVisitCommonV1 {
                            relative_path: &relative_path,
                            name,
                            parent: parent_fd,
                            handle: handle.as_fd(),
                            statx: &statx,
                            xattrs: &xattrs,
                        },
                        self.policy.regular_copy,
                    ) {
                        Ok(evidence) => evidence,
                        Err(source) => {
                            return Err(SourceTreeAcquireFailureV1::Visitor {
                                stage: SourceTreeStageV1::VisitRegular,
                                relative_path,
                                source,
                            }
                            .into());
                        }
                    };
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
                    self.revalidate_one(
                        parent_fd,
                        name,
                        handle.as_fd(),
                        &relative_path,
                        &statx,
                        SourceTreeStageV1::RevalidateEntry,
                    )?;
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
                        self.gate,
                        self.hooks,
                        &handle,
                        &relative_path,
                        target_cap,
                        self.remaining_plan_bytes(),
                    )?;
                    self.reserve_plan_bytes(&relative_path, target.capacity() as u64)?;
                    if let Err(source) = self.visitor.symlink(SourceSymlinkVisitV1 {
                        common: SourceVisitCommonV1 {
                            relative_path: &relative_path,
                            name,
                            parent: parent_fd,
                            handle: handle.as_fd(),
                            statx: &statx,
                            xattrs: &xattrs,
                        },
                        target: &target,
                    }) {
                        return Err(SourceTreeAcquireFailureV1::Visitor {
                            stage: SourceTreeStageV1::VisitSymlink,
                            relative_path,
                            source,
                        }
                        .into());
                    }
                    self.hooks
                        .after_leaf_visitor(&relative_path)
                        .map_err(|error| {
                            SourceTreeAcquireFailureV1::Source(io_failure(
                                SourceTreeStageV1::RevalidateEntry,
                                &relative_path,
                                error,
                            ))
                        })?;
                    self.revalidate_one(
                        parent_fd,
                        name,
                        handle.as_fd(),
                        &relative_path,
                        &statx,
                        SourceTreeStageV1::RevalidateEntry,
                    )?;
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
            stage: SourceTreeStageV1,
        ) -> Result<(), TraversalFailureV1<SourceTreeFailureV1>> {
            let reopened = openat2_owned(
                self.gate,
                self.hooks,
                parent_fd,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                SOURCE_RESOLVE,
                self.policy.openat2_attempts.get(),
            )
            .map_err(|error| {
                error.map_leaf(|error| map_reopen_error(stage, relative_path, error))
            })?;
            let depth = if relative_path.is_empty() {
                0
            } else {
                1 + relative_path.iter().filter(|byte| **byte == b'/').count() as u16
            };
            let fixed_fds = if stage == SourceTreeStageV1::RevalidateDirectory {
                5
            } else {
                4
            };
            self.hooks
                .observe_live_tree_fds(depth, u32::from(depth) * 2 + fixed_fds);
            let pinned = statx_identity(self.gate, self.hooks, handle).map_err(|error| {
                error.map_leaf(|error| map_statx_error(stage, relative_path, error))
            })?;
            let named =
                statx_identity(self.gate, self.hooks, reopened.as_fd()).map_err(|error| {
                    error.map_leaf(|error| map_statx_error(stage, relative_path, error))
                })?;
            if &pinned != expected || &named != expected {
                return Err(source_changed(stage, relative_path).into());
            }
            Ok(())
        }
    }

    fn normalize_plan<G: AttemptGateV1, H: EnumerationHooks, V: WalkVisitorV1>(
        builder: Builder<'_, '_, G, H, V>,
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
        builder.root_mount_id.ok_or_else(|| {
            failure(
                SourceTreeStageV1::NormalizePlan,
                SourceTreeFailureReasonV1::SourceChanged,
                None,
                b"",
            )
        })?;
        Ok(SourceTreePlanV1 {
            root_name: try_boxed_bytes(builder.root_name.to_bytes(), b"")?,
            entries: entries.into_boxed_slice(),
            hardlink_groups: hardlink_groups.into_boxed_slice(),
            has_unsettable_xattrs,
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

    fn read_directory_names<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        fd: BorrowedFd<'_>,
        relative_path: &[u8],
        limits: SourceTraversalLimitsV1,
        max_retained_storage_bytes: u64,
        syscall_attempts: u8,
    ) -> Result<Vec<Box<[u8]>>, TraversalFailureV1<SourceTreeFailureV1>> {
        run_io_with_retry(
            gate,
            syscall_attempts,
            |error| error.kind() == io::ErrorKind::Interrupted,
            || hooks.lseek_once(fd, 0, libc::SEEK_SET),
            libc::EINTR,
        )
        .map_err(|error| {
            error.map_leaf(|error| {
                io_failure(SourceTreeStageV1::EnumerateDirectory, relative_path, error)
            })
        })?;
        let mut output = Vec::new();
        let mut retained_name_bytes = 0u64;
        let mut buffer = [0u8; GETDENTS_BUFFER_BYTES];
        loop {
            let used = getdents64_with_retry(gate, syscall_attempts, || {
                hooks.getdents64_once(fd, &mut buffer)
            })
            .map_err(|error| {
                error.map_leaf(|error| {
                    io_failure(SourceTreeStageV1::EnumerateDirectory, relative_path, error)
                })
            })?;
            if used == 0 {
                break;
            }
            if used > buffer.len() {
                return Err(malformed(SourceTreeStageV1::EnumerateDirectory, relative_path).into());
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
        normalize_directory_names(output, relative_path).map_err(TraversalFailureV1::Leaf)
    }

    fn getdents64_with_retry<G: AttemptGateV1>(
        gate: &G,
        attempts: u8,
        operation: impl FnMut() -> io::Result<usize>,
    ) -> Result<usize, TraversalFailureV1<io::Error>> {
        run_io_with_retry(
            gate,
            attempts,
            |error| error.kind() == io::ErrorKind::Interrupted,
            operation,
            libc::EINTR,
        )
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
        Resource(SnapshotPipelineResourceErrorV1),
        Retry(Option<i32>),
        Fatal(SourceTreeFailureV1),
    }

    struct XattrCaptureBoundsV1 {
        max_xattr_bytes: u64,
        max_plan_bytes: u64,
    }

    fn capture_stable_xattrs_with_gate<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        fd: RawFd,
        relative_path: &[u8],
        limits: SourceXattrLimitsV1,
        attempts: u8,
        bounds: XattrCaptureBoundsV1,
    ) -> Result<Box<[CapturedXattrV1]>, TraversalFailureV1<SourceTreeFailureV1>> {
        let mut last_errno = None;
        for _ in 0..attempts {
            let first = match capture_xattr_pass(
                gate,
                hooks,
                fd,
                relative_path,
                limits,
                bounds.max_xattr_bytes,
                bounds.max_plan_bytes,
            ) {
                Ok(value) => value,
                Err(XattrPassError::Resource(error)) => {
                    return Err(TraversalFailureV1::Resource(error));
                }
                Err(XattrPassError::Retry(errno)) => {
                    last_errno = errno;
                    continue;
                }
                Err(XattrPassError::Fatal(error)) => return Err(error.into()),
            };
            let second = match capture_xattr_pass(
                gate,
                hooks,
                fd,
                relative_path,
                limits,
                bounds.max_xattr_bytes,
                bounds.max_plan_bytes,
            ) {
                Ok(value) => value,
                Err(XattrPassError::Resource(error)) => {
                    return Err(TraversalFailureV1::Resource(error));
                }
                Err(XattrPassError::Retry(errno)) => {
                    last_errno = errno;
                    continue;
                }
                Err(XattrPassError::Fatal(error)) => return Err(error.into()),
            };
            let (_, first_plan_bytes) = xattr_storage_bytes(&first)?;
            let (_, second_plan_bytes) = xattr_storage_bytes(&second)?;
            let combined_plan_bytes = first_plan_bytes
                .checked_add(second_plan_bytes)
                .ok_or_else(|| limit(relative_path, SourceTreeLimitV1::PlanBytes))?;
            if combined_plan_bytes > bounds.max_plan_bytes {
                return Err(limit(relative_path, SourceTreeLimitV1::PlanBytes).into());
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
        )
        .into())
    }

    #[cfg(test)]
    fn capture_stable_xattrs<H: EnumerationHooks>(
        hooks: &H,
        fd: RawFd,
        relative_path: &[u8],
        limits: SourceXattrLimitsV1,
        attempts: u8,
        max_xattr_bytes: u64,
        max_plan_bytes: u64,
    ) -> Result<Box<[CapturedXattrV1]>, SourceTreeFailureV1> {
        match capture_stable_xattrs_with_gate(
            &UnmeteredAttemptGateV1,
            hooks,
            fd,
            relative_path,
            limits,
            attempts,
            XattrCaptureBoundsV1 {
                max_xattr_bytes,
                max_plan_bytes,
            },
        ) {
            Ok(xattrs) => Ok(xattrs),
            Err(TraversalFailureV1::Leaf(error)) => Err(error),
            Err(TraversalFailureV1::Resource(_)) => {
                unreachable!("the test-only unmetered attempt gate cannot exhaust")
            }
        }
    }

    fn capture_xattr_pass<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        fd: RawFd,
        relative_path: &[u8],
        limits: SourceXattrLimitsV1,
        max_xattr_bytes: u64,
        max_plan_bytes: u64,
    ) -> Result<Vec<CapturedXattrV1>, XattrPassError> {
        let list_size =
            run_io_attempt(gate, || hooks.list_xattrs(fd, None)).map_err(|error| match error {
                TraversalFailureV1::Resource(error) => XattrPassError::Resource(error),
                TraversalFailureV1::Leaf(error) => map_xattr_call(relative_path, error),
            })?;
        if list_size > limits.max_list_bytes.get() as usize {
            return Err(XattrPassError::Fatal(limit(
                relative_path,
                SourceTreeLimitV1::XattrListBytes,
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
        let used =
            run_io_attempt(gate, || hooks.list_xattrs(fd, Some(&mut list))).map_err(|error| {
                match error {
                    TraversalFailureV1::Resource(error) => XattrPassError::Resource(error),
                    TraversalFailureV1::Leaf(error) => map_xattr_call(relative_path, error),
                }
            })?;
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
            let value = match run_io_attempt(gate, || hooks.get_xattr(fd, &c_name, None)) {
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
                    let used =
                        run_io_attempt(gate, || hooks.get_xattr(fd, &c_name, Some(&mut value)))
                            .map_err(|error| match error {
                                TraversalFailureV1::Resource(error) => {
                                    XattrPassError::Resource(error)
                                }
                                TraversalFailureV1::Leaf(error) => {
                                    map_xattr_call(relative_path, error)
                                }
                            })?;
                    if used > size {
                        return Err(XattrPassError::Retry(Some(libc::ERANGE)));
                    }
                    value.truncate(used);
                    CapturedXattrValueV1::Bytes(value.into_boxed_slice())
                }
                Err(TraversalFailureV1::Leaf(error))
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EACCES | libc::EPERM | libc::EOPNOTSUPP)
                    ) =>
                {
                    CapturedXattrValueV1::VisibleButUnsettable {
                        errno: error.raw_os_error().expect("matched Some errno"),
                    }
                }
                Err(TraversalFailureV1::Resource(error)) => {
                    return Err(XattrPassError::Resource(error));
                }
                Err(TraversalFailureV1::Leaf(error)) => {
                    return Err(map_xattr_call(relative_path, error));
                }
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

    fn read_stable_symlink_target<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        handle: &OwnedFd,
        relative_path: &[u8],
        max_bytes: u32,
        max_plan_bytes: u64,
    ) -> Result<Vec<u8>, TraversalFailureV1<SourceTreeFailureV1>> {
        let first =
            read_symlink_target_once(gate, hooks, handle.as_fd(), relative_path, max_bytes)?;
        let second =
            read_symlink_target_once(gate, hooks, handle.as_fd(), relative_path, max_bytes)?;
        if (first.capacity() as u64)
            .checked_add(second.capacity() as u64)
            .is_none_or(|bytes| bytes > max_plan_bytes)
        {
            return Err(limit(relative_path, SourceTreeLimitV1::PlanBytes).into());
        }
        if first != second {
            return Err(source_changed(SourceTreeStageV1::CaptureSymlink, relative_path).into());
        }
        Ok(first)
    }

    fn read_symlink_target_once<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        fd: BorrowedFd<'_>,
        relative_path: &[u8],
        max_bytes: u32,
    ) -> Result<Vec<u8>, TraversalFailureV1<SourceTreeFailureV1>> {
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
            let used = run_io_attempt(gate, || {
                hooks.read_symlink(fd.as_raw_fd(), relative_path, &mut output)
            })
            .map_err(|error| {
                error.map_leaf(|error| {
                    io_failure(SourceTreeStageV1::CaptureSymlink, relative_path, error)
                })
            })?;
            if used > output.len() {
                return Err(malformed(SourceTreeStageV1::CaptureSymlink, relative_path).into());
            }
            if used < capacity {
                if used == 0 || output[..used].contains(&0) {
                    return Err(malformed(SourceTreeStageV1::CaptureSymlink, relative_path).into());
                }
                output.truncate(used);
                return Ok(output);
            }
            if capacity == maximum_capacity {
                return Err(limit(relative_path, SourceTreeLimitV1::SymlinkTargetBytes).into());
            }
            capacity = capacity
                .checked_mul(2)
                .unwrap_or(maximum_capacity)
                .min(maximum_capacity);
        }
    }

    fn readlinkat_empty_path(fd: RawFd, output: &mut [u8]) -> io::Result<usize> {
        let result =
            unsafe { libc::readlinkat(fd, c"".as_ptr(), output.as_mut_ptr().cast(), output.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            usize::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
        }
    }

    fn raw_duplicate_fd_once(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
        let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(result) })
        }
    }

    fn duplicate_fd<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        fd: BorrowedFd<'_>,
    ) -> Result<OwnedFd, TraversalFailureV1<io::Error>> {
        run_io_attempt(gate, || hooks.duplicate_fd_once(fd))
    }

    fn raw_openat2_once(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        resolve: u64,
    ) -> io::Result<OwnedFd> {
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve,
        };
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
            Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn openat2_owned<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        resolve: u64,
        attempts: u8,
    ) -> Result<OwnedFd, TraversalFailureV1<io::Error>> {
        run_io_with_retry(
            gate,
            attempts,
            |error| error.raw_os_error() == Some(libc::EAGAIN),
            || hooks.openat2_once(parent, name, flags, resolve),
            libc::EAGAIN,
        )
    }

    fn raw_statx_identity_once(fd: BorrowedFd<'_>) -> io::Result<SourceStatxV1> {
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                fd.as_raw_fd(),
                c"".as_ptr(),
                AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                SOURCE_TREE_REQUESTED_STATX_MASK_V1,
                raw.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe { raw.assume_init() };
        SourceStatxV1::from_linux_statx_v1(&raw)
    }

    fn statx_identity<G: AttemptGateV1, H: EnumerationHooks>(
        gate: &G,
        hooks: &H,
        fd: BorrowedFd<'_>,
    ) -> Result<SourceStatxV1, TraversalFailureV1<io::Error>> {
        run_io_attempt(gate, || hooks.statx_once(fd))
    }

    fn raw_lseek_once(fd: BorrowedFd<'_>, offset: libc::off_t, whence: i32) -> io::Result<u64> {
        let result = unsafe { libc::lseek(fd.as_raw_fd(), offset, whence) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            u64::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
        }
    }

    fn raw_getdents64_once(fd: BorrowedFd<'_>, output: &mut [u8]) -> io::Result<usize> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                fd.as_raw_fd(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        syscall_size(result)
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

    fn map_reopen_error(
        stage: SourceTreeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SourceTreeFailureV1 {
        match error.raw_os_error() {
            Some(libc::ENOENT | libc::ESTALE | libc::EAGAIN) => failure(
                stage,
                SourceTreeFailureReasonV1::SourceChanged,
                error.raw_os_error(),
                relative_path,
            ),
            _ => map_open_error(stage, relative_path, error),
        }
    }

    fn map_statx_error(
        stage: SourceTreeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SourceTreeFailureV1 {
        if error.kind() == io::ErrorKind::InvalidData {
            return malformed(stage, relative_path);
        }
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

        use crate::linux_pytest::snapshot_policy::{
            SnapshotPipelineAttemptBucketV1, SnapshotPipelineForwardStageV1,
            SnapshotPipelineStageV1,
        };

        use super::*;

        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

        fn complete_raw_statx(mask: u32) -> libc::statx {
            let mut raw = unsafe { MaybeUninit::<libc::statx>::zeroed().assume_init() };
            raw.stx_mask = mask;
            raw.stx_mode = u16::try_from(libc::S_IFREG | 0o640).unwrap();
            raw.stx_uid = 1_001;
            raw.stx_gid = 1_002;
            raw.stx_nlink = 7;
            raw.stx_ino = 0x1122_3344_5566_7788;
            raw.stx_size = 0x8877_6655_4433_2211;
            raw.stx_mnt_id = 0x0102_0304_0506_0708;
            raw.stx_dev_major = 259;
            raw.stx_dev_minor = 65_535;
            raw.stx_atime.tv_sec = -11;
            raw.stx_atime.tv_nsec = 101;
            raw.stx_mtime.tv_sec = 22;
            raw.stx_mtime.tv_nsec = 999_999_999;
            raw.stx_ctime.tv_sec = -33;
            raw.stx_ctime.tv_nsec = 303;
            raw.stx_btime.tv_sec = 44;
            raw.stx_btime.tv_nsec = 404;
            raw
        }

        fn expected_source_statx(btime: Option<TimespecV1>) -> SourceStatxV1 {
            SourceStatxV1::for_test(
                0x0102_0304_0506_0708,
                259,
                65_535,
                0x1122_3344_5566_7788,
                libc::S_IFREG | 0o640,
                1_001,
                1_002,
                7,
                0x8877_6655_4433_2211,
                TimespecV1 {
                    seconds: -11,
                    nanoseconds: 101,
                },
                TimespecV1 {
                    seconds: 22,
                    nanoseconds: 999_999_999,
                },
                TimespecV1 {
                    seconds: -33,
                    nanoseconds: 303,
                },
                btime,
            )
        }

        #[test]
        fn source_statx_decoder_preserves_exact_commitment_with_btime() {
            let raw = complete_raw_statx(SOURCE_TREE_REQUESTED_STATX_MASK_V1);
            let decoded = SourceStatxV1::from_linux_statx_v1(&raw).unwrap();
            let expected = expected_source_statx(Some(TimespecV1 {
                seconds: 44,
                nanoseconds: 404,
            }));

            assert_eq!(decoded, expected);
            assert_eq!(
                decoded.commitment_bytes_v1(),
                expected.commitment_bytes_v1()
            );
        }

        #[test]
        fn source_statx_decoder_ignores_unreturned_btime_storage() {
            let mut raw = complete_raw_statx(SOURCE_TREE_REQUIRED_STATX_MASK_V1);
            raw.stx_btime.tv_nsec = u32::MAX;

            let decoded = SourceStatxV1::from_linux_statx_v1(&raw).unwrap();
            let expected = expected_source_statx(None);
            assert_eq!(decoded, expected);
            assert_eq!(
                decoded.commitment_bytes_v1(),
                expected.commitment_bytes_v1()
            );
            assert_eq!(decoded.commitment_bytes_v1()[89], 0);
        }

        #[test]
        fn source_statx_decoder_rejects_each_missing_required_mask_bit() {
            let required_bits = [
                libc::STATX_TYPE,
                libc::STATX_MODE,
                libc::STATX_NLINK,
                libc::STATX_UID,
                libc::STATX_GID,
                libc::STATX_ATIME,
                libc::STATX_MTIME,
                libc::STATX_CTIME,
                libc::STATX_INO,
                libc::STATX_SIZE,
                STATX_MNT_ID_V1,
            ];

            for missing in required_bits {
                let raw = complete_raw_statx(SOURCE_TREE_REQUESTED_STATX_MASK_V1 & !missing);
                let error = SourceStatxV1::from_linux_statx_v1(&raw).unwrap_err();
                assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
            }
        }

        #[test]
        fn source_statx_decoder_rejects_each_invalid_returned_timestamp() {
            for timestamp_index in 0..4 {
                let mut raw = complete_raw_statx(SOURCE_TREE_REQUESTED_STATX_MASK_V1);
                match timestamp_index {
                    0 => raw.stx_atime.tv_nsec = 1_000_000_000,
                    1 => raw.stx_mtime.tv_nsec = 1_000_000_000,
                    2 => raw.stx_ctime.tv_nsec = 1_000_000_000,
                    3 => raw.stx_btime.tv_nsec = 1_000_000_000,
                    _ => unreachable!(),
                }

                let error = SourceStatxV1::from_linux_statx_v1(&raw).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(error.raw_os_error(), None);
            }
        }

        #[test]
        fn source_statx_decoder_errors_map_to_exact_typed_refusals() {
            let malformed = map_statx_error(
                SourceTreeStageV1::InspectEntry,
                b"file",
                io::Error::from(io::ErrorKind::InvalidData),
            );
            assert_eq!(
                malformed.reason(),
                SourceTreeFailureReasonV1::MalformedKernelResponse
            );
            assert_eq!(malformed.errno(), None);

            let unavailable = map_statx_error(
                SourceTreeStageV1::InspectEntry,
                b"file",
                io::Error::from_raw_os_error(libc::EOPNOTSUPP),
            );
            assert_eq!(
                unavailable.reason(),
                SourceTreeFailureReasonV1::RequiredKernelCapability
            );
            assert_eq!(unavailable.errno(), Some(libc::EOPNOTSUPP));
        }

        struct TestAttemptGateV1 {
            remaining: Cell<u64>,
            charged: Cell<u64>,
        }

        impl TestAttemptGateV1 {
            const fn new(remaining: u64) -> Self {
                Self {
                    remaining: Cell::new(remaining),
                    charged: Cell::new(0),
                }
            }
        }

        impl AttemptGateV1 for TestAttemptGateV1 {
            fn run_attempt<T>(
                &self,
                attempt: impl FnOnce() -> T,
            ) -> Result<T, SnapshotPipelineResourceErrorV1> {
                let Some(remaining) = self.remaining.get().checked_sub(1) else {
                    return Err(source_observation_budget_exhausted());
                };
                self.remaining.set(remaining);
                self.charged.set(self.charged.get() + 1);
                Ok(attempt())
            }
        }

        const fn source_observation_budget_exhausted() -> SnapshotPipelineResourceErrorV1 {
            SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                stage: SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::SourceObservation,
                ),
                bucket: SnapshotPipelineAttemptBucketV1::Forward,
            }
        }

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

        #[derive(Default)]
        struct FirstAttemptHooks {
            duplicate_calls: Cell<u64>,
        }

        impl EnumerationHooks for FirstAttemptHooks {
            fn duplicate_fd_once(&self, _fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
                self.duplicate_calls.set(self.duplicate_calls.get() + 1);
                Err(io::Error::from_raw_os_error(libc::EIO))
            }

            fn list_xattrs(&self, _fd: RawFd, _output: Option<&mut [u8]>) -> io::Result<usize> {
                unreachable!("zero budget must stop before xattr observation")
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                _name: &CStr,
                _output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                unreachable!("zero budget must stop before xattr observation")
            }
        }

        struct EagainOpenHooksV1 {
            calls: Cell<u64>,
            eagain_before_success: u64,
        }

        impl EnumerationHooks for EagainOpenHooksV1 {
            fn openat2_once(
                &self,
                parent: BorrowedFd<'_>,
                name: &CStr,
                flags: i32,
                resolve: u64,
            ) -> io::Result<OwnedFd> {
                let call = self.calls.get() + 1;
                self.calls.set(call);
                if call <= self.eagain_before_success {
                    Err(io::Error::from_raw_os_error(libc::EAGAIN))
                } else {
                    raw_openat2_once(parent, name, flags, resolve)
                }
            }

            fn list_xattrs(&self, _fd: RawFd, _output: Option<&mut [u8]>) -> io::Result<usize> {
                unreachable!("the direct openat2 retry test does not inspect xattrs")
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                _name: &CStr,
                _output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                unreachable!("the direct openat2 retry test does not inspect xattrs")
            }
        }

        type BarrierAction = Box<dyn FnOnce() -> io::Result<()>>;

        #[derive(Default)]
        struct TestHooks {
            directory_action: RefCell<Option<(Vec<u8>, BarrierAction)>>,
            leaf_action: RefCell<Option<(Vec<u8>, BarrierAction)>>,
            symlink_targets: BTreeMap<Vec<u8>, Vec<u8>>,
            destination_observation: bool,
            list_xattr_calls: Cell<u64>,
            symlink_xattr_calls: Cell<u64>,
            readlink_calls: Cell<u64>,
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

            fn with_symlink_target(relative_path: &[u8], target: &[u8]) -> Self {
                Self {
                    symlink_targets: BTreeMap::from([(relative_path.to_vec(), target.to_vec())]),
                    ..Self::default()
                }
            }

            fn destination_observation() -> Self {
                Self {
                    destination_observation: true,
                    ..Self::default()
                }
            }
        }

        impl EnumerationHooks for TestHooks {
            fn list_xattrs(&self, fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
                self.list_xattr_calls.set(self.list_xattr_calls.get() + 1);
                if self.destination_observation {
                    let mut status = MaybeUninit::<libc::stat>::zeroed();
                    // SAFETY: `status` points to writable storage for one
                    // `libc::stat`; the traversal keeps `fd` live for this hook.
                    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // SAFETY: successful `fstat` initialized the full value.
                    let status = unsafe { status.assume_init() };
                    if status.st_mode & libc::S_IFMT == libc::S_IFLNK {
                        self.symlink_xattr_calls
                            .set(self.symlink_xattr_calls.get() + 1);
                    }
                }
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

            fn read_symlink(
                &self,
                _fd: RawFd,
                relative_path: &[u8],
                output: &mut [u8],
            ) -> io::Result<usize> {
                self.readlink_calls.set(self.readlink_calls.get() + 1);
                let target = self
                    .symlink_targets
                    .get(relative_path)
                    .expect("test symlink target must be explicit");
                let used = output.len().min(target.len());
                output[..used].copy_from_slice(&target[..used]);
                Ok(used)
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

            fn directory_open_flags(&self) -> i32 {
                // These unit fixtures are owned by the current user but do
                // not represent a real `QualifiedNoAtimeSourceViewV1`.
                // `O_NOATIME` makes their directory reads deterministic
                // without forging timestamps or weakening the production
                // capability boundary.
                source_directory_open_flags() | libc::O_NOATIME
            }

            fn rejects_symlinks_before_xattrs(&self) -> bool {
                self.destination_observation
            }

            fn observe_live_tree_fds(&self, depth: u16, live: u32) {
                self.fd_observations.borrow_mut().push((depth, live));
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum OpenedFdRoleV1 {
            EntryHandle,
            DirectoryReader,
            ReopenedName,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum AttemptEventV1 {
            DuplicateFd,
            OpenEntryHandle,
            OpenDirectoryReader,
            OpenReopenedName,
            InspectEntryHandleStatx,
            InspectDirectoryReaderStatx,
            ListXattrsSize,
            ListXattrsValue,
            SeekDirectory,
            ReadDirectory,
            RevalidateDirectoryReaderStatx,
            RevalidatePinnedHandleStatx,
            RevalidateReopenedNameStatx,
        }

        /// Records only hook calls that stand in for a charged kernel attempt.
        /// Pure barriers and FD-peak observers are deliberately excluded.
        #[derive(Default)]
        struct CountingEnumerationHooksV1 {
            events: RefCell<Vec<AttemptEventV1>>,
            opened_fds: RefCell<BTreeMap<RawFd, OpenedFdRoleV1>>,
            path_open_calls: Cell<u8>,
            entry_statx_calls: Cell<u8>,
            directory_statx_calls: Cell<u8>,
        }

        impl CountingEnumerationHooksV1 {
            fn record(&self, event: AttemptEventV1) {
                self.events.borrow_mut().push(event);
            }

            fn into_events(self) -> Vec<AttemptEventV1> {
                self.events.into_inner()
            }
        }

        impl EnumerationHooks for CountingEnumerationHooksV1 {
            fn duplicate_fd_once(&self, fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
                self.record(AttemptEventV1::DuplicateFd);
                raw_duplicate_fd_once(fd)
            }

            fn openat2_once(
                &self,
                parent: BorrowedFd<'_>,
                name: &CStr,
                flags: i32,
                resolve: u64,
            ) -> io::Result<OwnedFd> {
                let role = if flags & libc::O_DIRECTORY != 0 {
                    self.record(AttemptEventV1::OpenDirectoryReader);
                    OpenedFdRoleV1::DirectoryReader
                } else {
                    let path_open_call = self.path_open_calls.get();
                    self.path_open_calls.set(path_open_call + 1);
                    if path_open_call == 0 {
                        self.record(AttemptEventV1::OpenEntryHandle);
                        OpenedFdRoleV1::EntryHandle
                    } else {
                        self.record(AttemptEventV1::OpenReopenedName);
                        OpenedFdRoleV1::ReopenedName
                    }
                };
                let opened = raw_openat2_once(parent, name, flags, resolve)?;
                self.opened_fds
                    .borrow_mut()
                    .insert(opened.as_raw_fd(), role);
                Ok(opened)
            }

            fn statx_once(&self, fd: BorrowedFd<'_>) -> io::Result<SourceStatxV1> {
                let role = self
                    .opened_fds
                    .borrow()
                    .get(&fd.as_raw_fd())
                    .copied()
                    .expect("every inspected descriptor is opened through the counting hook");
                let event = match role {
                    OpenedFdRoleV1::EntryHandle => {
                        let call = self.entry_statx_calls.get();
                        self.entry_statx_calls.set(call + 1);
                        if call == 0 {
                            AttemptEventV1::InspectEntryHandleStatx
                        } else {
                            AttemptEventV1::RevalidatePinnedHandleStatx
                        }
                    }
                    OpenedFdRoleV1::DirectoryReader => {
                        let call = self.directory_statx_calls.get();
                        self.directory_statx_calls.set(call + 1);
                        if call == 0 {
                            AttemptEventV1::InspectDirectoryReaderStatx
                        } else {
                            AttemptEventV1::RevalidateDirectoryReaderStatx
                        }
                    }
                    OpenedFdRoleV1::ReopenedName => AttemptEventV1::RevalidateReopenedNameStatx,
                };
                self.record(event);
                raw_statx_identity_once(fd)
            }

            fn lseek_once(
                &self,
                fd: BorrowedFd<'_>,
                offset: libc::off_t,
                whence: i32,
            ) -> io::Result<u64> {
                self.record(AttemptEventV1::SeekDirectory);
                raw_lseek_once(fd, offset, whence)
            }

            fn getdents64_once(&self, fd: BorrowedFd<'_>, output: &mut [u8]) -> io::Result<usize> {
                self.record(AttemptEventV1::ReadDirectory);
                raw_getdents64_once(fd, output)
            }

            fn list_xattrs(&self, _fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
                self.record(if output.is_some() {
                    AttemptEventV1::ListXattrsValue
                } else {
                    AttemptEventV1::ListXattrsSize
                });
                Ok(0)
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                _name: &CStr,
                _output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                unreachable!("an empty synthetic xattr list cannot request a value")
            }

            fn read_symlink(
                &self,
                _fd: RawFd,
                _relative_path: &[u8],
                _output: &mut [u8],
            ) -> io::Result<usize> {
                unreachable!("the whole-tree fixture contains no symlink")
            }

            fn directory_open_flags(&self) -> i32 {
                source_directory_open_flags() | libc::O_NOATIME
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
            let mut visitor = MaterializationVisitorAdapterV1 { visitor };
            match enumerate_source_tree_view_at_with(
                parent.as_fd(),
                c"tree",
                policy,
                &UnmeteredAttemptGateV1,
                hooks,
                &mut visitor,
            ) {
                Ok(plan) => Ok(plan),
                Err(TraversalFailureV1::Leaf(error)) => Err(error),
                Err(TraversalFailureV1::Resource(_)) => {
                    unreachable!("the test-only unmetered attempt gate cannot exhaust")
                }
            }
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
        fn zero_budget_stops_before_the_first_raw_attempt() {
            let tree = TestTree::new();
            let parent = tree.open_parent();
            let gate = TestAttemptGateV1::new(0);
            let hooks = FirstAttemptHooks::default();
            let mut visitor = RecordingVisitor::default();

            let error = {
                let mut adapter = MaterializationVisitorAdapterV1 {
                    visitor: &mut visitor,
                };
                enumerate_source_tree_view_at_with(
                    parent.as_fd(),
                    c"tree",
                    policy(1, 1),
                    &gate,
                    &hooks,
                    &mut adapter,
                )
                .unwrap_err()
            };
            let TraversalFailureV1::Resource(error) = error else {
                panic!("zero budget must produce a resource failure")
            };
            assert_eq!(error, source_observation_budget_exhausted());
            assert_eq!(gate.remaining.get(), 0);
            assert_eq!(gate.charged.get(), 0);
            assert_eq!(hooks.duplicate_calls.get(), 0);
            assert!(visitor.events.is_empty());
        }

        #[test]
        fn getdents_retry_succeeds_on_exact_n_and_exhausts_after_n_interrupts() {
            let mut success_calls = 0;
            let size = getdents64_with_retry(&UnmeteredAttemptGateV1, 3, || {
                success_calls += 1;
                if success_calls == 3 {
                    Ok(17)
                } else {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                }
            })
            .unwrap();
            assert_eq!(size, 17);
            assert_eq!(success_calls, 3);

            let mut exhausted_calls = 0;
            let error = getdents64_with_retry(&UnmeteredAttemptGateV1, 3, || {
                exhausted_calls += 1;
                Err(io::Error::from_raw_os_error(libc::EINTR))
            })
            .unwrap_err();
            let TraversalFailureV1::Leaf(error) = error else {
                panic!("the unmetered attempt gate cannot exhaust")
            };
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(exhausted_calls, 3);

            let failure = io_failure(SourceTreeStageV1::EnumerateDirectory, b"dir", error);
            assert_eq!(failure.stage(), SourceTreeStageV1::EnumerateDirectory);
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::Io);
            assert_eq!(failure.errno(), Some(libc::EINTR));
        }

        #[test]
        fn getdents_charges_each_attempt_and_stops_before_n_plus_one() {
            let exact_gate = TestAttemptGateV1::new(3);
            let mut exact_calls = 0;
            let size = getdents64_with_retry(&exact_gate, 3, || {
                exact_calls += 1;
                if exact_calls == 3 {
                    Ok(17)
                } else {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                }
            })
            .unwrap();
            assert_eq!(size, 17);
            assert_eq!(exact_calls, 3);
            assert_eq!(exact_gate.charged.get(), 3);
            assert_eq!(exact_gate.remaining.get(), 0);

            let short_gate = TestAttemptGateV1::new(2);
            let mut short_calls = 0;
            let error = getdents64_with_retry(&short_gate, 3, || {
                short_calls += 1;
                Err::<usize, _>(io::Error::from_raw_os_error(libc::EINTR))
            })
            .unwrap_err();
            let TraversalFailureV1::Resource(error) = error else {
                panic!("N - 1 budget must fail before raw attempt N")
            };
            assert_eq!(error, source_observation_budget_exhausted());
            assert_eq!(short_calls, 2);
            assert_eq!(short_gate.charged.get(), 2);
            assert_eq!(short_gate.remaining.get(), 0);
        }

        #[test]
        fn openat2_eagain_retry_charges_exact_n_and_stops_before_n_plus_one() {
            let tree = TestTree::new();
            let parent = tree.open_parent();
            let exact_gate = TestAttemptGateV1::new(3);
            let exact_hooks = EagainOpenHooksV1 {
                calls: Cell::new(0),
                eagain_before_success: 2,
            };
            let opened = openat2_owned(
                &exact_gate,
                &exact_hooks,
                parent.as_fd(),
                c"tree",
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                SOURCE_RESOLVE,
                3,
            )
            .expect("attempt N must succeed");
            drop(opened);
            assert_eq!(exact_hooks.calls.get(), 3);
            assert_eq!(exact_gate.charged.get(), 3);
            assert_eq!(exact_gate.remaining.get(), 0);

            let short_gate = TestAttemptGateV1::new(2);
            let short_hooks = EagainOpenHooksV1 {
                calls: Cell::new(0),
                eagain_before_success: 2,
            };
            let error = openat2_owned(
                &short_gate,
                &short_hooks,
                parent.as_fd(),
                c"tree",
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                SOURCE_RESOLVE,
                3,
            )
            .unwrap_err();
            let TraversalFailureV1::Resource(error) = error else {
                panic!("N - 1 must fail before raw openat2 attempt N")
            };
            assert_eq!(error, source_observation_budget_exhausted());
            assert_eq!(short_hooks.calls.get(), 2);
            assert_eq!(short_gate.charged.get(), 2);
            assert_eq!(short_gate.remaining.get(), 0);
        }

        #[test]
        fn whole_empty_directory_charges_every_attempt_and_stops_before_final_name_statx() {
            struct AttemptRunV1 {
                result: Result<(), SnapshotPipelineResourceErrorV1>,
                charged: u64,
                remaining: u64,
                events: Vec<AttemptEventV1>,
            }

            fn run(tree: &TestTree, budget: u64) -> AttemptRunV1 {
                let parent = tree.open_parent();
                let gate = TestAttemptGateV1::new(budget);
                let hooks = CountingEnumerationHooksV1::default();
                let mut visitor = RecordingVisitor::default();
                let result = {
                    let mut adapter = MaterializationVisitorAdapterV1 {
                        visitor: &mut visitor,
                    };
                    enumerate_source_tree_view_at_with(
                        parent.as_fd(),
                        c"tree",
                        policy(1, 1),
                        &gate,
                        &hooks,
                        &mut adapter,
                    )
                };
                let result = match result {
                    Ok(_) => Ok(()),
                    Err(TraversalFailureV1::Resource(error)) => Err(error),
                    Err(TraversalFailureV1::Leaf(_)) => {
                        panic!("the attempt-accounting fixture must not produce a leaf failure")
                    }
                };
                AttemptRunV1 {
                    result,
                    charged: gate.charged.get(),
                    remaining: gate.remaining.get(),
                    events: hooks.into_events(),
                }
            }

            let tree = TestTree::new();
            let generous = run(&tree, 10_000);
            generous
                .result
                .expect("a generous attempt budget must enumerate the empty tree");
            let exact = u64::try_from(generous.events.len()).unwrap();
            assert_eq!(
                generous.charged, exact,
                "every attempted hook call must be charged"
            );
            assert_eq!(
                generous.events.last(),
                Some(&AttemptEventV1::RevalidateReopenedNameStatx),
                "the whole-tree success path must end by inspecting the reopened name"
            );

            let exact_run = run(&tree, exact);
            exact_run
                .result
                .expect("the exact successful budget must be sufficient");
            assert_eq!(exact_run.charged, exact);
            assert_eq!(exact_run.remaining, 0);
            assert_eq!(exact_run.events, generous.events);

            let short = run(&tree, exact - 1);
            let error = short
                .result
                .expect_err("N - 1 must fail closed as source-observation exhaustion");
            assert_eq!(error, source_observation_budget_exhausted());
            assert_eq!(short.charged, exact - 1);
            assert_eq!(short.remaining, 0);
            assert_eq!(short.events, generous.events[..generous.events.len() - 1]);
            assert!(
                !short
                    .events
                    .contains(&AttemptEventV1::RevalidateReopenedNameStatx)
            );
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
            assert_eq!(
                KernelHooks::SOURCE.directory_open_flags(),
                source_directory_open_flags()
            );
            assert_eq!(
                KernelHooks::DESTINATION.directory_open_flags(),
                source_directory_open_flags() | libc::O_NOATIME
            );
            assert!(!KernelHooks::SOURCE.rejects_symlinks_before_xattrs());
            assert!(KernelHooks::DESTINATION.rejects_symlinks_before_xattrs());
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
            let failure = {
                let mut adapter = MaterializationVisitorAdapterV1 {
                    visitor: &mut visitor,
                };
                enumerate_source_tree_view_at_with(
                    root.as_fd(),
                    c"proc",
                    policy(2, 2),
                    &UnmeteredAttemptGateV1,
                    &TestHooks::default(),
                    &mut adapter,
                )
                .unwrap_err()
            };
            let TraversalFailureV1::Leaf(failure) = failure else {
                panic!("the test-only unmetered attempt gate cannot exhaust")
            };
            let failure = source_failure(failure);
            assert_eq!(failure.stage(), SourceTreeStageV1::OpenEntry);
            assert_eq!(failure.reason(), SourceTreeFailureReasonV1::MountCrossing);
            assert_eq!(failure.errno(), Some(libc::EXDEV));
            assert!(visitor.events.is_empty());
        }

        #[test]
        fn destination_symlink_refuses_after_statx_without_xattrs_or_readlink() {
            let tree = TestTree::new();
            std::os::unix::fs::symlink("target", tree.root.join("link")).unwrap();
            let hooks = TestHooks::destination_observation();
            let mut visitor = RecordingVisitor::default();

            let failure =
                source_failure(enumerate(&tree, policy(2, 4), &hooks, &mut visitor).unwrap_err());

            assert_eq!(failure.stage(), SourceTreeStageV1::InspectEntry);
            assert_eq!(
                failure.reason(),
                SourceTreeFailureReasonV1::UnsupportedObject
            );
            // A stable empty-xattr capture makes two passes of size + value
            // calls for the root directory. The inspected file-type marker
            // independently proves none of those calls targeted the symlink.
            assert_eq!(hooks.list_xattr_calls.get(), 4);
            assert_eq!(hooks.symlink_xattr_calls.get(), 0);
            assert_eq!(hooks.readlink_calls.get(), 0);
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

            // The actual symlink supplies kernel identity and file type. The
            // explicit target hook avoids mutating its atime on this
            // unqualified disposable fixture; production still uses
            // `readlinkat` only after source-view qualification.
            let hooks = TestHooks::with_symlink_target(b"s", b"target");
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
        fn directory_name_replacement_with_equal_membership_is_refused() {
            let tree = TestTree::new();
            let root = tree.root.clone();
            let displaced = tree.parent.join("displaced-tree");
            let hooks = TestHooks::mutate_directory(b"", move || {
                fs::rename(&root, displaced)?;
                fs::create_dir(root)
            });
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
            enumerate(&deep, policy(8, 16), &hooks, &mut visitor).unwrap();
            let committed_bound = 2 * 8 + 5;
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

    pub(super) fn enumerate_source_tree_view_charged_at<V: SourceObservationTreeVisitorV1>(
        _source_view: QualifiedNoAtimeSourceViewV1<'_>,
        _root_name: &CStr,
        _session: &SnapshotSourceObservationSessionV1<'_>,
        _visitor: &mut V,
    ) -> Result<
        SourceTreePlanV1,
        SnapshotSourceObservationErrorV1<SourceTreeAcquireFailureV1<V::Error>>,
    > {
        Err(SnapshotSourceObservationErrorV1::Leaf(
            unsupported_platform(),
        ))
    }

    #[cfg(test)]
    pub(super) fn enumerate_source_tree_view_at<V: SourceTreeVisitorV1>(
        _source_view: QualifiedNoAtimeSourceViewV1<'_>,
        _root_name: &CStr,
        _policy: SourceEnumerationPolicyV1,
        _visitor: &mut V,
    ) -> Result<SourceTreePlanV1, SourceTreeAcquireFailureV1<V::Error>> {
        Err(unsupported_platform())
    }

    fn unsupported_platform<E>() -> SourceTreeAcquireFailureV1<E> {
        #[cfg(not(target_os = "linux"))]
        let code = RefusalCode::UnsupportedOs;
        #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
        let code = RefusalCode::UnsupportedArchitecture;
        SourceTreeAcquireFailureV1::Source(SourceTreeFailureV1::new(
            code,
            SourceTreeStageV1::ValidatePolicy,
            SourceTreeFailureReasonV1::RequiredKernelCapability,
            None,
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
    fn source_tree_acquire_failure_debug_redacts_visitor_path_and_source() {
        let failure = SourceTreeAcquireFailureV1::Visitor {
            stage: SourceTreeStageV1::VisitRegular,
            relative_path: b"path-secret-91".to_vec(),
            source: "source-secret-73",
        };

        let rendered = format!("{failure:?}");
        assert!(rendered.contains("VisitRegular"));
        assert_eq!(rendered.matches("<redacted>").count(), 2);
        assert!(!rendered.contains("path-secret-91"));
        assert!(!rendered.contains("source-secret-73"));
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
        assert_eq!(committed.regular_copy.syscall_attempts(), 3);
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
            + 2 * std::mem::size_of::<ExtentV1>() as u64
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

        let mut spare_capacity = Vec::with_capacity(8);
        spare_capacity.push(ExtentV1 {
            offset: 0,
            length: 1,
        });
        let spare_capacity =
            SourceRegularEvidenceV1::checked(FileContentDigest([8; 32]), spare_capacity, 1)
                .unwrap();
        let allocated_bytes =
            spare_capacity.data_extents.capacity() as u64 * std::mem::size_of::<ExtentV1>() as u64;
        assert!(allocated_bytes > std::mem::size_of::<ExtentV1>() as u64);
        assert_eq!(
            validate_regular_evidence(&spare_capacity, 1, 1, allocated_bytes),
            Ok(allocated_bytes)
        );
        assert_eq!(
            validate_regular_evidence(&spare_capacity, 1, 1, allocated_bytes - 1)
                .unwrap_err()
                .reason(),
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
    fn source_view_and_regular_visit_authorities_are_linear() {
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
        <SourceObservedRegularVisitV1<'static, 'static> as AmbiguousIfClone<_>>::probe();
        <SourceObservedRegularVisitV1<'static, 'static> as AmbiguousIfCopy<_>>::probe();
        <QualifiedNoAtimeSourceViewV1<'static> as AmbiguousIfClone<_>>::probe();
        <QualifiedNoAtimeSourceViewV1<'static> as AmbiguousIfCopy<_>>::probe();
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
        assert_eq!(policy.max_live_source_fds(), 2 * 16 + 5);
    }
}
